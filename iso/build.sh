#!/usr/bin/env bash
#
# build.sh — build the SteelOS live installer ISO.
#
# Four steps, in this order, because each depends on the one before:
#
#   1. Build every steel-* package from packages/ in this checkout.
#   2. Build Calamares, which Arch does not ship in its official repositories.
#   3. Assemble those into a local pacman repository.
#   4. Run mkarchiso against a copy of iso/ whose pacman.conf points at it.
#
# Step 4 works on a COPY of the profile. mkarchiso needs a pacman.conf naming an
# absolute repository path, and the profile in the repository cannot know what
# that path will be, so the placeholder is substituted into the copy and the
# checked-in profile stays free of build-host specifics.
#
# Requires root (mkarchiso mounts things) and an Arch host or container with
# archiso installed. CI runs it in a privileged archlinux container; see
# .github/workflows/ci.yml.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ISO_DIR="$REPO_ROOT/iso"
OUT_DIR=${STEELOS_ISO_OUT:-$ISO_DIR/out}
WORK_DIR=${STEELOS_ISO_WORK:-$ISO_DIR/work}
REPO_DIR=${STEELOS_REPO_DIR:-$WORK_DIR/repo}
# Who to run makepkg as. makepkg refuses to run as root, so a build user is
# required even though everything else here needs root.
BUILD_USER=${STEELOS_BUILD_USER:-build}

# Every package built from packages/. steel-installer is included because the
# ISO installs the Calamares sequence from it rather than embedding a copy.
PACKAGES=(
  steel-check
  steel-config
  steel-kernel-hardening
  steel-malloc
  steel-network
  steel-sandbox
  steel-apparmor
  steel-desktop
  steel-identity
  steel-backup
  steel-duress
  steel-custody
  steel-vault
  steel-boot
  steel-base
  steel-installer
)

die() { printf 'iso/build: %s\n' "$*" >&2; exit 1; }
note() { printf '\033[1miso/build:\033[0m %s\n' "$*" >&2; }

# --- 0. Preflight -------------------------------------------------------------

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "must be run as root (mkarchiso mounts filesystems)"

for tool in mkarchiso makepkg repo-add pacman mksquashfs mkfs.fat mcopy; do
  command -v "$tool" >/dev/null || die "$tool is required but not installed
     Arch host: pacman -S archiso squashfs-tools dosfstools mtools"
done

id "$BUILD_USER" >/dev/null 2>&1 \
  || die "user '$BUILD_USER' does not exist; makepkg cannot run as root.
     Create one with: useradd -m $BUILD_USER"

mkdir -p "$OUT_DIR" "$WORK_DIR" "$REPO_DIR"
# makepkg runs as $BUILD_USER and writes into the work directory, so it has to
# be able to. Everything else here runs as root.
chown "$BUILD_USER" "$WORK_DIR"

# --- 1. The steel-* packages --------------------------------------------------

note "snapshotting the workspace for the packages that build from it"
"$REPO_ROOT/packages/prepare-workspace-source.sh"

note "building ${#PACKAGES[@]} packages from packages/"
for pkg in "${PACKAGES[@]}"; do
  [[ -f "$REPO_ROOT/packages/$pkg/PKGBUILD" ]] || die "no PKGBUILD for $pkg"
  note "  $pkg"
  # --nodeps because the dependency graph is between our own packages and is
  # satisfied at install time by the repository we are about to build, not at
  # build time. -f so a rebuild does not stop on an existing artefact.
  ( cd "$REPO_ROOT/packages/$pkg" \
    && chown -R "$BUILD_USER" . \
    && sudo -u "$BUILD_USER" makepkg --nodeps --noconfirm --clean -f )
done

# --- 2. Calamares -------------------------------------------------------------
#
# Arch does not ship Calamares in core or extra, so it is built from the AUR
# PKGBUILD. Deliberately not pulled from a third-party binary repository: this
# ISO installs an operating system whose entire claim is that you can verify
# what it is made of, and adding an unaudited binary repo to that build would be
# the single least defensible dependency in the project.

CALAMARES_DIR="$WORK_DIR/calamares-pkg"
if compgen -G "$REPO_DIR/calamares-*.pkg.tar.*" >/dev/null; then
  note "calamares already built; reusing it"
else
  note "building calamares from the AUR PKGBUILD"
  rm -rf "$CALAMARES_DIR"
  sudo -u "$BUILD_USER" git clone --depth 1 \
    https://aur.archlinux.org/calamares.git "$CALAMARES_DIR" \
    || die "could not clone the calamares AUR package"
  # -s installs makedepends; this needs the sudoers rule CI sets up.
  ( cd "$CALAMARES_DIR" && sudo -u "$BUILD_USER" makepkg -s --noconfirm --clean -f ) \
    || die "calamares failed to build"
  cp "$CALAMARES_DIR"/calamares-*.pkg.tar.* "$REPO_DIR/"
fi

# --- 3. The local repository --------------------------------------------------

note "assembling the local pacman repository at $REPO_DIR"
for pkg in "${PACKAGES[@]}"; do
  # Debug packages are build by-products, not something the ISO should carry.
  for artefact in "$REPO_ROOT/packages/$pkg"/*.pkg.tar.*; do
    [[ -e $artefact ]] || continue
    if [[ $artefact == *-debug-* ]]; then
      continue
    fi
    cp "$artefact" "$REPO_DIR/"
  done
done

rm -f "$REPO_DIR"/steelos.db* "$REPO_DIR"/steelos.files*
repo-add "$REPO_DIR/steelos.db.tar.gz" "$REPO_DIR"/*.pkg.tar.* >/dev/null
note "repository holds $(find "$REPO_DIR" -name '*.pkg.tar.*' | wc -l) packages"

# --- 4. mkarchiso -------------------------------------------------------------

PROFILE_DIR="$WORK_DIR/profile"
rm -rf "$PROFILE_DIR"
cp -a "$ISO_DIR" "$PROFILE_DIR"
# The copy must not contain the build's own output, or each rebuild embeds the
# previous ISO in the next one.
rm -rf "$PROFILE_DIR/work" "$PROFILE_DIR/out" "$PROFILE_DIR/build.sh"
sed -i "s|@STEELOS_REPO@|$REPO_DIR|" "$PROFILE_DIR/pacman.conf"
if grep -q '@STEELOS_REPO@' "$PROFILE_DIR/pacman.conf"; then
  die "the repository placeholder was not substituted"
fi

note "running mkarchiso"
mkarchiso -v -w "$WORK_DIR/archiso" -o "$OUT_DIR" "$PROFILE_DIR"

iso=$(find "$OUT_DIR" -maxdepth 1 -name '*.iso' -print -quit)
[[ -n $iso ]] || die "mkarchiso reported success but produced no ISO"

( cd "$OUT_DIR" && sha256sum "${iso##*/}" > "${iso##*/}.sha256" )
note "built ${iso##*/} ($(du -h "$iso" | cut -f1))"
cat "$iso.sha256"
