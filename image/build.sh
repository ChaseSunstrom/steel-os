#!/usr/bin/env bash
#
# build.sh — build a SteelOS image, its verity tree, and its signed UKI.
#
# The ordering here is the design, so it is worth stating before the code:
#
#   1. Build the root filesystem from a PINNED Arch snapshot.
#   2. Compute the dm-verity hash tree over it. This yields a root hash that did
#      not and could not exist before step 1 finished.
#   3. Build the UKI with that root hash inside its embedded command line.
#   4. Sign the UKI.
#
# Because the root hash is inside the thing being signed, signing the kernel
# signs the identity of the entire root filesystem. Any change to any block of
# /usr changes the root hash, which changes the UKI, which invalidates the
# signature. That is what makes this verified boot of the OS rather than
# verified boot of the kernel.
#
# Reversing steps 2 and 3 — signing a UKI and then computing verity — would
# produce something that looks identical and guarantees nothing.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE_DIR="$REPO_ROOT/image"
OUT_DIR="${STEELOS_OUT:-$IMAGE_DIR/out}"

MANIFEST=${STEELOS_MANIFEST:-$REPO_ROOT/image/manifest.default.toml}
CHANNEL=${STEELOS_CHANNEL:-stable}

# Signing key material. Never in the repo; supplied by the CI secret store or by
# a local key for development builds.
SB_KEY=${STEELOS_SB_KEY:-}
SB_CERT=${STEELOS_SB_CERT:-}
VERITY_KEY=${STEELOS_VERITY_KEY:-}
VERITY_CERT=${STEELOS_VERITY_CERT:-}

die() { printf 'build: %s\n' "$*" >&2; exit 1; }
note() { printf '\033[1mbuild:\033[0m %s\n' "$*" >&2; }

# --- 0. Preflight -------------------------------------------------------------

for tool in mkosi veritysetup ukify systemd-measure sbsign openssl; do
  command -v "$tool" >/dev/null || die "$tool is required but not installed"
done

[[ -f $MANIFEST ]] || die "manifest not found: $MANIFEST"

# Read the snapshot pin. Building against "current" makes reproducibility a lie,
# and Arch moves every day — so this is a hard failure, not a warning.
SNAPSHOT=$(sed -n 's/^[[:space:]]*snapshot[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$MANIFEST" | head -1)
[[ -n $SNAPSHOT ]] || die "the manifest has no snapshot pin; refusing to build against a moving target"
[[ $SNAPSHOT =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "snapshot must be YYYY-MM-DD, got: $SNAPSHOT"

KERNEL_PKG=$(sed -n 's/^[[:space:]]*kernel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$MANIFEST" | head -1)
KERNEL_PKG=${KERNEL_PKG:-linux-hardened}

# Every timestamp in the image comes from the snapshot date rather than the wall
# clock, so two builds of the same manifest on different days are identical.
SOURCE_DATE_EPOCH=$(date -u -d "$SNAPSHOT" +%s)
export SOURCE_DATE_EPOCH TZ=UTC LC_ALL=C.UTF-8

MIRROR="https://archive.archlinux.org/repos/${SNAPSHOT//-//}/"

note "snapshot   $SNAPSHOT"
note "mirror     $MIRROR"
note "kernel     $KERNEL_PKG"
note "epoch      $SOURCE_DATE_EPOCH"

mkdir -p "$OUT_DIR"

# --- 1. Root filesystem -------------------------------------------------------

note "building the root filesystem"

mkosi \
  --directory "$IMAGE_DIR" \
  --output-dir "$OUT_DIR" \
  --mirror "$MIRROR" \
  --environment "STEELOS_CHANNEL=$CHANNEL" \
  --environment "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --package "$KERNEL_PKG" \
  --format disk \
  build

ROOT_IMG="$OUT_DIR/steelos.root.raw"
[[ -f $ROOT_IMG ]] || die "mkosi did not produce $ROOT_IMG"

# --- 2. Verity ----------------------------------------------------------------
#
# This must happen after the root image is final and before the UKI is built.

note "computing the dm-verity hash tree"

VERITY_IMG="$OUT_DIR/steelos.verity.raw"

# --salt is fixed rather than random. A random salt would make two builds of the
# same manifest produce different root hashes, which would break the
# reproducibility claim outright — the salt adds nothing here because the data
# being hashed is public.
ROOT_HASH=$(veritysetup format "$ROOT_IMG" "$VERITY_IMG" \
  --salt=0000000000000000000000000000000000000000000000000000000000000000 \
  --hash=sha256 \
  --data-block-size=4096 \
  --hash-block-size=4096 \
  | sed -n 's/^Root hash:[[:space:]]*//p')

[[ -n $ROOT_HASH ]] || die "veritysetup produced no root hash"
[[ ${#ROOT_HASH} -eq 64 ]] || die "root hash is not a sha256: $ROOT_HASH"

note "root hash  $ROOT_HASH"
printf '%s\n' "$ROOT_HASH" > "$OUT_DIR/steelos.roothash"

# Verify immediately rather than trusting the tool. This costs seconds and
# catches a corrupted hash tree before it becomes an unbootable machine.
veritysetup verify "$ROOT_IMG" "$VERITY_IMG" "$ROOT_HASH" >/dev/null \
  || die "the hash tree does not verify against the image it was just built from"

# Sign the root hash separately, so systemd-veritysetup can check it against the
# kernel keyring. That gives a second independent path to the same guarantee.
if [[ -n $VERITY_KEY && -n $VERITY_CERT ]]; then
  note "signing the verity root hash"
  printf '%s' "$ROOT_HASH" \
    | openssl smime -sign -nocerts -noattr -binary \
        -signer "$VERITY_CERT" -inkey "$VERITY_KEY" -outform der \
        -out "$OUT_DIR/steelos.roothash.p7s"
else
  note "WARNING: no verity signing key; the root hash is unsigned"
  note "         a development build only — this will not boot under our"
  note "         enrolled Secure Boot keys, which is the intended behaviour"
fi

# --- 3. UKI -------------------------------------------------------------------

note "building the UKI with the root hash embedded"

CMDLINE_FILE="$OUT_DIR/cmdline"
{
  # The hardening fragment the packages ship, so what CI bakes in and what
  # steel-check audits against cannot drift apart.
  grep -v '^[[:space:]]*#' \
    "$REPO_ROOT/packages/steel-kernel-hardening/src/cmdline/hardening" | tr '\n' ' '
  grep -v '^[[:space:]]*#' \
    "$REPO_ROOT/packages/steel-apparmor/src/apparmor-cmdline" | tr '\n' ' '
  # Image-only settings: safe here because modules are built and signed during
  # this build, so there is no DKMS-at-runtime path to break.
  printf ' lockdown=confidentiality module.sig_enforce=1'
  printf ' intel_iommu=on amd_iommu=force_isolation iommu.passthrough=0'
  # The crux.
  printf ' roothash=%s systemd.verity=yes' "$ROOT_HASH"
  printf ' rw quiet splash'
} > "$CMDLINE_FILE"

note "cmdline    $(tr -s ' ' < "$CMDLINE_FILE")"

UKI="$OUT_DIR/steelos.efi"

ukify build \
  --linux "$OUT_DIR/steelos.vmlinuz" \
  --initrd "$OUT_DIR/steelos.initrd" \
  --cmdline "@$CMDLINE_FILE" \
  --os-release "@$OUT_DIR/steelos.os-release" \
  --splash "$IMAGE_DIR/splash.bmp" \
  --uname "$(cat "$OUT_DIR/steelos.kver" 2>/dev/null || echo unknown)" \
  --output "$UKI"

# CLAUDE.md gotcha 5: some firmware chokes on large PE binaries. Fail the build
# rather than shipping an image that boots in QEMU and not on a ThinkPad.
UKI_SIZE=$(stat -c %s "$UKI")
UKI_MAX=$((60 * 1024 * 1024))
note "UKI size   $((UKI_SIZE / 1024 / 1024)) MiB"
if (( UKI_SIZE > UKI_MAX )); then
  die "UKI is $((UKI_SIZE / 1024 / 1024)) MiB, over the $((UKI_MAX / 1024 / 1024)) MiB limit.
     Some firmware refuses to load PE binaries this large. Trim the initrd —
     firmware for undetected hardware is usually the bulk of it."
fi

# --- 4. Sign ------------------------------------------------------------------

if [[ -n $SB_KEY && -n $SB_CERT ]]; then
  note "signing the UKI"
  sbsign --key "$SB_KEY" --cert "$SB_CERT" --output "$UKI" "$UKI"
  sbverify --cert "$SB_CERT" "$UKI" >/dev/null \
    || die "the UKI does not verify against the certificate it was just signed with"

  # Pre-compute the PCR 11 policy so TPM enrollment can bind to this UKI's
  # measurement before it has ever been booted. Without this, TPM unlock cannot
  # be sealed until after the first boot of each new image — which would mean
  # every update breaks auto-unlock.
  note "pre-computing PCR 11 policy digests"
  systemd-measure calculate \
    --linux "$OUT_DIR/steelos.vmlinuz" \
    --initrd "$OUT_DIR/steelos.initrd" \
    --cmdline "@$CMDLINE_FILE" \
    --bank sha256 > "$OUT_DIR/steelos.pcrs" || \
    note "WARNING: PCR pre-computation failed; TPM unlock will need a reseal after update"
else
  note "WARNING: no Secure Boot signing key; the UKI is unsigned"
fi

# --- 5. Identity and provenance ----------------------------------------------

GENERATION="steelos-${SNAPSHOT//-/}-$(printf '%s' "$ROOT_HASH" | cut -c1-8)"
MANIFEST_HASH=$(sha256sum "$MANIFEST" | cut -d' ' -f1)

cat > "$OUT_DIR/steelos.metadata" <<EOF
image-id=$GENERATION
channel=$CHANNEL
snapshot=$SNAPSHOT
kernel=$KERNEL_PKG
roothash=$ROOT_HASH
manifest-hash=sha256:$MANIFEST_HASH
source-date-epoch=$SOURCE_DATE_EPOCH
EOF

# Publish hashes so anyone can check a rebuild against ours. "Same inputs =>
# same image hash" is only a meaningful claim if the hashes are public.
( cd "$OUT_DIR" && sha256sum steelos.root.raw steelos.verity.raw steelos.efi \
    > steelos.sha256 )

note "generation $GENERATION"
note "artefacts in $OUT_DIR"
cat "$OUT_DIR/steelos.sha256" >&2
