#!/usr/bin/env bash
#
# prepare-workspace-source.sh — snapshot the repository into the source tarball
# that steel-check, steel-config and steel-installer build from.
#
# Three packages are built from the workspace rather than from files next to
# their PKGBUILD: the two Rust binaries and the Calamares configuration. makepkg
# cannot take a directory as a local source, and reaching out of the package
# directory with $startdir is rejected by namcap and breaks the moment anyone
# builds in a clean chroot. A tarball is the mechanism makepkg is built around,
# so this produces one.
#
# Run it before makepkg in those three directories. CI and iso/build.sh both do.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=${STEELOS_VERSION:-0.1.0}
PREFIX="steel-os-$VERSION"
TARBALL="$PREFIX.tar.gz"

# The packages that consume it. Adding a fourth means adding it here as well as
# to its own source=() array.
CONSUMERS=(steel-check steel-config steel-installer)

note() { printf '\033[1mprepare-source:\033[0m %s\n' "$*" >&2; }

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT

# What goes in: sources only. Build output, VCS metadata and previously
# generated tarballs are excluded — a tarball that contains the last tarball
# grows without bound and makes the build depend on its own history.
tar --create --file - --directory "$REPO_ROOT" \
  --exclude-vcs \
  --exclude='./target' \
  --exclude='./packages/*/pkg' \
  --exclude='./packages/*/src' \
  --exclude='./packages/*/*.pkg.tar.*' \
  --exclude='./packages/*/steel-os-*.tar.gz' \
  --exclude='./image/out' \
  --exclude='./iso/out' \
  --exclude='./iso/work' \
  . | tar --extract --file - --directory "$staging" --one-top-level="$PREFIX"

# Deterministic: fixed ownership, sorted entries, and mtimes pinned to
# SOURCE_DATE_EPOCH. "Same inputs, same artefact" has to hold here too, or the
# reproducibility claim stops at the image boundary.
tar --create --gzip --file "$staging/$TARBALL" \
  --directory "$staging" \
  --sort=name \
  --mtime="@${SOURCE_DATE_EPOCH:-0}" \
  --owner=0 --group=0 --numeric-owner \
  "$PREFIX"

for pkg in "${CONSUMERS[@]}"; do
  install -Dm644 "$staging/$TARBALL" "$REPO_ROOT/packages/$pkg/$TARBALL"
done

note "wrote $TARBALL ($(du -h "$staging/$TARBALL" | cut -f1)) into ${#CONSUMERS[@]} package directories"
