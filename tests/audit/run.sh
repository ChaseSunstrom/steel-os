#!/usr/bin/env bash
#
# tests/audit — assertions shared by steel-check and CI.
#
# The unit tests inside steel-check verify individual checks. This verifies
# properties of the suite as a whole, against synthetic sysroots:
#
#   1. A fully-configured system audits green. If the check suite cannot pass
#      even in principle, it is a list of complaints rather than a definition of
#      done, and people stop reading it.
#
#   2. The deniability requirement holds end to end. Two sysroots identical
#      except that one has duress fully configured must produce byte-identical
#      output. CLAUDE.md states this as a requirement on steel-check and says
#      the assertion is itself a CI test; this is that test.
#
#   3. The JSON contract is stable and complete — every check appears, with a
#      status, on every run.
#
# Run: tests/audit/run.sh [path-to-steel-check]

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
STEEL_CHECK=${1:-$REPO_ROOT/target/release/steel-check}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass_count=0
fail_count=0

ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; pass_count=$((pass_count + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fail_count=$((fail_count + 1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[[ -x $STEEL_CHECK ]] || {
  echo "tests/audit: $STEEL_CHECK not found or not executable" >&2
  echo "build it first: cargo build --release" >&2
  exit 2
}

# ---------------------------------------------------------------------------
# Fixture construction
# ---------------------------------------------------------------------------

# A sysroot representing a correctly-configured image deployment. Everything the
# checks read is synthesised here, which is also a readable specification of
# what "configured" means — if a check needs something this function does not
# provide, that check will not pass on a real machine either.
make_green_sysroot() {
  local root=$1
  mkdir -p "$root"

  # --- kernel: effective sysctls, read from /proc/sys ---------------------
  local conf="$REPO_ROOT/packages/steel-kernel-hardening/99-steel-hardening.conf"
  while IFS= read -r line; do
    [[ $line =~ ^[[:space:]]*# ]] && continue
    [[ -z ${line// } ]] && continue
    local key value path
    key=${line%%=*}; key=${key// }
    value=${line#*=}; value=${value# }
    path="$root/proc/sys/${key//./\/}"
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$value" > "$path"
  done < "$conf"
  mkdir -p "$root/proc/sys/user"
  printf '10000\n' > "$root/proc/sys/user/max_user_namespaces"
  printf '6.12.0-hardened1\n' > "$root/proc/sys/kernel/osrelease"

  # --- kernel: cmdline ----------------------------------------------------
  local fragment
  fragment=$(grep -v '^[[:space:]]*#' \
    "$REPO_ROOT/packages/steel-kernel-hardening/hardening" | tr '\n' ' ')
  mkdir -p "$root/proc"
  printf 'ro quiet roothash=deadbeefcafe %s\n' "$fragment" > "$root/proc/cmdline"

  # --- kernel: lockdown, module signatures, blacklist ---------------------
  mkdir -p "$root/sys/kernel/security" "$root/sys/module/module/parameters"
  printf 'none integrity [confidentiality]\n' > "$root/sys/kernel/security/lockdown"
  printf 'Y\n' > "$root/sys/module/module/parameters/sig_enforce"
  mkdir -p "$root/etc/modprobe.d"
  cp "$REPO_ROOT/packages/steel-kernel-hardening/99-steel-blacklist.conf" \
     "$root/etc/modprobe.d/"
  printf '' > "$root/proc/modules"

  # --- memory -------------------------------------------------------------
  mkdir -p "$root/usr/lib"
  printf '' > "$root/usr/lib/libhardened_malloc-light.so"
  printf '/usr/lib/libhardened_malloc-light.so\n' > "$root/etc/ld.so.preload"
  mkdir -p "$root/sys/kernel/iommu_groups/0"
  mkdir -p "$root/sys/kernel/mm/mem_encrypt"
  printf '1\n' > "$root/sys/kernel/mm/mem_encrypt/active"

  # --- filesystem ---------------------------------------------------------
  cat > "$root/proc/mounts" <<'EOF'
/dev/mapper/steelos-root / erofs ro,relatime 0 0
/dev/mapper/steelos-root /usr erofs ro,relatime 0 0
/dev/mapper/steelos-var /var btrfs rw,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0
EOF
  mkdir -p "$root/etc/udisks2"
  cp "$REPO_ROOT/packages/steel-desktop/udisks2-mount-options.conf" \
     "$root/etc/udisks2/mount_options.conf"
  mkdir -p "$root/etc/security/limits.d" "$root/etc/systemd/coredump.conf.d"
  cp "$REPO_ROOT/packages/steel-kernel-hardening/99-steel-coredump.conf" \
     "$root/etc/security/limits.d/"
  cp "$REPO_ROOT/packages/steel-kernel-hardening/coredump-99-steel.conf" \
     "$root/etc/systemd/coredump.conf.d/99-steel.conf"

  # --- network ------------------------------------------------------------
  mkdir -p "$root/etc/systemd/resolved.conf.d" "$root/etc/NetworkManager/conf.d"
  cp "$REPO_ROOT/packages/steel-network/resolved.conf" \
     "$root/etc/systemd/resolved.conf.d/99-steel.conf"
  cp "$REPO_ROOT/packages/steel-network/nm-steel-privacy.conf" \
     "$root/etc/NetworkManager/conf.d/99-steel-privacy.conf"
  cp "$REPO_ROOT/packages/steel-network/nm-steel-connectivity.conf" \
     "$root/etc/NetworkManager/conf.d/98-steel-connectivity.conf"
  mkdir -p "$root/usr/lib/steelos"
  printf '' > "$root/usr/lib/steelos/captive-portal-helper"

  # --- sandbox ------------------------------------------------------------
  mkdir -p "$root/sys/module/apparmor/parameters" "$root/sys/kernel/security/apparmor"
  printf 'Y\n' > "$root/sys/module/apparmor/parameters/enabled"
  printf '/usr/bin/firefox (enforce)\n/usr/lib/systemd/systemd-resolved (enforce)\n' \
    > "$root/sys/kernel/security/apparmor/profiles"
  mkdir -p "$root/usr/bin" "$root/var/lib/flatpak/overrides"
  printf '' > "$root/usr/bin/flatpak"
  cp "$REPO_ROOT/packages/steel-sandbox/flatpak-global-override" \
     "$root/var/lib/flatpak/overrides/global"
  printf '' > "$root/usr/bin/bubblejail"
  mkdir -p "$root/usr/share/steel-sandbox/bubblejail"
  cp "$REPO_ROOT"/packages/steel-sandbox/*.toml \
     "$root/usr/share/steel-sandbox/bubblejail/"

  # --- identity -----------------------------------------------------------
  # No human users: homectl is not available in CI, so a populated passwd would
  # only produce an unavoidable Skip with less information in it.
  printf 'root:x:0:0::/root:/bin/bash\n' > "$root/etc/passwd"

  # --- storage ------------------------------------------------------------
  mkdir -p "$root/sys/block/dm-0/dm" "$root/sys/block/dm-1/dm"
  printf 'steelos-root\n' > "$root/sys/block/dm-0/dm/name"
  printf 'CRYPT-VERITY-abc123-steelos-root\n' > "$root/sys/block/dm-0/dm/uuid"
  printf 'steelos-var\n' > "$root/sys/block/dm-1/dm/name"
  printf 'CRYPT-LUKS2-def456-steelos-var\n' > "$root/sys/block/dm-1/dm/uuid"
  printf 'Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n' > "$root/proc/swaps"

  # --- deployment ---------------------------------------------------------
  printf 'steelos-20260727-a\n' > "$root/usr/lib/steelos/image-id"
  printf 'sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0\n' \
    > "$root/usr/lib/steelos/manifest-hash"
  mkdir -p "$root/var/lib/steelos/slots/a" "$root/var/lib/steelos/slots/b"
  mkdir -p "$root/efi/loader/entries"
  for entry in steelos-a steelos-b maintenance recovery; do
    printf 'title SteelOS\n' > "$root/efi/loader/entries/$entry.conf"
  done

  # --- backup -------------------------------------------------------------
  mkdir -p "$root/var/lib/steelos/backup/keys"
  cat > "$root/var/lib/steelos/backup/state" <<'EOF'
target=restic:sftp:backup.example:/steelos
append_only_verified=yes
last_run_age_days=1
last_verify_age_days=6
EOF
  printf 'age1examplepublickeyonly000000000000000000000000000000000000\n' \
    > "$root/var/lib/steelos/backup/keys/outer.pub"

  # --- duress: universal, identical on every install ----------------------
  mkdir -p "$root/usr/lib/initcpio/hooks" "$root/usr/lib/initcpio/install"
  printf '' > "$root/usr/lib/initcpio/hooks/steel-duress"
  printf '' > "$root/usr/lib/initcpio/install/steel-duress"
  head -c $((4 * 1024 * 1024)) /dev/zero > "$root/var/lib/steelos/custody.region"
  printf 'steelos-var UUID=00000000-0000-0000-0000-000000000000 none luks\n' \
    > "$root/etc/crypttab"

  mkdir -p "$root/etc/steelos"
  printf 'balanced\n' > "$root/etc/steelos/preset"
}

# ---------------------------------------------------------------------------
# 1. A configured system audits green
# ---------------------------------------------------------------------------

head_ "A fully-configured system audits green"

green="$WORK/green"
make_green_sysroot "$green"

set +e
"$STEEL_CHECK" --sysroot "$green" --no-color > "$WORK/green.txt" 2>&1
green_status=$?
set -e

if [[ $green_status -eq 0 ]]; then
  ok "exit status 0 with no failures"
else
  bad "exit status $green_status; failing checks:"
  grep -E '^\s+FAIL' "$WORK/green.txt" | sed 's/^/        /'
fi

# Skips are legitimate — several checks need a live system, and CI does not have
# sbctl, nft, or a TPM. But a suite that is almost entirely skips proves nothing,
# so assert that a meaningful fraction actually ran.
passed=$(grep -cE '^\s+PASS' "$WORK/green.txt" || true)
if (( passed >= 20 )); then
  ok "$passed checks actively passed (not skipped)"
else
  bad "only $passed checks actively passed; the fixture is not exercising the suite"
fi

# ---------------------------------------------------------------------------
# 2. The deniability requirement
# ---------------------------------------------------------------------------

head_ "Output is byte-identical with and without duress configured"

plain="$WORK/den-plain"
configured="$WORK/den-configured"
make_green_sysroot "$plain"
make_green_sysroot "$configured"

# The only difference: duress is fully configured on the second machine, inside
# the encrypted volume where it belongs. An examiner running steel-check from a
# context that has not unlocked the real volume must not be able to tell.
mkdir -p "$configured/var/lib/steelos/private"
cat > "$configured/var/lib/steelos/private/duress-drill" <<'EOF'
configured=yes
playbook=A
decoy=yes
decoy_volume=/dev/disk/by-uuid/11111111-1111-1111-1111-111111111111
duress_action=decoy-and-wipe
last_drill_age_days=9
EOF

for fmt in "--no-color" "--json"; do
  "$STEEL_CHECK" --sysroot "$plain" $fmt > "$WORK/plain.out" 2>&1 || true
  "$STEEL_CHECK" --sysroot "$configured" $fmt > "$WORK/configured.out" 2>&1 || true
  if cmp -s "$WORK/plain.out" "$WORK/configured.out"; then
    ok "${fmt} output is identical"
  else
    bad "${fmt} output DIFFERS — duress configuration is leaking:"
    diff "$WORK/plain.out" "$WORK/configured.out" | head -20 | sed 's/^/        /'
  fi
done

# The same must hold in verbose mode, which prints evidence for passing checks
# too — that is the mode most likely to leak something the summary hides.
"$STEEL_CHECK" --sysroot "$plain" --no-color -v > "$WORK/plain.v" 2>&1 || true
"$STEEL_CHECK" --sysroot "$configured" --no-color -v > "$WORK/configured.v" 2>&1 || true
if cmp -s "$WORK/plain.v" "$WORK/configured.v"; then
  ok "verbose output is identical"
else
  bad "verbose output DIFFERS:"
  diff "$WORK/plain.v" "$WORK/configured.v" | head -20 | sed 's/^/        /'
fi

# ---------------------------------------------------------------------------
# 3. Output stability and JSON completeness
# ---------------------------------------------------------------------------

head_ "Output contract"

"$STEEL_CHECK" --sysroot "$green" --json > "$WORK/a.json" 2>&1 || true
"$STEEL_CHECK" --sysroot "$green" --json > "$WORK/b.json" 2>&1 || true
if cmp -s "$WORK/a.json" "$WORK/b.json"; then
  ok "repeated runs produce identical output (no volatile fields)"
else
  bad "repeated runs differ; something volatile is in the report"
fi

listed=$("$STEEL_CHECK" --list | wc -l)
reported=$(grep -c '"id":' "$WORK/a.json" || true)
if [[ $listed -eq $reported ]]; then
  ok "all $listed checks appear in the report (none skipped out of the run)"
else
  bad "--list reports $listed checks but the JSON contains $reported"
fi

if grep -qE '"(timestamp|hostname|machine_id|uuid|date)"' "$WORK/a.json"; then
  bad "the report contains a volatile field"
else
  ok "no volatile fields in the JSON report"
fi

# Every check must document why it exists and how to turn it off. This is
# design principles 6 and 7 as an executable assertion rather than a habit.
missing_docs=0
while read -r id _; do
  if ! "$STEEL_CHECK" --explain "$id" 2>/dev/null | grep -q "How to turn it off:"; then
    bad "$id has no escape hatch documented"
    missing_docs=$((missing_docs + 1))
  fi
done < <("$STEEL_CHECK" --list)
(( missing_docs == 0 )) && ok "every check documents a rationale and an escape hatch"

# ---------------------------------------------------------------------------
# 4. Preset behaviour
# ---------------------------------------------------------------------------

head_ "Presets change what is required"

"$STEEL_CHECK" --sysroot "$green" --preset strict --no-color > "$WORK/strict.txt" 2>&1 || true
"$STEEL_CHECK" --sysroot "$green" --preset compatible --no-color > "$WORK/compat.txt" 2>&1 || true

if grep -q 'usbguard' "$WORK/strict.txt" && \
   grep -qE 'SKIP.*sandbox\.usbguard' "$WORK/compat.txt"; then
  ok "USBGuard is required under strict and skipped otherwise"
else
  bad "the preset does not change USBGuard's applicability"
fi

if ! cmp -s "$WORK/strict.txt" "$WORK/compat.txt"; then
  ok "strict and compatible produce different audits"
else
  bad "the preset has no effect on the audit"
fi

# ---------------------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$pass_count" "$fail_count"
exit $(( fail_count > 0 ? 1 : 0 ))
