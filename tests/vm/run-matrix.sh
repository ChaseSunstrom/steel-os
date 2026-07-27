#!/usr/bin/env bash
#
# The VM test matrix. Gates every publish.
#
# From CLAUDE.md's definition of done:
#
#   "CI: install → boot → steel-check green → update → rollback → restore
#    drill, for all presets, unattended."
#
# The sequence matters as much as the contents. Each step depends on the one
# before it, and the ones people are tempted to skip — rollback and restore —
# are precisely the ones that only matter when something has already gone wrong,
# which is when nobody is in a position to test them.
#
# Two tests here exist because CLAUDE.md says the feature is not done without
# them:
#
#   * The demotion test deliberately ships a BROKEN image and asserts the
#     machine recovers unattended. A rollback path that has never rolled back
#     is not a rollback path.
#
#   * The restore drill installs, writes data, backs up, wipes, reinstalls from
#     the manifest, restores, and asserts equality. "If this test doesn't exist,
#     the backup feature isn't done."

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WORK=${STEELOS_VM_WORK:-$(mktemp -d)}
IMAGE=${STEELOS_IMAGE:-$REPO_ROOT/image/out/steelos.raw}
PRESETS=${STEELOS_PRESETS:-"balanced strict compatible"}

OVMF_CODE=${OVMF_CODE:-/usr/share/edk2/x64/OVMF_CODE.4m.fd}
OVMF_VARS=${OVMF_VARS:-/usr/share/edk2/x64/OVMF_VARS.4m.fd}

pass_count=0
fail_count=0

step()  { printf '\n\033[1m▸ %s\033[0m\n' "$*"; }
ok()    { printf '  \033[32mok\033[0m    %s\n' "$*"; pass_count=$((pass_count+1)); }
bad()   { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fail_count=$((fail_count+1)); }
info()  { printf '  %s\n' "$*"; }

for tool in qemu-system-x86_64 swtpm qemu-img; do
  command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 2; }
done

# --- VM plumbing --------------------------------------------------------------

# A software TPM per VM. Without one, TPM+PIN unlock and PCR binding cannot be
# tested at all — and those are the parts most likely to break silently on real
# hardware, so testing them in CI is the only coverage they get before a
# hardware pass.
start_swtpm() {
  local name=$1
  local dir="$WORK/$name/tpm"
  mkdir -p "$dir"
  swtpm socket --tpmstate "dir=$dir" \
    --ctrl "type=unixio,path=$dir/sock" \
    --tpm2 --daemon
  echo "$dir/sock"
}

boot_vm() {
  local name=$1 disk=$2 timeout=${3:-300}
  local tpm_sock
  tpm_sock=$(start_swtpm "$name")
  local vars="$WORK/$name/OVMF_VARS.fd"
  [[ -f $vars ]] || cp "$OVMF_VARS" "$vars"

  timeout "$timeout" qemu-system-x86_64 \
    -machine q35,smm=on,accel=kvm:tcg \
    -cpu max \
    -m 4096 \
    -smp 2 \
    -drive "if=pflash,format=raw,unit=0,file=$OVMF_CODE,readonly=on" \
    -drive "if=pflash,format=raw,unit=1,file=$vars" \
    -drive "file=$disk,format=qcow2,if=virtio" \
    -chardev "socket,id=chrtpm,path=$tpm_sock" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    -nographic \
    -serial "file:$WORK/$name/console.log" \
    -monitor none \
    || return $?
}

vm_exec() {
  # Commands reach the guest over the serial console with a marker, so the
  # matrix needs no SSH and therefore no listening port in the test image —
  # which matters, because "no listening ports by default" is one of the
  # properties being tested.
  local name=$1; shift
  printf 'STEELOS-EXEC %s\n' "$*" > "$WORK/$name/console.in"
  grep -m1 "STEELOS-DONE" "$WORK/$name/console.log" >/dev/null
}

# --- 1. Unattended install of each preset ------------------------------------

test_install() {
  local preset=$1
  step "install: $preset"
  mkdir -p "$WORK/$preset"

  qemu-img create -f qcow2 "$WORK/$preset/disk.qcow2" 128G >/dev/null

  cat > "$WORK/$preset/answers.conf" <<EOF
# Unattended install answers.
steelosPreset=$preset
steelosUseTpm=yes
steelosDnsProvider=quad9
steelosMacMode=stable
steelosProfiles=test
steelosBackupTarget=rest:http://10.0.2.2:8000/repo
EOF

  if boot_vm "$preset" "$WORK/$preset/disk.qcow2" 900; then
    ok "$preset installed"
  else
    bad "$preset install failed (console: $WORK/$preset/console.log)"
    return 1
  fi
}

# --- 2. Boot and audit --------------------------------------------------------

test_steel_check() {
  local preset=$1
  step "steel-check: $preset"

  boot_vm "$preset" "$WORK/$preset/disk.qcow2" 300 || { bad "$preset would not boot"; return 1; }
  vm_exec "$preset" "steel-check --json > /tmp/check.json; echo STEELOS-DONE"

  local failures
  failures=$(grep -c '"status": "fail"' "$WORK/$preset/check.json" || echo 0)
  if (( failures == 0 )); then
    ok "$preset: steel-check green"
  else
    bad "$preset: $failures failing checks"
    grep -B4 '"status": "fail"' "$WORK/$preset/check.json" | grep '"id"' | sed 's/^/        /'
  fi

  # The preset must actually change the audit. A preset that produces identical
  # output regardless of setting is a preset that does nothing.
  local strict_only
  strict_only=$(grep -A2 'sandbox.usbguard' "$WORK/$preset/check.json" | grep -o '"status": "[a-z]*"')
  case "$preset/$strict_only" in
    strict/*fail*|strict/*pass*) ok "strict requires USBGuard" ;;
    balanced/*skip*|compatible/*skip*) ok "$preset skips USBGuard" ;;
    *) bad "$preset: USBGuard applicability is wrong ($strict_only)" ;;
  esac
}

# --- 3. Update ----------------------------------------------------------------

test_update() {
  local preset=$1
  step "update: $preset"
  boot_vm "$preset" "$WORK/$preset/disk.qcow2" 300 || return 1

  vm_exec "$preset" "steelctl history --json > /tmp/before.json; echo STEELOS-DONE"
  vm_exec "$preset" "steelctl update; echo STEELOS-DONE"
  boot_vm "$preset" "$WORK/$preset/disk.qcow2" 300 || { bad "$preset did not boot after update"; return 1; }
  vm_exec "$preset" "steelctl history --json > /tmp/after.json; echo STEELOS-DONE"

  # Both slots must be populated afterwards. A machine with one slot has no
  # rollback target, which is the state rollback exists for.
  local slots
  slots=$(grep -c '"slot"' "$WORK/$preset/after.json" || echo 0)
  if (( slots >= 2 )); then
    ok "$preset: both slots populated after update"
  else
    bad "$preset: only $slots slot(s) after update — nothing to roll back to"
  fi
}

# --- 4. Rollback --------------------------------------------------------------

test_rollback() {
  local preset=$1
  step "rollback: $preset"
  boot_vm "$preset" "$WORK/$preset/disk.qcow2" 300 || return 1

  vm_exec "$preset" "steelctl status > /tmp/before.txt; echo STEELOS-DONE"
  vm_exec "$preset" "steelctl rollback; echo STEELOS-DONE"
  boot_vm "$preset" "$WORK/$preset/disk.qcow2" 300 || { bad "$preset did not boot after rollback"; return 1; }
  vm_exec "$preset" "steelctl status > /tmp/after.txt; echo STEELOS-DONE"

  if ! cmp -s "$WORK/$preset/before.txt" "$WORK/$preset/after.txt"; then
    ok "$preset: rollback changed the running generation"
  else
    bad "$preset: rollback did not change anything"
  fi
}

# --- 5. Automatic demotion ----------------------------------------------------
#
# The milestone from Phase 2, and the test people are most tempted to skip:
# "deliberately ship a broken image; the machine demotes and boots the previous
# generation unattended."
#
# It has to be unattended. A machine that boots to a black screen cannot show a
# menu or run a rollback command, so an operator-assisted test proves nothing
# about the case that matters.

test_demotion() {
  local preset=$1
  step "automatic demotion: $preset"
  boot_vm "$preset" "$WORK/$preset/disk.qcow2" 300 || return 1

  vm_exec "$preset" "steelctl status | grep generation > /tmp/good.txt; echo STEELOS-DONE"
  local good
  good=$(cat "$WORK/$preset/good.txt")

  # Stage something that cannot reach boot-complete.target. Breaking the health
  # check specifically, rather than the kernel, tests the signal we actually
  # wired up (gotcha 6) rather than the trivial case.
  info "staging a deployment whose health check will fail"
  vm_exec "$preset" "steel-boot stage /usr/lib/steelos/test-broken.efi; echo STEELOS-DONE"

  # Three attempts, then the bootloader gives up on it. No interaction.
  local attempt
  for attempt in 1 2 3 4; do
    info "boot attempt $attempt"
    boot_vm "$preset" "$WORK/$preset/disk.qcow2" 300 || true
  done

  vm_exec "$preset" "steelctl status | grep generation > /tmp/now.txt; echo STEELOS-DONE"
  if grep -qF "$good" "$WORK/$preset/now.txt"; then
    ok "$preset: demoted to the previous generation with no interaction"
  else
    bad "$preset: did NOT demote. A bad update would be unrecoverable for every
        user who took it — they cannot see a boot menu on a machine that does
        not display anything."
  fi
}

# --- 6. Restore drill ---------------------------------------------------------
#
# "If this test doesn't exist, the backup feature isn't done."

test_restore_drill() {
  local preset=$1
  step "restore drill: $preset"

  boot_vm "$preset" "$WORK/$preset/disk.qcow2" 300 || return 1

  info "writing known data"
  vm_exec "$preset" "mkdir -p /home/test/drill && \
    for i in \$(seq 1 200); do head -c 4096 /dev/urandom > /home/test/drill/\$i; done && \
    sha256sum /home/test/drill/* | sort > /tmp/before.sha256; echo STEELOS-DONE"

  info "backing up, then verifying the backup restores"
  vm_exec "$preset" "runuser -u test -- steel-backup run; echo STEELOS-DONE"
  vm_exec "$preset" "runuser -u test -- steel-backup verify; echo STEELOS-DONE"

  info "wiping and reinstalling from the manifest"
  rm -f "$WORK/$preset/disk.qcow2"
  qemu-img create -f qcow2 "$WORK/$preset/disk.qcow2" 128G >/dev/null
  boot_vm "$preset" "$WORK/$preset/disk.qcow2" 900 || { bad "reinstall failed"; return 1; }

  info "restoring"
  vm_exec "$preset" "runuser -u test -- restic restore latest --target /; echo STEELOS-DONE"
  vm_exec "$preset" "sha256sum /home/test/drill/* | sort > /tmp/after.sha256; echo STEELOS-DONE"

  if cmp -s "$WORK/$preset/before.sha256" "$WORK/$preset/after.sha256"; then
    ok "$preset: every file restored byte-identical"
  else
    bad "$preset: restored data does not match. The backup feature is not done."
    diff "$WORK/$preset/before.sha256" "$WORK/$preset/after.sha256" | head -10 | sed 's/^/        /'
  fi
}

# --- 7. Reproducibility -------------------------------------------------------

test_reproducible() {
  step "reproducibility"
  # Same manifest and snapshot pin must produce the same image hash. The claim
  # is checkable, so it gets checked rather than asserted in a README.
  local first second
  first=$(sha256sum "$IMAGE" | cut -d' ' -f1)
  info "rebuilding from the same manifest"
  STEELOS_OUT="$WORK/rebuild" "$REPO_ROOT/image/build.sh" >/dev/null 2>&1 || {
    bad "the rebuild failed"; return 1; }
  second=$(sha256sum "$WORK/rebuild/steelos.root.raw" | cut -d' ' -f1)

  if [[ $first == "$second" ]]; then
    ok "two builds of the same manifest produced the same image hash"
  else
    bad "image hashes differ between builds:
        $first
        $second
        Something non-deterministic got into the image. Check timestamps,
        machine-id, and cache generation order."
  fi
}

# --- 8. The deniability assertion --------------------------------------------

test_deniability() {
  local preset=$1
  step "deniability: $preset"
  boot_vm "$preset" "$WORK/$preset/disk.qcow2" 300 || return 1

  vm_exec "$preset" "steel-check --json > /tmp/unconfigured.json; echo STEELOS-DONE"
  vm_exec "$preset" "steel-duress configure --non-interactive --playbook A \
    --action alert-only; echo STEELOS-DONE"
  # From a context that has NOT unlocked the real volume.
  vm_exec "$preset" "rm -f /run/steelos/real-volume-unlocked; \
    steel-check --json > /tmp/configured.json; echo STEELOS-DONE"

  if cmp -s "$WORK/$preset/unconfigured.json" "$WORK/$preset/configured.json"; then
    ok "$preset: steel-check output is identical with and without duress configured"
  else
    bad "$preset: steel-check LEAKS duress configuration state"
    diff "$WORK/$preset/unconfigured.json" "$WORK/$preset/configured.json" \
      | head -20 | sed 's/^/        /'
  fi

  # And nothing in the ESP may differ either.
  vm_exec "$preset" "ls -la /efi/loader/entries /efi/EFI/Linux > /tmp/esp.txt; echo STEELOS-DONE"
  if grep -qiE 'decoy|duress|custody' "$WORK/$preset/esp.txt"; then
    bad "$preset: the ESP names a duress or decoy artefact"
  else
    ok "$preset: the ESP reveals nothing"
  fi
}

# --- Run ----------------------------------------------------------------------

printf '\033[1mSteelOS VM test matrix\033[0m\n'
printf 'presets: %s\n' "$PRESETS"
printf 'work:    %s\n' "$WORK"

for preset in $PRESETS; do
  test_install "$preset"       || continue
  test_steel_check "$preset"   || continue
  test_deniability "$preset"   || true
  test_update "$preset"        || true
  test_rollback "$preset"      || true
  test_demotion "$preset"      || true
  test_restore_drill "$preset" || true
done

test_reproducible || true

printf '\n%d passed, %d failed\n' "$pass_count" "$fail_count"
if (( fail_count > 0 )); then
  printf '\nA preset that fails to boot fails the release. Consoles are in %s\n' "$WORK"
  exit 1
fi
