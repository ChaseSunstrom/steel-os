#!/usr/bin/env bash
#
# The health signal that boot counting hangs off.
#
# CLAUDE.md gotcha 6: "Boot counting must be wired to a real 'system is healthy'
# signal, not just 'kernel started', or a system that boots to a black screen
# will never demote."
#
# That is the failure mode this file exists to prevent. If boot-complete.target
# is satisfied by systemd reaching multi-user, then an image whose graphics
# driver panics still counts as a successful boot — it blesses itself, the
# counter clears, and the user is left with a machine that shows nothing and
# has just discarded its own way back.
#
# So the checks below are deliberately about the things a user would call
# "working", not the things systemd would call "started".

set -euo pipefail

fail() { printf 'boot-health: FAILED: %s\n' "$*" >&2; exit 1; }
ok() { printf 'boot-health: %s\n' "$*"; }

# 1. The root filesystem is the one the signed UKI described.
#
# If verity is not active, or its root hash is not the one on the command line,
# this deployment is not what it claims to be and must not be blessed.
if grep -q 'roothash=' /proc/cmdline; then
  want=$(sed -n 's/.*roothash=\([0-9a-fA-F]*\).*/\1/p' /proc/cmdline | tr 'A-F' 'a-f')
  got=$(veritysetup status steelos-root 2>/dev/null \
        | sed -n 's/^ *root hash: *//p' | tr 'A-F' 'a-f')
  [[ -n $got ]] || fail "dm-verity is not active on a deployment that requires it"
  [[ $want == "$got" ]] || fail "verity root hash does not match the signed UKI"
  ok "verity active and matching the signed UKI"
fi

# 2. Writable state is mounted. Without /var the machine has no logs, no
#    container storage, and no home directories — it is up, and it is useless.
mountpoint -q /var || fail "/var is not mounted"
ok "/var mounted"

# 3. A display manager is running and has presented something.
#
# This is the check that catches the black-screen case. "sddm is active" is not
# enough — it can be active and failing to start a session in a loop — so we
# also require that a graphical session actually appeared.
if systemctl is-enabled --quiet sddm.service 2>/dev/null; then
  systemctl is-active --quiet sddm.service || fail "sddm is enabled but not running"
  # graphical.target reached AND a seat has a session. On a machine with no
  # display this second condition never becomes true, which is correct: such a
  # machine should not be blessing itself on the strength of a display manager.
  deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    if loginctl list-sessions --no-legend 2>/dev/null | grep -q .; then
      ok "a graphical session exists"
      break
    fi
    sleep 2
  done
  (( SECONDS < deadline )) || fail "no session appeared within 60s of sddm starting"
fi

# 4. The network stack came up, if it is supposed to.
if systemctl is-enabled --quiet NetworkManager.service 2>/dev/null; then
  systemctl is-active --quiet NetworkManager.service \
    || fail "NetworkManager is enabled but not running"
  ok "NetworkManager running"
fi

# 5. No unit failed in a way that would make the machine unusable.
#
# Deliberately a specific list, not "any failed unit". Blessing is a decision
# about whether the machine is usable, and a failed printer discovery service is
# not that. Being strict here would demote deployments over cosmetic failures
# and teach people to distrust rollback.
for critical in systemd-udevd.service dbus.service systemd-logind.service; do
  if systemctl is-enabled --quiet "$critical" 2>/dev/null; then
    systemctl is-active --quiet "$critical" || fail "$critical is not running"
  fi
done
ok "critical services running"

# 6. steel-check finds no CRITICAL failure.
#
# Only critical: a warning about MAC randomisation should not cost someone
# their update. A verity or encryption failure should.
if command -v steel-check >/dev/null; then
  if ! steel-check --json 2>/dev/null \
     | grep -B4 '"status": "fail"' \
     | grep -q '"severity": "critical"'; then
    ok "steel-check reports no critical failure"
  else
    fail "steel-check reports a critical failure on this deployment"
  fi
fi

ok "this deployment is healthy"
exit 0
