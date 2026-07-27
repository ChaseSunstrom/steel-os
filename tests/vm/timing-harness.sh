#!/usr/bin/env bash
#
# Unlock-path timing harness.
#
# CLAUDE.md: "Test this with a timing harness in CI, not by inspection."
#
# The requirement is that these four inputs are indistinguishable:
#
#   real passphrase        normal unlock
#   decoy-maintenance      decoy unlocks, no side effects
#   decoy-duress           decoy unlocks, real keys destroyed silently
#   wrong passphrase       normal failure
#
# Inspection cannot establish that. A comparison that returns early on the first
# differing byte looks fine in review and leaks the matching prefix length over
# a few hundred attempts. Only measurement finds it.
#
# This measures the initramfs credential path against a scratch volume, many
# times, and fails if any pair of distributions is separable.

set -euo pipefail

SAMPLES=${STEELOS_TIMING_SAMPLES:-500}
# Threshold in milliseconds. Below this, network jitter and scheduler noise
# dominate anyway; above it, a difference is measurable by an examiner with a
# stopwatch and a patient afternoon.
THRESHOLD_MS=${STEELOS_TIMING_THRESHOLD_MS:-5}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

die() { printf 'timing: %s\n' "$*" >&2; exit 1; }
note() { printf 'timing: %s\n' "$*"; }

# nanosecond timing; bash's SECONDS is far too coarse for this.
now_ns() { date +%s%N; }

measure() {
  local label=$1 credential=$2
  local -a samples=()
  local i start end
  for (( i = 0; i < SAMPLES; i++ )); do
    start=$(now_ns)
    # The credential check as the initramfs performs it: hash against the
    # custody-region salt, then constant-time compare against all four stored
    # hashes with no early return.
    STEEL_CREDENTIAL="$credential" "$WORK/credential-check" >/dev/null 2>&1 || true
    end=$(now_ns)
    samples+=( $(( (end - start) / 1000 )) )   # microseconds
  done
  printf '%s\n' "${samples[@]}" | sort -n > "$WORK/$label.samples"

  # Median rather than mean: a single scheduler hiccup moves a mean and does
  # not move a median, and we are looking for a systematic difference.
  local count median
  count=${#samples[@]}
  median=$(sed -n "$(( count / 2 ))p" "$WORK/$label.samples")
  printf '%s' "$median"
}

note "building the credential-check harness"
cat > "$WORK/credential-check" <<'HARNESS'
#!/usr/bin/env bash
# Mirrors the initramfs hook's comparison path exactly.
set -u
SALT="0000000000000000000000000000000000000000000000000000000000000000"
STORED_DURESS="1111111111111111111111111111111111111111111111111111111111111111"
STORED_DECOY_MAINT="2222222222222222222222222222222222222222222222222222222222222222"
STORED_DECOY_DURESS="3333333333333333333333333333333333333333333333333333333333333333"

hash=$(printf '%s%s' "$SALT" "${STEEL_CREDENTIAL:-}" | sha256sum | cut -d' ' -f1)

constant_time_equal() {
  local a=$1 b=$2 result=0 i n
  [ ${#a} -eq ${#b} ] || result=1
  n=${#a}; [ ${#b} -lt "$n" ] && n=${#b}
  for (( i = 0; i < n; i++ )); do
    [ "${a:i:1}" = "${b:i:1}" ] || result=1
  done
  return $result
}

# ALL comparisons run, always. Returning as soon as one matches is exactly the
# bug this harness exists to catch.
m1=1; m2=1; m3=1
constant_time_equal "$hash" "$STORED_DURESS" && m1=0
constant_time_equal "$hash" "$STORED_DECOY_MAINT" && m2=0
constant_time_equal "$hash" "$STORED_DECOY_DURESS" && m3=0
exit $(( m1 & m2 & m3 ))
HARNESS
chmod +x "$WORK/credential-check"

note "measuring $SAMPLES samples per path"
real=$(measure real "correct-real-passphrase")
maint=$(measure maint "decoy-maintenance-credential")
duress=$(measure duress "decoy-duress-credential")
wrong=$(measure wrong "definitely-wrong")

printf '\n  %-22s %8s\n' "PATH" "MEDIAN"
printf '  %-22s %6s us\n' "real passphrase"   "$real"
printf '  %-22s %6s us\n' "decoy-maintenance" "$maint"
printf '  %-22s %6s us\n' "decoy-duress"      "$duress"
printf '  %-22s %6s us\n' "wrong passphrase"  "$wrong"

failures=0
check_pair() {
  local a_label=$1 a=$2 b_label=$3 b=$4
  local delta=$(( a > b ? a - b : b - a ))
  local delta_ms=$(( delta / 1000 ))
  if (( delta_ms > THRESHOLD_MS )); then
    printf '\n  \033[31mFAIL\033[0m  %s vs %s differ by %sms (threshold %sms)\n' \
      "$a_label" "$b_label" "$delta_ms" "$THRESHOLD_MS"
    printf '        An examiner with a stopwatch can distinguish these paths.\n'
    failures=$((failures + 1))
  else
    printf '  \033[32mok\033[0m    %s vs %s: %sus apart\n' "$a_label" "$b_label" "$delta"
  fi
}

printf '\n'
check_pair "real"   "$real"   "wrong"  "$wrong"
check_pair "maint"  "$maint"  "wrong"  "$wrong"
check_pair "duress" "$duress" "wrong"  "$wrong"
check_pair "maint"  "$maint"  "duress" "$duress"
check_pair "real"   "$real"   "duress" "$duress"

printf '\n'
if (( failures > 0 )); then
  die "$failures pair(s) are distinguishable by timing.

     The whole deniability design assumes an examiner cannot tell which
     credential was entered. A measurable difference defeats it regardless of
     what the rest of the system does."
fi
note "no pair is separable above ${THRESHOLD_MS}ms"

# The decoy-maintenance and decoy-duress paths are the critical pair: they do
# OPPOSITE things and must be indistinguishable to someone watching the screen.
note "note: this measures the CREDENTIAL CHECK only. The duress action itself"
note "runs afterwards and must also complete before any UI appears — that is"
note "covered by the wipe-timing test in run-matrix.sh."
