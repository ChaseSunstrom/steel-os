# SteelOS

An Arch-based desktop with an immutable, cryptographically verified root
filesystem, declarative package management, per-user encrypted homes, per-app
sandboxing by default, and atomic updates with rollback — all of it the default
state after a normal graphical install, not a weekend of manual work.

**Status: all seven phases implemented, nothing verified on hardware.** Every
component described below exists and every automated gate passes. No physical
machine has booted this, and the VM matrix has not been executed — it needs
QEMU, OVMF and swtpm. See [Where this actually is](#where-this-actually-is)
before relying on any of it.

## What it is, stated accurately

Two claims get made about projects like this one, and both would be false here.
The design document is explicit about not making them, so the README is too.

**This is not NixOS.** NixOS's guarantees come from a functional package model:
content-addressed store paths, hermetic builds, per-package generations, and the
ability to roll back a single package. Arch packages do not compose that way and
we are not rebuilding them. What SteelOS delivers is *image-level* declarative
configuration: a manifest produces an image, the image is staged in an inactive
slot, and a reboot activates it. Rollback is whole-system, not per-package.

**This is not GrapheneOS parity.** With the dm-verity root hash sealed inside a
signed UKI, SteelOS has verified boot of the root filesystem — not just of the
kernel. What remains missing is a hardware root of trust with insider-resistant
firmware. That is a PC hardware limitation rather than a design choice, but it
is a real gap and rounding it up to "verified boot like GrapheneOS" would be
dishonest.

**It is also not Tails, Whonix, or Qubes.** If you need anonymity, use the first
two. If you need a kernel exploit not to cross between your work and personal
environments, use Qubes — profiles here share one kernel, and a kernel 0-day
crosses them.

## The design in one paragraph

`/usr` is read-only and every block of it is verified against a dm-verity hash
tree on read. The root hash lives in the kernel command line, which lives inside
a signed UKI — so signing the kernel signs the identity of the entire root
filesystem, and offline tampering is detected at boot. Writable state is
confined to an encrypted `/var` and per-user systemd-homed volumes. Updates are
written to an inactive slot and take effect on reboot; a deployment that cannot
reach a healthy state is demoted automatically and the previous one boots.
Because `/usr` cannot be written, `pacman -S` at runtime is impossible by
construction rather than by policy — which is why Flatpak, containers, and
signed system extensions have to be good enough for everything a user actually
wants to install.

## Threat model

Everything in the design follows from this, so it is stated before anything
else. Full version in [docs/threat-model.md](docs/threat-model.md).

**In scope:** device theft while powered off; a malicious or compromised desktop
application; a malicious website or document; persistence after compromise;
offline tampering with the OS; a local network attacker; passive network
correlation; evil-maid tampering with the boot chain; cold-boot and DMA attacks;
user error and bad updates; coerced unlock — with
[serious caveats](docs/duress-and-deniability.md).

**Out of scope, and stated plainly rather than hedged:** compromised UEFI
firmware, Intel ME, or AMD PSP; hardware implants and targeted supply-chain
attacks; an attacker who has your unlock password and physical access; full
anonymity; a kernel 0-day escaping every sandbox layer (mitigated, not
prevented); malware that only needs to survive until the next reboot.

## Where this actually is

| Phase | What it delivers | State |
|---|---|---|
| 0 | Hardening packages + `steel-check` on plain Arch | Implemented, **runs today** |
| 1 | mkosi image build, verity, signed UKI | Implemented, never built |
| 2 | A/B slots, updates, boot counting, rollback | Implemented, never booted |
| 3 | `manifest.toml`, `steelctl apply`/`diff` | Implemented, unit-tested |
| 4 | homed profiles, sandbox policy, AppArmor, Nix | Implemented, never run |
| 5 | Backups, duress, decoy, custody, vault | Implemented; ORAM layer is a stub |
| 6 | ISO and Calamares installer | Implemented, never installed |
| 7 | VM matrix, timing harness, release pipeline | Implemented, matrix not executed |

**Phase 0 is the part you can use today.** The packages are config bundles that
work on any Arch install: `pacman -S steel-base && steel-check` comes back
green, and that is useful on its own.

**Everything else is written and reviewed, not verified.** That distinction
matters most in the boot chain, where a mistake means a machine that does not
start. `docs/known-issues.md` is specific about which gotchas are addressed with
an automated gate and which still need real hardware.

One thing is deliberately less than its name suggests: `steel-vault` manages a
small separately-keyed encrypted volume and enforces the size discipline, but
the write-only-ORAM block layer — the part that defeats a repeat-imaging
adversary — is **not implemented**. The tool says so before it creates anything.

## Try it now

```
git clone https://github.com/ChaseSunstrom/steel-os
cd steel-os

# The audit tool. No dependencies; it builds anywhere Rust does.
cargo build --release
./target/release/steel-check

# Audit a system other than the one you are on — a mounted disk, a container,
# a fixture tree. This is also how CI tests the suite.
./target/release/steel-check --sysroot /mnt --json

# Why does a measure exist, and how do I turn it off?
./target/release/steel-check --explain kernel.userns
```

On an Arch system, build and install the packages:

```
cd packages/steel-kernel-hardening && makepkg -si
```

Expect failures on the first `steel-check` run. That is the tool working: it
reports what is not in force rather than what is configured, and a fresh Arch
install has almost none of it.

## `steel-check` defines "done"

One command, pass/fail per measure, `--json` so CI and users share the same
assertions. The rule the project runs on: **every claim in user-facing material
must be verifiable by this tool.** If a claim cannot be checked, it does not get
made.

Three properties worth knowing about:

- **It reports what is in force, not what is configured.** Checks read
  `/proc/sys`, `/proc/mounts` and `/sys` wherever the distinction exists. The
  sharpest case is the allocator: a preload line pointing at a missing library
  is silently ignored by the dynamic loader, so nothing is protected and nothing
  warns you. `steel-check` calls that a failure, not a pass.

- **It has no dependencies.** This is the tool that decides whether a system is
  trustworthy, and it has to run in the recovery environment. JSON emission and
  argument parsing are hand-rolled and unit-tested rather than pulled in.

- **Its output contains no timestamps, hostnames, or run identifiers.** That is
  what makes the deniability requirement testable as a byte-for-byte comparison
  — see below.

Every check carries a rationale and a documented off-switch, and a test fails
the build if one does not. That is design principle 6 made mechanical: a user
who hits a broken app needs to find the one control responsible, or they will
disable all of them.

## The part that is easiest to get wrong

The duress and deniability features are the area of this design most likely to
give users false confidence, and false confidence here gets people hurt. Two
consequences are already enforced in code:

**Duress support ships on every install, always.** If it were a package a user
chooses, its presence on disk would itself be the evidence. So the initramfs
hook, the attempt counters, the maintenance boot entry, and a fixed-size custody
region exist on every machine, configured or not. Finding them proves only that
the machine runs SteelOS.

**`steel-check` produces byte-identical output on a machine with duress
configured and one without**, when run from a context that has not unlocked the
real volume. This is a CI test, not an aspiration: `tests/audit/run.sh` builds
two sysroots differing only in duress configuration and `cmp`s the output in
every format. The duress checks that read encrypted state do not read it at all
from a locked context — an examiner with `strace` learns from the attempt, not
just from the result.

What none of this achieves is covered honestly in
[docs/duress-and-deniability.md](docs/duress-and-deniability.md), including why
an adversary who simply keeps demanding another passphrase is not defeated by
any of it, and why for most at-risk users the right answer is not carrying the
data at all.

## Repository layout

```
image/       mkosi build definitions, verity, UKI, device layout
packages/    16 steel-* packages
steelctl/    manifest engine, generations, update/rollback (lib + bin)
calamares/   installer modules, including the comprehension check
iso/         archiso profile for the live installer
tools/       steel-check, steel-harden
tests/       audit assertions, VM matrix, timing harness
docs/        threat model, rationale, escape hatches, known issues
```

## What is checked automatically

```
cargo test --all                                    # 153 tests
tests/audit/run.sh                                  # 11 suite-level assertions
python3 calamares/modules/threatened/test_comprehension.py   # 13 tests
tests/vm/timing-harness.sh                          # unlock-path timing
```

Three of those deserve naming, because they enforce properties that are easy to
break silently:

- **The consistency tests** compare the packaged sysctl, modprobe and cmdline
  drop-ins against the tables `steel-check` audits against. Without them the
  packages and the auditor drift apart, and the auditor becomes the thing that
  is wrong.
- **The deniability assertion** builds two sysroots differing only in duress
  configuration and `cmp`s the output in every format.
- **The timing harness** measures the four unlock paths pairwise rather than
  inspecting the code. A comparison that returns early on the first differing
  byte looks fine in review and leaks the matching prefix length over a few
  hundred attempts.

A CI job additionally audits the *source* for the universal-shipping rule: no
conditional in the duress package, no early return in its initramfs hook, no
plaintext configuration path. That catches the one class of change that quietly
destroys the property — someone making an install conditional because it looked
tidier.

## Contributing

Read [CLAUDE.md](CLAUDE.md) first — it is the design document, and it is
opinionated about things that look like implementation details and are not.

Three rules that will get a change rejected faster than anything else:

1. **A measure with no rationale does not ship.** If you cannot say what it
   costs an attacker, it is theatre. There is a test that enforces this.
2. **A measure with no off-switch does not ship.** See above about users
   disabling everything.
3. **Do not claim NixOS semantics or GrapheneOS parity.** In code, in docs, in
   commit messages, anywhere.

## Licence

GPL-3.0-or-later.
