# calamares/ — the installer

Calamares configuration and the SteelOS modules. Design principle 1 is the whole
brief: *everything must be the default state after a normal GUI install. No
post-install hardening checklist.*

## Modules

| Module | What it owns |
|---|---|
| `bootsec` | Secure Boot key enrollment, TPM+PIN binding, recovery key |
| `hardening` | Preset selection with a details expander that names the costs |
| `graphics` | Driver detection, and verifying the chosen image contains it |
| `profiles` | systemd-homed profile creation and sandbox strictness |
| `backup` | Target configuration, with local targets refused in the UI |
| `netprivacy` | DNS provider, MAC handling |
| `threatened` | Optional. Duress, decoy, custody, vault — behind a comprehension check |

## Three things these modules must get right

**Microsoft's keys are included by default.** Some firmware needs them to run
option ROMs — a discrete GPU's, most commonly — and a machine that enrolls only
our keys can fail to POST. That is very hard for a user to diagnose and, on some
hardware, hard to recover from. Removing them is available as an explicit expert
choice.

**TPM enrollment without a PIN is not offered at all.** Not defaulted-off —
absent. A TPM-sealed key with no PIN unlocks for whoever is holding the machine,
which converts full-disk encryption into a speed bump against exactly the
attacker it exists to stop. Offering the option means some people pick it.

**A missing graphics driver is a wrong-image error, not a fixable one.** On a
mutable distribution the installer would install a package. Here `/usr` is
sealed, so the user needs to know *now* rather than after their first reboot
into a black screen.

## The threatened-user step

`CLAUDE.md` requires "a comprehension confirmation, not just an 'I agree' box",
and that distinction is the entire module. An agreement checkbox measures
whether someone can find a checkbox. The failure modes here are irreversible —
a wiped volume with no backup, a decoy that was never aged, a 2-of-3 quorum
never reassembled — and several are legal rather than technical.

So the user reads seven limits and answers a question about each. A wrong answer
returns them to the paragraph it came from; it does not lock them out, because
someone who genuinely needs these features and misses a question needs the
explanation rather than a refusal.

The correct answers are **not** all in the same position. If they were, the
check could be passed by picking the first option every time, and it would
measure nothing. `test_comprehension.py` asserts this, along with the
configuration rules the module refuses to violate:

- A wiping duress action with no off-device append-only backup.
- A decoy with only one credential.
- Playbook C — claiming both custody and deniability — with no rehearsed answer
  for the moment the two stories collide.
- `steel-vault` before its write amplification has been shown.

```
python3 calamares/modules/threatened/test_comprehension.py
```

## What the installer refuses to do

- **Install alongside another OS, or leave free space.** SteelOS allocates the
  whole disk and fills what it does not use with random data. Unallocated
  high-entropy regions are a forensic signal, and a partition table that varies
  between installs weakens the deniability design for everyone, not just the
  person who chose it.
- **Cancel during the write phase.** Better to disable the button than to leave
  someone with a machine that neither boots nor has their old system.
- **Skip the recovery key confirmation.** It asks for one segment at random,
  not the whole key: asking for the whole thing invites copy-paste from the
  screen, which proves nothing.
