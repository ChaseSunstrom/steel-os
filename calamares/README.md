# calamares/ — the installer

Design principle 1 is the whole brief: *everything must be the default state
after a normal GUI install. No post-install hardening checklist.*

## How it is put together

| | |
|---|---|
| `settings.conf` | The sequence: which pages are shown, in what order, and which jobs run |
| `branding/steelos/` | The mark, the palette, the slideshow, and every page — all QML |
| `modules/` | The install jobs. Python, `type: job` |
| `modules-config/` | One config file per page and per stock module |
| `viewmodule/` | ~80 lines of C++. The only compiled part; see below |
| `tests/` | The comprehension check, the refusals, and the wiring |

Calamares supplies the frame — welcome, locale, keyboard, summary, finished —
and the stock `localecfg`, `keyboard`, `hwclock` and `machineid` jobs, which
work normally once `steelos_deploy` has set `rootMountPoint`. Everything
SteelOS-specific is ours.

**The exec phase is entirely ours.** Calamares' `partition` module cannot
express this layout: two root slots, two verity trees, an always-allocated
custody region, an always-allocated decoy region, an ESP and an encrypted
`/var`. So `steelos_partition` applies the same systemd-repart definitions the
image build uses — which is what keeps the installed geometry and the built
geometry from drifting apart — and `steelos_deploy` writes the image, verifies
it against its published checksum, and hands back a mounted target.

## Why there is any C++ at all

Calamares 3.4 has no Python view modules; PythonQt is gone. The pages are
therefore QML, loaded straight out of the branding directory, which is a good
outcome — they can be read and changed without a compiler.

But a QML page cannot refuse to go forward, and several of these pages collect
input that later jobs act on irreversibly: a target disk, a passphrase, a
recovery-key confirmation, a comprehension check covering things that destroy
data. Calamares gates the Next button through
`ViewManager::updateNextStatus()`, which begins

```cpp
ViewStep* vs = qobject_cast< ViewStep* >( sender() );
```

so it only does anything when invoked as a slot connected to a ViewStep's
signal. Called from QML, `sender()` is null and the call is silently a no-op.
Worse, `ViewManager::next()` re-reads the incoming step's `isNextEnabled()`
*after* calling `onActivate()`, so even a correctly-timed gate is overwritten a
few lines later.

`viewmodule/` is the answer: a view step that owns a `valid` flag, which QML
writes and which `isNextEnabled()` reports. That is all it does. It ships as
`steel-installer-page` so that building the rest of the installer needs no
compiler.

## Pages

| Page | What it decides |
|---|---|
| Disk | Target device, encryption passphrase |
| Boot security | Secure Boot key enrolment, TPM+PIN, the recovery key |
| Hardening | Preset, with a full list of what each one changes |
| Graphics | Detected GPU, update channel |
| Profiles | systemd-homed profiles, per-profile sandbox strictness |
| Network | DNS provider, MAC randomisation, captive-portal helper, kill switch |
| Backups | Target, append-only, outer encryption recipient |
| Duress | Optional. Duress, decoy, custody, vault — behind a comprehension check |

Each page writes one map into global storage under a `steelos.*` key, and the
job modules read exactly those keys. Nothing else passes between the UI and the
install — no files, no environment, no second copy of a decision that could
disagree with the first.

## Three things these pages must get right

**Microsoft's keys are included by default.** Some firmware needs them to run
option ROMs — a discrete GPU's, most commonly — and a machine that enrols only
our keys can fail to POST. That is very hard for a user to diagnose and, on some
hardware, hard to recover from. Removing them is available as an explicit expert
choice.

**TPM enrolment without a PIN is not offered at all.** Not defaulted-off —
absent. A TPM-sealed key with no PIN unlocks for whoever is holding the machine,
which converts full-disk encryption into a speed bump against exactly the
attacker it exists to stop. Offering the option means some people pick it.

**A missing graphics driver is a wrong-image error, not a fixable one.** On a
mutable distribution the installer would install a package. Here `/usr` is
sealed, so the user needs to know *now* rather than after their first reboot
into a black screen.

## Where the machine's facts come from

`steelos-live-probe` runs once at boot on the live medium and writes
`/run/steelos/hardware.json` and `/run/steelos/recovery-key`. The pages read
that file; they never run a process. Giving an installer UI the ability to shell
out is a bad idea in a program that runs as root against block devices, and it
means the facts can be audited in one readable script instead of scattered
across eight QML files.

The recovery key is generated there, once, for the same reason: the user is
shown it and has to type a randomly-chosen group of it back before the install
starts, and the job that enrols it must enrol exactly what they were shown. QML's
`Math.random()` is not a cryptographic RNG and must never be what stands between
someone and their disk.

## The threatened-user step

`CLAUDE.md` requires "a comprehension confirmation, not just an 'I agree' box",
and that distinction is the entire page. An agreement checkbox measures whether
someone can find a checkbox. The failure modes here are irreversible — a wiped
volume with no backup, a decoy that was never aged, a 2-of-3 quorum never
reassembled — and several are legal rather than technical.

So the user reads seven limits and answers a question about each. A wrong answer
returns them to the paragraph it came from; it does not lock them out, because
someone who genuinely needs these features and misses a question needs the
explanation rather than a refusal.

The correct answers are **not** all in the same position. If they were, the check
could be passed by picking the first option every time, and it would measure
nothing. The limits, the questions and the playbooks live in
`branding/steelos/threatened-limits.json`, read by the page that renders them and
by the job that enforces them — one file, so the text someone answered questions
about is the text that gets enforced.

`tests/test_installer.py` asserts that, along with the configurations the
installer refuses:

- A wiping duress action with no off-device append-only backup.
- `decoy-and-wipe` without a decoy, which needs two credentials.
- Playbook C — claiming both custody and deniability — with no rehearsed answer
  for the moment the two stories collide.
- `steel-vault` before its write amplification has been acknowledged.
- Attempt-limit wiping without acknowledging that anyone with physical access
  can trigger it.

```
python3 calamares/tests/test_installer.py
```

The same suite asserts the wiring: every page in the sequence has a config, every
config points at QML that exists, every job module is reached, every branding
image exists, and every page that can disable Next says why. Those are the
failures that otherwise surface as a Calamares error on a stranger's machine.

## What the installer refuses to do

- **Install alongside another OS, or leave free space.** SteelOS allocates the
  whole disk and fills what it does not use with random data. Unallocated
  high-entropy regions are a forensic signal, and a partition table that varies
  between installs weakens the deniability design for everyone, not just the
  person who chose it.
- **Install onto the disk it booted from.** Refused on the page and again in the
  job, because the job runs on whatever is in global storage.
- **Cancel during the write phase.** Better to disable the button than to leave
  someone with a machine that neither boots nor has their old system.
- **Skip the recovery key confirmation.** It asks for one group at random, not
  the whole key: asking for the whole thing invites copy-paste from the screen,
  which proves nothing.
- **Store the private half of the outer backup key.** Recognised and rejected,
  because a seized machine that can decrypt its own history gets nothing from
  the outer layer.
