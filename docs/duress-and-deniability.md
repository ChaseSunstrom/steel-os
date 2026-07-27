# Duress, decoys, and custody — what these actually do

This is the user-facing honest-limits document. It is written to be read before
enabling anything in this category, because the failure modes here are
irreversible and several of them are legal rather than technical.

If you take one thing from this page: **for most people at risk, the effective
answer is not carrying the data at all.** A clean device plus a remote restore
afterwards beats every on-device trick described below, and `steelctl export`
with a remote restic repository makes it a supported workflow. Everything else
on this page is for the cases where that is not possible.

## The mechanism: destroying keys, not data

Overwriting a modern SSD takes far too long to be useful under duress, and wear
levelling means you cannot reliably overwrite anything anyway. Every destructive
feature here works by destroying **key material**, which makes the ciphertext
permanently unreadable in milliseconds.

The consequence is a hard tradeoff you have to choose between, per volume, at
install time:

> **A machine that is recoverable from a header backup is not destroyable under
> duress. A machine that is destroyable under duress is not recoverable from a
> header backup.**

If a LUKS header backup exists anywhere — our installer offers one, and restic
backups may contain one — then key destruction is reversible from that backup.
Silently backing up a header the user believes is destroyable is the worst
outcome this project can produce, which is why the choice is explicit and why
`steel-backup` stores header backups *only* inside the outer-encrypted remote
repository, never on the device and never on the ESP.

## The limits, before the features

### 1. This hides whether you used it, not that it exists

An examiner who identifies the OS as SteelOS knows every install has decoy
capability. That is the point of shipping it universally — a machine without it
would be the anomaly — and it is also the ceiling on what this achieves.

They cannot prove from the disk that you configured one. They can simply demand
another passphrase anyway, indefinitely, and an adversary willing to do that is
not defeated by cryptography. This is the central unsolved problem with all
decoy-volume systems and is why informed analyses consider VeraCrypt
hidden-volume deniability defeated in practice.

### 2. An adversary who images the disk twice defeats it

If your adversary can image the disk on more than one occasion — a repeated
border crossing, a seized-and-returned laptop, a compromised backup target —
then blocks that changed between images while the decoy claims to have been idle
are direct evidence of a hidden volume.

Defending against this requires ORAM-style oblivious write patterns at severe
performance cost. `steel-vault` is where that belongs, for a small documents
volume — but **its ORAM block layer is not implemented yet**. Today `steel-vault`
is a small separately-keyed encrypted volume with an honest warning, and it does
not yet provide this property. The main volume does not have it and will not.

**If your adversary has repeated physical access, assume decoys do not work for
you.**

### 3. SSD internals are outside our control

The flash translation layer remaps and retains blocks invisibly. Wear-level
statistics and over-provisioned areas can indicate write volume inconsistent
with the decoy's story, and we can neither inspect nor sanitise this from the
OS. No software fix exists. `steel-vault` on an HDD is meaningfully stronger
than the same design on an SSD.

### 4. Other disk forensics leak too

Partition sizes that do not add up, unallocated regions with high-entropy data,
free-space distribution. We reduce these — every install allocates the whole
disk and fills unused space with random data, and the decoy partition is
allocated on every machine whether or not it is used — but we do not eliminate
them.

### 5. Off-device evidence dominates everything here

Cloud backups, ISP records, purchase history, phone contents, VPN account
records, and your own backup remote all testify about what the machine actually
did. A decoy on the disk does nothing about any of it. This is usually the
largest hole and the one people think about least.

### 6. Key-disclosure law varies and may not care

Several jurisdictions can compel passphrase disclosure with penalties for
refusal. Destroying data during an investigation or at a border can itself be an
offence, in some places a more serious one than whatever was being protected.

**If you are facing real legal jeopardy, get advice from a lawyer in your
jurisdiction. This software is not a legal strategy.**

### 7. Coercion is not a technical problem

These features address a narrow slice of it.

### 8. Wiping can make your situation worse

Destroying data in front of someone who was going to let you go can escalate a
search into an arrest. It is not universally the safe choice, which is why
`alert-only` exists as a duress action and why it is the recommended default for
anyone whose adversary might react badly to discovering data was destroyed.

## The features

### Duress credentials

A second passphrase accepted at the unlock prompt that triggers a configured
action instead of a normal unlock: `wipe-keys`, `decoy`, `decoy-and-wipe`, or
`alert-only`.

The credential is checked against a separate salted hash, never a LUKS keyslot —
a keyslot would appear in `cryptsetup luksDump` and destroy the entire point.
The check runs before any keyslot is tried, in constant time, with timing
indistinguishable from a wrong password.

**Two decoy credentials, or none.** A decoy that always wipes cannot be used
routinely, and a decoy that is never used does not age credibly. So the decoy
volume takes `decoy-maintenance` (unlocks, no side effects — for the owner's
routine use, never disclosed) and `decoy-duress` (unlocks and destroys the real
volume's keys silently — the one disclosed under coercion). Confusing them is
the most likely way a real user loses everything, which is why provisioning
requires typing each one twice, separately, with distinct labels.

### Attempt limits

**Default: off.** Read this before enabling it:

Count-based auto-wipe is a self-destruct that anyone with physical access can
trigger. A child. A roommate. A coworker. A thief who only wants to resell the
hardware and will happily burn your data trying. You, on a bad day, with the
wrong keyboard layout.

GrapheneOS deliberately does not enable count-based auto-wipe as a default for
exactly this reason. Escalating delays give you most of the anti-brute-force
benefit with none of the self-destruct risk, and a 40-character passphrase makes
brute force irrelevant regardless. **Use the delays. Think hard before using the
wipe.**

### Decoy profiles

A separate LUKS volume with its own header, its own homed user, and its own
`/var` — not a hidden volume in the VeraCrypt sense. `/usr` is byte-identical
across all installs of a generation, so the decoy's system reveals nothing
because it *is* the same system.

Two things make or break this:

**Aging beats content.** A profile whose every file was created in the same
ninety seconds is not credible. `steel-decoy` therefore automates *use*, not
*forgery*: it boots the decoy on a randomised schedule and runs a real session —
a real browser visiting real sites, real updates, real backups. Cached remote
content is why: HTTP `Date` headers and TLS certificate validity windows come
from other people's servers and cannot be backdated. A cache full of pages whose
certificates were issued last week, in a profile claiming to be two years old,
is dispositive.

**The decoy is not confidential.** The unattended session needs to open the
volume with nobody present, so the decoy key is TPM-sealed and released
automatically on a dedicated maintenance boot path. That means anyone holding
the hardware can open the decoy. This is acceptable only because the decoy is
designed to be surrendered — and it turns "the decoy should contain nothing
real" from advice into a hard requirement. `steel-decoy` refuses to import user
data into a decoy profile.

**No red herrings.** Planting intriguing-but-innocuous material is a common idea
and a bad one. It invites deeper scrutiny when the goal is for examination to
end early; fabricated material fails forensic consistency checks more often than
real activity does; and deliberately planting misleading material for an
investigator can constitute fabricating evidence or obstruction, which is a
materially different legal posture from merely encrypting data. The credible
decoy is a boring one.

### Split-key custody (`steel-custody`)

**This is the strongest thing here, and it is stronger than any decoy.** For a
whistleblower or a travelling researcher, it should be the recommended
configuration.

The real volume's key is protected by a KEK that is never stored whole. Shamir
2-of-3 shares go to a hardware token kept elsewhere, a remote release service
with a delay policy, and a trusted second party. The device stores only the
encrypted volume key and share *identifiers*.

The point is to change what is true rather than what is provable: on the road,
the device physically cannot be decrypted by anyone, including you. *"I cannot"*
is a materially different position from *"I will not"* — legally, practically,
and in terms of what continued coercion can accomplish.

Four things are required, and possession of the hardware is deliberately never
enough: something known (passphrase and token PIN), something held (the token,
left at home), someone else's consent (the release delay and the co-signer), and
this machine in this state (TPM sealing to PCR 7 and 11).

**What custody does not do:** it does not prevent coerced unlock. An adversary
with you, the device, the token, and the ability to compel a PIN at a time the
release policy permits gets in. What custody does is convert an instant, private
compulsion into a slow, witnessed one. Marketing that says more than that is
lying.

**Total-loss condition:** if two of the three shares are lost, the data is gone
permanently and nobody can recover it. That is the direct cost of the guarantee.
Enrollment requires a real reassembly drill using each pair combination, and the
installer will not let you finish with a single token — non-extractable keys
cannot be cloned later, so the second token has to be enrolled in the same
session.

## Choose a playbook, and rehearse it

Custody and deniability pull in opposite directions and cannot both be claimed.
Custody says *"I cannot open this."* Deniability says *"there is nothing here to
open."* An examiner who finds evidence of split-key enrollment on a machine you
claim is an ordinary laptop has caught the contradiction.

- **Playbook A — Deniable.** Decoy plus duress credentials, no visible custody.
  Best where the goal is for examination to end early.
- **Playbook B — Openly locked.** Custody enabled and not hidden: "this device is
  under a key-management policy, I physically cannot open it here." Best for a
  professional carrying work data under an organisational policy, where being
  *seen* to have one is normal and protective.
- **Playbook C — Layered.** Both, with custody enrollment concealed by the
  universal custody region, and a rehearsed answer for when the two stories
  collide. Only for people who have thought hard about their specific adversary.

`steel-duress drill` walks through your chosen playbook end to end on scratch
volumes: entering each credential, seeing what an examiner would see, confirming
the recovery path. **A playbook that has never been rehearsed will be performed
badly under stress, which is the only time it matters.**

## How this is enforced in code today

Phase 0 does not implement duress. What exists now is the auditing that keeps
the future implementation honest:

- `duress.universal-hook`, `duress.universal-maintenance-entry`,
  `duress.custody-region` — verify the universal components are present on
  *every* machine, so their presence proves nothing.
- `duress.no-plaintext-config-leak` — scans the ESP and unencrypted state for
  anything whose presence would differ between a configured and unconfigured
  machine, including a second `/etc/crypttab` entry.
- `duress.esp-uniformity` — the ESP is the first thing an examiner reads and
  must be identical in shape across installs.
- `tests/audit/run.sh` — builds two sysroots differing only in duress
  configuration and asserts byte-identical `steel-check` output in every format.
  This is the requirement from CLAUDE.md made executable.

The checks that read encrypted state do not read it at all from a locked
context. Not "read it and hide the result" — an examiner with `strace` and the
binary learns from the attempt, not just from the answer.
