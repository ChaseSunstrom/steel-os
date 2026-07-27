# SteelOS — Immutable, Hardened, Compartmentalized Arch-Based Desktop

## What this is

An Arch-based desktop distribution with GrapheneOS-inspired design goals adapted
to PC hardware: an **immutable, cryptographically verified root filesystem**,
**declarative package management** (the installed system is defined by a config
file, not by accumulated terminal commands), per-user encrypted homes, per-app
sandboxing by default, a hardened kernel/allocator/sysctl baseline, atomic
updates with rollback, integrated backups, and a graphical installer that makes
all of it the default rather than a weekend of manual work.

Deliverables: a reproducible image build system, a GUI installer, a declarative
system configuration format and tooling, and documentation.

## Design principles

1. **Secure by default, not by tutorial.** Everything here must be the default
   state after a normal GUI install. No post-install hardening checklist.
2. **The running system is a build artifact, not a history of commands.** Two
   machines with the same manifest are the same machine. There is no
   "it works on mine because I once ran something."
3. **The root filesystem is read-only and verified.** If it can't be modified at
   runtime, malware persistence has nowhere to live, and dm-verity means
   tampering while powered off is detected at boot.
4. **Every state change is atomic and reversible.** Updates apply to an inactive
   slot and take effect on reboot. The previous deployment always remains
   bootable.
5. **Don't fork what you can package.** We are Arch packages + an image builder +
   an installer + tooling. We maintain no patched upstream software.
6. **Every hardening measure must be reversible and documented.** A user who hits
   a broken app needs a discoverable escape hatch, or they will disable
   everything instead of one control.
7. **No security theater.** If it doesn't raise real cost for an attacker in the
   threat model, it doesn't ship.
8. **Usability failures are security failures.** An unusable secure system gets
   replaced with an insecure usable one.

## Threat model (explicit — everything else follows from this)

**In scope:**
- Device theft / seizure while powered off (FDE + per-user encryption)
- Malicious or compromised desktop application (sandboxing, per-app network)
- Malicious website or document exploiting a browser/viewer (sandboxing,
  hardened malloc, kernel hardening)
- **Persistence after compromise** (immutable verified root — an attacker who
  gets root at runtime cannot durably modify the OS; reboot restores a known
  image)
- **Offline tampering with the OS** (dm-verity root hash sealed in a signed UKI)
- Local network attacker (default-deny inbound, encrypted DNS, MAC randomization)
- Passive network surveillance / correlation (per-app tunnels via Trrod, DoT)
- Evil-maid tampering with bootloader/kernel/initramfs (Secure Boot own keys, UKI)
- Cold-boot / DMA attacks (memory encryption where CPU supports it, IOMMU)
- **User error / bad update** (atomic rollback, backups)
- **Coerced unlock** — user is compelled to enter a password (duress credentials,
  decoy profiles). See the honest-limits analysis in "Duress & deniability";
  this is the weakest area in the whole design and must not be oversold.

**Out of scope — state clearly in docs, do not pretend otherwise:**
- Compromised UEFI firmware / Intel ME / AMD PSP
- Hardware implants, targeted supply-chain attacks against the hardware
- Attacker with the user's unlock password and physical access at rest
- Full anonymity (this is not Tails/Whonix; use those if that's the need)
- Kernel 0-day escaping every sandbox layer (mitigated, not prevented)
- Malware that only needs to survive until the next reboot (immutability bounds
  persistence, it does not prevent session-scoped compromise)

## Prior art to study BEFORE writing code

Read these and steal shamelessly; do not reinvent:
- **arkdep** (Arkane Linux) — image-based deployment on Arch; the closest
  existing implementation of what our deployment layer must do. Study first.
- **blendOS** — another immutable Arch approach, container-centric layering
- **Fedora Silverblue / bootc / ostree** — the reference model for image-based
  desktops, atomic updates, and rollback UX
- **systemd-sysupdate, systemd-sysext, systemd-confext, mkosi** — the systemd
  ecosystem's A/B update and extension primitives; prefer these over inventing
- **NixOS** — the reference for declarative configuration UX (and read the
  honest-limits note below before promising Nix semantics)
- **secureblue** — hardened immutable Fedora; hardened_malloc integration,
  flatpak permission hardening, sysctl set
- **Kicksecure** — security-misc package layout, the model for our config packages
- **Qubes OS** — what they concluded requires VMs; be honest where we're weaker
- **GrapheneOS** — hardened_malloc, verified boot philosophy
- **snapper / btrbk / restic / borg** — backup layer; pick, don't write

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Build side (CI, reproducible)                               │
│  manifest.toml ──> mkosi/archiso build ──> rootfs image     │
│                       │                                     │
│                       ├─> dm-verity hash tree + root hash   │
│                       ├─> UKI (kernel+initramfs+cmdline     │
│                       │    containing the verity root hash) │
│                       └─> signed with our key + user's SB key│
├─────────────────────────────────────────────────────────────┤
│ Device side                                                 │
│  ESP: signed UKI slot A / slot B (+ recovery UKI)           │
│  Root: verity-protected read-only image, slot A / slot B    │
│  /var: writable, encrypted (LUKS2), holds state             │
│  /home: systemd-homed, per-user LUKS images                 │
│  /etc: writable overlay, but DECLARED (see config layer)    │
│  Apps: Flatpak (user scope) + bubblejail + containers       │
└─────────────────────────────────────────────────────────────┘
```

### Filesystem layout (this is the core design decision)

| Path | Mode | Backing |
|---|---|---|
| `/usr` | read-only, dm-verity verified | image slot A/B |
| `/etc` | writable overlay, reconciled from manifest | on `/var` |
| `/var` | writable, encrypted | LUKS2 volume |
| `/home` | per-user encrypted | systemd-homed LUKS images |
| `/opt`, `/srv` | writable | on `/var` (symlinked) |
| `/tmp` | tmpfs, `nodev,nosuid,noexec` | RAM |
| root `/` | read-only | verity image |

**Consequence to design around:** `pacman -S` at runtime is impossible by
construction — `/usr` is read-only and its hash is sealed. This is the
enforcement mechanism for declarative package management. It is not a policy
that can be bypassed by a determined user in a terminal; it's physics.

**Escape hatch (mandatory):** `steel-devmode` boots a special deployment with
verity disabled and `/usr` writable, clearly marked in Plymouth and in the
session. Requires physical presence at boot (not a runtime toggle). Exists so
that hardware bring-up and debugging are possible without reinstalling.

## Declarative package management — what we can and cannot promise

**Be honest with users and with yourself.** NixOS's guarantees come from a
functional package model: content-addressed store paths, hermetic builds,
per-package generations, atomic per-user profiles, and the ability to roll back
a single package. **We are not building that.** Arch packages are not
content-addressed and do not compose that way. Do not claim "NixOS-like" without
qualification in any user-facing text.

**What we actually deliver — image-based declarative configuration:**

- The system is defined by `/etc/steelos/manifest.toml` (version-controllable).
- Applying a manifest **builds or fetches a new image** and stages it in the
  inactive slot; a reboot activates it.
- Rollback is **whole-system generation rollback** (previous slot), not
  per-package.
- Reproducibility guarantee: same manifest + same package snapshot pin = same
  image hash. We pin the Arch repo state (via an Arch Linux Archive snapshot
  date or our own mirrored snapshot) so "same manifest" is meaningful over time.

Example manifest:

```toml
[system]
channel      = "stable"          # stable | testing
snapshot     = "2026-07-20"      # Arch repo snapshot pin
hardening    = "balanced"        # balanced | strict | compatible
kernel       = "linux-hardened"

[packages]
system = ["firefox", "neovim", "git", "podman"]   # baked into the image

[flatpak]
user = ["org.mozilla.firefox", "com.github.tchx84.Flatseal"]

[users.chase]
storage      = "luks"
sandbox      = "strict"
tunnel_policy = "rotate-3d"      # consumed by Trrod if installed

[services]
enable  = ["tailscaled"]
disable = ["bluetooth"]

[backup]
enabled     = true
targets     = ["/var/lib/steelos/backup", "restic:sftp:host:/backups"]
schedule    = "daily"
retention   = "7d 4w 6m"
```

`steelctl apply` diffs the manifest against the running generation, builds/fetches
the resulting image, stages it, and reports what will change on reboot.
`steelctl diff` shows it without applying. `steelctl rollback` returns to the
previous generation. `steelctl history` lists generations with their manifest hashes.

**Where users install things without rebuilding** (all of these are runtime,
writable, and outside the verified root — by design):
1. **Flatpak (`--user`)** — the primary path for GUI apps. Instant, sandboxed,
   per-profile. Most users never touch the manifest for apps.
2. **Containers** (distrobox/toolbox on Podman) — the primary path for CLI tools
   and dev environments. `steel-shell` wraps this: a mutable Arch container with
   the user's home mounted, where `pacman -S` works normally and affects nothing
   outside the container.
3. **Nix (optional, user-scope)** — for users who genuinely want functional
   package management, ship optional support for the Nix package manager in
   single-user mode on `/var`. This is how we honestly offer Nix semantics
   without claiming to be NixOS.
4. **systemd-sysext** — for signed system-level extensions (e.g. a driver bundle)
   that layer onto `/usr` at runtime without rebuilding the image. Extensions
   must be signed; unsigned sysexts are rejected under our boot policy.

**Rule for the implementer:** if a user's need can be met by Flatpak, a
container, or a sysext, it must NOT require an image rebuild. Image rebuilds are
for kernel, drivers, base system, and hardening posture only. If we get this
wrong, the OS feels hostile and people leave.

## Boot chain (build this first — everything depends on it)

1. Firmware with admin password (installer instructs; cannot be automated)
2. Secure Boot in setup mode → installer enrolls sbctl keys (with Microsoft keys
   included by default) → user re-enables Secure Boot
3. systemd-boot, signed
4. **UKI**: kernel + initramfs + cmdline + splash in one signed PE binary. The
   cmdline inside it contains `roothash=<dm-verity root hash>`. This is the
   crux: signing the UKI signs the identity of the entire root filesystem.
5. **dm-verity root**: kernel verifies every block of `/usr` against the hash
   tree on read. Offline modification is detected immediately; runtime
   modification is impossible.
6. LUKS2 for `/var` and swap, unlocked by:
   - **Default**: passphrase at Plymouth prompt
   - **Optional**: TPM2 + PIN (`systemd-cryptenroll --tpm2-device=auto
     --tpm2-with-pin=yes`), bound to PCR 7 and PCR 11 (UKI measurement). PIN is
     mandatory when TPM is used — TPM alone unlocks for whoever holds the machine.
   - Recovery key generated and shown at install, with a confirmation step that
     requires re-typing part of it
7. **A/B slots**: two root image slots + two UKI entries. Updates write to the
   inactive slot. `systemd-boot` counts boot attempts; a deployment that fails to
   reach `boot-complete.target` N times is automatically demoted and the previous
   generation boots (`systemd-bless-boot`). **Implement this before shipping any
   update mechanism** — it's what makes bad updates survivable.
8. **Recovery UKI**: a signed minimal environment with `steelctl`, disk tools,
   and network. Always present, always bootable, tested in CI.

**This closes the gap I flagged in the previous architecture**: with dm-verity's
root hash sealed inside the signed UKI, SteelOS has verified boot of the root
filesystem, not just the kernel. What remains missing versus GrapheneOS is a
hardware root of trust with insider-resistant firmware — a PC hardware
limitation, not a design choice. Say exactly this in the README; do not round it
up to "verified boot like GrapheneOS."

## Updates

- `steelctl update` fetches the current channel's image (delta-transferred via
  `systemd-sysupdate` or casync-style chunking — evaluate both, prefer sysupdate
  if adequate), verifies signature, writes to inactive slot, stages UKI.
- Reboot activates. Boot counting demotes on failure.
- Update cadence: our CI rebuilds against the current Arch snapshot; images
  publish only after the full VM test matrix passes. Users are never exposed to
  an untested Arch state — this is a real advantage over rolling Arch, and it's
  the reason the snapshot pin exists.
- Security fast-path: critical CVEs can publish out-of-cycle with an expedited
  (but not skipped) test run.
- `steelctl rollback` and the boot-menu generation list give users an escape
  independent of network access.

## Duress, wipe-on-failure, and deniability

Three related features for users facing coercion, seizure, or theft. **Read the
honest limits before implementing** — this is the area of the design most likely
to give users false confidence, and false confidence here gets people hurt.

### Mechanism: key destruction, not data destruction

Physically overwriting a modern SSD takes far too long, and wear-leveling means
you can't reliably overwrite anything. Everything below works by destroying **key
material**, which renders the ciphertext permanently unreadable in milliseconds:

- Wipe the LUKS2 keyslots and header (`cryptsetup luksErase`, plus overwrite of
  the header area and the detached header if used)
- Wipe the TPM-sealed key objects (`systemd-cryptenroll --wipe-slot=tpm2` and
  clear the TPM NV index)
- Wipe per-user homed headers for every profile
- Discard/TRIM the LUKS header region as a best-effort secondary step

**Hard requirement:** if a header backup exists anywhere (our installer offers
one; restic backups may contain one), destruction is reversible from that backup.
The installer must make this tradeoff explicit at setup time — "recoverable from
backup" and "destroyable under duress" are opposing properties, and the user
chooses which one they want per-volume.

### Feature 1 — Duress credentials

A second passphrase/PIN accepted at the Plymouth unlock prompt (and optionally at
the SDDM login prompt) that triggers a configured action instead of a normal unlock.

Configurable actions, chosen at install:
- `wipe-keys` — destroy all key material, then power off. Screen shows a normal-
  looking "wrong passphrase" or a plausible boot failure, never "wipe complete."
- `decoy` — unlock the decoy volume only (see Feature 3)
- `decoy-and-wipe` — unlock decoy, silently destroy the real volume's keys.
  **This requires two distinct decoy credentials** (see "Dual decoy credentials"),
  or the user can never boot their own decoy without destroying everything.
- `alert-only` — unlock normally but fire a configured signal (mark a canary
  file, send a message via a pre-configured channel if network is up). Useful
  when destruction is the wrong response.

Implementation notes:
- Implemented in an initramfs hook comparing against a **separate salted hash**;
  the duress credential must never be a LUKS keyslot, or its existence is
  visible in `cryptsetup luksDump`.
- Must run before any keyslot is tried, and must be constant-time.
- Timing must be indistinguishable from a normal wrong-password path.
- `steel-duress test` performs a full dry run against a scratch volume, because
  a duress feature that has never been tested is worse than none.

### Feature 2 — Attempt limits

After N consecutive failed unlock attempts, run a configured action.

- Default: **OFF**. Opt-in during install, with the warning below shown inline.
- Recommended default when enabled: 10 attempts → `wipe-keys`, with escalating
  delays (1s, 2s, 4s… capped) applied from attempt 3 regardless of setting.
- Counter stored in a TPM NV index with a monotonic counter where available
  (so power-cycling doesn't reset it); fall back to `/var` state with a clear
  docs note that the fallback is resettable by an attacker who can boot elsewhere.
- Separate, independently-configured counters for: pre-boot LUKS unlock, homed
  per-user unlock, and lock-screen unlock.

**Warning that MUST appear in the installer UI, not just the docs:** attempt-limit
wiping is a self-destruct that anyone with physical access can trigger — a child,
a roommate, a coworker, a thief who just wants the hardware, or the user
themselves on a bad day with a keyboard-layout problem. GrapheneOS deliberately
does not enable count-based auto-wipe as a default for exactly this reason.
Escalating delays give most of the anti-brute-force benefit with none of the
self-destruct risk; a 40-character passphrase makes brute force irrelevant
anyway. Recommend delays; offer wiping.

### Feature 3 — Decoy profiles ("plausible deniability")

A second, fully functional system that unlocks with a different passphrase and
looks like an ordinary, lightly-used machine.

Design:
- Decoy is a **separate LUKS volume with its own header**, plus its own homed
  user, its own generation, and its own `/var` state. Not a hidden volume in the
  VeraCrypt sense — see limits below for why we reject that model.
- `steel-decoy create` provisions one in minutes: installs the same base image
  (so `/usr` is byte-identical and reveals nothing), creates a user, and
  optionally seeds it with mundane activity — browser history, a few documents,
  realistic timestamps spread over months.
- **Aging matters more than content.** A profile whose every file was created in
  the same 90-second window is not credible. The seeder must backdate
  consistently across file mtimes, journal entries, browser history, and shell
  history, and the docs must tell users to actually *use* the decoy periodically.
- Boot menu shows only one entry; the passphrase entered selects the volume.
- Decoy must have working network, working apps, and no reference to the real
  volume: no `/etc/crypttab` entry, no fstab line, no NetworkManager profiles
  shared, no Trrod config, no backup credentials.

### Dual decoy credentials (required if `decoy-and-wipe` is offered)

The deniability design requires the user to boot and genuinely use the decoy
periodically so it ages credibly. A decoy that always wipes makes that
impossible, and one mistyped-context password destroys everything. So the decoy
volume accepts **two credentials that are indistinguishable to an examiner**:

- `decoy-maintenance` — unlocks the decoy, no side effects. Used by the owner for
  routine aging and use. Never disclosed to anyone.
- `decoy-duress` — unlocks the decoy *and* destroys the real volume's key
  material silently, before the desktop session starts. This is the one disclosed
  under coercion.

Both must be handled by the same code path with identical timing, identical
logging (i.e. none), and identical on-screen behaviour. The wipe must complete
before any UI appears, must be key-material-only (milliseconds), and must leave
the real volume's region indistinguishable from the random fill present on every
SteelOS install — which the universal geometry design (below) already provides.

Implementer note: because destruction is irreversible and the two credentials do
opposite things, `steel-duress test` must exercise both against scratch volumes,
and the provisioning UI must require the user to type each one twice, separately,
with distinct labels. Confusing them is the most likely way a real user loses
everything.

### Making the decoy unprovable — what actually helps

The goal is that examining the device yields no evidence that a second volume or
a duress credential exists. Full deniability against an all-knowing adversary is
not achievable (see limits below), but several design choices move the needle a
long way, and most decoy systems fail because they skip them.

**1. The feature must be universal, not optional.** If `steel-duress` is a
package a user chooses to install, its presence on disk is itself the evidence.
Therefore: the duress hook, the attempt-counter code, and the decoy support ship
**in every SteelOS image, always, for every user**, active or not. Finding them
proves only that the machine runs SteelOS. Corollary for the implementer: there
must be no configuration file, no systemd unit, no journal entry, and no
`steel-check` output difference that distinguishes "duress configured" from
"duress not configured" to anyone who has not unlocked the real volume. Store
duress configuration *inside* the encrypted volume it protects, never in the ESP
or in plaintext `/var`.

**2. Disk geometry must be identical for everyone.** Every SteelOS install, decoy
or not, allocates the entire disk and fills all unallocated space with random
data at install time. A second LUKS volume therefore occupies space that already
looked like high-entropy random data on every other SteelOS machine. Partition
tables must be identical in shape regardless of whether a decoy exists — allocate
the decoy's partition always; leave it as random noise if unused. **This is the
single highest-value item in this section** and it must be an install-time
default, because it cannot be retrofitted convincingly later.

**3. Identical base image.** `/usr` is byte-identical across all installs of a
given generation (already true by design — it's a verified image). The decoy's
system reveals nothing because it *is* the same system.

**4. Timing and behavioral indistinguishability.** Unlock paths for real
passphrase, decoy passphrase, duress passphrase, and wrong passphrase must be
constant-time and produce identical output, identical retry behavior, and
identical log entries. Test this with a timing harness in CI, not by inspection.

**5. The decoy must have a life.** It needs its own backup configuration pointing
at its own remote (a decoy repo that genuinely receives backups), its own
credentials in its own keyring, its own browser profile with history that grew
over months, its own shell history, its own installed Flatpaks. A profile with no
backup config on an OS that sets up backups by default is itself an anomaly.
`steel-decoy` must provision all of this, and the docs must tell users to
actually boot and use the decoy periodically — automated aging gets you
plausible, real use gets you credible.

**6. Log and metadata hygiene across volumes.** No `/etc/crypttab` entry, no
fstab line, no NetworkManager connection UUIDs shared between volumes, no
Tailscale node identity reused, no `steelctl` generation history referencing the
other volume, no shared machine-id. Two volumes must look like two machines.

**7. Nothing in the ESP may differ.** The ESP is unencrypted and is the first
thing an examiner reads. One UKI, one loader config, one boot entry, identical
for all installs. The passphrase entered selects the volume; the ESP never
records which volumes exist.

### Honest limits — put this verbatim in user-facing docs

1. **The measures above hide *whether you used it*, not *that it exists*.** An
   examiner who identifies the OS as SteelOS knows every install has decoy
   capability — that is the point of shipping it universally, and it is also the
   ceiling on what this achieves. They cannot prove from the disk that you
   configured one; they can simply demand another passphrase anyway, indefinitely,
   and an adversary willing to do that is not defeated by cryptography. This is
   the central unsolved problem with all decoy-volume systems and is why informed
   analyses consider VeraCrypt hidden-volume deniability defeated in practice.
2. **A multiple-snapshot adversary defeats it.** If the adversary images the disk
   on more than one occasion — a repeated border crossing, a seized-and-returned
   laptop, a compromised backup target — then blocks that changed between
   snapshots while the decoy claims to have been idle are direct evidence of a
   hidden volume. Defending against this requires ORAM-style oblivious write
   patterns (see the HIVE literature) at a severe performance cost, and we do not
   implement it. Users facing an adversary with repeated physical access should
   assume decoys do not work for them.
3. **SSD internals are outside our control.** The flash translation layer remaps
   and retains blocks invisibly; wear-level statistics and over-provisioned areas
   can indicate write volume inconsistent with the decoy's story. We can neither
   inspect nor sanitize this from the OS.
4. **Other disk forensics leak too.** Partition sizes that don't add up,
   unallocated regions with high-entropy data, SSD wear patterns, firmware-level
   remapped blocks, and free-space distributions can all indicate a second
   encrypted volume. We can reduce but not eliminate these signals.
5. **Off-device evidence dominates.** Cloud backups, ISP records, purchase
   history, phone contents, Tailscale/VPN account records, and your own
   `steel-backup` remote target all testify about what the machine actually did.
   A decoy on the disk does nothing about any of it.
6. **Key-disclosure law varies and may not care.** Several jurisdictions can
   compel passphrase disclosure with penalties for refusal, and destroying data
   during an investigation or at a border can itself be an offence. Users facing
   real legal jeopardy should get advice from a lawyer in their jurisdiction —
   this software is not a legal strategy.
7. **Coercion is not a technical problem.** These features address a narrow slice
   of it. For most at-risk users, not carrying the data across the border at all
   (clean device, restore from a remote backup afterward) is dramatically more
   effective than any on-device trick. The docs should recommend that first, and
   `steelctl export` + a remote restic repo makes it a supported workflow.
8. **Wiping can escalate the situation** the user is in. It is not universally
   the safe choice, which is why `alert-only` exists.

### Decoy realism engineering

**Principle: generate genuine artifacts, do not fabricate history.** Backdating
mtimes is trivial; producing an internally consistent multi-year history across
dozens of correlated stores is extremely hard, and inconsistency between them is
exactly what an examiner looks for. The cheapest way to have real artifacts is to
really use the decoy — so `steel-decoy` automates *use*, not *forgery*.

**Correlated stores that must agree** (a synthetic profile usually fails on the
last three):
- filesystem mtime/ctime/btime, inode allocation order, btrfs generation numbers
- systemd journal: boot IDs, monotonic timestamps, sequence numbers, file
  rotation boundaries; `wtmp`/`btmp` login records
- browser: history DB visit chains, cookies with issue dates, session restore,
  favicons, localStorage
- shell history with timestamps; KDE recent documents and thumbnails
- package and Flatpak install/update timestamps
- **HTTP `Date` headers and TLS certificate validity windows inside cached
  content** — these come from remote servers and cannot be backdated. A cache
  full of pages whose certificates were issued last week, sitting in a profile
  that claims to be two years old, is dispositive.
- **block-level write distribution** — a "two-year-old" profile whose every block
  was written in one burst is visible to anyone looking

**How the unattended session unlocks — and what it costs.**
Something must open the decoy volume with no human present, so the decoy key is
**TPM-sealed and released automatically**, bound to the PCR state of a dedicated
*maintenance boot path*. Design requirements:

- The maintenance boot entry ships in **every** SteelOS image, decoy or not
  (universal-shipping principle). On machines without a decoy it performs real
  work — staging updates, running backups, scrubbing the verity/btrfs state — so
  the path has an honest purpose and its presence proves nothing.
- The machine wakes itself via RTC alarm at scheduled times, boots the
  maintenance path, runs the session, and powers off.
- The decoy key is sealed to that path's measurements only. Entering the decoy
  passphrase interactively remains the normal user-facing route; the sealed key
  is not usable from the ordinary boot path.
- **Security cost, stated plainly:** a TPM-sealed decoy key means the decoy
  volume can be opened by the machine itself. It therefore provides *no*
  confidentiality against anyone holding the hardware. This is acceptable only
  because the decoy is designed to be surrendered — but it converts "the decoy
  should contain nothing real" from advice into a hard requirement. `steel-decoy`
  must refuse to import user data into a decoy profile.
- The real volume's key is never TPM-auto-released this way, and under
  `steel-custody` it cannot be, since its shares are off-device.

*Inferior alternative, documented but not default:* run the decoy session in a VM
from the unlocked real profile. It avoids auto-unlock entirely, but the decoy's
journal and DMI data then carry virtualization artifacts, which is itself
evidence the profile is staged.

**Therefore, `steel-decoy` implements scheduled genuine sessions:**
- The machine boots the decoy on a randomized schedule (default: several times a
  week, spread across plausible hours of day for the user's timezone) and runs a
  real user session, unattended, for a realistic duration.
- Inside it: a real browser visits a configured, boring set of real sites; a
  document is opened and edited; updates run; mail or feeds sync if configured.
  Artifacts are then genuine — real server dates, real cert chains, real journal
  entries, real write distribution over time.
- Sessions are jittered: variable duration, occasional skipped weeks, occasional
  long sessions. Perfect regularity is itself a signature.
- The decoy's own clock and timezone must match the real profile's, and its
  locale, keyboard layout, and hostname must be consistent with the hardware.
- **Automation must leave no trace of itself**: no cron/systemd unit visible
  inside the decoy, no scripts in its home, no autologin config. Scheduling is
  driven from outside the decoy volume (initramfs/boot policy), and the decoy
  session must be indistinguishable from a human one from inside.
- The decoy gets its own backup repo that genuinely receives these backups on a
  real schedule (see Backups) — an unbacked-up profile on an OS that configures
  backups by default is an anomaly.

**On red herrings — the spec's position is: don't.**
Planting intriguing-but-innocuous material to satisfy a searcher is a common idea
and a bad one:
1. It invites deeper scrutiny rather than ending it. The goal of a decoy is to be
   boring enough that examination stops; interesting content does the opposite.
2. Fabricated material must itself survive forensic consistency checks, and it is
   generated content — it fails the correlated-store tests above more often than
   real activity does.
3. Deliberately planting misleading material for an investigator can constitute
   fabricating evidence or obstruction in many jurisdictions, converting a
   passive protective measure into an active offence. This is a materially
   different legal posture from merely encrypting data, and users must be told so
   before they enable anything of the sort.

The credible decoy is a boring one: a privacy-conscious person with an ordinary
digital life, which is also a true and unremarkable description of most SteelOS
users. `steel-decoy` therefore ships only mundane profiles and provides no
"interesting content" generator.

### Pushing past the limits — what is actually possible

Each of the three hard limits has a partial technical answer. None is free, and
one of them is not a technical answer at all. Implement these as *optional,
clearly-labelled* modes, not defaults.

**Limit 1 — "the adversary just keeps demanding another passphrase."**
No decoy scheme solves this, because the adversary cannot distinguish "there is
nothing more" from "I refuse," and neither can any cryptographic construction.
The only real answer is to change what is true rather than what is provable:
make the user genuinely unable to decrypt.

- **Off-device key custody**: the real volume's key is split (Shamir, threshold
  2-of-3) between a hardware token the user does not carry, a remote service, and
  a trusted second party. On the road, the device physically cannot be decrypted
  by anyone, including its owner. "I cannot" is a materially different position
  from "I will not" — legally, practically, and in terms of what continued
  coercion can achieve.
- **Time-delayed release**: the remote share is released only after a fixed delay
  (hours to days) and the request is logged and notifiable. Coercion in a border
  booth or a hotel room stops being productive.
- **Dead-man / co-signer policies**: release requires approval from a second
  party who is instructed not to approve under specified conditions.
- Mechanics: the LUKS volume key is protected by a KEK that is never stored
  whole. Shamir 2-of-3 shares go to (a) a FIDO2/PIV token kept at home or with
  counsel, (b) a remote release service, (c) a trusted second party. The device
  stores only the encrypted volume key and share *identifiers* — no share, no
  KEK, no reconstructible material. At unlock, the initramfs collects two shares,
  reconstructs the KEK in RAM only, unwraps the volume key, and zeroes the KEK.
  Nothing recoverable persists after boot; suspend must be disabled or the volume
  locked on suspend, or the reconstructed key sits in RAM and defeats the point.
- **What binds unlock to the *person*, not just to objects.** Possession of the
  hardware is deliberately never sufficient. Four independent factors, each
  required:
  1. *Something known* — the volume passphrase and the token PIN. This is the
     only factor that lives in the user's head, and it is what makes a stolen
     laptop-plus-token useless. Token PIN lockout caps guessing.
  2. *Something held* — the FIDO2/PIV token, non-extractable and physically
     separated from the machine during travel.
  3. *Someone else's consent* — the release service's delay and the co-signer's
     approval. A thief or an opportunistic searcher cannot obtain share B at all;
     a determined adversary can only obtain it slowly, visibly, and with a third
     party informed.
  4. *This machine, in this state* — TPM sealing to PCR 7/11 means secrets are
     released only when the signed UKI and Secure Boot state match. Pulling the
     drive and reading it in another machine yields ciphertext; swapping in a
     tampered OS to capture the passphrase changes the measurements and the TPM
     refuses.
- **What this does not stop:** an adversary who has the user, the device, the
  token, and the ability to compel a PIN, at a time and place where the release
  policy permits. That is the rubber-hose case, and the delay/co-signer policy is
  the only lever against it — it converts an instant, private compulsion into a
  slow, witnessed one. Do not describe custody as preventing coerced unlock; it
  raises the cost and creates a record.
- **Post-unlock is a separate problem.** Once open, the volume key is in RAM and
  the machine is as accessible as any unlocked laptop. Under custody mode the
  spec requires: lock on suspend or suspend disabled, short idle lock, and
  re-authentication (token touch) to unlock the session — not just a password.
- Biometrics are not offered as an unlock factor. Beyond spoofing concerns, in
  several jurisdictions compelled biometric unlock is treated differently from a
  compelled passphrase; users should not be steered into the weaker position by a
  convenience default.
- **Token handling (share A).** The token must never hold the share as a
  readable file — a file can be copied off, and then leaving the token at home
  stops meaning anything. Two supported modes:
  - **FIDO2 with `hmac-secret`** (default). At enrollment the token is given a
    random salt, stored on the device in the clear; the token computes an HMAC
    over that salt with a hardware-bound, non-extractable key, and the result
    derives share A. Unlock therefore requires the physical token, a touch, and
    (mandatory in our config) the token PIN. `systemd-cryptenroll
    --fido2-device=auto --fido2-with-user-verification=yes` handles this, with
    initramfs support already present in systemd.
  - **PIV / PKCS#11 smartcard**, for users standardized on one: an on-card
    private key unwraps a wrapped share. Card PIN required. Only generate the key
    on-card; importing an externally generated key means a copy existed and may
    still exist.
- **Backup tokens, because you cannot clone one.** Non-extractable is the point,
  so a lost token cannot be duplicated after the fact. Enroll **two tokens at
  setup**, each with its own salt and its own wrapped share — kept in different
  physical locations. The third-party share remains the second line of defence.
  The installer must not let a user finish custody setup with a single token.
- **Token PIN lockout is a feature**: consumer FIDO2 tokens brick the credential
  after a small number of wrong PINs. This means a seized token plus guessing
  does not yield share A. Tell users the retry count of their specific model.
- **The token is never used by the maintenance/decoy path** — that path is
  unattended and cannot press a button, which is exactly why the decoy key is
  TPM-sealed and the real key is not. This asymmetry is deliberate: the real
  volume can only ever be opened with a human present.
- Failure modes to document: token firmware updates that reset credentials, dead
  tokens, USB-C/A availability on the travel machine, and the fact that a token
  in the same bag as the laptop provides no protection at all.
- **How you get back in.** The key is not destroyed and quorum is not permanent —
  it is *contextual*. Everyday use at home: the token (share A) is present and the
  release service returns share B immediately, so unlock is a normal, fast
  operation. Travel or coercion: the token stays home and the release service
  enforces its delay/co-signer policy, so quorum genuinely cannot be assembled in
  the room. Recovery after travel: return home, or have the second party approve
  release, and quorum reforms. 2-of-3 also tolerates losing any single share —
  a lost token is replaced by the third-party share.
- **Total-loss condition, which the installer must state in plain words:** if two
  of the three shares are lost, the data is gone permanently and no one can
  recover it. This is the direct cost of the guarantee. Mandatory at enrollment:
  a real reassembly drill using each pair combination, plus an offline
  `steel-custody export` recovery sheet for the third-party share.
- **Do not depend on a service that can disappear.** The release service must be
  self-hostable, and the third-party share must be sufficient to recover without
  it. Document the failure mode where a hosted release service shuts down.
- Ship as `steel-custody` (split-key enrollment, remote share service, recovery
  drills). Document loudly: this trades away offline access; a user who loses
  their shares loses their data. Run the recovery drill at setup, not later.

This is the strongest thing in this entire document for the whistleblower and
travelling-researcher case, and it is stronger than any decoy. It should be the
recommended configuration for that audience.

**Limit 2 — the multiple-snapshot adversary.**
This one *is* technically solvable, at a cost, and the literature is mature:
write-only ORAM gives provable deniability against an adversary who images the
disk repeatedly (HIVE; later PD-DM, DataLair). The cost is heavy write
amplification, which is unacceptable for a root filesystem but perfectly
tolerable for a small volume holding documents.

- Ship `steel-vault`: an optional, small (default 8–32 GB) write-only-ORAM
  deniable volume for sensitive files only — not the OS, not the home directory.
  Mount on demand inside the real profile.
- Cheaper partial mitigation for the main volume, offered separately: **continuous
  cover churn**. The decoy runs a legitimate workload that rewrites large disk
  regions on a schedule (rolling media cache, a VM image that gets rebuilt, a
  backup staging area). Blocks that differ between snapshots then have an
  innocent explanation. Weaker than ORAM — a careful analyst may still separate
  churn patterns from real activity — and it must be labelled as such.

**Limit 3 — SSD flash translation layers.**
The FTL problem comes from the drive lying about where data physically lives.
The mitigation is to put the deniable volume on media whose block mapping is
predictable:

- An **HDD** (no wear levelling, direct LBA mapping) for the deniable volume,
  internal or external. This is why most deniable-storage research assumes a
  conventional block device.
- Failing that, a dedicated SSD that is **fully allocated and encrypted end to
  end**, so the FTL only ever sees ciphertext and uniform write pressure; this
  reduces but does not remove the signal, since write *volume and timing* still
  leak.
- Document plainly that no software fix exists for a drive whose firmware retains
  remapped blocks, and that `steel-vault` on an SSD is weaker than the same
  design on an HDD.

**What none of this fixes**, and the docs must keep saying: off-device records,
behavioural evidence, and legal compulsion. A user whose adversary can subpoena a
cloud provider, correlate travel records, or hold them in contempt indefinitely
is not helped by better block-layer engineering. `steel-custody` plus not
carrying the data remains the honest recommendation.

### How duress, decoy, and custody interact

These three features are not additive; two of them pull in opposite directions.
The spec forces the user to choose a **playbook** at setup and rehearse it,
rather than enabling everything and hoping.

**The core tension.** Custody says *"I cannot open this."* Deniability says
*"there is nothing here to open."* Claimed together they undermine each other: if
the decoy is supposedly the whole machine, an examiner who finds evidence of
split-key enrollment has caught the contradiction. The two coherent postures are:

- **Playbook A — Deniable.** Decoy + duress credentials, no visible custody. The
  story is an ordinary machine belonging to a privacy-conscious person. Real
  volume protected by passphrase (+ TPM binding), duress credential available.
  Best against searches where the goal is for examination to end early.
- **Playbook B — Openly locked.** Custody enabled and not hidden. The story is
  "this device is under a key-management policy; I physically cannot open it
  here, and the release requires a delay and a second party." No decoy claimed.
  Best for a professional carrying work data under an organizational policy —
  a journalist, an auditor, a lawyer — where being *seen* to have a policy is
  normal and protective.
- **Playbook C — Layered (advanced, rehearsal required).** Both, with the custody
  enrollment concealed by the universal-blob mechanism below, and a rehearsed
  answer for the moment the two stories collide. Only appropriate for users who
  have thought hard about their specific adversary.

**Making custody enrollment invisible (required for Playbook A/C).** The
initramfs needs the wrapped key and salts before anything is decrypted, so they
cannot live inside the encrypted volume. Therefore: every SteelOS install ships a
fixed-size **custody region** of random data in the same location. On
custody-enabled machines it holds the wrapped key and share identifiers; on all
others it stays random fill. Presence proves nothing, exactly as with the decoy
partition and the maintenance boot entry.

**What the duress action should be, given custody.** If the real volume is under
custody, its data is already unreachable without quorum, so destroying local key
material is not what protects it — and destroying the on-device wrapped key makes
future quorum useless, i.e. permanent loss. Guidance:
- Custody enabled + remote backups configured → `decoy` or `alert-only` by
  default. Wiping is available and *safe* (backups are off-device, outer-key
  protected, append-only) but is rarely the best response.
- Custody disabled → `decoy-and-wipe` is the meaningful duress action, and the
  remote-only header backup is what makes it survivable.
- `alert-only` is the right default for anyone whose adversary might escalate on
  discovering data was destroyed.

**Boot-path summary** (all four inputs must be timing- and log-identical):

| Credential entered | Result |
|---|---|
| decoy-maintenance | decoy unlocks, no side effects (owner's routine use) |
| decoy-duress | decoy unlocks, configured duress action fires silently |
| real passphrase | custody flow: token touch + PIN, remote share, quorum, unlock |
| wrong | standard failure, attempt counter increments |

Unattended maintenance boots use the TPM-sealed decoy key only; the real volume
is never opened without a human present.

**Rehearsal is part of the feature.** `steel-duress drill` walks the user through
their chosen playbook end to end on scratch volumes: entering each credential,
observing what an examiner would see, and confirming the recovery path afterwards.
A playbook that has never been rehearsed will be performed badly under stress,
which is when it matters.

### Packaging

`steel-duress` — initramfs hook, dual decoy credentials, attempt counters,
`steel-duress test`, and `steel-decoy` provisioning/seeding/aging.
`steel-custody` — split-key enrollment, remote/delayed share release, drills.
`steel-vault` — optional write-only-ORAM deniable volume for documents. Off by default; the
installer's optional "Threatened-user setup" step enables it and walks through
the limits above with a comprehension confirmation, not just an "I agree" box.

## Backups

Three distinct problems; solve each explicitly. **Governing rule: no backup
target may live on the device being protected.** This is what resolves the
recoverable-vs-destroyable tension — local key material is destroyable under
duress precisely because recovery lives elsewhere. Backup targets are restricted
by policy to: a removable drive that is not attached during normal operation, or
a remote server. Writing backups to the internal disk is refused by
`steel-backup` (a local btrfs snapshot on `/var` is a convenience rollback, is
labelled as such in the UI, and is never counted as a backup by `steel-check`).

### Layered encryption and target hardening

Every archive passes through two independent encryption layers with independent
key material:

- **Inner**: restic or borg client-side encryption. Key derived from a
  per-profile passphrase, stored in that profile's keyring.
- **Outer**: an `age` (or gpg) layer applied to each pack before upload, keyed by
  a **recipient public key only**. The corresponding private key never exists on
  the device — it lives on a hardware token (FIDO2/PIV/YubiKey), on a printed
  paper backup, or with a trusted third party.

Why the outer layer matters more than "double encryption" sounds: because only
the *public* key is on the device, a fully compromised or seized machine cannot
decrypt its own historical backups. The inner layer protects the data in transit
and at rest against the storage provider; the outer layer protects it against
whoever ends up holding the laptop. Losing the outer private key means losing the
backups — the installer must state this and require the user to confirm they have
stored it off-device.

**Target must be append-only.** Configure restic via rest-server `--append-only`
or borg with an append-only SSH-forced command, using a credential that cannot
delete or prune. Malware or a coercer with the running machine can then add
garbage but cannot destroy history. Pruning happens from a separate trusted
context (another machine, or a token-gated admin credential), never from the
protected device. **Implement this before shipping backups** — without it,
ransomware or an adversary simply deletes the backups the duress design depends on.

**Remote-only header backups.** The LUKS header backup that makes a machine
recoverable is stored *only* inside the outer-encrypted remote repo, never on the
device and never on the ESP. This is what lets `wipe-keys` be genuinely
destructive to whoever holds the hardware while remaining recoverable by the
legitimate user later.

**Decoy profiles get their own real backup config** pointing at their own repo
with their own keys — an at-risk profile with no backup configured on an OS that
configures backups by default is itself an anomaly (see deniability section).

**1. System state (`/etc`, `/var`)**
- The image itself needs no backup — it's reproducible from the manifest.
- `/etc` is reconciled from the manifest; local deltas are captured by
  `steelctl export` into a portable bundle (manifest + /etc delta + service state).
- `/var` gets scheduled btrfs snapshots (snapper) for local rollback, plus
  restic/borg for offsite.

**2. User data (`/home` under systemd-homed)** — the sharp edge. A homed LUKS
home is an opaque encrypted image when locked; naive block-level backup produces
a blob that can only be restored wholesale and can't be verified or deduplicated
well. **Required design:** back up from *inside* the user's session while
unlocked, per-user, with the user's own restic/borg repo and key. Each profile
therefore has its own backup config, own credentials, and own schedule — which
is also correct for the compartmentalization model, since one profile must not
be able to read another's backups.
- `steel-backup` is a per-user systemd user service, triggered on session idle,
  with a Plasma applet showing last-run status and a "back up now" action.
- Restore path must be testable: `steel-backup verify` performs a real restore of
  a sampled subset into a scratch directory and compares hashes. A backup system
  that has never restored is not a backup system.

**3. Recovery credentials**
- LUKS recovery key, sbctl keys, TPM enrollment state, and the manifest are the
  minimum to reconstruct a machine. The installer produces a printable
  "recovery sheet" and `steelctl export --recovery` regenerates it later.
- Document explicitly: sbctl private keys live on the machine. If the disk is
  lost, Secure Boot keys must be re-enrolled from firmware setup mode on the
  replacement machine — this is expected, not a failure.

**Restore drill in CI**: a test that installs, writes data, backs up, wipes,
reinstalls from manifest, restores, and asserts equality. If this test doesn't
exist, the backup feature isn't done.

## Our packages

Shipped in our signed repo; each is a config bundle installable on plain Arch too
(this keeps Phase 0 useful and keeps us honest about coupling).

- `steel-keyring`, `steel-base` (meta)
- `steel-kernel-hardening` — sysctl drop-ins, modprobe blacklists, cmdline
  fragment, limits.d (ptrace, coredumps)
- `steel-boot` — UKI generation, verity hash embedding, sbctl hooks, A/B slot
  management, boot counting, TPM enrollment helper, recovery UKI
- `steel-image` — mkosi/archiso build definitions, snapshot pinning, signing
- `steel-config` — manifest schema, `steelctl` reconciliation engine
- `steel-malloc` — hardened_malloc + ld.so.preload management + per-app opt-out
- `steel-apparmor` — profile set, audit config, `steel-profile` guided CLI
- `steel-network` — nftables ruleset, MAC randomization, resolved DoT
- `steel-sandbox` — bubblejail + profiles, Flatpak default-permission overrides,
  `steel-shell` container wrapper
- `steel-duress` — duress credentials, attempt limits, decoy provisioning/seeding
- `steel-backup` — per-user backup service, applet, outer-layer key handling,
  append-only target setup, verify/restore tooling
- `steel-desktop` — Plasma Wayland defaults, SDDM + Plymouth themes, privacy
  defaults (telemetry off, no thumbnails for removable media, etc.)
- `steel-installer` — Calamares config + our modules
- `steel-doc` — offline docs: rationale, escape hatches, known issues

## Identity & compartmentalization

- **systemd-homed, LUKS storage, for every user.** Each home is independently
  encrypted; unlocked at login, locked at logout and on suspend (verify suspend
  behavior explicitly — it's a common silent failure).
- User B, even as root, cannot read user A's data at rest.
- Installer's "Profiles" step creates profiles (Personal / Work / Untrusted) as
  homed users with per-profile sandbox strictness and backup config. Not a
  bespoke concept — just users, so all existing tooling works.
- Per-profile Flatpak (`--user`) app sets and permissions.
- Fast user switching is the profile-switch UX (Plasma native).
- **Honest limit**: profiles share one kernel. A kernel exploit crosses them.
  This defends against data leakage and application compromise, not against
  kernel 0-day. Qubes is the answer if that's the requirement.

## Sandboxing model

- **GUI apps: Flatpak by default**, with global overrides stripping dangerous
  defaults (`--nofilesystem=home`, `--nodevice=all`, no fallback-x11), then
  per-app grants of the minimum. Discover configured Flatpak-only.
- **Native binaries: bubblejail** (bubblewrap, no SUID). Do NOT ship firejail —
  its SUID-root design contradicts the threat model.
- **CLI/dev work: `steel-shell`** — rootless Podman container, mutable, where
  pacman works normally and nothing escapes into the verified root.
- **AppArmor enforcing** underneath everything, with `steel-profile` wrapping the
  genprof → complain → logprof → enforce workflow so users can confine new apps.
- **User namespaces ENABLED** (linux-hardened disables them by default). Rationale:
  unprivileged sandboxing depends on them, and unprivileged bwrap is a better
  tradeoff than SUID helpers. Document the counterargument and ship
  `steel-harden userns off`.
- **Optional managed launch**: desktop entries rewritten so apps start inside
  their sandbox and, if Trrod is installed, their assigned network namespace.

## Memory & exploit mitigation

- `hardened_malloc` via `/etc/ld.so.preload`, **light variant by default**.
  Mandatory escape hatches: `steel-malloc exempt <binary>`, and a boot entry with
  the preload disabled. Strict variant offered as a toggle.
- **CPU memory encryption**: detect AMD SME/TSME or Intel TME. If supported but
  disabled in firmware, the installer tells the user the exact BIOS setting.
  Add `mem_encrypt=on` where applicable. Docs must state plainly: this defends
  cold-boot/DMA/bus attacks, not software memory reads via the kernel.
- **IOMMU on** (`intel_iommu=on` / `amd_iommu=force_isolation`) to constrain DMA
  from Thunderbolt/PCIe peripherals.
- Kernel cmdline baseline (validate each on real hardware):
  `slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1
   randomize_kstack_offset=on vsyscall=none lockdown=confidentiality
   module.sig_enforce=1 mitigations=auto`
- **Out-of-tree module conflict, resolved by the image model:** because modules
  are built at *image build time* in CI, we sign them with our key during the
  build. NVIDIA's open modules ship signed inside the verified image, so
  `lockdown=confidentiality` + `module.sig_enforce=1` can be the default without
  breaking NVIDIA. There is no DKMS-at-runtime path — that's a feature, and it's
  a direct advantage of immutability over the mutable design. Users needing an
  unsupported out-of-tree module must build a custom image (documented) or use
  devmode.
- **USBGuard** on in strict preset; new USB devices require approval via a Plasma
  prompt.

## Network defaults

- nftables ruleset generated by `steel-network`: input drop, forward drop,
  output allow (kill-switch mode available), loopback allowed, ICMP rate-limited.
- systemd-resolved with DNS-over-TLS; provider chosen at install (Quad9 /
  Cloudflare / Mullvad / custom). **Captive portal detection must be implemented**
  or hotel wifi appears broken and users disable DNS security permanently.
- NetworkManager MAC randomization (scan + connection) by default.
- Optional **Trrod** package for per-app tunnels with rotation.
- No listening ports by default. sshd not installed.

## Installer (Calamares + our modules)

1. Language / keyboard / timezone
2. **Disk**: guided A/B slot layout + LUKS2 for `/var` + homed for users.
   Passphrase strength meter with honest guidance (length beats complexity).
3. **Boot security**: detect Secure Boot state; enroll keys if in setup mode,
   else show vendor-specific instructions for entering setup mode. Offer TPM2+PIN.
   Generate and display recovery key with a confirmation that requires re-typing
   part of it.
4. **Hardening preset** with a details expander showing exactly what changes:
   - *Balanced* (default): verified immutable root, hardened kernel, sandboxing,
     nftables, DoT, homed, hardened_malloc light, lockdown, signed modules
   - *Strict*: adds hardened_malloc strict, USBGuard, noexec everywhere,
     stricter Flatpak defaults, no devmode boot entry
   - *Compatible*: mutable-friendly fallback for problem hardware — devmode
     available, lockdown=integrity, no malloc preload. Clearly marked as reduced
     protection.
5. **Graphics**: detect NVIDIA; since modules are signed at image build, this is
   no longer a conflict — but verify the correct driver variant is in the chosen
   image and warn about very new GPUs needing a newer channel.
6. **Profiles**: create 1..N homed profiles, each with password, sandbox
   strictness, backup target, optional Trrod policy.
7. **Backup setup**: local target always; optional remote (restic/borg) with
   credential entry and an immediate test run.
8. **Network privacy**: DNS provider, MAC randomization, optional Trrod.
9. Summary → install → **post-install checklist screen** (printable/savable):
   set firmware admin password, re-enable Secure Boot, enable TSME/TME if
   detected-but-off, save the recovery sheet.

## Build & release engineering

- Images built by CI with `mkosi` (evaluate archiso as fallback), from a pinned
  Arch snapshot, reproducibly. Same inputs → same image hash; publish hashes.
- Signed repo, signed images, signed UKIs. Key handling documented; release
  signing key offline where practical.
- **Automated VM test matrix, gating every publish** (QEMU + OVMF + swtpm):
  unattended install of each preset; boot; `steel-check` must pass; update to a
  newer image; roll back; restore-from-backup drill. A preset that fails to boot
  fails the release.
- Hardware matrix before each stable release: NVIDIA desktop, AMD laptop, Intel
  laptop, no-TPM machine, vendor-locked-Secure-Boot machine.

## Repo layout

```
steelos/
├─ CLAUDE.md
├─ image/                  # mkosi configs, snapshot pins, signing
├─ packages/               # PKGBUILDs for steel-* packages
├─ steelctl/               # manifest engine, generations, update/rollback (Rust)
├─ calamares/
│  └─ modules/{bootsec,hardening,profiles,backup,netprivacy,graphics}/
├─ tools/
│  ├─ steel-check          # audit: verifies every claimed measure (--json)
│  ├─ steel-harden         # toggle individual measures
│  ├─ steel-profile        # AppArmor guided workflow
│  ├─ steel-shell          # mutable dev container wrapper
│  └─ steel-backup         # per-user backup/verify/restore
├─ tests/
│  ├─ vm/                  # QEMU+OVMF+swtpm: install, update, rollback, restore
│  └─ audit/               # shared assertions for steel-check and CI
└─ docs/                   # threat model, escape hatches, rationale, known issues
```

## `steel-check` — defines "done"

One command auditing the running system, pass/fail per measure, `--json` output
so CI and users share assertions: Secure Boot state and key ownership, UKI
signature validity, **dm-verity active and root hash matching the signed UKI**,
LUKS parameters and enrolled slots, homed status per user, effective kernel
cmdline, effective sysctls, AppArmor enforce ratio, nftables policy, DoT active,
hardened_malloc loaded, memory encryption active, IOMMU active, module signature
enforcement, userns state, Flatpak override state, **current generation + slot +
boot-count status**, **last successful backup and last successful verify**, last `steel-duress
test` result, backup target separateness, append-only enforcement, and
outer-key-is-public verification. **`steel-check` must produce byte-identical
output on a machine with duress configured and one without, when run from a
context that has not unlocked the real volume** — this assertion is itself a CI
test.

Rule: every claim in user-facing material must be verifiable by this tool.

## Implementation phases

**Phase 0 — hardening packages on plain Arch.** No image, no installer. Build
the `steel-*` config packages and `steel-check`. Milestone: on a normal Arch VM,
`pacman -S steel-base && steel-check` is green. Useful immediately; de-risks
everything else.

**Phase 1 — image build.** mkosi build from a pinned snapshot producing a rootfs
image + verity hash tree + signed UKI containing the root hash. Milestone: image
boots in QEMU with Secure Boot and verity enforcing; `/usr` is provably read-only.

**Phase 2 — A/B deployment, updates, rollback.** Slot layout, `systemd-sysupdate`
integration, boot counting with automatic demotion, recovery UKI, `steelctl
update|rollback|history`. Milestone: deliberately ship a broken image; the
machine demotes and boots the previous generation unattended.

**Phase 3 — declarative layer.** manifest.toml schema, `steelctl apply|diff`,
/etc reconciliation, service enable/disable, Flatpak list handling. Milestone:
two machines from the same manifest produce identical image hashes.

**Phase 4 — identity, sandboxing, escape valves.** homed provisioning, Flatpak
override defaults, bubblejail profiles, AppArmor set, `steel-shell`, optional
Nix user-scope. Milestone: profile A cannot read profile B at rest; a developer
can do normal work without leaving the OS.

**Phase 5 — backups + duress.** Duress credentials, attempt counters (TPM NV
where available), decoy provisioning and aging, `steel-duress test` in CI. Also: per-user backup service, applet, `verify`, recovery sheet,
`steelctl export`. Milestone: full CI restore drill passes.

**Phase 6 — ISO + installer.** archiso live Plasma Wayland session; Calamares
with our modules; unattended install of all presets in CI.

**Phase 7 — hardware reality pass + release engineering.** Real-hardware matrix,
known-issues list, signed release pipeline, security contact, documented
rollback for every component.

## Gotchas the implementer must not discover the hard way

1. **Read-only `/usr` breaks a long tail of software** that writes into system
   paths (some installers, some proprietary apps, anything expecting to drop
   files in `/usr/share` at runtime). The answer is containers/Flatpak — but the
   *error messages* users see will be confusing. Ship a troubleshooting doc that
   maps common failures to the right escape valve.
2. **dm-verity + any runtime modification = unbootable.** Every tool that
   historically edited system files must be audited. `steel-check` should fail
   loudly if something has been layered in unexpectedly.
3. **A/B doubles root storage.** Size slots deliberately; document minimum disk.
4. **TPM PCR bindings break on firmware updates** — a BIOS update invalidates
   PCR 7 and auto-unlock stops. Recovery key handling, a clear error message, and
   `steel-boot reseal` are mandatory.
5. **UKI size limits**: some firmware chokes on large PE binaries (initramfs with
   NVIDIA + plymouth + firmware blobs gets big). Test on real hardware; consider
   trimming firmware to detected hardware where safe.
6. **Boot counting must be wired to a real "system is healthy" signal**, not just
   "kernel started," or a system that boots to a black screen will never demote.
7. **hardened_malloc breaks games and some proprietary apps.** Light variant
   default, per-app exemption, alternate boot entry.
8. **systemd-homed sharp edges**: SSH login, sudo, PAM stacking, and suspend-lock
   behavior all need explicit tests. Also: homed homes don't shrink easily —
   size guidance at install matters.
9. **Backing up homed homes naively produces useless blobs.** Per-user,
   in-session, file-level backup is the only correct approach.
10. **Flatpak global overrides break app launching in confusing ways** (portal
    grants). Test the top-30 desktop apps after applying defaults.
11. **Arch is a moving target.** The snapshot pin is what makes us sane; never
    build against "current" without pinning, or reproducibility is a lie.
12. **Don't ship a custom kernel build.** Use `linux-hardened`. Maintaining a
    kernel means owning its security updates, and we cannot.
13. **Secure Boot key enrollment can brick machines** whose firmware needs vendor
    keys for option ROMs. Enroll with Microsoft keys included by default; removing
    them is an explicit expert choice.
14. **Duress credentials must not be LUKS keyslots** — `luksDump` would reveal
    the extra slot and destroy the whole point. Separate salted hash, checked in
    the initramfs hook, constant-time, timing-identical to a wrong password.
15. **A wipe feature that has never been tested does not work.** `steel-duress
    test` against a scratch volume is mandatory, and CI must run it.
16. **Attempt-limit wiping is a self-DoS vector.** Default off, escalating delays
    recommended instead, and the installer warning must be unmissable.
17. **Header backups and duress wiping are mutually exclusive properties.** Make
    the user choose per-volume, explicitly, at install time. Silently backing up
    a header the user believes is destroyable is the worst possible outcome.
18. **Backups on the protected device are not backups.** Enforce the
    separate-target rule in code, not just docs.
19. **Without append-only targets, the duress design is hollow** — an adversary
    with the unlocked machine deletes the backups, then the local wipe is total.
20. **The outer backup key must never touch the device.** If it lands in the
    keyring "for convenience," the entire benefit is gone; `steel-check` must
    verify only a public key is present.
21. **Universal shipping of duress code is a hard requirement, not a preference.**
    Any conditional file, unit, or log line that reveals configuration state
    defeats the deniability design. Audit for this specifically.
22. **A TPM-auto-unlocked decoy is not confidential.** Anyone with the machine
    can read it. `steel-decoy` must hard-refuse importing real user data, and the
    docs must not describe the decoy as protecting anything.
23. **The maintenance boot path must exist on every install** or its presence is
    itself the tell. Give it real, useful work to do on non-decoy machines.
24. **Cached remote content cannot be backdated.** Any decoy-aging design based
    on synthetic file generation will fail on TLS validity windows and HTTP Date
    headers. Scheduled genuine sessions are the only approach that survives.
25. **Decoy automation must be invisible from inside the decoy.** A cron job that
    drives the decoy's own activity, visible in the decoy, proves the decoy is
    staged.
26. **Two decoy credentials, or none.** Shipping only a wiping decoy guarantees
    users destroy their own data and makes credible aging impossible.
27. **`steel-custody` must be drilled at setup.** Split-key custody that has
    never been reassembled is a data-loss event waiting to happen.
28. **`steel-vault` write amplification must be measured and shown** in the UI
    before enabling; users will otherwise enable it for their home directory and
    conclude the OS is broken.
29. **Never finish custody setup with one token.** Non-extractable keys cannot
    be cloned later; the second token must be enrolled at the same session.
30. **Custody does not prevent coerced unlock** and marketing must never imply
    it does. It delays, witnesses, and records — that is the whole claim.
31. **Custody and deniability conflict; make the user choose a playbook.**
    Enabling both without a rehearsed story produces a contradiction an examiner
    can exploit.
32. **Don't claim NixOS semantics or GrapheneOS parity.** We have image-level
    declarative config and whole-system rollback (not per-package generations),
    and verified boot without a hardware root of trust. State both plainly.

## Definition of done (v1)

- CI: install → boot → `steel-check` green → update → rollback → restore drill,
  for all presets, unattended
- Real NVIDIA hardware: Secure Boot on, verity enforcing, TPM+PIN unlock, signed
  NVIDIA modules loading under `module.sig_enforce=1`
- Two machines, same manifest, identical image hash
- A non-expert can install, create two profiles, install Firefox, set up backups,
  and browse — without reading documentation
- A developer can do a day's normal CLI work via `steel-shell` without touching
  devmode
- Every hardening measure has a rationale doc, an off-switch, and a test
- Known-issues list is honest and current
