# Threat model

Everything else in SteelOS follows from this document. A measure that does not
raise cost for an attacker in this model does not ship, however good it looks in
a feature list.

## In scope

### Device theft or seizure while powered off

The most common realistic attack on a laptop. `/var` is LUKS2-encrypted, every
home is an independently encrypted systemd-homed volume, and swap is either
encrypted or absent — the last one matters more than it sounds, because swap
receives page contents verbatim and unencrypted swap silently undoes full-disk
encryption for whatever happened to be paged out.

*Audited by:* `storage.var-encrypted`, `storage.luks-parameters`,
`storage.swap-encrypted`, `identity.homed-users`.

### A malicious or compromised desktop application

GUI applications run as Flatpaks with the dangerous default permissions revoked
globally, then granted back per app from nothing. Native binaries get bubblejail,
which is unprivileged bubblewrap rather than a SUID helper. AppArmor confines
what escapes or never entered a sandbox.

*Audited by:* `sandbox.flatpak-overrides`, `sandbox.apparmor-enforcing`,
`sandbox.no-suid-sandbox`, `sandbox.bubblejail`.

### A malicious website or document

The browser and document viewers are the processes most exposed to hostile
input. hardened_malloc turns a large class of heap corruption bugs into crashes
rather than exploits; the kernel hardening baseline removes the primitives that
kernel exploits chain through (`vm.unprivileged_userfaultfd`,
`kernel.unprivileged_bpf_disabled`, `dev.tty.ldisc_autoload`).

*Audited by:* `memory.hardened-malloc`, `kernel.sysctl-baseline`,
`kernel.cmdline-baseline`.

### Persistence after compromise

This is the one the whole architecture exists for. An attacker who gets root at
runtime cannot durably modify the OS: `/usr` is read-only and its hash is sealed
in a signed UKI, so there is nowhere for a persistent implant to live. A reboot
restores a known image.

The bound is precise and worth stating: immutability limits *persistence*, not
*session-scoped compromise*. Malware that only needs to survive until the next
reboot is not affected by any of this.

*Audited by:* `filesystem.usr-read-only`, `storage.verity-active`,
`deployment.no-unexpected-layering`, `deployment.sysext-signed`.

### Offline tampering with the OS

dm-verity verifies every block of `/usr` against a hash tree on read. The root
hash is in the kernel command line, which is inside the signed UKI — so
modifying the root filesystem requires either forging our signature or
persuading the firmware to boot an unsigned kernel.

*Audited by:* `storage.verity-roothash-matches-uki`, `boot.uki-signed`,
`boot.secure-boot-enabled`, `boot.own-keys-enrolled`.

### A local network attacker

Default-deny inbound, no listening ports, sshd not installed. DNS over TLS in
strict mode so an on-path attacker cannot see or forge lookups — and, critically,
so it fails closed rather than downgrading.

*Audited by:* `network.nftables-policy`, `network.no-listening-ports`,
`network.dns-over-tls`.

### Passive network surveillance and correlation

MAC randomisation on both scanning and connection, IPv6 privacy addresses, no
hostname disclosure over DHCP, no mDNS/LLMNR. Per-application tunnels via Trrod
where installed.

*Audited by:* `network.mac-randomization`, `kernel.sysctl-baseline`
(`use_tempaddr`).

### Evil-maid tampering with the boot chain

Secure Boot with our own enrolled keys rather than only the vendor's — the
distinction matters, because Secure Boot with stock keys will boot anything
Microsoft signed, including well-known vulnerable shims.

*Audited by:* `boot.secure-boot-enabled`, `boot.own-keys-enrolled`,
`boot.tpm-binding`.

### Cold-boot and DMA attacks

IOMMU enabled so peripherals cannot read arbitrary memory; CPU memory encryption
where the hardware supports it. Note carefully what memory encryption does and
does not do: it defends the DRAM bus and powered-off DIMMs. It does **not**
defend against software reading memory through the kernel, and any document that
implies otherwise is wrong.

*Audited by:* `memory.iommu`, `memory.cpu-encryption`.

### User error and bad updates

Updates apply to an inactive slot; the previous deployment stays bootable; a
deployment that cannot reach a healthy state is demoted automatically after N
failed boots. Backups are layered, off-device, and append-only.

*Audited by:* `deployment.slot-health`, `deployment.boot-counting`,
`backup.*`.

### Coerced unlock

Duress credentials, decoy profiles, and split-key custody. **This is the weakest
area in the design and must not be oversold.** The honest analysis, including
the cases where none of it works, is in
[duress-and-deniability.md](duress-and-deniability.md). Read that before
enabling anything in this category.

*Audited by:* `duress.*`.

## Out of scope

These are not oversights. Each one is a decision, and stating it clearly is more
useful than a longer feature list.

### Compromised UEFI firmware, Intel ME, AMD PSP

Our trust chain starts at the firmware. If the firmware lies, everything above
it is theatre. This is the single largest gap versus a phone with a hardware
root of trust, and it is a property of PC hardware rather than something we can
engineer around.

### Hardware implants and targeted supply-chain attacks against the hardware

Same reason. An attacker who can modify the machine before you receive it is
outside anything the OS can address.

### An attacker with your unlock password and physical access at rest

Encryption defends against people who do not have the key. There is no
cryptographic answer to someone who has it. `steel-custody` changes *who* holds
the key rather than solving this — see the duress document for what that does
and does not achieve.

### Full anonymity

SteelOS reduces passive correlation. It does not anonymise. There is no Tor
integration by default, no traffic shaping, no protection against
browser fingerprinting. If anonymity is the requirement, use Tails or Whonix,
which are built for it.

### A kernel 0-day escaping every sandbox layer

Mitigated, not prevented. Profiles share one kernel; a kernel exploit crosses
between them. This defends against data leakage and application compromise, not
against a kernel 0-day. Qubes is the answer if that is the requirement, and its
authors concluded the answer requires VMs for reasons that remain valid.

### Malware that only needs to survive until the next reboot

Immutability bounds persistence. Everything in a session is still reachable by
something that compromises that session.

## What "audited by" means

Every entry above names the `steel-check` IDs that verify it. This is the
project's governing rule: a claim that cannot be checked does not get made. Run
`steel-check --explain <id>` for the rationale and the documented off-switch for
any of them.

If you find a claim in our documentation with no corresponding check, that is a
bug — either the check is missing or the claim is.
