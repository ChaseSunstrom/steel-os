# Hardware matrix

The VM matrix gates every publish, but a VM has an obliging firmware, a
cooperative TPM, and no vendor quirks. Real hardware is where verified boot
actually gets tested.

## Required before each stable release

| Class | Why this one | Tests |
|---|---|---|
| NVIDIA desktop | The case the image model exists to resolve | Signed modules load under `module.sig_enforce=1` and `lockdown=confidentiality` |
| AMD laptop | SME/TSME, and the most common Linux laptop | Memory encryption active; suspend locks homes |
| Intel laptop | TME, Thunderbolt, and vendor Secure Boot | TB security levels; IOMMU; TPM+PIN |
| No-TPM machine | Passphrase unlock must be a first-class path | Install and unlock with no TPM present |
| Vendor-locked Secure Boot | Where key enrollment goes wrong | Machine still boots after enrollment |

## What each one is actually looking for

**NVIDIA desktop.** Modules are built and signed in CI, so the conflict between
out-of-tree drivers and `module.sig_enforce=1` should not exist. "Should not"
needs a machine to confirm it. Also: UKI size — an initrd with NVIDIA firmware
is the case most likely to hit a firmware's PE size limit (gotcha 5).

**AMD laptop.** Whether TSME is actually on, which firmware reports
inconsistently. And suspend: `identity.home-lock-on-suspend` is the check, and
lock-on-suspend failing silently is the specific thing CLAUDE.md flags.

**Intel laptop.** Thunderbolt with the IOMMU, which is the whole reason
`memory.iommu` is a High-severity check. Under the strict preset the driver is
blacklisted and docks stop working — verify that is what happens, rather than
something worse.

**No-TPM machine.** Passphrase unlock is the default and must stay a
first-class path, not a degraded one. A machine with no TPM should install and
run with no warnings beyond the informational one.

**Vendor-locked Secure Boot.** Gotcha 13: enrollment can brick machines whose
firmware needs vendor keys for option ROMs. We include Microsoft's keys by
default precisely because of this, and the test is that the machine still POSTs
afterwards.

## Firmware update regression

Not a machine class, a scenario, and the one most likely to generate support
load: **update the BIOS on a machine with TPM unlock enrolled.**

PCR 7 changes, auto-unlock stops, and the user is at a recovery key prompt they
were not expecting. That is not preventable. What is testable is that the
recovery key works, the message says what happened, and `steel-boot reseal`
restores auto-unlock. All three, on real hardware, before TPM unlock ships.

## Recording results

One file per machine under `tests/hardware/`, with the firmware version, the
`steel-check --json` output, and anything that needed a workaround. `steel-check`
output carries no identifying data, so these can be published.

A machine that has not been tested against the current stable release is not a
supported machine, and the known-issues list should say so rather than implying
broader coverage than we have.
