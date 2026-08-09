# Known issues

Kept current and honest. A stale or optimistic known-issues list is worse than
none, because it teaches people not to read it.

## Current

### The repository is not signed

`steel-keyring` does not exist yet, because there is no signing key yet. Packages
are built from source with `makepkg`, and that is the only verification
available. See `packages/steel-keyring/README.md` for what has to exist first —
committing a placeholder keypair would make `pacman` appear to verify signatures
while verifying nothing, which is worse than the current honest gap.

### The installer has never installed anything

The GUI is complete and verified: Calamares loads the sequence, all eight SteelOS
pages construct, the palette applies, the Next button is genuinely gated by each
page's validation, and the refusals fire. That is checked in CI and was checked
by rendering the installer headlessly and driving it.

What has **not** happened is a real install. `steelos_partition` has never
partitioned a disk, `steelos_deploy` has never written an image, and
`steelos_bootsec` has never enrolled a key. Those jobs are written to the design
and reviewed, and every one of them refuses rather than guesses when its inputs
are wrong — but reviewed is not verified, and this is the part where a mistake
destroys someone's disk.

The VM matrix in `tests/vm/` is what closes this, and it has not been run.

### The ISO carries no system image

`steelos_deploy` looks for one on the medium and falls back to fetching the
channel's image over the network. `iso/build.sh` does not embed one, because
building an image needs signing keys that CI does not have. So an ISO built from
this repository can install only with a network connection, and a genuinely
offline install needs a release ISO with the image alongside it.

### Calamares is built from an unpinned AUR revision

Arch does not ship Calamares in `core` or `extra`, so `iso/build.sh` builds it
from the AUR PKGBUILD during the ISO build, at whatever revision that repository
is at. An upstream change can therefore break our ISO build, and the installer
we ship is built from a PKGBUILD we do not control.

The alternative — pulling a binary from a third-party repository — is worse: this
project's central claim is that you can verify what the system is made of, and an
unaudited binary repo in the build pipeline would be the least defensible
dependency in it. Building from source at least keeps the inputs inspectable.
Pinning the AUR revision is the obvious next step and has not been done yet.

### `module.sig_enforce=1` and `lockdown=confidentiality` are not applied on plain Arch

Both are in the audited baseline but deliberately left out of the shipped cmdline
fragment. On a mutable Arch install with DKMS, `module.sig_enforce=1` makes the
machine unbootable after the next kernel update, because locally-built modules
are not signed by any key the kernel trusts.

This is resolved by the image model rather than by configuration: modules are
built and signed in CI at image build time, so both settings become safe
defaults. `steel-check` reports the gap as a warning on `arch` deployments and a
failure on `image` ones.

### The captive portal helper is untested against real portals

`packages/steel-network/captive-portal-helper` implements the intended
design — bounded plaintext window, disposable browser profile, unconditional
restore — but it has not been run against actual hotel or airport portals. The
polling loop's use of `nmcli` connectivity state in particular is likely to need
adjustment per portal implementation.

Until it is tested: if wifi appears dead on a portal network, `steel-network dns
opportunistic` gets you online, and `steel-network dns strict` afterwards. Do not
leave it opportunistic.

### `steel-check` cannot verify LUKS KDF parameters

`storage.luks-parameters` verifies the header version and cipher but not the
PBKDF. The KDF lives in the header, which requires the backing device path rather
than the mapper name, plus root. The check says so in its evidence rather than
implying it verified more than it did. Verify by hand with
`cryptsetup luksDump <device>` and confirm `PBKDF: argon2id`.

### No `steel-check` coverage of the repo signing key

There is a `boot.repo-key-trusted` check described in the keyring README and not
implemented, because there is nothing to check yet.

### Nothing has run on real hardware

Every phase is implemented and every automated gate passes, but the VM matrix
has not been executed and no physical machine has booted this. The matrix needs
QEMU, OVMF, and swtpm; the hardware pass needs the five machine classes in
`docs/hardware-matrix.md`.

Treat everything below the Phase 0 packages as **written and reviewed, not
verified**. That distinction matters most for the boot chain, where a mistake
means a machine that does not start.

### The duress initramfs hook has not run in an initramfs

`packages/steel-duress/initcpio-hook` is written to the constraints —
no early return, constant-time comparison, identical work on configured and
unconfigured machines — and the timing harness measures a faithful
reimplementation of its comparison path. It has not yet run inside a real
initramfs against a real LUKS volume.

`steel-duress test` and `steel-duress drill` exist to establish that on a
specific machine, and the docs say plainly that a wipe feature which has never
been tested does not work.

## Addressed, but unverified on hardware

Each of these is implemented and has an automated gate. None has run on a
physical machine, which is a different thing from being fixed.

| Gotcha | How it is addressed | Still needs |
|---|---|---|
| A/B doubles root storage | 6 GiB slots, 64 GiB minimum enforced by the installer and reported by `steelos-check-hardware` | A real disk that is near the minimum |
| UKI size limits | `build.sh` fails the build over 60 MiB | An NVIDIA machine, where the initrd is largest |
| TPM PCRs break on firmware update | `steel-boot reseal`, and the enrollment prompt says so before you opt in | Actually updating a BIOS with TPM unlock enrolled |
| Boot counting on a fake health signal | `boot-complete-health.sh` checks verity matches the UKI, `/var` mounted, a graphical session actually appeared, no critical `steel-check` failure | The demotion test in the VM matrix |
| Duress credentials as LUKS keyslots | Separate salted hash in the custody region, never a keyslot | `luksDump` on a configured machine |
| Timing distinguishability | Measured in CI, not inspected; fails above 5 ms | The real initramfs path, not a reimplementation |
| Universal shipping | CI audits the source for conditionals, early returns, and plaintext config paths | — |

## Still open

### systemd-homed sharp edges

SSH login, sudo, PAM stacking, and suspend-lock behaviour need explicit tests.
`identity.home-lock-on-suspend` checks the configuration, but the failure mode
CLAUDE.md warns about is that it silently does not work — and only suspending a
real laptop establishes that.

Homed homes also do not shrink easily. The installer prompts with that caveat
attached, which is the best we can do at the moment of the decision.

### Flatpak global overrides break app launching confusingly

The top 30 desktop applications need testing after the defaults are applied. The
symptoms — an empty file dialog, an app that cannot find its own data — do not
point at the cause. `docs/escape-hatches.md` maps the ones we know about, and
that table needs to grow as real cases appear.

### Read-only `/usr` breaks a long tail of software

Anything expecting to drop files into `/usr/share` at runtime. The answer is
containers or Flatpak, but the *error messages* users see will not say that.

### `steel-vault`'s ORAM layer is a stub

`steel-vault` creates and manages an encrypted volume, measures and reports
write amplification, and refuses to be large. The write-only-ORAM block layer
itself — the thing that actually defeats a repeat-imaging adversary — is not
implemented. Until it is, `steel-vault` is a small encrypted volume with an
honest warning attached, and it should not be relied on for the property it is
named for.

## Reporting

Issues with a `steel-check` ID attached are much easier to act on. Include
`steel-check --json` output where you can — it contains no hostname, timestamp,
or other identifying data by design, so it is safe to paste.
