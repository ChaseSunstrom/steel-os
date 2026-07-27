# Known issues

Kept current and honest. A stale or optimistic known-issues list is worse than
none, because it teaches people not to read it.

## Phase 0 (current)

### The repository is not signed

`steel-keyring` does not exist yet, because there is no signing key yet. Packages
are built from source with `makepkg`, and that is the only verification
available. See `packages/steel-keyring/README.md` for what has to exist first —
committing a placeholder keypair would make `pacman` appear to verify signatures
while verifying nothing, which is worse than the current honest gap.

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

`packages/steel-network/src/captive-portal-helper` implements the intended
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

## Expected to bite in later phases

Recorded now because they are cheaper to design around than to discover.

### A/B slots double root storage

Two full root images. Size the slots deliberately and document a minimum disk
size before the installer ships, not after someone runs out of space mid-update.

### UKI size limits

Some firmware chokes on large PE binaries, and an initramfs with NVIDIA
firmware, Plymouth, and broad hardware support gets big. This needs testing on
real hardware, and probably firmware trimming to detected hardware.

### TPM PCR bindings break on firmware updates

A BIOS update invalidates PCR 7 and auto-unlock stops. This is not preventable;
what matters is that the recovery key works, the error message says what
happened, and `steel-boot reseal` exists. All three before TPM unlock ships.

### Boot counting must be wired to a real health signal

If the counter is satisfied by "the kernel started", a system that boots to a
black screen will never demote — which is precisely the failure that makes
rollback necessary. `boot-complete.target` has to depend on something that means
the desktop actually came up.

### systemd-homed sharp edges

SSH login, sudo, PAM stacking, and suspend-lock behaviour all need explicit
tests. Homed homes also do not shrink easily, so the size chosen at install
matters more than users will expect.

### Flatpak global overrides break app launching confusingly

The top 30 desktop applications need testing after the defaults are applied. The
symptoms — an empty file dialog, an app that cannot find its own data — do not
point at the cause. `docs/escape-hatches.md` maps them, and that table needs to
grow as real cases appear.

### Read-only `/usr` breaks a long tail of software

Anything expecting to drop files into `/usr/share` at runtime. The answer is
containers or Flatpak, but the *error messages* users see will not say that.

## Reporting

Issues with a `steel-check` ID attached are much easier to act on. Include
`steel-check --json` output where you can — it contains no hostname, timestamp,
or other identifying data by design, so it is safe to paste.
