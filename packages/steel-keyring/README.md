# steel-keyring

Ships the public keys that verify the SteelOS package repository, and installs
them into pacman's keyring.

**This package is not yet built, deliberately.** It requires a real signing key,
and there is not one yet. Committing a placeholder keypair would be worse than
having nothing: it would make `pacman -S steel-base` appear to verify signatures
while verifying nothing, and someone would eventually ship it.

## What has to exist before this package can

1. **A repository signing key**, generated on an offline machine, with the
   private half never touching a network-connected system. `CLAUDE.md` calls for
   the release signing key to be offline where practical; for a project whose
   central claim is verified boot, "where practical" means always.

2. **A published fingerprint**, on more than one channel, so a user can check
   the key they received against something the same server did not hand them. A
   fingerprint published only on the site that serves the packages verifies
   nothing.

3. **A documented revocation and rotation path**, written before the first
   release rather than after the first incident.

4. **A decision on who holds the key**, and what happens when that person is
   unavailable, compromised, or compelled. This is a governance question, not a
   technical one, and it is the one most projects answer implicitly and badly.

## Until then

Phase 0 packages are built from this repository with `makepkg`, and users verify
them by building from source. That is a weaker guarantee than a signed
repository and the documentation says so plainly rather than implying otherwise.

## When it does exist

The package installs:

- `usr/share/pacman/keyrings/steelos.gpg` — the public key
- `usr/share/pacman/keyrings/steelos-trusted` — the trust database
- `usr/share/pacman/keyrings/steelos-revoked` — revoked keys

and its `.install` script runs `pacman-key --populate steelos`.

`steel-check` will gain a `boot.repo-key-trusted` check verifying that the key
in the local keyring matches the published fingerprint, so the claim is
auditable like every other one.
