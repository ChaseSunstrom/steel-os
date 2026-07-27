# calamares/ — Phase 6

Not yet implemented. Calamares configuration and the SteelOS modules:
`bootsec`, `hardening`, `profiles`, `backup`, `netprivacy`, `graphics`.

**Milestone:** unattended install of every preset, in CI.

## Two things the installer must get right

**The attempt-limit warning must be in the UI, not the docs.** Count-based
auto-wipe is a self-destruct that anyone with physical access can trigger — a
child, a roommate, a thief who only wants the hardware, or the user themselves
with the wrong keyboard layout. GrapheneOS deliberately does not enable it by
default for exactly this reason. Escalating delays give most of the
anti-brute-force benefit with none of the self-destruct risk. Recommend delays;
offer wiping; make the warning unmissable.

**Header backups and duress wiping are opposing properties.** A machine that is
recoverable from a header backup is not destroyable under duress, and the
reverse. The user must choose per volume, explicitly, at install time. Silently
backing up a header the user believes is destroyable is the worst outcome this
project can produce.
