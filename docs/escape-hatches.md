# Escape hatches

Design principle 6: *every hardening measure must be reversible and documented.
A user who hits a broken app needs a discoverable escape hatch, or they will
disable everything instead of one control.*

The second half of that sentence is the argument. Someone whose game will not
start has two options: find the one setting responsible, or replace the OS with
something that has none of it. If finding the one setting is hard, they take the
second option, and every other measure goes with it.

So this page is a security document, not a convenience one.

## Start here

```
steel-check                      # what is failing, and what fixes it
steel-check --explain <id>       # why the measure exists, and its off-switch
steel-harden status              # the preset, and every override in effect
```

Every check names its own escape hatch. Every override made with `steel-harden`
is recorded in `/etc/steelos/overrides/` and reported by `steel-check`, so a
deliberate exception stays distinguishable from a measure that quietly stopped
working. Those two states look identical in an audit six months later, and only
one of them was a decision.

## By symptom

| Symptom | Likely cause | Fix |
|---|---|---|
| A game or proprietary app crashes instantly on launch | hardened_malloc | `steel-malloc exempt /path/to/binary` |
| A Flatpak's file dialog shows an empty home | global Flatpak override | `flatpak override --user --filesystem=xdg-documents <app>`, or Flatseal |
| A Flatpak cannot find its own data | global Flatpak override | grant its data directory specifically |
| A Flatpak will not start at all | `fallback-x11` revoked | `flatpak run -v <app>` to confirm, then grant `--socket=fallback-x11` |
| No sound or camera in a sandboxed app | `devices=!all` | grant the specific device |
| A build system fails with "permission denied" in `/tmp` | `/tmp` mounted noexec | `steel-harden tmp-noexec off` |
| A portable app on a USB stick will not run | removable media noexec | `steel-harden removable-noexec off`, or copy it to `$HOME` first |
| A program is denied a file it should have | AppArmor | `journalctl -b -g apparmor`, then `steel-profile refine <binary>` |
| `pacman -S` fails, "read-only file system" | this is by design | `steel-shell`, Flatpak, or the manifest — see below |
| Hotel wifi appears completely dead | strict DoT plus a captive portal | the portal helper should fire automatically; if not, `steel-network dns opportunistic` **temporarily** |
| A Thunderbolt dock stopped working | strict preset blacklists `thunderbolt` | `steel-harden module thunderbolt allow` |
| Auto-unlock stopped after a BIOS update | TPM PCR 7 changed | recovery key, then `steel-boot reseal` |
| A container has no network | `forward` policy is drop | the runtime normally adds its own rules; check `nft list ruleset` |

## "I need to install a package"

This is the question the immutable design creates, and it has four answers
depending on what you are installing. The rule: **if your need is met by one of
the first two, it must not require an image rebuild.** If it does, we have got
the design wrong.

| What you want | Where it goes | How |
|---|---|---|
| A GUI application | Flatpak, user scope | `flatpak install --user <app>` |
| A CLI tool or dev toolchain | a container | `steel-shell`, where `pacman -S` works normally |
| Functional package management | Nix, user scope on `/var` | optional; how we offer Nix semantics without claiming to be NixOS |
| A kernel, driver, or base package | the manifest | `steelctl apply`, takes effect on reboot |
| A signed system extension | sysext | layered onto `/usr` at runtime; unsigned ones are rejected |

`steel-shell` is the one most people need. It is a rootless Podman container
running the same Arch base with your home mounted, where `pacman -S` works and
affects nothing outside the container.

## devmode

When none of the above is enough — hardware bring-up, debugging something that
genuinely requires writing to `/usr` — there is `steel-devmode`: a boot entry
with verity disabled and `/usr` writable.

Deliberate properties:

- **It requires physical presence at boot.** It is a boot entry, not a runtime
  toggle, so a remote attacker cannot enable it.
- **It is clearly marked**, in Plymouth and in the session, because a machine in
  devmode has none of the guarantees this project makes and you should not be
  able to forget that.
- **Changes do not survive into the normal deployment.** The verified image is
  unchanged; what you modify is a separate writable deployment.
- **`steel-check` reports `deployment=devmode`** and downgrades the affected
  checks to warnings rather than failures, because you opted into this.

The strict preset removes the devmode entry entirely.

## Presets

```
steel-harden preset balanced      # the default
steel-harden preset strict        # + USBGuard, full malloc, noexec everywhere,
                                  #   no thunderbolt, no devmode entry
steel-harden preset compatible    # for hardware that will not run the above
```

`compatible` is a real, supported configuration for problem hardware, not a
failure state. `steel-check` reports it as such rather than failing every check
that the preset deliberately does not apply. It is clearly marked as reduced
protection, and that is the honest framing: less protection on a machine that
runs beats full protection on a machine that does not boot.

## What has no escape hatch, and why

Three things. Each is load-bearing for a claim the project makes, and providing
a switch would mean the claim is conditional in a way users cannot see.

- **Verity on the root image.** Disabling it is not a setting; it is booting
  devmode, which announces itself.
- **The append-only requirement on backup targets.** Without it the duress design
  is hollow — an adversary with the unlocked machine deletes the backups first,
  and then the local wipe is total.
- **The backup-target separateness rule.** A backup on the device being protected
  is not a backup. `steel-backup` refuses local targets in code, not just in
  documentation.
