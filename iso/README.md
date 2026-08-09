# iso/ — the live installer medium

An archiso profile. The live environment's job is narrow: boot on the widest
possible range of hardware, run the installer, and get out of the way.

It is deliberately **not** a hardened environment. Hardening the installer medium
would make it fail to boot on exactly the machines that most need to be installed
onto, and the installed system is where the guarantees live. The one thing it
does get right is that the session runs as an unprivileged user with nothing
listening — a live ISO is a machine on someone else's network with no firewall
configured yet, and `sshd` is not installed.

## Building

```
sudo ./iso/build.sh
```

Requires an Arch host or container with `archiso`, `squashfs-tools`,
`dosfstools`, `mtools` and `libisoburn`, root (mkarchiso mounts things), and a
non-root build user (makepkg refuses to run as root). Output lands in `iso/out/`.

The script does four things in order, because each depends on the one before:

1. builds Calamares, which Arch does not ship in its official repositories, and
   installs it — `steel-installer-page` is a Calamares view module and compiles
   against its headers
2. builds every `steel-*` package from `packages/`
3. assembles both into a local pacman repository
4. runs `mkarchiso` against a **copy** of this directory whose `pacman.conf`
   points at that repository

Step 4 works on a copy because `pacman.conf` needs an absolute repository path
that the checked-in profile cannot know. `@STEELOS_REPO@` is the placeholder, and
`build.sh` is the supported entry point — running `mkarchiso` directly on this
directory gets you the placeholder verbatim.

CI runs the same script in a privileged `archlinux` container on every push, and
the release pipeline attaches the resulting ISO to the release.

## What is on it

| | |
|---|---|
| Desktop | Plasma on Wayland, autologin as the unprivileged `live` user |
| Installer | Calamares, driven by `steel-installer` — eight QML pages, the branding, and the install jobs, all from `calamares/` |
| SteelOS tooling | `steel-check`, `steelctl`, `steel-boot`, `steel-duress`, so the installed system's own tools do the work rather than a parallel implementation that drifts |
| Diagnosis | `steelos-check-hardware`, plus `pciutils`/`dmidecode`/`inxi` for the machines where installation will not be simple |
| Recovery | `restic`, `borg`, `age`, `cryptsetup`, `sbctl` — a live ISO is also what people reach for when an installed machine will not boot |

`steelos-install` is the single entry point the desktop file, the autostart entry
and the sudoers rule all name. It runs the hardware check first and shows the
result, because everything that check reports is a decision the installer would
otherwise make silently or discover too late. It is also where the installer's
environment is set up — Calamares run directly comes up with pages that silently
cannot read the machine's facts, which is why the sudoers rule names the launcher
and not the binary.

`steelos-live-probe` runs once at boot and writes `/run/steelos/hardware.json`
and `/run/steelos/recovery-key`. The installer pages read that file and never run
a process themselves.

## Two boot entries, both firmware paths

BIOS via syslinux and UEFI via systemd-boot, each with a `nomodeset` fallback.
The fallback is not padding: the medium has to boot on hardware nobody here has
seen, and "the installer shows a black screen" needs an answer other than "use a
different distribution".

## Status

The medium builds, the live environment works, and the installer's GUI is
complete and verified — the sequence loads, every page renders, and each page's
validation genuinely gates the Next button.

What has not happened is a real install: no disk has been partitioned, no image
written, no key enrolled. And this ISO carries no system image, so installing
from it currently requires a network connection. Both are in
`docs/known-issues.md`; do not describe this as tested until the VM matrix has
run.
