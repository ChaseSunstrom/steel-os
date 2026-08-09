# packages/

Each `steel-*` package is a config bundle that installs on plain Arch and works
there on its own. That is deliberate: it keeps Phase 0 useful to people who will
never install the full OS, and it keeps us honest about coupling. If
`steel-network` only worked when `steel-boot` were present, we would have built
a distribution that happens to ship packages rather than packages that happen to
compose into a distribution.

## Present

| Package | What it does |
|---|---|
| `steel-base` | Meta-package; sets the default preset |
| `steel-check` | The auditor (built from `tools/steel-check`) |
| `steel-kernel-hardening` | sysctls, module blacklists, cmdline fragment, coredump policy |
| `steel-malloc` | hardened_malloc preload, per-binary exemptions |
| `steel-network` | nftables default-deny, strict DoT, MAC randomisation, captive portal helper |
| `steel-sandbox` | Flatpak permission defaults, bubblejail profiles, `steel-shell` |
| `steel-apparmor` | AppArmor enablement and `steel-profile` |
| `steel-desktop` | Removable-media mount policy, lock-on-suspend, Plasma privacy defaults |
| `steel-installer` | Calamares sequence, branding, QML pages and install jobs |
| `steel-installer-page` | The installer's one compiled piece: a Calamares view module |
| `steel-keyring` | Not built yet — see its README for why |

## Later phases

`steel-image` (Phase 1) and `steel-doc` are still to come.

## Layout: payload sits next to the PKGBUILD

Config files, scripts and units live directly in `<package>/`, listed in
`source=()` by plain filename and installed from `$srcdir`. That is the
canonical Arch layout, and here it is also the only one that works:

* A **local** `source=()` entry is resolved by *basename* against `$startdir`.
  `source=('files/sysctl/99-steel-hardening.conf')` makes makepkg look for
  `99-steel-hardening.conf` next to the PKGBUILD, not find it, and fail with an
  error naming a path you never wrote. Subdirectories in local sources do not
  work at all — this is what broke the packaging job.
* Reaching out of the package directory with `$startdir` instead is worse: it
  breaks in a clean chroot, and `namcap` reports it as an error, which the CI
  lint gate treats as a failure.
* A payload directory named `src/` is deleted by its own build, because
  `$srcdir` is literally `$startdir/src` and `makepkg --clean` removes it.

`steel-check`, `steel-config` and `steel-installer` cannot use that layout —
they build from the whole workspace. They take a source tarball instead:

```
./packages/prepare-workspace-source.sh     # then makepkg in any of the three
```

The tarball is generated, git-ignored, and deterministic (sorted entries, fixed
ownership, `SOURCE_DATE_EPOCH` mtimes). CI and `iso/build.sh` run that script
before building.

## The rule these packages follow

Anything a package configures must be auditable by `steel-check`, and the values
must match. The sysctl, modprobe, and cmdline tables live in
`tools/steel-check/src/checks/kernel.rs`, and unit tests fail the build if the
shipped drop-ins drift away from them.

Without that, the packages and the auditor eventually disagree — and the auditor
is the one that would be wrong, which is the worst possible outcome for a tool
whose entire job is telling you the truth about the system.

## Building

```
cd packages/steel-kernel-hardening
makepkg -si
```

CI builds all of them and asserts the installed layout matches the paths
`steel-check` reads.
