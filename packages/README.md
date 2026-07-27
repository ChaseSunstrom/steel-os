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
| `steel-keyring` | Not built yet — see its README for why |

## Later phases

`steel-boot` (Phase 1-2), `steel-image` (Phase 1), `steel-config` (Phase 3),
`steel-duress` (Phase 5), `steel-backup` (Phase 5), `steel-installer` (Phase 6),
`steel-doc`.

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
