#!/usr/bin/env python3
"""Hardening preset selection.

The presets, and what each one costs. The details expander is not optional
polish: a preset the user cannot inspect is a preset they will not trust, and
`compatible` in particular must be presented as a real supported configuration
rather than as a failure state — less protection on a machine that runs beats
full protection on a machine that does not boot.
"""

import libcalamares
from libcalamares.utils import check_target_env_call

PRESETS = {
    "balanced": {
        "label": "Balanced (recommended)",
        "summary": "Everything that does not break normal desktop use.",
        "includes": [
            "Verified immutable root (dm-verity, sealed in a signed UKI)",
            "linux-hardened kernel and the full sysctl baseline",
            "Flatpak and bubblejail sandboxing, AppArmor enforcing",
            "Default-deny firewall, DNS over TLS, MAC randomisation",
            "systemd-homed per-user encryption",
            "hardened_malloc (light variant)",
            "Kernel lockdown, signed modules",
        ],
        "costs": [
            "`pacman -S` does not work on the host — use Flatpak or steel-shell",
            "Some Flatpak apps need permissions granted back explicitly",
        ],
    },
    "strict": {
        "label": "Strict",
        "summary": "For people who will trade functionality for margin.",
        "includes": [
            "Everything in Balanced, plus:",
            "hardened_malloc strict variant",
            "USBGuard: every new USB device needs approval",
            "noexec on /tmp, /var, and removable media",
            "Thunderbolt driver blacklisted",
            "ptrace disabled entirely (kernel.yama.ptrace_scope=3)",
            "No devmode boot entry",
        ],
        "costs": [
            "Thunderbolt docks, eGPUs and TB displays STOP WORKING",
            "USB prompts on every new device, including at inconvenient moments",
            "Debuggers do not work; some games and proprietary apps will not run",
            "No devmode means hardware bring-up needs a reinstall",
        ],
    },
    "compatible": {
        "label": "Compatible",
        "summary": "Reduced protection, for hardware the others will not run on.",
        "includes": [
            "Verified root, sandboxing, firewall, DNS over TLS, homed",
        ],
        "costs": [
            "NO hardened_malloc preload",
            "lockdown=integrity rather than confidentiality: kernel memory "
            "remains readable by root",
            "devmode boot entry available",
        ],
        "note": (
            "This is a real, supported configuration and not a failure state. "
            "Less protection on a machine that runs beats full protection on a "
            "machine that does not boot. steel-check reports it as a deliberate "
            "choice rather than failing every measure the preset does not apply."
        ),
    },
}


def apply_preset(name):
    if name not in PRESETS:
        raise ValueError(f"unknown preset: {name}")

    root = libcalamares.globalstorage.value("rootMountPoint")
    with open(f"{root}/etc/steelos/preset", "w") as handle:
        handle.write(name + "\n")

    check_target_env_call(["steel-harden", "preset", name])

    # The preset also selects the manifest's hardening field, so that a later
    # `steelctl apply` does not silently revert what was chosen here.
    manifest = f"{root}/etc/steelos/manifest.toml"
    try:
        with open(manifest) as handle:
            body = handle.read()
        body = body.replace('hardening = "balanced"', f'hardening = "{name}"')
        with open(manifest, "w") as handle:
            handle.write(body)
    except OSError:
        libcalamares.utils.warning("could not update the manifest's hardening field")


def run():
    preset = libcalamares.globalstorage.value("steelosPreset") or "balanced"
    apply_preset(preset)
    return None
