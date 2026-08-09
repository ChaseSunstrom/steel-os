#!/usr/bin/env python3
"""Write the hardening preset and the manifest.

The preset is the single switch every check consults to decide whether a
measure is required, optional, or deliberately absent. It has to end up in two
places that agree: /etc/steelos/preset, which steel-check and steel-harden
read, and the manifest's `hardening` field, so that a later `steelctl apply`
does not silently revert what was chosen here.
"""

import os
import subprocess

import libcalamares

PRESETS = ("balanced", "strict", "compatible")

MANIFEST_TEMPLATE = """# SteelOS system manifest.
#
# This file defines the machine. Two machines with the same manifest and the
# same snapshot pin produce the same image hash — that is the whole point, and
# it is why the pin exists.
#
# `steelctl diff` shows what a change would do. `steelctl apply` builds or
# fetches the resulting image and stages it in the inactive slot; a reboot
# activates it, and the previous generation stays bootable.

[system]
channel   = "{channel}"
snapshot  = "{snapshot}"
hardening = "{preset}"
kernel    = "{kernel}"

[packages]
system = []

[flatpak]
user = []

[services]
enable  = []
disable = []

[backup]
enabled  = {backup_enabled}
targets  = [{backup_targets}]
schedule = "{backup_schedule}"
retention = "{backup_retention}"
"""


def pretty_name():
    return "Applying the hardening preset"


def run():
    gs = libcalamares.globalstorage
    config = gs.value("steelos.hardening") or {}
    deployment = gs.value("steelos.deployment") or {}
    backup = gs.value("steelos.backup") or {}
    root = gs.value("rootMountPoint")

    preset = config.get("preset", "balanced")
    if preset not in PRESETS:
        return ("Unknown hardening preset", f"{preset!r} is not one of {PRESETS}.")

    if not root:
        return ("Nothing is mounted", "The deployment step did not set a root mount point.")

    steelos_etc = os.path.join(root, "etc/steelos")
    os.makedirs(steelos_etc, exist_ok=True)

    with open(os.path.join(steelos_etc, "preset"), "w") as handle:
        handle.write(preset + "\n")

    targets = []
    if backup.get("enabled") and backup.get("remoteUrl"):
        targets.append('"' + backup["remoteUrl"].replace('"', '') + '"')

    manifest = MANIFEST_TEMPLATE.format(
        channel=deployment.get("channel", "stable"),
        snapshot=deployment.get("snapshot", ""),
        preset=preset,
        kernel=config.get("kernel", "linux-hardened"),
        backup_enabled="true" if backup.get("enabled") else "false",
        backup_targets=", ".join(targets),
        backup_schedule=backup.get("schedule", "daily"),
        backup_retention=backup.get("retention", "7d 4w 6m"),
    )
    with open(os.path.join(steelos_etc, "manifest.toml"), "w") as handle:
        handle.write(manifest)

    # steel-harden reconciles the drop-ins for the chosen preset. It is
    # idempotent and reads the preset file we just wrote, so there is exactly
    # one place the answer comes from.
    #
    # It has no --root flag by design — it is a tool for the running system —
    # so it is pointed at the target through the same environment variables its
    # own tests use. Redirecting it is supported; adding a second way to say
    # "somewhere else" would not be.
    environment = dict(
        os.environ,
        STEEL_OVERRIDE_DIR=os.path.join(root, "etc/steelos/overrides"),
        STEEL_SYSCTL_DIR=os.path.join(root, "etc/sysctl.d"),
        STEEL_MODPROBE_DIR=os.path.join(root, "etc/modprobe.d"),
    )
    result = subprocess.run(
        ["steel-harden", "preset", preset],
        env=environment, capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return (
            "The hardening preset could not be applied",
            f"steel-harden preset {preset} failed: {result.stderr.strip()}",
        )
    libcalamares.utils.debug(f"steelos_hardening: applied preset {preset}")
    return None
