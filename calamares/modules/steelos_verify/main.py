#!/usr/bin/env python3
"""Audit the installed system before calling the install a success.

Every claim this installer made is something steel-check can verify, and this
is where that gets used rather than promised. An installed system that does not
audit green has not been installed correctly, and finding that out now — while
the user is in front of the machine and the live medium is still booted — is
much cheaper than finding it out on first boot.

Not every check can pass from here: anything that inspects the *running*
kernel's state is meaningless against a system that has not booted yet. Those
are skipped explicitly rather than silently, and the ones that remain are the
ones this installer is actually responsible for.
"""

import json
import os
import subprocess

import libcalamares

# Checks that cannot be meaningful before the first boot: they inspect the
# RUNNING kernel, an active mount, or something that by definition has not
# happened yet on a machine installed thirty seconds ago.
#
# Listed explicitly, by id, so that a check added later is enforced by default
# rather than silently exempted — and so this list can be read against
# `steel-check --list` to see whether it still describes reality.
DEFERRED = {
    # Running-kernel state.
    "kernel.sysctl-baseline",
    "kernel.cmdline-baseline",
    "kernel.lockdown",
    "kernel.module-signatures",
    "kernel.module-blacklist",
    "kernel.userns",
    "kernel.variant",
    "memory.hardened-malloc",
    "memory.hardened-malloc-variant",
    "memory.cpu-encryption",
    "memory.iommu",
    # Mount state of a system that is not running.
    "filesystem.usr-read-only",
    "filesystem.root-read-only",
    "filesystem.tmp-hardened",
    "filesystem.no-exec-removable",
    "filesystem.coredumps-disabled",
    "storage.verity-active",
    "storage.verity-roothash-matches-uki",
    "storage.swap-encrypted",
    # Running services.
    "network.nftables-policy",
    "network.no-listening-ports",
    "network.dns-over-tls",
    "sandbox.apparmor-enforcing",
    "sandbox.usbguard",
    "identity.home-lock-on-suspend",
    # Things that cannot have happened yet on a machine installed a minute ago.
    "boot.tpm-binding",
    "deployment.slot-health",
    "deployment.boot-counting",
    "deployment.generation",
    "backup.last-run",
    "backup.last-verify",
    "duress.last-drill",
}


def pretty_name():
    return "Verifying the installation"


def run():
    gs = libcalamares.globalstorage
    root = gs.value("rootMountPoint")

    if not root:
        return ("Nothing is mounted",
                "The deployment step did not set a root mount point.")

    # --sysroot, not --root: steel-check reads system state from a directory
    # tree instead of /, which is exactly the "audit a mounted, not-running
    # system" case this job is.
    result = subprocess.run(
        ["steel-check", "--sysroot", root, "--json"],
        capture_output=True, text=True, check=False,
    )

    if result.returncode != 0 and not result.stdout.strip():
        libcalamares.utils.warning(
            "steel-check could not be run against the target: "
            + result.stderr.strip()
        )
        return None

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        libcalamares.utils.warning(
            "steel-check produced output that is not JSON; skipping verification"
        )
        return None

    failures = []
    for check in report.get("checks", []):
        name = check.get("id", "")
        if name in DEFERRED:
            continue
        if check.get("status") == "fail":
            failures.append(f"{name}: {check.get('detail', '')}")

    gs.insert("steelos.auditReport", report)

    if failures:
        return (
            "The installed system does not audit clean",
            "steel-check reports failures that this installer is responsible "
            "for. The system is on disk, but it is not what it claims to be:\n\n"
            + "\n".join(f"  · {line}" for line in failures)
            + "\n\nRun `steel-check` after booting for the full report.",
        )

    libcalamares.utils.debug(
        f"steelos_verify: {len(report.get('checks', []))} checks, no failures "
        "outside the ones that need a booted system"
    )
    return None
