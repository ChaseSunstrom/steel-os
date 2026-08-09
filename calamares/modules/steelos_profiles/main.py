#!/usr/bin/env python3
"""Create the profiles.

A profile is a systemd-homed user with a LUKS-backed home. Deliberately not a
bespoke concept — they are just users, so every existing tool works on them,
and "profile switching" is Plasma's fast user switching rather than something
we had to invent and then maintain.

Each profile gets its own sandbox strictness and its own Flatpak scope, because
one profile must not be able to read another's data or reach another's
applications. What this does not do, and the installer says so on the page: it
does not defend against a kernel exploit. Profiles share one kernel.
"""

import json
import os
import subprocess

import libcalamares

SANDBOX_PRESETS = ("balanced", "strict", "permissive")


def _log(message):
    libcalamares.utils.debug(f"steelos_profiles: {message}")


def _run(argv, stdin_text=None, check=True):
    _log("run " + " ".join(argv[:3]) + (" ..." if len(argv) > 3 else ""))
    result = subprocess.run(
        argv, input=stdin_text, capture_output=True, text=True, check=False
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"{argv[0]} failed with status {result.returncode}: "
            f"{result.stderr.strip()}"
        )
    return result


def pretty_name():
    return "Creating profiles"


def run():
    gs = libcalamares.globalstorage
    config = gs.value("steelos.profiles") or {}
    profiles = config.get("profiles") or []
    root = gs.value("rootMountPoint")

    if not profiles:
        return ("No profiles were created",
                "At least one profile is needed or nobody can log in.")
    if not root:
        return ("Nothing is mounted",
                "The deployment step did not set a root mount point.")

    home_dir = os.path.join(root, "lib/systemd/home")
    os.makedirs(home_dir, exist_ok=True)

    created = []
    for profile in profiles:
        name = profile.get("name")
        password = profile.get("password")
        sandbox = profile.get("sandbox", "balanced")
        size_gb = int(profile.get("homeSizeGb", 64))

        if not name or not password:
            return ("A profile is incomplete",
                    "Every profile needs a user name and a password.")
        if sandbox not in SANDBOX_PRESETS:
            return ("Unknown sandbox strictness", f"{sandbox!r} for profile {name}.")

        # homectl writes a JSON user record. LUKS storage per home is what makes
        # "user B, even as root, cannot read user A's data at rest" true rather
        # than aspirational.
        record = {
            "userName": name,
            "storage": "luks",
            "diskSize": size_gb * 1000 * 1000 * 1000,
            "luksDiscard": True,
            # Locked at logout and on suspend. Suspend in particular is a common
            # silent failure and is checked by steel-check rather than assumed.
            "enforcePasswordPolicy": False,
            "memberOf": ["wheel"] if not created else [],
        }
        try:
            _run(
                ["homectl", "create", "--identity=-",
                 f"--image-path={home_dir}/{name}.home"],
                stdin_text=json.dumps(record),
            )
            _run(["homectl", "passwd", name], stdin_text=f"{password}\n{password}\n")
        except RuntimeError as error:
            return (f"Could not create the profile {name}", str(error))

        # Per-profile sandbox policy. The global Flatpak overrides are already
        # in the image; this records which of them apply to this profile so the
        # first login applies them rather than a script the user has to find.
        profile_dir = os.path.join(root, "lib/steelos/profiles", name)
        os.makedirs(profile_dir, exist_ok=True)
        with open(os.path.join(profile_dir, "sandbox"), "w") as handle:
            handle.write(sandbox + "\n")

        created.append(name)
        _log(f"created profile {name} with {sandbox} sandboxing")

    gs.insert("steelos.createdProfiles", created)
    return None
