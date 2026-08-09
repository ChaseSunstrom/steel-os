#!/usr/bin/env python3
"""Backup configuration.

Two rules are enforced in code rather than documented, because both silently
void the rest of the design when broken:

  * No backup target may live on the device being protected. A local snapshot is
    a convenience rollback and is labelled as one; it is never counted as a
    backup. This is what resolves the recoverable-versus-destroyable tension —
    local key material is destroyable under duress precisely because recovery
    lives somewhere else.

  * Only a public key may be stored for the outer encryption layer. If the
    private half lands in the keyring for convenience, a seized machine can
    decrypt its own history and the entire benefit is gone.
"""

import os
import re

import libcalamares

CONFIG_TEMPLATE = """# Written by the SteelOS installer. Per profile, by design.
#
# The backup runs from inside the session while the home is unlocked. A locked
# systemd-homed home is an opaque encrypted image; backing one up at block level
# produces a blob that restores only wholesale and cannot be verified, which is
# not a backup.
[target]
kind = "{kind}"
repository = "{repository}"
append_only = true

[encryption]
# Inner: restic's own encryption, keyed from this profile's keyring.
# Outer: an age layer keyed by a RECIPIENT PUBLIC KEY ONLY. Because the private
# half is not on this machine, a seized or fully compromised machine cannot
# decrypt its own historical backups.
outer_recipient = "{recipient}"

[schedule]
when = "{schedule}"
retention = "{retention}"
verify = "weekly"
"""


def pretty_name():
    return "Configuring backups"


def looks_like_private_key(value):
    """Refuse anything that is obviously a private key.

    Not a security boundary — a determined user can paste anything — but it
    catches the realistic mistake, which is pasting the wrong half of an age
    key pair because both are printed by the same command.
    """
    if not value:
        return False
    return bool(re.match(r"^AGE-SECRET-KEY-", value.strip(), re.IGNORECASE)) \
        or "PRIVATE KEY" in value.upper()


def run():
    gs = libcalamares.globalstorage
    config = gs.value("steelos.backup") or {}
    root = gs.value("rootMountPoint")
    profiles = gs.value("steelos.createdProfiles") or []

    if not config.get("enabled"):
        libcalamares.utils.warning(
            "Backups were not configured. The duress features depend on an "
            "off-device copy existing; without one, a wipe is total. "
            "`steel-backup setup` configures it later."
        )
        return None

    if not root:
        return ("Nothing is mounted",
                "The deployment step did not set a root mount point.")

    kind = config.get("targetKind", "remote")
    repository = (config.get("remoteUrl") or "").strip()
    recipient = (config.get("outerKeyRecipient") or "").strip()

    if looks_like_private_key(recipient):
        return (
            "That is a private key",
            "Only the recipient PUBLIC key may be stored on this machine. If the "
            "private half is here, a seized machine decrypts its own history and "
            "the outer layer protects nothing. steel-check verifies this on "
            "every run and would fail.",
        )

    if kind == "remote":
        if not repository:
            return ("No repository was given",
                    "A remote target needs a repository URL.")
        # The target must not be on the disk we just installed to. Enforced here
        # rather than only in the UI, because the UI is not the last word.
        if repository.startswith("/") or repository.startswith("file:"):
            return (
                "A backup target on this machine is not a backup",
                "Backups must live on a removable drive that is not normally "
                "attached, or on a remote server. Writing them to the internal "
                "disk means one event destroys both copies — which is exactly "
                "the event backups exist for.",
            )
    elif kind != "removable":
        return ("Unknown backup target kind", f"{kind!r}")

    for name in profiles:
        profile_dir = os.path.join(root, "lib/steelos/profiles", name)
        os.makedirs(profile_dir, exist_ok=True)
        with open(os.path.join(profile_dir, "backup.toml"), "w") as handle:
            handle.write(CONFIG_TEMPLATE.format(
                kind=kind,
                repository=repository,
                recipient=recipient,
                schedule=config.get("schedule", "daily"),
                retention=config.get("retention", "7d 4w 6m"),
            ))

    if not recipient:
        libcalamares.utils.warning(
            "No outer encryption recipient was configured. Backups are still "
            "encrypted by restic, but a compromised machine can decrypt its own "
            "history. `steel-backup outer-key` adds the layer later."
        )
    return None
