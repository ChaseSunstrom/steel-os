#!/usr/bin/env python3
"""Backup setup, with the rules enforced in the UI as well as in the tool.

The duress design depends on this layer. A user who finishes the installer
without an off-device backup has a machine where key destruction is permanent,
and they should be told that here rather than discovering it later.
"""

import libcalamares
from libcalamares.utils import check_target_env_call

LOCAL_TARGET_REFUSAL = (
    "That target is on the disk being protected.\n\n"
    "A backup destroyed by the same event that destroys the volume is not a "
    "backup. This is also what makes duress key destruction survivable: local "
    "key material can be destroyed precisely because recovery lives somewhere "
    "else.\n\n"
    "Use a remote repository, or removable media that is not attached during "
    "normal operation."
)

HEADER_BACKUP_TRADEOFF = (
    "Header backup: recoverable OR destroyable. Choose per volume.\n\n"
    "A LUKS header backup makes this machine recoverable if the header is "
    "damaged. It also makes duress key destruction REVERSIBLE by anyone who "
    "has the backup.\n\n"
    "These are opposing properties and you cannot have both:\n\n"
    "  Store the header backup in the remote repository only\n"
    "     -> destroyable under duress, recoverable by you later\n\n"
    "  Store it locally or on the ESP\n"
    "     -> recoverable from damage, NOT destroyable under duress\n\n"
    "Silently backing up a header you believe is destroyable is the worst "
    "possible outcome, which is why you are being asked rather than defaulted."
)


def is_local_target(target):
    remote_markers = ("sftp:", "rest:", "s3:", "b2:", "ssh://", "rclone:")
    if any(marker in target for marker in remote_markers):
        return False
    path = target.removeprefix("restic:").removeprefix("borg:")
    if not path.startswith("/"):
        return False
    removable = ("/run/media/", "/media/", "/mnt/")
    return not path.startswith(removable)


def validate_target(target):
    if is_local_target(target):
        raise ValueError(LOCAL_TARGET_REFUSAL)
    return True


def run():
    gs = libcalamares.globalstorage
    target = gs.value("steelosBackupTarget")

    if not target:
        # Recorded rather than silent, so steel-check reports a decision.
        check_target_env_call(["steel-backup", "disable"])
        libcalamares.utils.warning(
            "No backup configured. Note that with no off-device backup, duress "
            "key destruction is permanent."
        )
        return None

    validate_target(target)

    for profile in gs.value("steelosProfiles") or []:
        check_target_env_call([
            "runuser", "-u", profile["name"], "--",
            "steel-backup", "setup", "--target", target,
        ])
        # An immediate test run, here, while the user is still in front of the
        # machine. A backup that has never run is not a backup, and finding out
        # months later is worse than finding out now.
        check_target_env_call([
            "runuser", "-u", profile["name"], "--", "steel-backup", "probe",
        ])
        check_target_env_call([
            "runuser", "-u", profile["name"], "--", "steel-backup", "run",
        ])

    return None
