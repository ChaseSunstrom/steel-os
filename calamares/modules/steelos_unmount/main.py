#!/usr/bin/env python3
"""Unmount and close the target.

Last job in the sequence. It is deliberately forgiving about individual
failures and unforgiving about the final state: a target left mounted or a LUKS
mapping left open means the next thing the user does — rebooting — can leave a
dirty filesystem on a machine they have not booted yet.
"""

import os
import subprocess
import time

import libcalamares


def _log(message):
    libcalamares.utils.debug(f"steelos_unmount: {message}")


def _try(argv):
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        _log(f"{' '.join(argv)}: {result.stderr.strip()}")
    return result.returncode == 0


def pretty_name():
    return "Finishing up"


def run():
    gs = libcalamares.globalstorage
    root = gs.value("rootMountPoint")

    if not root:
        return None

    subprocess.run(["sync"], check=False)

    # Deepest first. /esp is inside the target, so it has to go before it.
    for path in (os.path.join(root, "esp"), root):
        for attempt in range(3):
            if not os.path.ismount(path):
                break
            if _try(["umount", path]):
                break
            time.sleep(1)
        else:
            _try(["umount", "-l", path])

    _try(["cryptsetup", "close", "steelos-var"])

    if os.path.ismount(root):
        return (
            "The target is still mounted",
            f"{root} could not be unmounted. Do not reboot yet — check what is "
            "holding it open, or the filesystem will be dirty on a machine that "
            "has never booted.",
        )

    subprocess.run(["sync"], check=False)
    return None
