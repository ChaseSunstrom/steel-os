#!/usr/bin/env python3
"""Lay out the target disk.

Calamares' own partition module cannot express this layout — two root slots,
two verity trees, an always-allocated custody region, an always-allocated decoy
region, an ESP and an encrypted /var — so we do not use it. The definitions are
the same systemd-repart files the image build uses, which is what keeps the
installed geometry and the built geometry from drifting apart.

Two properties this job exists to guarantee, and neither is cosmetic:

  * The whole disk is allocated. Unallocated regions with high-entropy data are
    a forensic signal, and free space that varies between installs weakens the
    deniability design for everyone rather than just for the person who left it.

  * The custody and decoy partitions are created on EVERY install, used or not,
    and filled with random data. If they only existed on machines that
    configured those features, their presence would be the evidence.
"""

import os
import subprocess

import libcalamares

DEFINITIONS = "/usr/share/steelos/device-layout"


def _log(message):
    libcalamares.utils.debug(f"steelos_partition: {message}")


def _run(argv, stdin_text=None, check=True):
    _log("run " + " ".join(argv))
    result = subprocess.run(
        argv, input=stdin_text, capture_output=True, text=True, check=False
    )
    if result.stdout.strip():
        _log(result.stdout.strip())
    if check and result.returncode != 0:
        raise RuntimeError(
            f"{' '.join(argv)} failed with status {result.returncode}\n"
            f"{result.stderr.strip()}"
        )
    return result


def pretty_name():
    return "Partitioning the disk"


def run():
    gs = libcalamares.globalstorage
    config = gs.value("steelos.disk") or {}

    device = config.get("device")
    passphrase = config.get("passphrase")

    if not device:
        return ("No disk was selected", "The disk page did not record a target device.")
    if not passphrase:
        return ("No passphrase was set", "The disk page did not record a passphrase.")
    if not os.path.exists(DEFINITIONS):
        return (
            "Partition definitions are missing",
            f"{DEFINITIONS} does not exist. The installer medium is incomplete; "
            "this is a packaging fault rather than something you can work around.",
        )

    # Refuse the disk we booted from, again. The UI already refuses it, but this
    # job runs against whatever is in global storage and is the last thing
    # standing between a mistake and a partition table.
    boot_source = subprocess.run(
        ["findmnt", "-no", "SOURCE", "/run/archiso/bootmnt"],
        capture_output=True, text=True, check=False,
    ).stdout.strip()
    if boot_source.startswith(device):
        return (
            "Refusing to install onto the live medium",
            f"{device} is the device this installer booted from.",
        )

    _log(f"wiping existing signatures on {device}")
    _run(["wipefs", "--all", "--force", device])
    # Any stale device-mapper nodes from a previous attempt would make repart's
    # view of the disk disagree with the kernel's.
    _run(["partprobe", device], check=False)

    _log("applying the SteelOS partition layout")
    _run([
        "systemd-repart",
        "--definitions", DEFINITIONS,
        "--empty=force",
        "--dry-run=no",
        # Discard first so the geometry starts from a known state on SSDs.
        "--discard=yes",
        device,
    ])
    _run(["udevadm", "settle"], check=False)

    var_partition = "/dev/disk/by-partlabel/steelos-var"
    if not os.path.exists(var_partition):
        return (
            "The partition layout was not created",
            f"{var_partition} does not exist after running systemd-repart.",
        )

    _log("formatting /var as LUKS2")
    # argon2id and a generous cost. The passphrase is the only thing between a
    # stolen machine and the data; the KDF is what makes a short one survivable
    # and a long one irrelevant to attack.
    _run([
        "cryptsetup", "luksFormat",
        "--type", "luks2",
        "--pbkdf", "argon2id",
        "--cipher", "aes-xts-plain64",
        "--key-size", "512",
        "--batch-mode",
        var_partition, "-",
    ], stdin_text=passphrase)

    _run([
        "cryptsetup", "open", var_partition, "steelos-var", "--key-file", "-",
    ], stdin_text=passphrase)
    _run(["mkfs.btrfs", "-f", "-L", "steelos-var", "/dev/mapper/steelos-var"])

    # Random fill for the regions that must look identical on every install
    # whether or not they hold anything. This is the single highest-value item
    # in the deniability design and it cannot be retrofitted convincingly later,
    # which is why it happens here and not behind a setting.
    for label, size_mb in (("steelos-custody", 4), ("steelos-decoy", None)):
        path = f"/dev/disk/by-partlabel/{label}"
        if not os.path.exists(path):
            _log(f"{label} is missing; the layout did not create it")
            continue
        _log(f"filling {label} with random data")
        argv = ["dd", "if=/dev/urandom", f"of={path}", "bs=1M", "status=none",
                "conv=fsync"]
        if size_mb is not None:
            argv.append(f"count={size_mb}")
        # The decoy region is large; a short write is fine (dd stops at the end
        # of the device with ENOSPC), so this one is not checked.
        _run(argv, check=check_fill(size_mb))

    gs.insert("steelos.partition", {
        "device": device,
        "varPartition": var_partition,
        "varMapper": "/dev/mapper/steelos-var",
    })
    # The stock jobs and steel-boot both read this.
    gs.insert("luksDevice", var_partition)
    return None


def check_fill(size_mb):
    """Whether a random-fill write is allowed to fail.

    A fixed-size fill must succeed. Filling a whole partition ends with ENOSPC
    by design, and treating that as an error would fail every install.
    """
    return size_mb is not None
