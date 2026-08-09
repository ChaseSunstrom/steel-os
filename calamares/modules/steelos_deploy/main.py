#!/usr/bin/env python3
"""Write the SteelOS image to slot A and make it bootable.

The ordering here is the design, and it is the same ordering image/build.sh
uses:

  1. Write the root image to slot A.
  2. Write its dm-verity hash tree to the matching verity partition.
  3. Install the UKI, whose embedded command line already contains that image's
     verity root hash.

Because the root hash is inside the signed kernel image, signing the kernel
signs the identity of the entire root filesystem. This job does not compute a
new root hash: it copies an image that was built and hashed together, and
verifies that the hash on the medium is the hash the image actually has. An
installer that recomputed the hash here would be verifying its own arithmetic
rather than the publisher's signature.

Where the image comes from, in order:

  1. The live medium, if it carries one (an offline install).
  2. The configured channel over the network.

Nothing else. In particular there is no "build it from the running live system"
path, because the thing that makes two SteelOS machines identical is that they
were given the same image, not that they ran the same script.
"""

import hashlib
import os
import shutil
import subprocess
import urllib.request

import libcalamares

MEDIUM_IMAGE_DIRS = [
    "/run/archiso/bootmnt/steelos/image",
    "/run/steelos/image",
]
CHANNEL_BASE = "https://github.com/ChaseSunstrom/steel-os/releases/latest/download"
TARGET_ROOT = "/tmp/steelos-target"


def _log(message):
    libcalamares.utils.debug(f"steelos_deploy: {message}")


def _run(argv, check=True):
    _log("run " + " ".join(argv))
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if result.stdout.strip():
        _log(result.stdout.strip())
    if check and result.returncode != 0:
        raise RuntimeError(
            f"{' '.join(argv)} failed with status {result.returncode}\n"
            f"{result.stderr.strip()}"
        )
    return result


def find_local_image():
    for directory in MEDIUM_IMAGE_DIRS:
        candidate = os.path.join(directory, "steelos.root.raw")
        if os.path.exists(candidate):
            return directory
    return None


def fetch_channel_image(channel, destination):
    """Download the channel's image. Used when the medium carries none."""
    os.makedirs(destination, exist_ok=True)
    for name in ("steelos.root.raw", "steelos.verity.raw", "steelos.efi",
                 "steelos.roothash", "steelos.sha256"):
        url = f"{CHANNEL_BASE}/{name}"
        target = os.path.join(destination, name)
        _log(f"fetching {url}")
        with urllib.request.urlopen(url) as response, open(target, "wb") as handle:
            shutil.copyfileobj(response, handle)
    return destination


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_image(directory):
    """Check the image against its published hash before writing it to a disk.

    'Same manifest and snapshot pin produce the same image hash' is a published
    claim, so it is checkable rather than asserted — and the cheapest place to
    check it is right before the bytes go onto someone's machine.
    """
    checksums = os.path.join(directory, "steelos.sha256")
    if not os.path.exists(checksums):
        return "The image has no published checksum file; it could not be verified."

    expected = {}
    with open(checksums) as handle:
        for line in handle:
            parts = line.split()
            if len(parts) == 2:
                expected[parts[1].lstrip("*")] = parts[0]

    for name, want in expected.items():
        path = os.path.join(directory, name)
        if not os.path.exists(path):
            continue
        got = sha256_of(path)
        if got != want:
            raise RuntimeError(
                f"{name} does not match its published checksum.\n"
                f"  expected {want}\n  got      {got}\n"
                "Do not install this image."
            )
        _log(f"{name} matches its published checksum")
    return None


def write_raw(source, target):
    _log(f"writing {source} to {target}")
    _run(["dd", f"if={source}", f"of={target}", "bs=4M", "status=none",
          "conv=fsync"])


def pretty_name():
    return "Writing the system image"


def run():
    gs = libcalamares.globalstorage
    graphics = gs.value("steelos.graphics") or {}
    channel = graphics.get("channel", "stable")

    directory = find_local_image()
    if directory is None:
        network = subprocess.run(
            ["ip", "-o", "route", "get", "1.1.1.1"],
            capture_output=True, check=False,
        ).returncode == 0
        if not network:
            return (
                "No system image is available",
                "This installer medium does not carry a SteelOS image and there "
                "is no network to fetch one. Use a release ISO, which embeds the "
                "image, or connect this machine to a network and try again.",
            )
        try:
            directory = fetch_channel_image(channel, "/tmp/steelos-image")
        except Exception as error:      # noqa: BLE001 - reported to the user
            return ("Could not download the system image", str(error))

    try:
        warning = verify_image(directory)
    except RuntimeError as error:
        return ("The system image failed verification", str(error))
    if warning:
        libcalamares.utils.warning(warning)

    root_image = os.path.join(directory, "steelos.root.raw")
    verity_image = os.path.join(directory, "steelos.verity.raw")
    uki = os.path.join(directory, "steelos.efi")

    for required in (root_image, verity_image, uki):
        if not os.path.exists(required):
            return (
                "The system image is incomplete",
                f"{required} is missing. A SteelOS image is the root image, its "
                "verity tree and the signed UKI that carries the root hash; "
                "without all three there is nothing to verify against.",
            )

    write_raw(root_image, "/dev/disk/by-partlabel/steelos-root-a")
    write_raw(verity_image, "/dev/disk/by-partlabel/steelos-verity-a")

    # Slot B is left as it was created: allocated, empty, and ready for the
    # first update. Populating both slots with the same image at install time
    # would look tidier and would mean the first update has nowhere to go.

    esp = "/dev/disk/by-partlabel/steelos-esp"
    _run(["mkfs.fat", "-F", "32", "-n", "STEELOS", esp])

    os.makedirs(TARGET_ROOT, exist_ok=True)
    _run(["mount", "/dev/mapper/steelos-var", TARGET_ROOT])

    # /etc is a writable overlay reconciled from the manifest, and lives on
    # /var along with everything else that can change.
    for directory_name in ("etc", "esp", "home", "opt", "srv",
                           "lib/steelos", "log", "tmp"):
        os.makedirs(os.path.join(TARGET_ROOT, directory_name), exist_ok=True)

    _run(["mount", esp, os.path.join(TARGET_ROOT, "esp")])

    # Seed /etc from the image's factory copy, which mkosi.postinst captured at
    # build time. Everything the stock Calamares jobs write next — locale,
    # keyboard, hwclock, machine-id — lands in here.
    _run(["mount", "-o", "ro", "/dev/disk/by-partlabel/steelos-root-a",
          "/mnt"], check=False)
    factory = "/mnt/usr/share/factory/etc"
    if os.path.isdir(factory):
        _run(["cp", "-a", f"{factory}/.", os.path.join(TARGET_ROOT, "etc")])
    else:
        libcalamares.utils.warning(
            "the image carries no /usr/share/factory/etc; /etc starts empty"
        )
    _run(["umount", "/mnt"], check=False)

    _run(["mkdir", "-p", os.path.join(TARGET_ROOT, "esp/EFI/Linux")])
    shutil.copy2(uki, os.path.join(TARGET_ROOT, "esp/EFI/Linux/steelos-a.efi"))

    roothash = ""
    roothash_file = os.path.join(directory, "steelos.roothash")
    if os.path.exists(roothash_file):
        with open(roothash_file) as handle:
            roothash = handle.read().strip()

    gs.insert("rootMountPoint", TARGET_ROOT)
    gs.insert("steelos.deployment", {
        "slot": "a",
        "roothash": roothash,
        "channel": channel,
        "espMountPoint": os.path.join(TARGET_ROOT, "esp"),
        "imageDirectory": directory,
    })
    return None
