#!/usr/bin/env python3
"""Graphics driver selection.

NVIDIA used to be the hard case: out-of-tree modules versus signed modules and
kernel lockdown. The image model resolves it — modules are built and signed in
CI at image build time, so `lockdown=confidentiality` and
`module.sig_enforce=1` can be defaults without breaking NVIDIA.

What remains is verifying the chosen image actually contains the right driver
variant, and warning about GPUs too new for the current channel.
"""

import re
import subprocess

import libcalamares

# Approximate first-supported kernel for recent NVIDIA generations. Used only
# to warn; being wrong here costs a spurious warning rather than a broken boot.
NVIDIA_GENERATIONS = [
    (0x2700, "Blackwell", "6.11"),
    (0x2600, "Ada Lovelace", "6.0"),
    (0x2200, "Ampere", "5.9"),
]


def detect_gpus():
    output = subprocess.run(
        ["lspci", "-nn"], capture_output=True, text=True, check=False
    ).stdout
    gpus = []
    for line in output.splitlines():
        if "VGA compatible controller" in line or "3D controller" in line:
            match = re.search(r"\[([0-9a-f]{4}):([0-9a-f]{4})\]", line)
            if match:
                gpus.append({
                    "vendor": match.group(1),
                    "device": match.group(2),
                    "description": line,
                })
    return gpus


def driver_for(gpu):
    return {
        "10de": "nvidia-open",
        "1002": "amdgpu",
        "8086": "i915",
    }.get(gpu["vendor"], "modesetting")


def check_image_has_driver(driver, root):
    """The image must already contain the driver; nothing can be added later.

    On a mutable distribution the installer would install a package. Here /usr
    is sealed, so a missing driver means the WRONG IMAGE was selected, and the
    only fix is a different image — which the user needs to know now rather
    than after their first reboot into a black screen.
    """
    import os
    modules = os.path.join(root, "usr/lib/modules")
    for dirpath, _, filenames in os.walk(modules):
        if any(f.startswith(driver) for f in filenames):
            return True
    return False


def run():
    gs = libcalamares.globalstorage
    root = gs.value("rootMountPoint")
    warnings = []

    for gpu in detect_gpus():
        driver = driver_for(gpu)
        if not check_image_has_driver(driver, root):
            warnings.append(
                f"The selected image does not contain the {driver} driver for "
                f"{gpu['description'].strip()}.\n"
                "Because /usr is sealed, this cannot be fixed after installation "
                "— you need a different image. Choose one that includes this "
                "driver, or the machine will boot without acceleration."
            )
        if gpu["vendor"] == "10de":
            device_id = int(gpu["device"], 16)
            for prefix, name, kernel in NVIDIA_GENERATIONS:
                if device_id >= prefix:
                    warnings.append(
                        f"NVIDIA {name} detected. It needs kernel {kernel} or "
                        "newer. If the stable channel is older than that, use "
                        "the testing channel — but note that testing images get "
                        "the same VM test matrix and less real-hardware time."
                    )
                    break

    gs.insert("steelosGraphicsWarnings", warnings)
    for message in warnings:
        libcalamares.utils.warning(message)
    return None
