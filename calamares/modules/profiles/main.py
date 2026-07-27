#!/usr/bin/env python3
"""Profile creation.

A profile is a systemd-homed user with LUKS storage, a sandbox strictness, and
its own backup configuration. Not a bespoke concept — being ordinary users is
what makes fast user switching, sudo, and every other existing tool work.

The suggested layout (Personal / Work / Untrusted) is a starting point, not a
requirement. What the module must get right is the size guidance: homed homes
do not shrink easily, and the moment of creation is the only place saying so
is useful.
"""

import libcalamares
from libcalamares.utils import check_target_env_call

SANDBOX_LEVELS = {
    "balanced": "Home, host, device, X11 and network revoked; granted back per app.",
    "strict": "As balanced, plus no secrets service, no location, no printing.",
    "permissive": "Flatpak defaults — many popular apps request full home access.",
}


def create_profile(name, password, sandbox="balanced", size=None):
    args = ["homectl", "create", name, "--storage=luks", "--shell=/bin/bash"]
    if size:
        args.append(f"--disk-size={size}")
    if libcalamares.globalstorage.value("steelosFirstUserIsAdmin"):
        args.append("--member-of=wheel")

    check_target_env_call(args, stdin=password)
    check_target_env_call(["steel-profile-manager", "sandbox", name, sandbox])


def size_guidance(disk_free_gb, profile_count):
    """Suggest a home size, and be honest about the asymmetry.

    Growing a homed home is straightforward. SHRINKING one is not: it needs
    free space and a logged-out user, and on a nearly-full disk it may not be
    possible at all. So the suggestion errs generous, and the UI says why.
    """
    if profile_count < 1:
        profile_count = 1
    # Leave a third of the disk unallocated to homes: /var holds container
    # images, logs, and staged updates, and a machine whose homes consumed
    # everything cannot take its next update.
    suggested = int((disk_free_gb * 0.66) / profile_count)
    return {
        "suggested_gb": suggested,
        "note": (
            "Growing a home later is straightforward. Shrinking one is not — it "
            "needs free space and a logged-out user, and on a full disk it may "
            "not be possible. Err generous.\n\n"
            "A third of the disk is left for /var, which holds container images, "
            "logs, and staged updates. A machine whose homes consumed everything "
            "cannot take its next update."
        ),
    }


def run():
    profiles = libcalamares.globalstorage.value("steelosProfiles") or []
    for profile in profiles:
        create_profile(
            profile["name"],
            profile["password"],
            profile.get("sandbox", "balanced"),
            profile.get("size"),
        )
    # Verify the claim rather than assuming it: user B, even as root, must not
    # be able to read user A's data at rest.
    check_target_env_call(["steel-profile-manager", "verify-isolation"])
    return None
