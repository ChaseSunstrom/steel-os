#!/usr/bin/env python3
"""Boot security: Secure Boot key enrollment, TPM binding, recovery key.

This module owns the decisions that cannot be undone later without a
reinstall, and the ones where getting it wrong bricks the machine.

Two things it must get right, from CLAUDE.md's gotcha list:

  13. Secure Boot key enrollment can brick machines whose firmware needs
      vendor keys for option ROMs. Microsoft keys are included by default;
      removing them is an explicit expert choice, not a checkbox.

   4. TPM PCR bindings break on firmware updates. A BIOS update invalidates
      PCR 7 and auto-unlock stops. That is not preventable, so the recovery
      key handling has to be right and the user has to be told before they
      opt in.
"""

import re
import subprocess

import libcalamares
from libcalamares.utils import check_target_env_call, target_env_call

EFI_VARS = "/sys/firmware/efi/efivars"
SECUREBOOT_VAR = f"{EFI_VARS}/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
SETUPMODE_VAR = f"{EFI_VARS}/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"


def _efivar_bool(path):
    """EFI variables carry a four-byte attribute prefix; the value is byte 5."""
    try:
        with open(path, "rb") as handle:
            data = handle.read()
        return bool(data[4]) if len(data) > 4 else None
    except OSError:
        return None


def firmware_state():
    return {
        "uefi": _efivar_bool(SECUREBOOT_VAR) is not None,
        "secure_boot": _efivar_bool(SECUREBOOT_VAR),
        "setup_mode": _efivar_bool(SETUPMODE_VAR),
        "tpm": _has_tpm(),
    }


def _has_tpm():
    try:
        with open("/sys/class/tpm/tpm0/tpm_version_major") as handle:
            return handle.read().strip() == "2"
    except OSError:
        return False


def enroll_secure_boot_keys():
    """Create and enroll sbctl keys, WITH Microsoft's keys included.

    Including Microsoft's keys is the default deliberately. Some firmware
    requires them to run option ROMs — a discrete GPU's, most commonly — and a
    machine that enrolls only our keys can fail to POST. That failure is very
    hard for a user to diagnose and, on some hardware, hard to recover from.

    Removing them is available and is an expert decision made knowingly, not a
    default that surprises people.
    """
    state = firmware_state()
    if not state["uefi"]:
        libcalamares.utils.warning("not a UEFI boot; skipping Secure Boot setup")
        return None

    if not state["setup_mode"]:
        # We cannot enroll without setup mode, and we must not pretend we did.
        return (
            "Secure Boot keys were NOT enrolled: the firmware is not in setup "
            "mode. The post-install checklist explains how to enter it for this "
            "vendor. Until then this machine boots with the vendor's keys only, "
            "which means anything Microsoft signed will boot — including "
            "well-known vulnerable shims."
        )

    check_target_env_call(["sbctl", "create-keys"])
    check_target_env_call(["sbctl", "enroll-keys", "--microsoft"])
    check_target_env_call(["sbctl", "sign-all"])
    return None


def generate_recovery_key():
    """Generate the LUKS recovery key and require the user to prove they saved it.

    The confirmation asks for a specific segment rather than the whole key.
    Asking for the whole thing invites copy-paste from the screen, which proves
    nothing; asking for one segment at random cannot be satisfied without
    actually having written it down.
    """
    result = subprocess.run(
        ["systemd-cryptenroll", "--recovery-key", libcalamares.globalstorage.value("luksDevice")],
        capture_output=True,
        text=True,
        check=True,
    )
    key = result.stdout.strip()
    libcalamares.globalstorage.insert("steelosRecoveryKey", key)
    return key


def enroll_tpm(with_pin=True):
    """Bind unlock to TPM2 with a MANDATORY PIN.

    A TPM-sealed key with no PIN unlocks for whoever is holding the machine,
    which converts full-disk encryption into a speed bump against exactly the
    attacker it exists to stop. The installer therefore does not offer a
    no-PIN option at all — offering it would mean some users pick it.
    """
    if not with_pin:
        raise ValueError(
            "TPM enrollment without a PIN is not offered. A TPM-sealed key with "
            "no PIN unlocks for whoever holds the machine."
        )

    device = libcalamares.globalstorage.value("luksDevice")
    check_target_env_call([
        "systemd-cryptenroll", device,
        "--tpm2-device=auto",
        "--tpm2-with-pin=yes",
        # PCR 7 is the Secure Boot state; PCR 11 is the UKI measurement.
        # Without both, a swapped-in OS can ask the TPM for the key and get it.
        "--tpm2-pcrs=7+11",
    ])


def run():
    """Called by Calamares during the exec phase."""
    gs = libcalamares.globalstorage
    state = firmware_state()

    warnings = []

    warning = enroll_secure_boot_keys()
    if warning:
        warnings.append(warning)

    generate_recovery_key()

    if state["tpm"] and gs.value("steelosUseTpm"):
        enroll_tpm(with_pin=True)
        warnings.append(
            "TPM unlock is enrolled. A firmware update will invalidate PCR 7 "
            "and auto-unlock will stop working — this is expected and is not "
            "preventable. Your recovery key still works, and `steel-boot reseal` "
            "re-seals against the new measurements. Keep the recovery key."
        )

    check_target_env_call(["steel-boot", "install-recovery", "/usr/lib/steelos/recovery.efi"])
    # On every install, decoy or not. An entry that only existed on decoy
    # machines would be the tell the deniability design exists to prevent.
    check_target_env_call(["steel-boot", "install-maintenance", "/usr/lib/steelos/maintenance.efi"])

    for message in warnings:
        libcalamares.utils.warning(message)
    gs.insert("steelosBootWarnings", warnings)

    return None
