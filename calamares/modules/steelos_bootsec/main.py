#!/usr/bin/env python3
"""Secure Boot keys, the recovery key, and TPM binding.

This module owns the decisions that cannot be undone later without a reinstall,
and the ones where getting it wrong bricks the machine.

Two things it must get right, from CLAUDE.md's gotcha list:

  13. Secure Boot key enrollment can brick machines whose firmware needs vendor
      keys for option ROMs. Microsoft's keys are included by default; removing
      them is an explicit expert choice, not a checkbox.

   4. TPM PCR bindings break on firmware updates. A BIOS update invalidates
      PCR 7 and auto-unlock stops. That is not preventable, so the recovery key
      handling has to be right and the user has to be told before they opt in.
"""

import os
import subprocess

import libcalamares

RECOVERY_KEY_FILE = "/run/steelos/recovery-key"


def _log(message):
    libcalamares.utils.debug(f"steelos_bootsec: {message}")


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
    return "Setting up the boot chain"


def enroll_secure_boot(config, esp, warnings):
    """Create and enroll sbctl keys, with Microsoft's keys included by default.

    Including Microsoft's keys is deliberate. Some firmware requires them to run
    option ROMs — a discrete GPU's, most commonly — and a machine that enrolls
    only our key can fail to POST. That failure is very hard for a user to
    diagnose and, on some hardware, hard to recover from.
    """
    if not config.get("enrollKeys"):
        warnings.append(
            "Secure Boot keys were NOT enrolled, because you did not ask for it. "
            "This machine boots with the vendor's keys only, which means "
            "anything Microsoft signed will boot — including well-known "
            "vulnerable shims. Run `steel-boot enroll` once the firmware is in "
            "setup mode."
        )
        return

    setup_mode = _efivar_bool(
        "/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    )
    if not setup_mode:
        warnings.append(
            "Secure Boot keys were NOT enrolled: the firmware is not in setup "
            "mode. The checklist on the final screen explains how to enter it. "
            "Until then this machine boots with the vendor's keys only."
        )
        return

    _run(["sbctl", "create-keys"])
    argv = ["sbctl", "enroll-keys"]
    if config.get("includeMicrosoft", True):
        argv.append("--microsoft")
    else:
        warnings.append(
            "Microsoft's keys were NOT enrolled. If this machine has a discrete "
            "GPU whose option ROM is Microsoft-signed, it may fail to POST. Have "
            "a way to clear the firmware's key store before rebooting."
        )
    _run(argv)
    _run(["sbctl", "sign", "-s", os.path.join(esp, "EFI/Linux/steelos-a.efi")])


def _efivar_bool(path):
    """EFI variables carry a four-byte attribute prefix; the value is byte 5."""
    try:
        with open(path, "rb") as handle:
            data = handle.read()
        return bool(data[4]) if len(data) > 4 else None
    except OSError:
        return None


def enroll_recovery_key(device):
    """Enrol the key the user was shown and confirmed.

    Generated once by steelos-live-probe, displayed by the installer, confirmed
    by the user, and enrolled here. Generating a different one at this point
    would enrol something nobody has written down.
    """
    if not os.path.exists(RECOVERY_KEY_FILE):
        raise RuntimeError(
            "The recovery key generated at boot is missing. Refusing to "
            "continue: a machine with TPM unlock and no recovery key is one "
            "firmware update away from being unopenable."
        )
    with open(RECOVERY_KEY_FILE) as handle:
        key = handle.read().strip()

    passphrase = (libcalamares.globalstorage.value("steelos.disk") or {}).get("passphrase")
    # systemd-cryptenroll would generate its own key; we need to enrol the exact
    # string the user copied down, so it goes in as an ordinary extra keyslot.
    _run(
        ["cryptsetup", "luksAddKey", "--batch-mode", device, "-"],
        stdin_text=f"{passphrase}\n{key}\n{key}\n",
    )
    return key


def enroll_tpm(device, pin):
    """Bind unlock to TPM2 with a MANDATORY PIN.

    A TPM-sealed key with no PIN unlocks for whoever is holding the machine,
    which converts full-disk encryption into a speed bump against exactly the
    attacker it exists to stop. There is no no-PIN path here, not even an
    internal one — offering it would mean some users pick it.
    """
    if not pin:
        raise ValueError(
            "TPM enrollment without a PIN is not offered. A TPM-sealed key with "
            "no PIN unlocks for whoever holds the machine."
        )
    passphrase = (libcalamares.globalstorage.value("steelos.disk") or {}).get("passphrase")
    environment = dict(os.environ, PASSWORD=passphrase, NEWPIN=pin)
    argv = [
        "systemd-cryptenroll", device,
        "--tpm2-device=auto",
        "--tpm2-with-pin=yes",
        # PCR 7 is the Secure Boot state; PCR 11 is the UKI measurement. Without
        # both, a swapped-in OS can ask the TPM for the key and get it.
        "--tpm2-pcrs=7+11",
    ]
    _log("run " + " ".join(argv))
    result = subprocess.run(argv, env=environment, capture_output=True, text=True,
                            check=False)
    if result.returncode != 0:
        raise RuntimeError(
            "TPM enrollment failed: " + result.stderr.strip()
        )


def run():
    gs = libcalamares.globalstorage
    config = gs.value("steelos.bootsec") or {}
    deployment = gs.value("steelos.deployment") or {}
    device = gs.value("luksDevice")
    esp = deployment.get("espMountPoint")

    if not device or not esp:
        return ("The deployment is incomplete",
                "No LUKS device or ESP was recorded by the earlier steps.")

    warnings = []

    try:
        enroll_secure_boot(config, esp, warnings)
        enroll_recovery_key(device)
        if config.get("tpm"):
            enroll_tpm(device, config.get("tpmPin"))
            warnings.append(
                "TPM unlock is enrolled. A firmware update will invalidate PCR 7 "
                "and automatic unlock will stop working — this is expected and "
                "is not preventable. Your recovery key still works, and "
                "`steel-boot reseal` re-seals against the new measurements. Keep "
                "the recovery key."
            )
    except (RuntimeError, ValueError) as error:
        return ("Boot security setup failed", str(error))

    # On every install, decoy or not. Entries that existed only on machines with
    # a decoy would be the tell the whole design exists to avoid, so the
    # recovery and maintenance entries are unconditional.
    for command in (
        ["steel-boot", "--esp", esp, "install-recovery"],
        ["steel-boot", "--esp", esp, "install-maintenance"],
        ["steel-boot", "--esp", esp, "install-loader"],
    ):
        _run(command, check=False)

    for message in warnings:
        libcalamares.utils.warning(message)
    gs.insert("steelos.bootWarnings", warnings)
    return None
