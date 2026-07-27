//! The boot chain: Secure Boot state, key ownership, UKI signatures, TPM state.
//!
//! Most of this is Phase 1 work. The checks exist now because the definition of
//! "done" should be visible from the start, and because a Phase 0 user on plain
//! Arch still benefits from knowing their Secure Boot state.

use crate::context::Context;
use crate::report::{Category, Check, Outcome, Severity};
use crate::sys;

pub const CHECKS: &[Check] = &[
    Check {
        id: "boot.secure-boot-enabled",
        title: "Secure Boot is enabled",
        category: Category::Boot,
        severity: Severity::High,
        rationale: "Secure Boot is what makes the UKI signature mean something. Without \
                    it, an evil-maid attacker replaces the kernel and the whole chain \
                    below — verity root hash included — is theirs to choose.",
        escape_hatch: "Firmware setting. Disabling it is visible in this check and in the \
                       boot screen, deliberately.",
        run: check_secure_boot,
    },
    Check {
        id: "boot.own-keys-enrolled",
        title: "Secure Boot uses our own platform keys",
        category: Category::Boot,
        severity: Severity::High,
        rationale: "Secure Boot with only the vendor's keys means anything Microsoft \
                    signed will boot, including well-known vulnerable shims. Enrolling \
                    our own PK/KEK/db is what turns it from a checkbox into a control.",
        escape_hatch: "sbctl reset returns the firmware to vendor keys.",
        run: check_own_keys,
    },
    Check {
        id: "boot.uki-signed",
        title: "The running UKI is signed and its signature verifies",
        category: Category::Boot,
        severity: Severity::Critical,
        rationale: "The UKI bundles kernel, initramfs and cmdline into one signed binary. \
                    Because the cmdline contains the dm-verity root hash, signing the UKI \
                    signs the identity of the entire root filesystem. This is the crux of \
                    the whole design.",
        escape_hatch: "None short of disabling Secure Boot.",
        run: check_uki_signed,
    },
    Check {
        id: "boot.tpm-binding",
        title: "TPM-sealed unlock is bound to PCRs and requires a PIN",
        category: Category::Boot,
        severity: Severity::High,
        rationale: "A TPM-sealed key with no PIN unlocks for whoever is holding the \
                    machine, which converts full-disk encryption into a speed bump. PIN \
                    is mandatory whenever the TPM is used.",
        escape_hatch: "Use a passphrase instead of TPM unlock; that is the default.",
        run: check_tpm_binding,
    },
    Check {
        id: "boot.recovery-entry",
        title: "A signed recovery entry is present",
        category: Category::Boot,
        severity: Severity::Medium,
        rationale: "Rollback and repair must not depend on network access or on external \
                    media the user does not have with them.",
        escape_hatch: "n/a",
        run: check_recovery_entry,
    },
];

fn efi_present(ctx: &Context) -> bool {
    ctx.sys.exists("/sys/firmware/efi")
}

/// EFI variables are exposed with a four-byte attribute prefix, so the value we
/// want is the fifth byte.
fn efivar_bool(ctx: &Context, name: &str) -> Option<bool> {
    let path = format!("/sys/firmware/efi/efivars/{name}");
    let bytes = std::fs::read(ctx.sys.path(&path)).ok()?;
    bytes.get(4).map(|b| *b == 1)
}

fn check_secure_boot(ctx: &Context) -> Outcome {
    if !efi_present(ctx) {
        return Outcome::skip("system did not boot via UEFI");
    }
    let secure_boot = efivar_bool(ctx, "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    let setup_mode = efivar_bool(ctx, "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c");

    match (secure_boot, setup_mode) {
        (Some(true), _) => Outcome::pass("enabled"),
        (Some(false), Some(true)) => Outcome::warn("disabled, firmware is in setup mode")
            .evidence("Setup mode is the state the installer needs in order to enrol keys.")
            .remedy(
                "Run `sbctl enroll-keys --microsoft`, then re-enable Secure Boot in \
                     firmware setup.",
            ),
        (Some(false), _) => Outcome::fail("disabled")
            .evidence(
                "The UKI signature is not checked, so kernel and initramfs can be \
                       replaced offline.",
            )
            .remedy(
                "Enable Secure Boot in firmware setup. If the machine will not boot \
                     afterwards, your keys are not enrolled — check boot.own-keys-enrolled.",
            ),
        (None, _) => Outcome::skip("SecureBoot EFI variable is not readable")
            .evidence("efivarfs may not be mounted, or steel-check is not running as root"),
    }
}

fn check_own_keys(ctx: &Context) -> Outcome {
    if !efi_present(ctx) {
        return Outcome::skip("system did not boot via UEFI");
    }
    if !ctx.sys.is_real() || !sys::have_binary("sbctl") {
        return Outcome::skip("sbctl is not installed");
    }
    let out = match sys::run("sbctl", ["status"]) {
        Some(o) => o.combined(),
        None => return Outcome::skip("sbctl could not be executed"),
    };

    let installed = out.contains("Installed:") && out.contains("sbctl is installed");
    let owner_present = out.contains("Owner GUID:");

    if installed && owner_present {
        Outcome::pass("sbctl keys are installed and owned by this machine")
    } else if owner_present {
        Outcome::warn("sbctl keys exist but are not enrolled in firmware")
            .evidence(
                out.lines()
                    .take(6)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
                    .join(" | "),
            )
            .remedy("Put the firmware in setup mode and run `sbctl enroll-keys --microsoft`.")
    } else {
        Outcome::fail("no sbctl-managed keys")
            .evidence("Secure Boot, if enabled, is trusting only the vendor's keys.")
            .remedy("sbctl create-keys && sbctl enroll-keys --microsoft")
    }
}

fn check_uki_signed(ctx: &Context) -> Outcome {
    if !ctx.deployment.is_image() {
        return Outcome::skip(ctx.not_image_reason());
    }
    if !ctx.sys.is_real() || !sys::have_binary("sbctl") {
        return Outcome::skip("sbctl is not installed; cannot verify signatures");
    }
    let out = match sys::run("sbctl", ["verify"]) {
        Some(o) => o,
        None => return Outcome::skip("sbctl could not be executed"),
    };
    let body = out.combined();
    let unsigned: Vec<String> = body
        .lines()
        .filter(|l| l.contains("is not signed"))
        .map(|l| l.trim().to_string())
        .collect();

    if unsigned.is_empty() && out.ok() {
        Outcome::pass("all EFI binaries verify against the enrolled keys")
    } else {
        Outcome::fail(format!("{} unsigned EFI binaries", unsigned.len().max(1)))
            .evidence_all(unsigned)
            .remedy("sbctl sign-all, then verify again before rebooting.")
    }
}

fn check_tpm_binding(ctx: &Context) -> Outcome {
    let tpm_present = ctx.sys.exists("/sys/class/tpm/tpm0");
    if !tpm_present {
        return Outcome::skip("no TPM present").evidence(
            "Unlock is by passphrase, which is the default and is not weaker \
                       against an attacker who does not have the passphrase.",
        );
    }
    if !ctx.deployment.is_image() {
        return Outcome::skip(ctx.not_image_reason());
    }

    // steel-boot records the enrollment shape when it seals the key. Reading it
    // from state rather than re-deriving it keeps this check cheap and keeps it
    // from needing the LUKS header.
    let enrollment = ctx
        .sys
        .read("/var/lib/steelos/boot/tpm-enrollment")
        .unwrap_or_default();
    if enrollment.trim().is_empty() {
        return Outcome::skip("TPM present but not enrolled; unlock is by passphrase");
    }

    let has_pin = enrollment.contains("with-pin=yes");
    let pcrs: Vec<&str> = enrollment
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pcrs="))
        .collect();
    let binds_7_and_11 =
        pcrs.iter().any(|p| p.contains('7')) && pcrs.iter().any(|p| p.contains("11"));

    match (has_pin, binds_7_and_11) {
        (true, true) => Outcome::pass("TPM2 with PIN, bound to PCR 7 and 11"),
        (false, _) => Outcome::fail("TPM unlock is enrolled without a PIN")
            .evidence(
                "The volume unlocks automatically for anyone who powers the machine \
                       on, which is exactly the theft scenario encryption is for.",
            )
            .remedy(
                "systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto \
                     --tpm2-with-pin=yes --tpm2-pcrs=7+11",
            ),
        (true, false) => Outcome::warn(format!("TPM PIN is set but PCR binding is {pcrs:?}"))
            .evidence(
                "Without PCR 7 (Secure Boot state) and PCR 11 (UKI measurement), a \
                       swapped-in OS can ask the TPM for the key and get it.",
            )
            .remedy("Re-enrol with --tpm2-pcrs=7+11."),
    }
}

fn check_recovery_entry(ctx: &Context) -> Outcome {
    if !ctx.deployment.is_image() {
        return Outcome::skip(ctx.not_image_reason());
    }
    let entries = ctx.sys.list_dir("/efi/loader/entries");
    let esp_linux = ctx.sys.list_dir("/efi/EFI/Linux");
    let has_recovery = entries
        .iter()
        .chain(esp_linux.iter())
        .any(|e| e.contains("recovery"));

    if has_recovery {
        Outcome::pass("a recovery entry is present on the ESP")
    } else {
        Outcome::fail("no recovery entry found")
            .evidence("Repair and rollback would require external media.")
            .remedy("steel-boot install-recovery")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Deployment, Preset};
    use crate::report::Status;
    use crate::sys::{KernelCmdline, Sysroot};
    use std::fs;

    #[test]
    fn efivar_skips_the_four_byte_attribute_prefix() {
        let dir = std::env::temp_dir().join(format!("steel-check-efi-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let vars = dir.join("sys/firmware/efi/efivars");
        fs::create_dir_all(&vars).unwrap();
        fs::write(dir.join("sys/firmware/efi/.keep"), "").unwrap();
        // attributes (4 bytes) then the value byte.
        fs::write(
            vars.join("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            [0x06, 0x00, 0x00, 0x00, 0x01],
        )
        .unwrap();

        let ctx = Context {
            sys: Sysroot::new(&dir),
            preset: Preset::Balanced,
            deployment: Deployment::Image,
            cmdline: KernelCmdline::parse(""),
            real_volume_unlocked: false,
        };
        assert_eq!(
            efivar_bool(&ctx, "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            Some(true)
        );
        assert_eq!(check_secure_boot(&ctx).status, Status::Pass);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tpm_without_pin_is_a_failure_not_a_warning() {
        let dir = std::env::temp_dir().join(format!("steel-check-tpm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sys/class/tpm/tpm0")).unwrap();
        fs::create_dir_all(dir.join("var/lib/steelos/boot")).unwrap();
        fs::write(
            dir.join("var/lib/steelos/boot/tpm-enrollment"),
            "with-pin=no\npcrs=7+11\n",
        )
        .unwrap();
        let ctx = Context {
            sys: Sysroot::new(&dir),
            preset: Preset::Balanced,
            deployment: Deployment::Image,
            cmdline: KernelCmdline::parse(""),
            real_volume_unlocked: false,
        };
        let out = check_tpm_binding(&ctx);
        assert_eq!(out.status, Status::Fail);
        let _ = fs::remove_dir_all(&dir);
    }
}
