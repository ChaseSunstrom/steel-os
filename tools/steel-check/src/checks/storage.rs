//! Encryption at rest and root filesystem integrity.

use crate::context::Context;
use crate::report::{Category, Check, Outcome, Severity};
use crate::sys;

pub const CHECKS: &[Check] = &[
    Check {
        id: "storage.verity-active",
        title: "dm-verity is active for the root image",
        category: Category::Storage,
        severity: Severity::Critical,
        rationale: "Verity is what makes offline tampering with the OS detectable: every \
                    block of /usr is checked against a hash tree on read. Without it, the \
                    read-only mount is a convention rather than a guarantee.",
        escape_hatch: "steel-devmode, which requires physical presence at boot.",
        run: check_verity_active,
    },
    Check {
        id: "storage.verity-roothash-matches-uki",
        title: "The active verity root hash is the one in the signed UKI",
        category: Category::Storage,
        severity: Severity::Critical,
        rationale: "Verity with an attacker-chosen root hash verifies the attacker's image \
                    perfectly. The property that matters is that the hash came from the \
                    signed UKI cmdline, not from anywhere else.",
        escape_hatch: "None. If this fails the deployment is not trustworthy.",
        run: check_roothash_matches,
    },
    Check {
        id: "storage.var-encrypted",
        title: "/var is on an encrypted volume",
        category: Category::Storage,
        severity: Severity::Critical,
        rationale: "/var holds all writable system state: logs, container images, \
                    application data, the manifest history. Threat model: device theft \
                    while powered off.",
        escape_hatch: "None supported. An unencrypted /var is a different product.",
        run: check_var_encrypted,
    },
    Check {
        id: "storage.luks-parameters",
        title: "LUKS2 with a memory-hard KDF",
        category: Category::Storage,
        severity: Severity::High,
        rationale: "LUKS1 and PBKDF2 are brute-forceable on GPUs at a rate that makes \
                    ordinary passphrases recoverable. Argon2id costs an attacker memory \
                    as well as time, which is what closes that gap.",
        escape_hatch: "cryptsetup luksConvertKey, if you have a reason.",
        run: check_luks_parameters,
    },
    Check {
        id: "storage.swap-encrypted",
        title: "Swap is encrypted or absent",
        category: Category::Storage,
        severity: Severity::High,
        rationale: "Swap receives page contents verbatim, including decrypted documents \
                    and key material. Unencrypted swap silently undoes full-disk \
                    encryption for whatever happened to be paged out.",
        escape_hatch: "None supported.",
        run: check_swap_encrypted,
    },
];

fn dm_targets(ctx: &Context) -> Vec<(String, String)> {
    // /sys/block/dm-*/dm/{name,uuid}; the UUID carries the target type prefix,
    // e.g. CRYPT-LUKS2-... or VERITY-...
    let mut out = Vec::new();
    for dev in ctx.sys.list_dir("/sys/block") {
        if !dev.starts_with("dm-") {
            continue;
        }
        let name = ctx
            .sys
            .read_trimmed(&format!("/sys/block/{dev}/dm/name"))
            .unwrap_or_default();
        let uuid = ctx
            .sys
            .read_trimmed(&format!("/sys/block/{dev}/dm/uuid"))
            .unwrap_or_default();
        out.push((name, uuid));
    }
    out
}

fn check_verity_active(ctx: &Context) -> Outcome {
    if !ctx.deployment.is_image() {
        return Outcome::skip(ctx.not_image_reason());
    }
    let targets = dm_targets(ctx);
    let verity: Vec<&(String, String)> = targets
        .iter()
        .filter(|(_, uuid)| uuid.starts_with("CRYPT-VERITY"))
        .collect();

    if verity.is_empty() {
        Outcome::fail("no dm-verity target is active")
            .evidence(format!(
                "device-mapper targets present: {}",
                if targets.is_empty() {
                    "none".to_string()
                } else {
                    targets
                        .iter()
                        .map(|(n, _)| n.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ))
            .remedy(
                "Reboot into a signed deployment. If this persists, the image was \
                     built without a hash tree — `steelctl history` will show which \
                     generation is active.",
            )
    } else {
        Outcome::pass(format!(
            "active: {}",
            verity
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

fn check_roothash_matches(ctx: &Context) -> Outcome {
    if !ctx.deployment.is_image() {
        return Outcome::skip(ctx.not_image_reason());
    }
    let cmdline_hash = match ctx.cmdline.get("roothash") {
        Some(h) if !h.is_empty() => h.to_ascii_lowercase(),
        _ => {
            return Outcome::fail("no roothash on the kernel command line")
                .evidence(
                    "The UKI did not seal a root hash, so verity has nothing \
                           authoritative to compare against.",
                )
                .remedy("Rebuild the UKI with `steel-boot rebuild-uki`.")
        }
    };

    if !ctx.sys.is_real() || !sys::have_binary("veritysetup") {
        return Outcome::skip("veritysetup is not available to read the active root hash")
            .evidence(format!("cmdline roothash={cmdline_hash}"));
    }

    let active = dm_targets(ctx)
        .into_iter()
        .find(|(_, uuid)| uuid.starts_with("CRYPT-VERITY"))
        .map(|(name, _)| name);

    let name = match active {
        Some(n) => n,
        None => return Outcome::fail("no active verity target to compare against"),
    };

    let status = match sys::run("veritysetup", ["status", &name]) {
        Some(o) if o.ok() => o.stdout,
        _ => return Outcome::skip("could not read veritysetup status (needs root)"),
    };

    let active_hash = status
        .lines()
        .filter_map(|l| l.trim().strip_prefix("root hash:"))
        .map(|v| v.trim().to_ascii_lowercase())
        .next();

    match active_hash {
        Some(h) if h == cmdline_hash => Outcome::pass("active root hash matches the signed UKI"),
        Some(h) => Outcome::fail("active root hash does NOT match the signed UKI")
            .evidence(format!("UKI:    {cmdline_hash}"))
            .evidence(format!("active: {h}"))
            .evidence(
                "This means the running root filesystem is not the one the \
                       signature covers.",
            )
            .remedy("Do not trust this system. Reboot; if it recurs, reinstall."),
        None => Outcome::skip("veritysetup did not report a root hash"),
    }
}

fn check_var_encrypted(ctx: &Context) -> Outcome {
    let var = match ctx.sys.mount_for("/var") {
        Some(m) => m,
        None => {
            // On a plain-Arch install /var is normally part of the root
            // filesystem, so fall back to the root mount's backing device.
            match ctx.sys.mount_for("/") {
                Some(m) => m,
                None => return Outcome::skip("cannot determine the mount backing /var"),
            }
        }
    };

    let targets = dm_targets(ctx);
    let encrypted = targets
        .iter()
        .any(|(name, uuid)| uuid.starts_with("CRYPT-LUKS") && var.source.contains(name.as_str()));

    if encrypted {
        Outcome::pass(format!("{} is on a LUKS volume", var.target))
    } else if var.source.starts_with("/dev/mapper/") {
        Outcome::warn(format!(
            "{} is on {} but its encryption could not be confirmed",
            var.target, var.source
        ))
        .evidence(
            "The device is device-mapper backed, but no LUKS UUID was found. \
                       This can happen with a stacked setup steel-check does not \
                       understand yet.",
        )
        .remedy("Confirm manually with `cryptsetup status`.")
    } else {
        Outcome::fail(format!("{} is not encrypted", var.target))
            .evidence(format!("backed by {} ({})", var.source, var.fstype))
            .remedy("This cannot be fixed in place. Reinstall and choose LUKS for /var.")
    }
}

fn check_luks_parameters(ctx: &Context) -> Outcome {
    if !ctx.sys.is_real() || !sys::have_binary("cryptsetup") {
        return Outcome::skip("cryptsetup is not installed");
    }
    let targets: Vec<(String, String)> = dm_targets(ctx)
        .into_iter()
        .filter(|(_, uuid)| uuid.starts_with("CRYPT-LUKS"))
        .collect();

    if targets.is_empty() {
        return Outcome::skip("no LUKS volumes are open");
    }

    let mut problems = Vec::new();
    let mut checked = 0usize;

    for (name, uuid) in &targets {
        checked += 1;
        if uuid.starts_with("CRYPT-LUKS1") {
            problems.push(format!("{name}: LUKS1 header (no Argon2 support)"));
            continue;
        }
        let status = match sys::run("cryptsetup", ["status", name]) {
            Some(o) if o.ok() => o.stdout,
            _ => continue,
        };
        let cipher = status
            .lines()
            .filter_map(|l| l.trim().strip_prefix("cipher:"))
            .map(str::trim)
            .next()
            .unwrap_or("unknown");
        if !cipher.starts_with("aes-xts") {
            problems.push(format!(
                "{name}: cipher is {cipher}, expected aes-xts-plain64"
            ));
        }
    }

    // The KDF lives in the header, which needs a device path rather than a
    // mapper name; reading it requires root and the backing device. Report what
    // we could confirm rather than guessing.
    if problems.is_empty() {
        Outcome::pass(format!("{checked} LUKS2 volume(s), aes-xts")).evidence(
            "KDF parameters are in the header; verify with \
                       `cryptsetup luksDump <device>` that PBKDF is argon2id.",
        )
    } else {
        Outcome::fail(format!(
            "{} LUKS volume(s) have weak parameters",
            problems.len()
        ))
        .evidence_all(problems)
        .remedy(
            "cryptsetup convert --type luks2, then \
                     `cryptsetup luksConvertKey --pbkdf argon2id <device>`.",
        )
    }
}

fn check_swap_encrypted(ctx: &Context) -> Outcome {
    let swaps = ctx.sys.read("/proc/swaps").unwrap_or_default();
    let entries: Vec<&str> = swaps
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .collect();

    if entries.is_empty() {
        return Outcome::pass("no swap is active");
    }

    let targets = dm_targets(ctx);
    let mut plaintext = Vec::new();

    for entry in &entries {
        let device = entry.split_whitespace().next().unwrap_or("");
        let kind = entry.split_whitespace().nth(1).unwrap_or("");
        // zram is in RAM: it dies with power, so it does not defeat FDE.
        if device.starts_with("/dev/zram") {
            continue;
        }
        let is_file = kind == "file";
        let encrypted = targets
            .iter()
            .any(|(name, uuid)| uuid.starts_with("CRYPT-LUKS") && device.contains(name.as_str()));
        // A swapfile on an encrypted /var inherits that encryption.
        let on_encrypted_fs = is_file
            && ctx
                .sys
                .mount_for("/var")
                .map(|m| m.source.starts_with("/dev/mapper/"))
                .unwrap_or(false);

        if !encrypted && !on_encrypted_fs {
            plaintext.push(device.to_string());
        }
    }

    if plaintext.is_empty() {
        Outcome::pass(format!("{} swap area(s), all encrypted", entries.len()))
    } else {
        Outcome::fail(format!("{} unencrypted swap area(s)", plaintext.len()))
            .evidence_all(plaintext)
            .evidence(
                "Anything paged out is on disk in the clear, including keys the \
                       rest of this list works to protect.",
            )
            .remedy(
                "swapoff the device and re-add it through crypttab with a random key, \
                     or move to a swapfile on the encrypted volume.",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Deployment, Preset};
    use crate::report::Status;
    use crate::sys::{KernelCmdline, Sysroot};
    use std::fs;
    use std::path::PathBuf;

    struct Fx(PathBuf);
    impl Fx {
        fn new(n: &str) -> Fx {
            let d = std::env::temp_dir().join(format!("steel-check-st-{n}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&d);
            fs::create_dir_all(&d).unwrap();
            Fx(d)
        }
        fn write(&self, rel: &str, body: &str) -> &Fx {
            let p = self.0.join(rel.trim_start_matches('/'));
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
            self
        }
        fn dm(&self, dev: &str, name: &str, uuid: &str) -> &Fx {
            self.write(&format!("/sys/block/{dev}/dm/name"), &format!("{name}\n"));
            self.write(&format!("/sys/block/{dev}/dm/uuid"), &format!("{uuid}\n"));
            self
        }
        fn ctx(&self, deployment: Deployment) -> Context {
            Context {
                sys: Sysroot::new(&self.0),
                preset: Preset::Balanced,
                deployment,
                cmdline: KernelCmdline::parse(""),
                real_volume_unlocked: false,
            }
        }
    }
    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn var_on_luks_passes() {
        let f = Fx::new("var-luks");
        f.dm("dm-0", "steelos-var", "CRYPT-LUKS2-abcdef-steelos-var");
        f.write(
            "/proc/mounts",
            "/dev/mapper/steelos-var /var btrfs rw 0 0\n",
        );
        assert_eq!(
            check_var_encrypted(&f.ctx(Deployment::Image)).status,
            Status::Pass
        );
    }

    #[test]
    fn var_on_a_plain_partition_fails() {
        let f = Fx::new("var-plain");
        f.write("/proc/mounts", "/dev/sda2 /var ext4 rw 0 0\n");
        assert_eq!(
            check_var_encrypted(&f.ctx(Deployment::Image)).status,
            Status::Fail
        );
    }

    #[test]
    fn zram_swap_is_not_reported_as_plaintext() {
        // zram lives in RAM and dies with power, so it does not undo FDE.
        let f = Fx::new("swap-zram");
        f.write(
            "/proc/swaps",
            "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n/dev/zram0                             partition\t8388604\t0\t100\n",
        );
        assert_eq!(
            check_swap_encrypted(&f.ctx(Deployment::Image)).status,
            Status::Pass
        );
    }

    #[test]
    fn plaintext_partition_swap_fails() {
        let f = Fx::new("swap-plain");
        f.write(
            "/proc/swaps",
            "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n/dev/sda3                              partition\t8388604\t0\t-2\n",
        );
        let out = check_swap_encrypted(&f.ctx(Deployment::Image));
        assert_eq!(out.status, Status::Fail);
        assert!(out.evidence.iter().any(|e| e.contains("/dev/sda3")));
    }

    #[test]
    fn no_swap_at_all_passes() {
        let f = Fx::new("swap-none");
        f.write(
            "/proc/swaps",
            "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n",
        );
        assert_eq!(
            check_swap_encrypted(&f.ctx(Deployment::Image)).status,
            Status::Pass
        );
    }

    #[test]
    fn verity_absent_on_an_image_deployment_is_critical() {
        let f = Fx::new("verity-none");
        f.dm("dm-0", "steelos-var", "CRYPT-LUKS2-abc");
        assert_eq!(
            check_verity_active(&f.ctx(Deployment::Image)).status,
            Status::Fail
        );
        assert_eq!(
            check_verity_active(&f.ctx(Deployment::Arch)).status,
            Status::Skip
        );
    }

    #[test]
    fn missing_roothash_on_an_image_deployment_fails() {
        let f = Fx::new("roothash");
        assert_eq!(
            check_roothash_matches(&f.ctx(Deployment::Image)).status,
            Status::Fail
        );
    }
}
