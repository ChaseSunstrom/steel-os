//! Mount-level properties: the read-only verified root, tmpfs restrictions, and
//! the writable-state layout.

use crate::context::{Context, Deployment};
use crate::report::{Category, Check, Outcome, Severity, Status};

pub const CHECKS: &[Check] = &[
    Check {
        id: "filesystem.usr-read-only",
        title: "/usr is mounted read-only",
        category: Category::Filesystem,
        severity: Severity::Critical,
        rationale: "This is the enforcement mechanism for the whole design. An attacker \
                    with root at runtime cannot durably modify the OS, and `pacman -S` \
                    is impossible by construction rather than by policy. Everything the \
                    README claims about persistence rests on this one property.",
        escape_hatch: "Boot the steel-devmode entry, which requires physical presence at \
                       boot and is not a runtime toggle.",
        run: check_usr_read_only,
    },
    Check {
        id: "filesystem.root-read-only",
        title: "/ is mounted read-only",
        category: Category::Filesystem,
        severity: Severity::High,
        rationale: "Writable state is confined to /var and /home so that the set of \
                    things an attacker can persist into is small and enumerable.",
        escape_hatch: "steel-devmode.",
        run: check_root_read_only,
    },
    Check {
        id: "filesystem.tmp-hardened",
        title: "/tmp is a tmpfs with nodev,nosuid,noexec",
        category: Category::Filesystem,
        severity: Severity::Medium,
        rationale: "/tmp is world-writable, so it is the natural staging ground for a \
                    dropped payload. noexec does not stop a determined attacker (an \
                    interpreter still runs a script) but it does stop a large fraction \
                    of off-the-shelf tooling, and tmpfs means nothing survives a reboot.",
        escape_hatch: "steel-harden tmp-noexec off — needed by some build systems and \
                       installers that extract and execute from /tmp.",
        run: check_tmp,
    },
    Check {
        id: "filesystem.no-exec-removable",
        title: "Removable media mounts are nosuid,nodev,noexec",
        category: Category::Filesystem,
        severity: Severity::Medium,
        rationale: "A USB stick is the most common physical delivery vector. Mounting \
                    it non-executable and without device nodes removes the easy paths.",
        escape_hatch: "steel-harden removable-noexec off.",
        run: check_removable_media,
    },
    Check {
        id: "filesystem.coredumps-disabled",
        title: "Core dumps are disabled",
        category: Category::Filesystem,
        severity: Severity::Medium,
        rationale: "A core dump is a complete copy of a process's memory, which for a \
                    browser or a keyring agent means keys and session tokens written to \
                    disk outside the user's control.",
        escape_hatch: "steel-harden coredumps on, for debugging.",
        run: check_coredumps,
    },
];

fn check_usr_read_only(ctx: &Context) -> Outcome {
    match ctx.deployment {
        Deployment::Arch => {
            return Outcome::skip(ctx.not_image_reason()).evidence(
                "The hardening packages can run on a mutable Arch install, but the \
                 immutability guarantee comes from the image, not from the packages.",
            )
        }
        Deployment::DevMode => {
            return Outcome::warn("/usr is writable: this is a devmode boot").evidence(
                "devmode exists so hardware bring-up and debugging are possible. \
                 Changes made here do not survive into the normal deployment.",
            )
        }
        Deployment::Image => {}
    }

    // /usr may not be a separate mount; when it is not, the root mount's flags
    // govern it.
    let mount = ctx.sys.mount_for("/usr").or_else(|| ctx.sys.mount_for("/"));
    match mount {
        Some(m) if m.is_read_only() => {
            Outcome::pass(format!("read-only ({} from {})", m.target, m.source))
        }
        Some(m) => Outcome::fail("/usr is writable on an image deployment")
            .evidence(format!(
                "{} mounted {} with options: {}",
                m.target,
                m.fstype,
                m.options.join(",")
            ))
            .remedy(
                "This should be impossible. Something has remounted the verified root. \
                 Reboot; if it persists, the deployment is damaged — roll back with \
                 `steelctl rollback`.",
            ),
        None => Outcome::fail("cannot determine the mount backing /usr")
            .remedy("Check that /proc is mounted."),
    }
}

fn check_root_read_only(ctx: &Context) -> Outcome {
    if !ctx.deployment.is_image() {
        return match ctx.deployment {
            Deployment::DevMode => Outcome::warn("/ is writable: this is a devmode boot"),
            _ => Outcome::skip(ctx.not_image_reason()),
        };
    }
    match ctx.sys.mount_for("/") {
        Some(m) if m.is_read_only() => Outcome::pass("read-only"),
        Some(m) => Outcome::fail("/ is writable")
            .evidence(format!("options: {}", m.options.join(",")))
            .remedy("Reboot into the current deployment; if it persists, roll back."),
        None => Outcome::fail("cannot determine the root mount"),
    }
}

fn check_tmp(ctx: &Context) -> Outcome {
    let m = match ctx.sys.mount_for("/tmp") {
        Some(m) => m,
        None => {
            return Outcome::fail("/tmp is not a separate mount")
                .evidence(
                    "It is part of the root filesystem, so it inherits its options \
                           and survives reboots.",
                )
                .remedy("Enable tmp.mount: `systemctl enable --now tmp.mount`.")
        }
    };

    let mut missing: Vec<&str> = ["nodev", "nosuid", "noexec"]
        .into_iter()
        .filter(|o| !m.has_option(o))
        .collect();

    let is_tmpfs = m.fstype == "tmpfs";
    if !is_tmpfs {
        missing.push("tmpfs");
    }

    if missing.is_empty() {
        return Outcome::pass("tmpfs with nodev,nosuid,noexec");
    }

    Outcome::warn(format!("/tmp is missing: {}", missing.join(", ")))
        .evidence(format!("{} mounted {} with options: {}", m.target, m.fstype, m.options.join(",")))
        .remedy(
            "Add a drop-in for tmp.mount setting Options=mode=1777,strictatime,nosuid,nodev,noexec, \
             or reinstall steel-kernel-hardening which ships one.",
        )
}

fn check_removable_media(ctx: &Context) -> Outcome {
    // udisks2 governs desktop automounting; the drop-in is what makes the
    // policy stick for media mounted by the file manager.
    let conf = ctx.sys.concat_dir("/etc/udev/rules.d", ".rules");
    let udisks = ctx
        .sys
        .read("/etc/udisks2/mount_options.conf")
        .unwrap_or_default();

    let configured = udisks.contains("noexec") || conf.contains("noexec");

    // Also report anything currently mounted from removable media without the
    // options, since configuration only applies to future mounts.
    let offenders: Vec<String> = ctx
        .sys
        .mounts()
        .into_iter()
        .filter(|m| m.target.starts_with("/run/media/") || m.target.starts_with("/media/"))
        .filter(|m| !(m.has_option("noexec") && m.has_option("nosuid") && m.has_option("nodev")))
        .map(|m| format!("{} ({})", m.target, m.options.join(",")))
        .collect();

    if !offenders.is_empty() {
        return Outcome::warn(format!(
            "{} removable mount(s) are executable",
            offenders.len()
        ))
        .evidence_all(offenders)
        .remedy(
            "Unmount and remount, or reinstall steel-desktop which ships the \
                     udisks2 mount option policy.",
        );
    }
    if configured {
        Outcome::pass("udisks2 mounts removable media nosuid,nodev,noexec")
    } else {
        Outcome::warn("no removable-media mount policy is configured")
            .evidence("/etc/udisks2/mount_options.conf does not restrict mount options")
            .remedy("pacman -S steel-desktop, or write the policy by hand.")
    }
}

fn check_coredumps(ctx: &Context) -> Outcome {
    let pattern = ctx.sys.sysctl("kernel.core_pattern").unwrap_or_default();
    let suid_dumpable = ctx.sys.sysctl("fs.suid_dumpable").unwrap_or_default();
    let limits = ctx.sys.concat_dir("/etc/security/limits.d", ".conf");
    let coredump_conf = ctx.sys.concat_dir("/etc/systemd/coredump.conf.d", ".conf");

    // "|/bin/false" pipes the dump to a program that immediately exits, so the
    // kernel writes nothing anywhere.
    let pattern_disabled = pattern.starts_with("|/bin/false");
    let limits_disabled = limits.lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() >= 4 && f[2] == "core" && f[3] == "0"
    });
    let systemd_disabled = coredump_conf.contains("Storage=none");

    let mut evidence = vec![
        format!("kernel.core_pattern = {pattern}"),
        format!("fs.suid_dumpable = {suid_dumpable}"),
    ];
    if systemd_disabled {
        evidence.push("systemd-coredump Storage=none".into());
    }
    if limits_disabled {
        evidence.push("limits.d sets a hard core limit of 0".into());
    }

    let status = if pattern_disabled && suid_dumpable == "0" {
        Status::Pass
    } else if limits_disabled || systemd_disabled {
        Status::Warn
    } else {
        Status::Fail
    };

    match status {
        Status::Pass => Outcome::pass("core dumps are discarded").evidence_all(evidence),
        Status::Warn => Outcome::warn("core dumps are partially restricted")
            .evidence_all(evidence)
            .remedy("Set kernel.core_pattern=|/bin/false and fs.suid_dumpable=0."),
        _ => Outcome::fail("core dumps are enabled")
            .evidence_all(evidence)
            .remedy("Reinstall steel-kernel-hardening, then `sysctl --system`."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Preset;
    use crate::sys::{KernelCmdline, Sysroot};
    use std::fs;
    use std::path::PathBuf;

    fn ctx_with(mounts: &str, deployment: Deployment, name: &str) -> (Context, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("steel-check-fs-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("proc")).unwrap();
        fs::write(dir.join("proc/mounts"), mounts).unwrap();
        let ctx = Context {
            sys: Sysroot::new(&dir),
            preset: Preset::Balanced,
            deployment,
            cmdline: KernelCmdline::parse(""),
            real_volume_unlocked: false,
        };
        (ctx, dir)
    }

    #[test]
    fn usr_writable_on_an_image_deployment_is_critical() {
        let (ctx, dir) = ctx_with(
            "/dev/mapper/root / btrfs rw,relatime 0 0\n",
            Deployment::Image,
            "usr-rw",
        );
        assert_eq!(check_usr_read_only(&ctx).status, Status::Fail);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn usr_check_skips_on_plain_arch_rather_than_failing() {
        // Phase 0 ships these packages on mutable Arch. Reporting the absent
        // image guarantee as a failure would make green output impossible and
        // train users to ignore it.
        let (ctx, dir) = ctx_with("", Deployment::Arch, "usr-arch");
        assert_eq!(check_usr_read_only(&ctx).status, Status::Skip);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn devmode_warns_instead_of_failing() {
        let (ctx, dir) = ctx_with("", Deployment::DevMode, "usr-dev");
        let out = check_usr_read_only(&ctx);
        assert_eq!(out.status, Status::Warn);
        assert!(out.detail.contains("devmode"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn tmp_must_be_tmpfs_and_restricted() {
        let (ctx, dir) = ctx_with(
            "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0\n",
            Deployment::Arch,
            "tmp-ok",
        );
        assert_eq!(check_tmp(&ctx).status, Status::Pass);
        let _ = fs::remove_dir_all(dir);

        let (ctx, dir) = ctx_with(
            "tmpfs /tmp tmpfs rw,nosuid,relatime 0 0\n",
            Deployment::Arch,
            "tmp-exec",
        );
        let out = check_tmp(&ctx);
        assert_eq!(out.status, Status::Warn);
        assert!(out.detail.contains("noexec"));
        assert!(out.detail.contains("nodev"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn tmp_absent_from_mounts_is_a_failure() {
        let (ctx, dir) = ctx_with("/dev/sda1 / ext4 rw 0 0\n", Deployment::Arch, "tmp-none");
        assert_eq!(check_tmp(&ctx).status, Status::Fail);
        let _ = fs::remove_dir_all(dir);
    }
}
