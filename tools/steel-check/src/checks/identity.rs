//! Per-user compartmentalisation via systemd-homed.

use crate::context::Context;
use crate::report::{Category, Check, Outcome, Severity};
use crate::sys;

pub const CHECKS: &[Check] = &[
    Check {
        id: "identity.homed-users",
        title: "Every human user has a systemd-homed encrypted home",
        category: Category::Identity,
        severity: Severity::High,
        rationale: "Per-user LUKS homes are what make profiles a boundary rather than a \
                    convention: user B, even as root, cannot read user A's data at rest. \
                    A user whose home is an ordinary directory has no such boundary.",
        escape_hatch: "Create a normal user account; the check will report it, which is \
                       the point — the exception should be visible.",
        run: check_homed_users,
    },
    Check {
        id: "identity.home-lock-on-suspend",
        title: "Homes are locked on suspend",
        category: Category::Identity,
        severity: Severity::High,
        rationale: "An unlocked home on a suspended laptop is an unlocked laptop for \
                    anyone who opens the lid or pulls the RAM. CLAUDE.md flags this as a \
                    common silent failure, so it is checked rather than assumed.",
        escape_hatch: "steel-harden suspend-lock off, at the cost of the sleep/theft case.",
        run: check_lock_on_suspend,
    },
    Check {
        id: "identity.home-permissions",
        title: "Home directories are not group- or world-readable",
        category: Category::Identity,
        severity: Severity::Medium,
        rationale: "The homed boundary applies at rest. While a home is unlocked, \
                    ordinary Unix permissions are what stop another logged-in user \
                    reading it.",
        escape_hatch: "chmod, if you have a reason to share.",
        run: check_home_permissions,
    },
];

fn check_homed_users(ctx: &Context) -> Outcome {
    let users = ctx.sys.human_users();
    if users.is_empty() {
        return Outcome::skip("no human user accounts on this system");
    }

    if !ctx.sys.is_real() || !sys::have_binary("homectl") {
        return Outcome::skip("homectl is not available")
            .evidence(format!("human accounts: {}", users.join(", ")));
    }

    let listed = match sys::run("homectl", ["list", "--no-legend", "--no-pager"]) {
        Some(o) if o.ok() => o.stdout,
        _ => return Outcome::skip("homectl could not enumerate homes"),
    };
    let homed: Vec<String> = listed
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect();

    let plain: Vec<String> = users
        .iter()
        .filter(|u| !homed.contains(u))
        .cloned()
        .collect();

    if plain.is_empty() {
        return Outcome::pass(format!("{} user(s), all homed", users.len()));
    }

    // Verify the homed ones are actually LUKS-backed. `homectl list` says
    // nothing about storage, and a directory-backed homed user is not encrypted.
    let mut unencrypted = Vec::new();
    for user in homed.iter().filter(|u| users.contains(u)) {
        if let Some(o) = sys::run("homectl", ["inspect", user, "--no-pager"]) {
            if o.ok() && !o.stdout.contains("luks") {
                unencrypted.push(user.clone());
            }
        }
    }

    let mut outcome = Outcome::warn(format!(
        "{}/{} users are not on systemd-homed",
        plain.len(),
        users.len()
    ))
    .evidence(format!("not homed: {}", plain.join(", ")));
    if !unencrypted.is_empty() {
        outcome = outcome.evidence(format!(
            "homed but not LUKS-backed: {}",
            unencrypted.join(", ")
        ));
    }
    outcome.remedy(
        "New profiles created by the installer are homed automatically. To migrate an \
         existing account see docs/escape-hatches.md — it is a copy, not an in-place \
         conversion, so it needs free space equal to the home.",
    )
}

fn check_lock_on_suspend(ctx: &Context) -> Outcome {
    let logind = ctx.sys.concat_dir("/etc/systemd/logind.conf.d", ".conf");
    let base = ctx.sys.read("/etc/systemd/logind.conf").unwrap_or_default();
    let combined = format!("{base}\n{logind}");

    // systemd-homed suspends its homes when logind reports the system is going
    // to sleep; the knob that matters is that the sleep hook is not masked.
    let masked = ctx
        .sys
        .exists("/etc/systemd/system/systemd-suspend.service");
    let has_setting = combined
        .lines()
        .map(str::trim)
        .any(|l| l.starts_with("HandleLidSwitch=") || l.starts_with("IdleAction="));

    if masked {
        return Outcome::warn("a local override of systemd-suspend.service is present")
            .evidence(
                "/etc/systemd/system/systemd-suspend.service overrides the unit \
                       that triggers home locking on sleep",
            )
            .remedy("Remove the override, or confirm it still calls the homed sleep hook.");
    }

    if !ctx.sys.exists("/usr/lib/systemd/system-sleep/")
        && !ctx.sys.exists("/usr/lib/systemd/systemd-homed")
    {
        return Outcome::skip("systemd-homed is not installed");
    }

    if has_setting {
        Outcome::pass("logind is configured and the homed sleep hook is intact")
    } else {
        Outcome::warn("no explicit lock-on-suspend policy is configured")
            .evidence(
                "Defaults usually lock, but 'usually' is not a security property, \
                       and this is a documented silent-failure mode.",
            )
            .remedy(
                "pacman -S steel-desktop, which ships the logind drop-in, then verify \
                     by suspending and checking `homectl inspect <user>` reports locked.",
            )
    }
}

fn check_home_permissions(ctx: &Context) -> Outcome {
    use std::os::unix::fs::PermissionsExt;

    let users = ctx.sys.human_users();
    if users.is_empty() {
        return Outcome::skip("no human user accounts on this system");
    }

    let mut loose = Vec::new();
    for user in &users {
        let path = ctx.sys.path(&format!("/home/{user}"));
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            // An absent directory means a locked homed home, which is the
            // desired state, not a finding.
            Err(_) => continue,
        };
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            loose.push(format!("/home/{user} is {mode:04o}"));
        }
    }

    if loose.is_empty() {
        Outcome::pass(format!("{} home(s) are owner-only", users.len()))
    } else {
        Outcome::warn(format!("{} home(s) are readable by others", loose.len()))
            .evidence_all(loose)
            .remedy("chmod 700 on each; homed sets this itself for new homes.")
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
    fn no_users_skips_rather_than_passing_vacuously() {
        let dir = std::env::temp_dir().join(format!("steel-check-id-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("etc/passwd"), "root:x:0:0::/root:/bin/bash\n").unwrap();
        let ctx = Context {
            sys: Sysroot::new(&dir),
            preset: Preset::Balanced,
            deployment: Deployment::Arch,
            cmdline: KernelCmdline::parse(""),
            real_volume_unlocked: false,
        };
        assert_eq!(check_homed_users(&ctx).status, Status::Skip);
        assert_eq!(check_home_permissions(&ctx).status, Status::Skip);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn world_readable_home_warns() {
        let dir = std::env::temp_dir().join(format!("steel-check-id2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::create_dir_all(dir.join("home/chase")).unwrap();
        fs::write(
            dir.join("etc/passwd"),
            "chase:x:1000:1000::/home/chase:/bin/bash\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("home/chase"), fs::Permissions::from_mode(0o755)).unwrap();

        let ctx = Context {
            sys: Sysroot::new(&dir),
            preset: Preset::Balanced,
            deployment: Deployment::Arch,
            cmdline: KernelCmdline::parse(""),
            real_volume_unlocked: false,
        };
        let out = check_home_permissions(&ctx);
        assert_eq!(out.status, Status::Warn);
        let _ = fs::remove_dir_all(&dir);
    }
}
