//! Backup posture.
//!
//! The duress design depends entirely on this layer. If backups live on the
//! protected device, or can be deleted by whoever holds it, then destroying
//! local key material destroys the data outright — and the user was told the
//! opposite. Every check here exists because of that dependency.

use crate::context::Context;
use crate::report::{Category, Check, Outcome, Severity};

pub const CHECKS: &[Check] = &[
    Check {
        id: "backup.configured",
        title: "A backup target is configured",
        category: Category::Backup,
        severity: Severity::High,
        rationale: "Threat model: user error and bad updates, plus the duress design's \
                    reliance on off-device recovery. A machine with no backup has no \
                    recovery path from either.",
        escape_hatch: "steel-backup disable, which records the choice so this check \
                       reports it as deliberate rather than broken.",
        run: check_configured,
    },
    Check {
        id: "backup.target-separateness",
        title: "No backup target is on the protected device",
        category: Category::Backup,
        severity: Severity::Critical,
        rationale: "CLAUDE.md governing rule: no backup target may live on the device \
                    being protected. This is what resolves the recoverable-vs-destroyable \
                    tension — local key material can be destroyed under duress precisely \
                    because recovery lives somewhere else.",
        escape_hatch: "None. steel-backup refuses local targets in code, not only in docs.",
        run: check_target_separateness,
    },
    Check {
        id: "backup.append-only",
        title: "Remote targets are append-only",
        category: Category::Backup,
        severity: Severity::Critical,
        rationale: "Without append-only enforcement the duress design is hollow: an \
                    adversary with the unlocked machine, or ransomware, deletes the \
                    backups first and then the local wipe is total.",
        escape_hatch: "None. Pruning happens from a separate trusted context.",
        run: check_append_only,
    },
    Check {
        id: "backup.outer-key-is-public",
        title: "Only the public half of the outer backup key is on this device",
        category: Category::Backup,
        severity: Severity::Critical,
        rationale: "The outer age/gpg layer's whole value is that a seized or fully \
                    compromised machine cannot decrypt its own history. If the private \
                    key lands in the keyring 'for convenience', that benefit is gone and \
                    nothing warns you.",
        escape_hatch: "None.",
        run: check_outer_key_public,
    },
    Check {
        id: "backup.last-run",
        title: "A backup has completed recently",
        category: Category::Backup,
        severity: Severity::Medium,
        rationale: "A configured backup that has not run is not a backup.",
        escape_hatch: "n/a",
        run: check_last_run,
    },
    Check {
        id: "backup.last-verify",
        title: "A restore verification has completed recently",
        category: Category::Backup,
        severity: Severity::High,
        rationale: "A backup system that has never restored is not a backup system. \
                    steel-backup verify performs a real restore of a sampled subset and \
                    compares hashes, so this check is the difference between having \
                    backups and believing you do.",
        escape_hatch: "n/a",
        run: check_last_verify,
    },
];

/// Parsed state written by `steel-backup` after each run. Kept as a plain
/// key=value file so the recovery environment can read it without our tooling.
struct BackupState {
    fields: Vec<(String, String)>,
}

impl BackupState {
    fn load(ctx: &Context) -> Option<BackupState> {
        let body = ctx.sys.read("/var/lib/steelos/backup/state")?;
        let fields = body
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();
        Some(BackupState { fields })
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn all(&self, key: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

fn check_configured(ctx: &Context) -> Outcome {
    let state = BackupState::load(ctx);
    let disabled = ctx.sys.exists("/etc/steelos/backup-disabled");

    match (state, disabled) {
        (_, true) => Outcome::warn("backups are explicitly disabled")
            .evidence(
                "/etc/steelos/backup-disabled is present, so this is a deliberate \
                       choice rather than a misconfiguration.",
            )
            .evidence(
                "Note that duress key-destruction is only survivable with an \
                       off-device backup. With backups off, wipe-keys is permanent.",
            )
            .remedy("steel-backup enable"),
        (Some(s), false) => {
            let targets = s.all("target");
            if targets.is_empty() {
                Outcome::fail("backup state exists but no target is configured")
                    .remedy("steel-backup add-target restic:sftp:host:/path")
            } else {
                Outcome::pass(format!("{} target(s) configured", targets.len()))
            }
        }
        (None, false) => Outcome::fail("no backup is configured")
            .evidence(
                "There is no recovery path from a bad update, a lost device, or a \
                       duress wipe.",
            )
            .remedy("steel-backup setup, or record the decision with `steel-backup disable`."),
    }
}

fn check_target_separateness(ctx: &Context) -> Outcome {
    let state = match BackupState::load(ctx) {
        Some(s) => s,
        None => return Outcome::skip("no backup is configured"),
    };
    let targets = state.all("target");
    if targets.is_empty() {
        return Outcome::skip("no backup targets are configured");
    }

    // Anything that resolves to a path on a currently-mounted local filesystem
    // that is not removable is on the protected device.
    let mut local = Vec::new();
    for target in &targets {
        let is_remote = target.contains("sftp:")
            || target.contains("rest:")
            || target.contains("s3:")
            || target.contains("b2:")
            || target.contains("ssh://")
            || target.contains('@');
        if is_remote {
            continue;
        }
        let path = target
            .trim_start_matches("restic:")
            .trim_start_matches("borg:");
        if !path.starts_with('/') {
            continue;
        }
        // Removable media is an allowed target; the rule is about the internal
        // disk that the wipe would destroy.
        let removable = path.starts_with("/run/media/")
            || path.starts_with("/media/")
            || path.starts_with("/mnt/");
        if !removable {
            local.push((*target).to_string());
        }
    }

    if local.is_empty() {
        Outcome::pass(format!(
            "{} target(s), none on the internal disk",
            targets.len()
        ))
    } else {
        Outcome::fail(format!(
            "{} target(s) are on the protected device",
            local.len()
        ))
        .evidence_all(local)
        .evidence(
            "A local btrfs snapshot is a convenience rollback, not a backup, \
                       and is never counted as one here.",
        )
        .remedy(
            "steel-backup remove-target <target>, then configure a removable or \
                     remote target. steel-backup refuses to create these; this one \
                     predates the check or was added by hand.",
        )
    }
}

fn check_append_only(ctx: &Context) -> Outcome {
    let state = match BackupState::load(ctx) {
        Some(s) => s,
        None => return Outcome::skip("no backup is configured"),
    };
    let targets = state.all("target");
    let remote: Vec<&&str> = targets
        .iter()
        .filter(|t| t.contains("sftp:") || t.contains("rest:") || t.contains("ssh://"))
        .collect();

    if remote.is_empty() {
        return Outcome::skip("no remote backup targets are configured");
    }

    // steel-backup records the result of its own probe: it writes a canary and
    // then attempts to delete it. Trusting a config flag would be trusting the
    // thing we are trying to verify.
    let probed = state.get("append_only_verified").unwrap_or("no");
    match probed {
        "yes" => Outcome::pass(format!(
            "{} remote target(s), append-only verified by probe",
            remote.len()
        )),
        "no" => Outcome::fail("append-only enforcement is not verified")
            .evidence("The credential used for backups may be able to delete history.")
            .remedy(
                "Configure rest-server with --append-only, or borg with an \
                     append-only forced SSH command, then run `steel-backup probe`.",
            ),
        other => Outcome::warn(format!("append-only probe state is '{other}'"))
            .remedy("Run `steel-backup probe` to re-test."),
    }
}

fn check_outer_key_public(ctx: &Context) -> Outcome {
    let dir = "/var/lib/steelos/backup/keys";
    let files = ctx.sys.list_dir(dir);
    if files.is_empty() {
        return Outcome::skip("no outer-layer key material is present");
    }

    let mut private = Vec::new();
    for name in &files {
        let body = ctx.sys.read(&format!("{dir}/{name}")).unwrap_or_default();
        // age private keys begin AGE-SECRET-KEY-; PEM/GPG private blocks are
        // equally recognisable. Anything matching is a hard failure.
        let looks_private = body.contains("AGE-SECRET-KEY-")
            || body.contains("BEGIN PGP PRIVATE KEY BLOCK")
            || body.contains("BEGIN OPENSSH PRIVATE KEY")
            || body.contains("BEGIN RSA PRIVATE KEY")
            || body.contains("BEGIN PRIVATE KEY");
        if looks_private {
            private.push(name.clone());
        }
    }

    if private.is_empty() {
        Outcome::pass(format!("{} key file(s), all public", files.len()))
    } else {
        Outcome::fail(format!(
            "{} private key(s) present on the device",
            private.len()
        ))
        .evidence_all(
            private
                .iter()
                .map(|n| format!("{dir}/{n}"))
                .collect::<Vec<_>>(),
        )
        .evidence(
            "The outer layer exists so that a seized machine cannot decrypt its \
                       own backup history. With the private key here, it can.",
        )
        .remedy(
            "Move the private key to a hardware token or offline media and delete \
                     it from this machine, then rotate: the key has been exposed for as \
                     long as it has been on disk.",
        )
    }
}

/// Age thresholds. Deliberately generous: a nagging check gets ignored, and an
/// ignored check is worse than no check.
const BACKUP_STALE_DAYS: i64 = 7;
const VERIFY_STALE_DAYS: i64 = 30;

fn check_last_run(ctx: &Context) -> Outcome {
    age_check(
        ctx,
        "last_run_age_days",
        BACKUP_STALE_DAYS,
        "backup",
        "steel-backup run",
    )
}

fn check_last_verify(ctx: &Context) -> Outcome {
    age_check(
        ctx,
        "last_verify_age_days",
        VERIFY_STALE_DAYS,
        "restore verification",
        "steel-backup verify",
    )
}

/// Ages are recorded by `steel-backup` as whole days, not as timestamps.
///
/// This is not laziness: a timestamp in the report would be a volatile field,
/// and the byte-identical-output rule forbids those. Days-since is stable for
/// 24 hours and is all the user needs.
fn age_check(ctx: &Context, key: &str, stale_after: i64, what: &str, fix: &str) -> Outcome {
    let state = match BackupState::load(ctx) {
        Some(s) => s,
        None => return Outcome::skip("no backup is configured"),
    };
    let age = match state.get(key).and_then(|v| v.parse::<i64>().ok()) {
        Some(a) => a,
        None => {
            return Outcome::fail(format!("no successful {what} has ever been recorded"))
                .remedy(fix.to_string())
        }
    };
    if age <= stale_after {
        Outcome::pass(format!("last {what} was {age} day(s) ago"))
    } else {
        Outcome::fail(format!(
            "last {what} was {age} day(s) ago (stale after {stale_after})"
        ))
        .remedy(fix.to_string())
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
            let d = std::env::temp_dir().join(format!("steel-check-bk-{n}-{}", std::process::id()));
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
        fn ctx(&self) -> Context {
            Context {
                sys: Sysroot::new(&self.0),
                preset: Preset::Balanced,
                deployment: Deployment::Image,
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
    fn a_target_on_the_internal_disk_is_a_critical_failure() {
        let f = Fx::new("local-target");
        f.write(
            "/var/lib/steelos/backup/state",
            "target=/var/lib/steelos/backup\n",
        );
        let out = check_target_separateness(&f.ctx());
        assert_eq!(out.status, Status::Fail);
    }

    #[test]
    fn removable_and_remote_targets_are_accepted() {
        let f = Fx::new("good-targets");
        f.write(
            "/var/lib/steelos/backup/state",
            "target=restic:sftp:backup.example:/repo\ntarget=/run/media/chase/usb/repo\n",
        );
        assert_eq!(check_target_separateness(&f.ctx()).status, Status::Pass);
    }

    #[test]
    fn append_only_must_be_probed_not_asserted() {
        let f = Fx::new("append-only");
        f.write(
            "/var/lib/steelos/backup/state",
            "target=restic:sftp:backup.example:/repo\n",
        );
        assert_eq!(check_append_only(&f.ctx()).status, Status::Fail);

        f.write(
            "/var/lib/steelos/backup/state",
            "target=restic:sftp:backup.example:/repo\nappend_only_verified=yes\n",
        );
        assert_eq!(check_append_only(&f.ctx()).status, Status::Pass);
    }

    #[test]
    fn a_private_outer_key_on_the_device_is_a_critical_failure() {
        let f = Fx::new("outer-key");
        f.write(
            "/var/lib/steelos/backup/keys/outer.pub",
            "age1qz9v0lz3zwr8kk2mtlfp0v0wq3jz3xk8yq0f6t0v9x8sdfghjklqwertyu\n",
        );
        assert_eq!(check_outer_key_public(&f.ctx()).status, Status::Pass);

        f.write(
            "/var/lib/steelos/backup/keys/outer.key",
            "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n",
        );
        let out = check_outer_key_public(&f.ctx());
        assert_eq!(out.status, Status::Fail);
        assert!(out.remedy.unwrap().contains("rotate"));
    }

    #[test]
    fn a_backup_that_never_ran_fails() {
        let f = Fx::new("never-ran");
        f.write("/var/lib/steelos/backup/state", "target=restic:sftp:h:/r\n");
        assert_eq!(check_last_run(&f.ctx()).status, Status::Fail);
        assert_eq!(check_last_verify(&f.ctx()).status, Status::Fail);
    }

    #[test]
    fn stale_backups_fail_and_fresh_ones_pass() {
        let f = Fx::new("staleness");
        f.write(
            "/var/lib/steelos/backup/state",
            "target=restic:sftp:h:/r\nlast_run_age_days=2\nlast_verify_age_days=45\n",
        );
        assert_eq!(check_last_run(&f.ctx()).status, Status::Pass);
        assert_eq!(check_last_verify(&f.ctx()).status, Status::Fail);
    }
}
