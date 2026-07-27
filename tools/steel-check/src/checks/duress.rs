//! Duress, decoy, and custody — audited under a constraint the other categories
//! do not have.
//!
//! # The rule
//!
//! CLAUDE.md, gotcha 21: *"Universal shipping of duress code is a hard
//! requirement, not a preference. Any conditional file, unit, or log line that
//! reveals configuration state defeats the deniability design."*
//!
//! And under `steel-check`: *"steel-check must produce byte-identical output on
//! a machine with duress configured and one without, when run from a context
//! that has not unlocked the real volume."*
//!
//! So every check in this module obeys one of two shapes:
//!
//! * **Universality checks** read only things that are identical on every
//!   SteelOS install by construction — the initramfs hook, the maintenance boot
//!   entry, the fixed-size custody region. Their output does not vary with
//!   configuration because their input does not.
//!
//! * **Configuration checks** read state that lives *inside* the encrypted
//!   volume. When `real_volume_unlocked` is false they return a fixed `Skip`
//!   with a constant reason and read nothing at all. Not "read it and hide the
//!   result" — an examiner with the binary can see which paths it opens, and a
//!   conditional read is itself a signal.
//!
//! If you add a check here, it must fit one of those two shapes. `tests/audit/`
//! runs the whole suite against a configured and an unconfigured fixture and
//! diffs the bytes.

use crate::context::Context;
use crate::report::{Category, Check, Outcome, Severity};

/// The exact wording used whenever a duress check declines to read encrypted
/// state. A constant, because two machines must emit the same bytes and a
/// formatted string is an invitation to leak a variable into it.
const LOCKED_CONTEXT_REASON: &str =
    "duress configuration lives inside the encrypted volume and is not readable from this context";

pub const CHECKS: &[Check] = &[
    Check {
        id: "duress.universal-hook",
        title: "The duress initramfs hook is present",
        category: Category::Duress,
        severity: Severity::High,
        rationale: "The hook ships in every image, active or not. Finding it proves only \
                    that the machine runs SteelOS. If it were installed conditionally, its \
                    presence would be the evidence the whole design exists to avoid.",
        escape_hatch: "None, and that is the point: it cannot be removed without making \
                       the machines that keep it identifiable.",
        run: check_universal_hook,
    },
    Check {
        id: "duress.universal-maintenance-entry",
        title: "The maintenance boot entry is present",
        category: Category::Duress,
        severity: Severity::Medium,
        rationale: "The maintenance path exists on every install and does real work on \
                    machines with no decoy — staging updates, running backups, scrubbing \
                    filesystem state. An entry that only appeared on decoy machines would \
                    be a tell.",
        escape_hatch: "None, for the same reason.",
        run: check_maintenance_entry,
    },
    Check {
        id: "duress.custody-region",
        title: "The custody region is present and fixed-size",
        category: Category::Duress,
        severity: Severity::Medium,
        rationale: "The initramfs needs wrapped key material before anything is \
                    decrypted, so it cannot live inside the encrypted volume. Every \
                    install therefore ships a fixed-size region of random data in the \
                    same place; on custody machines it holds the wrapped key, on all \
                    others it stays random fill.",
        escape_hatch: "None.",
        run: check_custody_region,
    },
    Check {
        id: "duress.no-plaintext-config-leak",
        title: "No plaintext location reveals duress configuration",
        category: Category::Duress,
        severity: Severity::Critical,
        rationale: "This is the check that enforces gotcha 21 against ourselves. It scans \
                    the ESP and unencrypted state for anything whose presence, absence, or \
                    size would differ between a configured and an unconfigured machine. A \
                    failure here means the deniability design is broken on this machine \
                    regardless of what else passes.",
        escape_hatch: "None.",
        run: check_no_plaintext_leak,
    },
    Check {
        id: "duress.esp-uniformity",
        title: "The ESP is identical in shape across installs",
        category: Category::Duress,
        severity: Severity::High,
        rationale: "The ESP is unencrypted and is the first thing an examiner reads. One \
                    UKI, one loader config, one boot entry, identical for all installs. \
                    The passphrase entered selects the volume; the ESP never records which \
                    volumes exist.",
        escape_hatch: "None.",
        run: check_esp_uniformity,
    },
    Check {
        id: "duress.last-drill",
        title: "The duress playbook has been rehearsed",
        category: Category::Duress,
        severity: Severity::High,
        rationale: "A wipe feature that has never been tested does not work, and a \
                    playbook that has never been rehearsed will be performed badly under \
                    stress — which is the only time it matters. The drill result lives \
                    inside the encrypted volume, so this check is only meaningful from an \
                    unlocked real profile.",
        escape_hatch: "n/a",
        run: check_last_drill,
    },
];

fn check_universal_hook(ctx: &Context) -> Outcome {
    // Presence only. Never report which actions are configured, which
    // credentials exist, or how many — those live in the encrypted volume.
    let hook = ctx.sys.exists("/usr/lib/initcpio/hooks/steel-duress");
    let install = ctx.sys.exists("/usr/lib/initcpio/install/steel-duress");

    match (hook, install) {
        (true, true) => Outcome::pass("present"),
        _ => Outcome::fail("the duress hook is not installed")
            .evidence(
                "Every SteelOS image ships it. Its absence makes this machine \
                       distinguishable from every other SteelOS machine, which is itself \
                       a finding even for a user who never configures duress.",
            )
            .remedy("pacman -S steel-duress and rebuild the initramfs."),
    }
}

fn check_maintenance_entry(ctx: &Context) -> Outcome {
    let entries = ctx.sys.list_dir("/efi/loader/entries");
    if entries.is_empty() {
        return Outcome::skip("cannot read /efi/loader/entries");
    }
    if entries.iter().any(|e| e.contains("maintenance")) {
        Outcome::pass("present")
    } else {
        Outcome::fail("no maintenance boot entry")
            .evidence(
                "The entry must exist on every install, decoy or not, or its \
                       presence identifies the machines that have one.",
            )
            .remedy("steel-boot install-maintenance")
    }
}

/// The custody region is a fixed allocation. Both its presence and its exact
/// size must be identical everywhere, so the check reports the size and
/// compares it against the one value the installer ever writes.
const CUSTODY_REGION_BYTES: u64 = 4 * 1024 * 1024;

fn check_custody_region(ctx: &Context) -> Outcome {
    let path = ctx.sys.path("/var/lib/steelos/custody.region");
    match std::fs::metadata(&path) {
        Ok(m) if m.len() == CUSTODY_REGION_BYTES => Outcome::pass("present, 4 MiB"),
        Ok(m) => Outcome::fail(format!(
            "custody region is {} bytes, expected {CUSTODY_REGION_BYTES}",
            m.len()
        ))
        .evidence(
            "A region whose size differs from every other install is a \
                   distinguishing feature, which is what this design cannot have.",
        )
        .remedy("steel-custody repair-region"),
        Err(_) => Outcome::fail("no custody region")
            .evidence(
                "Custody enrollment would have nowhere to hide, and machines that \
                       have one would be distinguishable from machines that do not.",
            )
            .remedy("steel-custody repair-region"),
    }
}

/// Paths that must never differ between a configured and an unconfigured
/// machine. Anything here is unencrypted, so anything conditional in it is a
/// direct leak.
const PLAINTEXT_LEAK_PATHS: &[&str] = &[
    "/etc/steelos/duress.conf",
    "/etc/steelos/duress.d",
    "/etc/steelos/decoy.conf",
    "/etc/steelos/custody.conf",
    "/etc/systemd/system/steel-duress.service",
    "/etc/systemd/system/steel-decoy.timer",
    "/etc/systemd/system/multi-user.target.wants/steel-duress.service",
    "/var/lib/steelos/duress-state",
    "/var/lib/steelos/decoy",
    "/efi/steelos/duress",
    "/efi/loader/entries/steelos-decoy.conf",
];

fn check_no_plaintext_leak(ctx: &Context) -> Outcome {
    let found: Vec<String> = PLAINTEXT_LEAK_PATHS
        .iter()
        .filter(|p| ctx.sys.exists(p))
        .map(|p| (*p).to_string())
        .collect();

    // /etc/crypttab must not name a second volume: an examiner reads it first.
    let crypttab = ctx.sys.read("/etc/crypttab").unwrap_or_default();
    let crypttab_entries: Vec<&str> = crypttab
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let mut problems = found;
    if crypttab_entries.len() > 1 {
        problems.push(format!(
            "/etc/crypttab names {} volumes; a decoy must never appear here",
            crypttab_entries.len()
        ));
    }

    if problems.is_empty() {
        Outcome::pass("no duress or decoy state in any plaintext location")
    } else {
        Outcome::fail(format!("{} plaintext leak(s)", problems.len()))
            .evidence_all(problems)
            .evidence(
                "Each of these tells an examiner something about how this machine \
                       is configured, which no other SteelOS machine would tell them.",
            )
            .remedy(
                "Move the state inside the encrypted volume it protects and remove \
                     the plaintext copy. See docs/duress-and-deniability.md.",
            )
    }
}

fn check_esp_uniformity(ctx: &Context) -> Outcome {
    let entries = ctx.sys.list_dir("/efi/loader/entries");
    if entries.is_empty() {
        return Outcome::skip("cannot read /efi/loader/entries");
    }

    // The expected set is fixed: the A and B deployment entries, maintenance,
    // recovery, and (unless the preset removes it) devmode. Anything else is a
    // machine-specific difference visible without decrypting anything.
    let allowed = [
        "steelos-a",
        "steelos-b",
        "maintenance",
        "recovery",
        "devmode",
    ];
    let unexpected: Vec<String> = entries
        .iter()
        .filter(|e| !allowed.iter().any(|a| e.contains(a)))
        .cloned()
        .collect();

    if unexpected.is_empty() {
        Outcome::pass(format!(
            "{} entries, all from the standard set",
            entries.len()
        ))
    } else {
        Outcome::warn(format!("{} non-standard boot entry(ies)", unexpected.len()))
            .evidence_all(unexpected)
            .evidence(
                "Entries beyond the standard set distinguish this machine from a \
                       stock install to anyone who reads the ESP.",
            )
            .remedy("Remove them, or accept that the ESP identifies this machine.")
    }
}

fn check_last_drill(ctx: &Context) -> Outcome {
    // The load-bearing branch. When the real volume is not unlocked we do not
    // read the state at all: an examiner with strace and the binary would learn
    // from the attempt, not just from the result.
    if !ctx.real_volume_unlocked {
        return Outcome::skip(LOCKED_CONTEXT_REASON);
    }

    let state = ctx
        .sys
        .read("/var/lib/steelos/private/duress-drill")
        .unwrap_or_default();
    let configured = state.lines().any(|l| l.trim() == "configured=yes");
    if !configured {
        return Outcome::skip("no duress playbook is configured on this profile");
    }

    let age = state
        .lines()
        .filter_map(|l| l.trim().strip_prefix("last_drill_age_days="))
        .filter_map(|v| v.parse::<i64>().ok())
        .next();

    match age {
        Some(days) if days <= 180 => Outcome::pass(format!("last rehearsed {days} day(s) ago")),
        Some(days) => Outcome::warn(format!("last rehearsed {days} day(s) ago"))
            .evidence("Rehearsal is part of the feature, not preparation for it.")
            .remedy("steel-duress drill"),
        None => Outcome::fail("a playbook is configured but has never been rehearsed")
            .evidence(
                "An unrehearsed playbook is performed badly under stress, and the \
                       failure modes here are irreversible.",
            )
            .remedy(
                "steel-duress drill — it runs against scratch volumes and destroys \
                     nothing real.",
            ),
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
            let d = std::env::temp_dir().join(format!("steel-check-du-{n}-{}", std::process::id()));
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
        fn ctx(&self, unlocked: bool) -> Context {
            Context {
                sys: Sysroot::new(&self.0),
                preset: Preset::Balanced,
                deployment: Deployment::Image,
                cmdline: KernelCmdline::parse(""),
                real_volume_unlocked: unlocked,
            }
        }
    }
    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The core invariant, at the level of a single check: configuring duress
    /// must not change what a locked context reports.
    #[test]
    fn drill_check_is_identical_whether_or_not_duress_is_configured() {
        let unconfigured = Fx::new("drill-off");
        let configured = Fx::new("drill-on");
        configured.write(
            "/var/lib/steelos/private/duress-drill",
            "configured=yes\nlast_drill_age_days=3\n",
        );

        let a = check_last_drill(&unconfigured.ctx(false));
        let b = check_last_drill(&configured.ctx(false));
        assert_eq!(a.status, b.status);
        assert_eq!(a.detail, b.detail);
        assert_eq!(a.evidence, b.evidence);
        assert_eq!(a.remedy, b.remedy);
        assert_eq!(a.detail, LOCKED_CONTEXT_REASON);
    }

    #[test]
    fn drill_check_reports_normally_once_the_real_volume_is_unlocked() {
        let f = Fx::new("drill-unlocked");
        f.write(
            "/var/lib/steelos/private/duress-drill",
            "configured=yes\nlast_drill_age_days=3\n",
        );
        assert_eq!(check_last_drill(&f.ctx(true)).status, Status::Pass);

        f.write("/var/lib/steelos/private/duress-drill", "configured=yes\n");
        assert_eq!(check_last_drill(&f.ctx(true)).status, Status::Fail);
    }

    #[test]
    fn plaintext_duress_config_is_a_critical_failure() {
        let f = Fx::new("leak");
        f.write("/etc/steelos/duress.conf", "action=wipe-keys\n");
        let out = check_no_plaintext_leak(&f.ctx(false));
        assert_eq!(out.status, Status::Fail);
        assert!(out.evidence.iter().any(|e| e.contains("duress.conf")));
    }

    #[test]
    fn a_second_crypttab_entry_is_a_leak() {
        let f = Fx::new("crypttab");
        f.write(
            "/etc/crypttab",
            "steelos-var UUID=1111 none luks\nsteelos-decoy UUID=2222 none luks\n",
        );
        let out = check_no_plaintext_leak(&f.ctx(false));
        assert_eq!(out.status, Status::Fail);
        assert!(out.evidence.iter().any(|e| e.contains("crypttab")));
    }

    #[test]
    fn a_single_crypttab_entry_is_fine() {
        let f = Fx::new("crypttab-ok");
        f.write(
            "/etc/crypttab",
            "# comment\nsteelos-var UUID=1111 none luks\n",
        );
        assert_eq!(check_no_plaintext_leak(&f.ctx(false)).status, Status::Pass);
    }

    #[test]
    fn custody_region_must_be_exactly_the_standard_size() {
        let f = Fx::new("custody");
        f.write("/var/lib/steelos/custody.region", "too small");
        assert_eq!(check_custody_region(&f.ctx(false)).status, Status::Fail);

        let big = vec![0u8; CUSTODY_REGION_BYTES as usize];
        let p = f.0.join("var/lib/steelos/custody.region");
        fs::write(p, big).unwrap();
        assert_eq!(check_custody_region(&f.ctx(false)).status, Status::Pass);
    }
}
