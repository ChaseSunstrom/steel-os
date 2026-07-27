//! What changes when a manifest changes.
//!
//! `steelctl diff` is the thing standing between a user and a surprise. It has
//! to be honest about two distinctions people get wrong:
//!
//!  1. **What needs a rebuild vs. what does not.** Adding a Flatpak or changing
//!     a backup schedule takes effect now; adding a system package rebuilds the
//!     image and takes effect on reboot. Presenting those identically trains
//!     people to reboot for no reason, and then to ignore the message when it
//!     matters.
//!
//!  2. **What takes effect immediately vs. on reboot.** A user who applies a
//!     manifest and does not reboot is running the old system with the new
//!     configuration file. `steelctl` says so in as many words.

use crate::manifest::Manifest;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effect {
    /// Applied by reconciliation, in force as soon as `apply` finishes.
    Immediate,
    /// Requires building a new image and rebooting into it.
    Reboot,
}

impl Effect {
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Immediate => "immediate",
            Effect::Reboot => "on reboot",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    pub effect: Effect,
    pub category: String,
    pub description: String,
}

#[derive(Debug, Clone, Default)]
pub struct Diff {
    pub changes: Vec<Change>,
}

impl Diff {
    pub fn compute(from: &Manifest, to: &Manifest) -> Diff {
        let mut changes = Vec::new();

        // --- image-affecting -------------------------------------------------
        if from.system.snapshot != to.system.snapshot {
            changes.push(Change {
                effect: Effect::Reboot,
                category: "snapshot".into(),
                description: format!(
                    "{} -> {} (every package in the image may change)",
                    from.system.snapshot, to.system.snapshot
                ),
            });
        }
        if from.system.kernel != to.system.kernel {
            changes.push(Change {
                effect: Effect::Reboot,
                category: "kernel".into(),
                description: format!("{} -> {}", from.system.kernel, to.system.kernel),
            });
        }
        if from.system.channel != to.system.channel {
            changes.push(Change {
                effect: Effect::Reboot,
                category: "channel".into(),
                description: format!(
                    "{} -> {}",
                    from.system.channel.as_str(),
                    to.system.channel.as_str()
                ),
            });
        }
        if from.system.hardening != to.system.hardening {
            changes.push(Change {
                effect: Effect::Reboot,
                category: "hardening".into(),
                description: format!(
                    "{} -> {}{}",
                    from.system.hardening.as_str(),
                    to.system.hardening.as_str(),
                    hardening_warning(from.system.hardening, to.system.hardening)
                ),
            });
        }

        for added in added(&from.packages, &to.packages) {
            changes.push(Change {
                effect: Effect::Reboot,
                category: "package".into(),
                description: format!("+ {added}"),
            });
        }
        for removed in added(&to.packages, &from.packages) {
            changes.push(Change {
                effect: Effect::Reboot,
                category: "package".into(),
                description: format!("- {removed}"),
            });
        }

        // --- immediate -------------------------------------------------------
        for added in added(&from.flatpak_user, &to.flatpak_user) {
            changes.push(Change {
                effect: Effect::Immediate,
                category: "flatpak".into(),
                description: format!("+ {added}"),
            });
        }
        for removed in added(&to.flatpak_user, &from.flatpak_user) {
            changes.push(Change {
                effect: Effect::Immediate,
                category: "flatpak".into(),
                description: format!("- {removed}"),
            });
        }
        for service in added(&from.services_enable, &to.services_enable) {
            changes.push(Change {
                effect: Effect::Immediate,
                category: "service".into(),
                description: format!("enable {service}"),
            });
        }
        for service in added(&from.services_disable, &to.services_disable) {
            changes.push(Change {
                effect: Effect::Immediate,
                category: "service".into(),
                description: format!("disable {service}"),
            });
        }

        if from.backup != to.backup {
            changes.push(Change {
                effect: Effect::Immediate,
                category: "backup".into(),
                description: describe_backup_change(from, to),
            });
        }

        for (name, user) in &to.users {
            match from.users.get(name) {
                None => changes.push(Change {
                    effect: Effect::Immediate,
                    category: "user".into(),
                    description: format!(
                        "+ {name} (storage={}, sandbox={})",
                        user.storage, user.sandbox
                    ),
                }),
                Some(previous) if previous != user => changes.push(Change {
                    effect: Effect::Immediate,
                    category: "user".into(),
                    description: format!("~ {name}: {}", describe_user_change(previous, user)),
                }),
                _ => {}
            }
        }
        for name in from.users.keys() {
            if !to.users.contains_key(name) {
                // Deliberately not "remove the user". Deleting a homed volume
                // destroys the only copy of that person's data, and a manifest
                // edit is not a strong enough signal to do that.
                changes.push(Change {
                    effect: Effect::Immediate,
                    category: "user".into(),
                    description: format!(
                        "- {name} (the account is left in place; \
                         `homectl remove {name}` deletes the data, and nothing else will)"
                    ),
                });
            }
        }

        changes.sort_by(|a, b| {
            a.effect
                .cmp(&b.effect)
                .then(a.category.cmp(&b.category))
                .then(a.description.cmp(&b.description))
        });

        Diff { changes }
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn needs_rebuild(&self) -> bool {
        self.changes.iter().any(|c| c.effect == Effect::Reboot)
    }
}

impl fmt::Display for Diff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.changes.is_empty() {
            return writeln!(
                f,
                "No changes. The running system already matches the manifest."
            );
        }

        let immediate: Vec<&Change> = self
            .changes
            .iter()
            .filter(|c| c.effect == Effect::Immediate)
            .collect();
        let reboot: Vec<&Change> = self
            .changes
            .iter()
            .filter(|c| c.effect == Effect::Reboot)
            .collect();

        if !immediate.is_empty() {
            writeln!(f, "Takes effect immediately:")?;
            for c in &immediate {
                writeln!(f, "  {:<10} {}", c.category, c.description)?;
            }
        }
        if !reboot.is_empty() {
            if !immediate.is_empty() {
                writeln!(f)?;
            }
            writeln!(f, "Requires a new image and a reboot:")?;
            for c in &reboot {
                writeln!(f, "  {:<10} {}", c.category, c.description)?;
            }
            writeln!(f)?;
            writeln!(
                f,
                "  Until you reboot, this machine runs the PREVIOUS image with the new\n  \
                 configuration file. `steelctl history` shows which generation is live."
            )?;
        }
        Ok(())
    }
}

fn added(from: &[String], to: &[String]) -> Vec<String> {
    let mut out: Vec<String> = to.iter().filter(|x| !from.contains(x)).cloned().collect();
    out.sort();
    out.dedup();
    out
}

fn hardening_warning(
    from: crate::manifest::Hardening,
    to: crate::manifest::Hardening,
) -> &'static str {
    use crate::manifest::Hardening::*;
    match (from, to) {
        (_, Compatible) => {
            " — WARNING: compatible is reduced protection. No hardened_malloc preload, \
             lockdown drops to integrity, devmode stays available."
        }
        (_, Strict) => {
            " — strict removes functionality: Thunderbolt is blacklisted (docks stop \
             working), USBGuard prompts on every new device, and there is no devmode \
             boot entry"
        }
        _ => "",
    }
}

fn describe_backup_change(from: &Manifest, to: &Manifest) -> String {
    let mut parts = Vec::new();
    if from.backup.enabled != to.backup.enabled {
        parts.push(if to.backup.enabled {
            "enabled".to_string()
        } else {
            // Worth naming, because it silently changes what a duress wipe means.
            "DISABLED — note that with no off-device backup, duress key destruction \
             is permanent"
                .to_string()
        });
    }
    if from.backup.targets != to.backup.targets {
        parts.push(format!(
            "targets: {} -> {}",
            from.backup.targets.len(),
            to.backup.targets.len()
        ));
    }
    if from.backup.schedule != to.backup.schedule {
        parts.push(format!(
            "schedule {} -> {}",
            from.backup.schedule, to.backup.schedule
        ));
    }
    if from.backup.retention != to.backup.retention {
        parts.push(format!(
            "retention {} -> {}",
            from.backup.retention, to.backup.retention
        ));
    }
    parts.join(", ")
}

fn describe_user_change(from: &crate::manifest::User, to: &crate::manifest::User) -> String {
    let mut parts = Vec::new();
    if from.storage != to.storage {
        let note = if to.storage == "directory" {
            " (NOT independently encrypted — root can read it at rest)"
        } else {
            ""
        };
        parts.push(format!(
            "storage {} -> {}{}",
            from.storage, to.storage, note
        ));
    }
    if from.sandbox != to.sandbox {
        parts.push(format!("sandbox {} -> {}", from.sandbox, to.sandbox));
    }
    if from.tunnel_policy != to.tunnel_policy {
        parts.push(format!(
            "tunnel_policy {:?} -> {:?}",
            from.tunnel_policy, to.tunnel_policy
        ));
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(body: &str) -> Manifest {
        Manifest::parse(&format!("[system]\nsnapshot = \"2026-07-20\"\n{body}")).unwrap()
    }

    #[test]
    fn an_identical_manifest_produces_no_changes() {
        let a = manifest("");
        let d = Diff::compute(&a, &a);
        assert!(d.is_empty());
        assert!(!d.needs_rebuild());
        assert!(d.to_string().contains("No changes"));
    }

    #[test]
    fn flatpaks_are_immediate_and_packages_need_a_reboot() {
        // Presenting these identically trains people to reboot for no reason,
        // and then to ignore the message when it matters.
        let a = manifest("");
        let b = manifest("[flatpak]\nuser = [\"org.example.App\"]\n");
        let d = Diff::compute(&a, &b);
        assert!(!d.needs_rebuild());
        assert_eq!(d.changes[0].effect, Effect::Immediate);

        let c = manifest("[packages]\nsystem = [\"vim\"]\n");
        let d = Diff::compute(&a, &c);
        assert!(d.needs_rebuild());
        assert!(d.to_string().contains("PREVIOUS image"));
    }

    #[test]
    fn package_removal_is_reported_as_well_as_addition() {
        let a = manifest("[packages]\nsystem = [\"vim\", \"git\"]\n");
        let b = manifest("[packages]\nsystem = [\"git\"]\n");
        let d = Diff::compute(&a, &b);
        assert_eq!(d.changes.len(), 1);
        assert!(d.changes[0].description.starts_with("- vim"));
    }

    #[test]
    fn moving_to_compatible_warns_about_reduced_protection() {
        let a = manifest("");
        let b =
            Manifest::parse("[system]\nsnapshot = \"2026-07-20\"\nhardening = \"compatible\"\n")
                .unwrap();
        let d = Diff::compute(&a, &b);
        assert!(d.to_string().contains("reduced protection"));
    }

    #[test]
    fn moving_to_strict_names_what_stops_working() {
        let a = manifest("");
        let b = Manifest::parse("[system]\nsnapshot = \"2026-07-20\"\nhardening = \"strict\"\n")
            .unwrap();
        assert!(Diff::compute(&a, &b).to_string().contains("docks stop"));
    }

    #[test]
    fn removing_a_user_does_not_promise_to_delete_their_data() {
        // A manifest edit is not a strong enough signal to destroy the only
        // copy of somebody's home directory.
        let a = manifest("[users.chase]\nstorage = \"luks\"\n");
        let b = manifest("");
        let d = Diff::compute(&a, &b);
        let text = d.to_string();
        assert!(text.contains("left in place"), "{text}");
        assert!(text.contains("homectl remove"), "{text}");
    }

    #[test]
    fn disabling_backups_names_the_consequence_for_duress() {
        let a = manifest("[backup]\nenabled = true\n");
        let b = manifest("[backup]\nenabled = false\n");
        assert!(Diff::compute(&a, &b)
            .to_string()
            .contains("duress key destruction is permanent"));
    }

    #[test]
    fn a_snapshot_change_says_everything_may_change() {
        let a = manifest("");
        let b = Manifest::parse("[system]\nsnapshot = \"2026-08-01\"\n").unwrap();
        let d = Diff::compute(&a, &b);
        assert!(d.needs_rebuild());
        assert!(d
            .to_string()
            .contains("every package in the image may change"));
    }

    #[test]
    fn changes_are_ordered_deterministically() {
        let a = manifest("");
        let b = manifest(
            "[packages]\nsystem = [\"zsh\", \"apache\"]\n[flatpak]\nuser = [\"org.z\", \"org.a\"]\n",
        );
        assert_eq!(
            Diff::compute(&a, &b).to_string(),
            Diff::compute(&a, &b).to_string()
        );
        // Immediate changes come first, so the user reads what already happened
        // before what will happen.
        let d = Diff::compute(&a, &b);
        assert_eq!(d.changes[0].effect, Effect::Immediate);
    }
}
