//! The manifest schema.
//!
//! `/etc/steelos/manifest.toml` defines the system. Two machines with the same
//! manifest and the same snapshot pin are the same machine — that is the claim,
//! and it is checkable, which means the parsing has to be strict enough that
//! "the same manifest" is unambiguous.
//!
//! Validation refuses unknown keys. That sounds unfriendly and is deliberate: a
//! typo'd key that is silently ignored produces a machine that is not what its
//! manifest says, and the user has no way to find out. The error message names
//! the closest known key.

use crate::toml::{self, Table, Value};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub system: System,
    pub packages: Vec<String>,
    pub flatpak_user: Vec<String>,
    pub services_enable: Vec<String>,
    pub services_disable: Vec<String>,
    pub backup: Backup,
    pub users: BTreeMap<String, User>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct System {
    pub channel: Channel,
    /// Arch Linux Archive pin, YYYY-MM-DD. Not optional: without it,
    /// "same manifest => same image" is false, because the package repository
    /// it resolves against moves every day.
    pub snapshot: String,
    pub hardening: Hardening,
    pub kernel: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Stable,
    Testing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hardening {
    Balanced,
    Strict,
    Compatible,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Backup {
    pub enabled: bool,
    pub targets: Vec<String>,
    pub schedule: String,
    pub retention: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub storage: String,
    pub sandbox: String,
    pub tunnel_policy: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Error {
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

fn err<T>(message: impl Into<String>) -> Result<T, Error> {
    Err(Error {
        message: message.into(),
    })
}

/// Keys we understand, per table. Anything else is rejected.
const KNOWN: &[(&str, &[&str])] = &[
    ("system", &["channel", "snapshot", "hardening", "kernel"]),
    ("packages", &["system"]),
    ("flatpak", &["user", "system"]),
    ("services", &["enable", "disable"]),
    ("backup", &["enabled", "targets", "schedule", "retention"]),
];

const KNOWN_USER_KEYS: &[&str] = &["storage", "sandbox", "tunnel_policy"];

impl Manifest {
    pub fn parse(source: &str) -> Result<Manifest, Error> {
        let root = toml::parse(source).map_err(|e| Error {
            message: format!("manifest is not valid TOML: {e}"),
        })?;

        Self::check_unknown_tables(&root)?;
        for (table_name, allowed) in KNOWN {
            if let Some(Value::Table(t)) = root.get(*table_name) {
                Self::check_unknown_keys(table_name, t, allowed)?;
            }
        }

        let system = Self::parse_system(&root)?;

        let packages = string_array(&root, "packages.system").unwrap_or_default();
        let flatpak_user = string_array(&root, "flatpak.user").unwrap_or_default();
        let services_enable = string_array(&root, "services.enable").unwrap_or_default();
        let services_disable = string_array(&root, "services.disable").unwrap_or_default();

        // A service in both lists is a manifest that does not describe a
        // reachable state. Better to say so than to pick one.
        for service in &services_enable {
            if services_disable.contains(service) {
                return err(format!(
                    "service '{service}' is in both services.enable and services.disable"
                ));
            }
        }

        let backup = Backup {
            enabled: toml::get(&root, "backup.enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            targets: string_array(&root, "backup.targets").unwrap_or_default(),
            schedule: string_or(&root, "backup.schedule", "daily"),
            retention: string_or(&root, "backup.retention", "7d 4w 6m"),
        };

        // The governing rule from CLAUDE.md, enforced at parse time rather than
        // at run time: no backup target may live on the device being protected.
        // This is what resolves the recoverable-vs-destroyable tension, so a
        // manifest that violates it is rejected outright.
        for target in &backup.targets {
            if is_on_protected_device(target) {
                return err(format!(
                    "backup target '{target}' is on the device being protected.\n\
                     No backup target may live on the internal disk — that is what makes \
                     local key material destroyable under duress while recovery remains \
                     possible.\n\
                     Use a remote target (restic:sftp:..., rest:..., borg over ssh) or \
                     removable media that is not attached during normal operation."
                ));
            }
        }

        let users = Self::parse_users(&root)?;

        Ok(Manifest {
            system,
            packages,
            flatpak_user,
            services_enable,
            services_disable,
            backup,
            users,
        })
    }

    fn parse_system(root: &Table) -> Result<System, Error> {
        let Some(Value::Table(system)) = root.get("system") else {
            return err("manifest has no [system] table");
        };

        let channel = match system.get("channel").and_then(|v| v.as_str()) {
            Some("stable") => Channel::Stable,
            Some("testing") => Channel::Testing,
            Some(other) => {
                return err(format!(
                    "unknown channel '{other}' (expected stable or testing)"
                ))
            }
            None => Channel::Stable,
        };

        let snapshot = match system.get("snapshot").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                return err("manifest has no system.snapshot.\n\
                     The Arch repository state must be pinned, or 'the same manifest' \
                     means something different every day and reproducibility is a lie.\n\
                     Add a date, e.g. snapshot = \"2026-07-20\".")
            }
        };
        validate_snapshot(&snapshot)?;

        let hardening = match system.get("hardening").and_then(|v| v.as_str()) {
            Some("balanced") | None => Hardening::Balanced,
            Some("strict") => Hardening::Strict,
            Some("compatible") => Hardening::Compatible,
            Some(other) => {
                return err(format!(
                    "unknown hardening preset '{other}' (expected balanced, strict, or compatible)"
                ))
            }
        };

        let kernel = system
            .get("kernel")
            .and_then(|v| v.as_str())
            .unwrap_or("linux-hardened")
            .to_string();

        Ok(System {
            channel,
            snapshot,
            hardening,
            kernel,
        })
    }

    fn parse_users(root: &Table) -> Result<BTreeMap<String, User>, Error> {
        let mut users = BTreeMap::new();
        let Some(Value::Table(table)) = root.get("users") else {
            return Ok(users);
        };
        for (name, value) in table {
            let Value::Table(fields) = value else {
                return err(format!("[users.{name}] must be a table"));
            };
            for key in fields.keys() {
                if !KNOWN_USER_KEYS.contains(&key.as_str()) {
                    return err(format!(
                        "unknown key '{key}' in [users.{name}]{}",
                        suggestion(key, KNOWN_USER_KEYS)
                    ));
                }
            }
            let storage = fields
                .get("storage")
                .and_then(|v| v.as_str())
                .unwrap_or("luks")
                .to_string();
            if storage != "luks" && storage != "directory" {
                return err(format!(
                    "[users.{name}] storage = \"{storage}\" (expected luks or directory).\n\
                     'directory' means the home is NOT independently encrypted — user B, \
                     as root, can read it at rest."
                ));
            }
            let sandbox = fields
                .get("sandbox")
                .and_then(|v| v.as_str())
                .unwrap_or("balanced")
                .to_string();
            users.insert(
                name.clone(),
                User {
                    storage,
                    sandbox,
                    tunnel_policy: fields
                        .get("tunnel_policy")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                },
            );
        }
        Ok(users)
    }

    fn check_unknown_tables(root: &Table) -> Result<(), Error> {
        let known: Vec<&str> = KNOWN
            .iter()
            .map(|(name, _)| *name)
            .chain(["users"])
            .collect();
        for key in root.keys() {
            if !known.contains(&key.as_str()) {
                return err(format!("unknown table [{key}]{}", suggestion(key, &known)));
            }
        }
        Ok(())
    }

    fn check_unknown_keys(table_name: &str, table: &Table, allowed: &[&str]) -> Result<(), Error> {
        for key in table.keys() {
            if !allowed.contains(&key.as_str()) {
                return err(format!(
                    "unknown key '{key}' in [{table_name}]{}",
                    suggestion(key, allowed)
                ));
            }
        }
        Ok(())
    }

    /// A stable hash of the manifest's *meaning*, not its bytes.
    ///
    /// Reformatting, reordering a package list, or editing a comment must not
    /// produce a new generation — otherwise `steelctl apply` rebuilds on every
    /// whitespace change and users stop trusting the diff.
    pub fn semantic_hash(&self) -> String {
        let mut canonical = String::new();
        canonical.push_str(&format!("channel={}\n", self.system.channel.as_str()));
        canonical.push_str(&format!("snapshot={}\n", self.system.snapshot));
        canonical.push_str(&format!("hardening={}\n", self.system.hardening.as_str()));
        canonical.push_str(&format!("kernel={}\n", self.system.kernel));

        let mut sorted = |label: &str, items: &[String]| {
            let mut v: Vec<&String> = items.iter().collect();
            v.sort();
            v.dedup();
            for item in v {
                canonical.push_str(&format!("{label}={item}\n"));
            }
        };
        sorted("package", &self.packages);
        sorted("flatpak", &self.flatpak_user);
        sorted("enable", &self.services_enable);
        sorted("disable", &self.services_disable);

        // Backup targets and per-user settings do not change the image, so they
        // are excluded: including them would make `steelctl apply` rebuild the
        // whole system because someone changed a backup schedule.
        format!("sha256:{}", crate::hash::sha256_hex(canonical.as_bytes()))
    }
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::Testing => "testing",
        }
    }
}

impl Hardening {
    pub fn as_str(self) -> &'static str {
        match self {
            Hardening::Balanced => "balanced",
            Hardening::Strict => "strict",
            Hardening::Compatible => "compatible",
        }
    }
}

fn validate_snapshot(s: &str) -> Result<(), Error> {
    let parts: Vec<&str> = s.split('-').collect();
    let valid = parts.len() == 3
        && parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()));
    if !valid {
        return err(format!("system.snapshot must be YYYY-MM-DD, got '{s}'"));
    }
    let month: u32 = parts[1].parse().unwrap();
    let day: u32 = parts[2].parse().unwrap();
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return err(format!("system.snapshot is not a real date: '{s}'"));
    }
    Ok(())
}

/// Would this backup target land on the internal disk?
fn is_on_protected_device(target: &str) -> bool {
    let remote_markers = [
        "sftp:", "rest:", "s3:", "b2:", "gs:", "azure:", "ssh://", "rclone:",
    ];
    if remote_markers.iter().any(|m| target.contains(m)) {
        return false;
    }
    let path = target
        .trim_start_matches("restic:")
        .trim_start_matches("borg:");
    if !path.starts_with('/') {
        // A bare hostname or a repository name; not a local path.
        return false;
    }
    // Removable media is allowed — the rule is about the disk a duress wipe
    // would destroy, not about all local storage.
    let removable = ["/run/media/", "/media/", "/mnt/"];
    !removable.iter().any(|prefix| path.starts_with(prefix))
}

fn string_array(root: &Table, path: &str) -> Option<Vec<String>> {
    toml::get(root, path).and_then(|v| v.as_str_array())
}

fn string_or(root: &Table, path: &str, default: &str) -> String {
    toml::get(root, path)
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

/// "did you mean" for a mistyped key, by edit distance. A rejected manifest
/// with no hint is a worse experience than a silently ignored key, which is
/// what makes rejection defensible.
fn suggestion(got: &str, known: &[&str]) -> String {
    let best = known
        .iter()
        .map(|k| (*k, edit_distance(got, k)))
        .filter(|(_, d)| *d <= 3)
        .min_by_key(|(_, d)| *d);
    match best {
        Some((k, _)) => format!(" (did you mean '{k}'?)"),
        None => format!(" (known: {})", known.join(", ")),
    }
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        current[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            current[j] = (prev[j] + 1)
                .min(current[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut current);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[system]
snapshot = "2026-07-20"
"#;

    #[test]
    fn a_minimal_manifest_gets_sensible_defaults() {
        let m = Manifest::parse(MINIMAL).unwrap();
        assert_eq!(m.system.channel, Channel::Stable);
        assert_eq!(m.system.hardening, Hardening::Balanced);
        assert_eq!(m.system.kernel, "linux-hardened");
        assert!(m.backup.enabled);
    }

    #[test]
    fn the_snapshot_pin_is_mandatory() {
        // Without it, "same manifest => same image" is false.
        let e = Manifest::parse("[system]\nchannel = \"stable\"\n").unwrap_err();
        assert!(e.message.contains("snapshot"));
        assert!(e.message.contains("reproducibility"));
    }

    #[test]
    fn the_snapshot_pin_must_be_a_real_date() {
        assert!(Manifest::parse("[system]\nsnapshot = \"current\"\n").is_err());
        assert!(Manifest::parse("[system]\nsnapshot = \"2026-7-20\"\n").is_err());
        assert!(Manifest::parse("[system]\nsnapshot = \"2026-13-01\"\n").is_err());
        assert!(Manifest::parse("[system]\nsnapshot = \"2026-07-20\"\n").is_ok());
    }

    #[test]
    fn unknown_keys_are_rejected_with_a_suggestion() {
        // A silently ignored typo produces a machine that is not what its
        // manifest says, and the user cannot find out.
        let e = Manifest::parse("[system]\nsnapshot = \"2026-07-20\"\nkernal = \"linux\"\n")
            .unwrap_err();
        assert!(e.message.contains("kernal"));
        assert!(e.message.contains("did you mean 'kernel'"), "{}", e.message);
    }

    #[test]
    fn unknown_tables_are_rejected() {
        let e = Manifest::parse("[system]\nsnapshot = \"2026-07-20\"\n\n[packags]\nsystem = []\n")
            .unwrap_err();
        assert!(
            e.message.contains("did you mean 'packages'"),
            "{}",
            e.message
        );
    }

    #[test]
    fn a_local_backup_target_is_rejected_at_parse_time() {
        // CLAUDE.md's governing rule: no backup target may live on the device
        // being protected. Enforced in code, not just documented.
        let src = r#"
[system]
snapshot = "2026-07-20"
[backup]
targets = ["/var/lib/steelos/backup"]
"#;
        let e = Manifest::parse(src).unwrap_err();
        assert!(
            e.message.contains("device being protected"),
            "{}",
            e.message
        );
    }

    #[test]
    fn remote_and_removable_backup_targets_are_accepted() {
        let src = r#"
[system]
snapshot = "2026-07-20"
[backup]
targets = ["restic:sftp:host:/repo", "/run/media/chase/usb/repo", "rest:https://b/repo"]
"#;
        let m = Manifest::parse(src).unwrap();
        assert_eq!(m.backup.targets.len(), 3);
    }

    #[test]
    fn a_service_in_both_lists_is_an_error() {
        let src = r#"
[system]
snapshot = "2026-07-20"
[services]
enable = ["foo"]
disable = ["foo"]
"#;
        assert!(Manifest::parse(src).is_err());
    }

    #[test]
    fn semantic_hash_ignores_formatting_and_ordering() {
        // Rebuilding the whole system because someone reordered a package list
        // would make `steelctl diff` useless and people would stop reading it.
        let a = Manifest::parse(
            "[system]\nsnapshot = \"2026-07-20\"\n[packages]\nsystem = [\"git\", \"vim\"]\n",
        )
        .unwrap();
        let b = Manifest::parse(
            "# a comment\n[packages]\nsystem = [\n  \"vim\",\n  \"git\",\n]\n\n[system]\n\
             snapshot   =   \"2026-07-20\"\n",
        )
        .unwrap();
        assert_eq!(a.semantic_hash(), b.semantic_hash());
    }

    #[test]
    fn semantic_hash_changes_when_meaning_changes() {
        let a = Manifest::parse(MINIMAL).unwrap();
        let b = Manifest::parse("[system]\nsnapshot = \"2026-07-21\"\n").unwrap();
        assert_ne!(a.semantic_hash(), b.semantic_hash());

        let c = Manifest::parse(
            "[system]\nsnapshot = \"2026-07-20\"\n[packages]\nsystem = [\"git\"]\n",
        )
        .unwrap();
        assert_ne!(a.semantic_hash(), c.semantic_hash());
    }

    #[test]
    fn backup_settings_do_not_change_the_image_hash() {
        // Changing a backup schedule must not rebuild the operating system.
        let a = Manifest::parse(MINIMAL).unwrap();
        let b = Manifest::parse(
            "[system]\nsnapshot = \"2026-07-20\"\n[backup]\nschedule = \"hourly\"\n",
        )
        .unwrap();
        assert_eq!(a.semantic_hash(), b.semantic_hash());
    }

    #[test]
    fn directory_storage_for_a_user_is_allowed_but_named() {
        let src = r#"
[system]
snapshot = "2026-07-20"
[users.chase]
storage = "directory"
"#;
        let m = Manifest::parse(src).unwrap();
        assert_eq!(m.users["chase"].storage, "directory");

        let bad = src.replace("directory", "encrypted");
        assert!(Manifest::parse(&bad).is_err());
    }

    #[test]
    fn the_shipped_default_manifest_validates() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("image/manifest.default.toml");
        let body = std::fs::read_to_string(path).unwrap();
        Manifest::parse(&body).expect("the manifest we ship must validate");
    }
}
