//! `/etc` reconciliation and the immediate half of `apply`.
//!
//! `/etc` is a writable overlay over the image's factory copy. Reconciliation
//! means: make the overlay say what the manifest says, and record the delta so
//! `steelctl export` can reproduce this machine elsewhere.
//!
//! # The rule that keeps this from being destructive
//!
//! We only touch files we own — the ones under our marker comment, and the
//! systemd unit enablement symlinks the manifest names. A user's hand edit to
//! something we do not manage survives reconciliation untouched.
//!
//! The alternative — resetting all of `/etc` to the manifest — would be more
//! "declarative" and would silently destroy local configuration a user needed.
//! CLAUDE.md is explicit that we deliver image-level declarative configuration,
//! not NixOS semantics, and this is one of the places where pretending otherwise
//! would do real damage.

use crate::manifest::Manifest;
use std::io;
use std::path::{Path, PathBuf};

/// Written at the top of every file steelctl owns. Its presence is what makes a
/// file ours to overwrite; its absence is what makes a file the user's.
pub const MARKER: &str =
    "# Managed by steelctl. Edits are overwritten on the next `steelctl apply`.";

pub struct Reconciler {
    root: PathBuf,
    dry_run: bool,
    pub actions: Vec<String>,
}

impl Reconciler {
    pub fn new(root: impl Into<PathBuf>, dry_run: bool) -> Reconciler {
        Reconciler {
            root: root.into(),
            dry_run,
            actions: Vec::new(),
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative.trim_start_matches('/'))
    }

    fn record(&mut self, action: impl Into<String>) {
        self.actions.push(action.into());
    }

    /// Write a file we own. Refuses to overwrite one we do not.
    fn write_managed(&mut self, relative: &str, body: &str) -> io::Result<()> {
        let target = self.path(relative);

        if target.exists() {
            let existing = std::fs::read_to_string(&target).unwrap_or_default();
            if !existing.starts_with(MARKER) {
                // Not ours. Leaving it alone is the whole point; say so loudly
                // rather than silently skipping, because the user asked for
                // something that is not going to happen.
                self.record(format!(
                    "SKIPPED {relative}: it exists and was not written by steelctl. \
                     Move it aside if you want steelctl to manage it."
                ));
                return Ok(());
            }
            if existing.trim_end() == format!("{MARKER}\n{body}").trim_end() {
                return Ok(()); // Already correct; do not touch the mtime.
            }
        }

        self.record(format!("write {relative}"));
        if self.dry_run {
            return Ok(());
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = format!("{MARKER}\n{body}");
        let temp = target.with_extension("steelctl-tmp");
        std::fs::write(&temp, contents)?;
        std::fs::rename(&temp, &target)?;
        Ok(())
    }

    /// Apply everything in the manifest that does not need a new image.
    pub fn apply_immediate(&mut self, manifest: &Manifest) -> io::Result<()> {
        self.write_preset(manifest)?;
        self.write_flatpak_list(manifest)?;
        self.write_service_policy(manifest)?;
        self.write_backup_config(manifest)?;
        Ok(())
    }

    fn write_preset(&mut self, manifest: &Manifest) -> io::Result<()> {
        // steel-check and steel-harden both read this. It is a single word so
        // the recovery environment can read it without any of our tooling.
        let preset = manifest.system.hardening.as_str();
        let target = self.path("/etc/steelos/preset");
        let current = std::fs::read_to_string(&target).unwrap_or_default();
        if current.trim() == preset {
            return Ok(());
        }
        self.record(format!("preset {} -> {preset}", current.trim()));
        if self.dry_run {
            return Ok(());
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(target, format!("{preset}\n"))
    }

    fn write_flatpak_list(&mut self, manifest: &Manifest) -> io::Result<()> {
        // The per-user Flatpak sync service reads this at login. Writing a list
        // rather than running `flatpak install` here is deliberate: apply may
        // run with no network, and it must not hang or fail because of that.
        let mut body = String::from(
            "# Flatpaks the manifest asks for, installed per-user at login by\n\
             # steel-flatpak-sync.service. Installing them here would make\n\
             # `steelctl apply` require a network connection.\n",
        );
        for app in &manifest.flatpak_user {
            body.push_str(app);
            body.push('\n');
        }
        self.write_managed("/etc/steelos/flatpak-user.list", &body)
    }

    fn write_service_policy(&mut self, manifest: &Manifest) -> io::Result<()> {
        let mut body = String::from("# unit\tstate\n");
        for unit in &manifest.services_enable {
            body.push_str(&format!("{}\tenable\n", normalise_unit(unit)));
        }
        for unit in &manifest.services_disable {
            body.push_str(&format!("{}\tdisable\n", normalise_unit(unit)));
        }
        self.write_managed("/etc/steelos/services.policy", &body)?;

        for unit in &manifest.services_enable {
            self.record(format!("systemctl enable {}", normalise_unit(unit)));
        }
        for unit in &manifest.services_disable {
            self.record(format!("systemctl disable {}", normalise_unit(unit)));
        }
        Ok(())
    }

    fn write_backup_config(&mut self, manifest: &Manifest) -> io::Result<()> {
        let mut body = String::new();
        body.push_str(&format!("enabled={}\n", manifest.backup.enabled));
        body.push_str(&format!("schedule={}\n", manifest.backup.schedule));
        body.push_str(&format!("retention={}\n", manifest.backup.retention));
        for target in &manifest.backup.targets {
            body.push_str(&format!("target={target}\n"));
        }
        self.write_managed("/etc/steelos/backup.conf", &body)
    }

    /// Files under /etc that differ from the image's factory copy.
    ///
    /// This is what `steelctl export` captures: the manifest reproduces the
    /// image, and this delta reproduces everything the user changed by hand.
    /// Without it, "reinstall from the manifest" loses local configuration and
    /// people stop trusting the export.
    pub fn etc_delta(&self) -> io::Result<Vec<String>> {
        let factory = self.path("/usr/share/factory/etc");
        let etc = self.path("/etc");
        if !factory.exists() {
            return Ok(Vec::new());
        }
        let mut delta = Vec::new();
        collect_delta(&factory, &etc, Path::new(""), &mut delta)?;
        delta.sort();
        Ok(delta)
    }
}

/// systemd wants a unit name; manifests are written with bare service names.
fn normalise_unit(unit: &str) -> String {
    if unit.contains('.') {
        unit.to_string()
    } else {
        format!("{unit}.service")
    }
}

fn collect_delta(
    factory: &Path,
    etc: &Path,
    relative: &Path,
    out: &mut Vec<String>,
) -> io::Result<()> {
    let etc_dir = etc.join(relative);
    let entries = match std::fs::read_dir(&etc_dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    // Sorted, so the export is byte-identical between runs on the same machine.
    let mut names: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    names.sort();

    for path in names {
        let name = match path.file_name() {
            Some(n) => n,
            None => continue,
        };
        let rel = relative.join(name);
        let factory_path = factory.join(&rel);

        if path.is_dir() {
            collect_delta(factory, etc, &rel, out)?;
            continue;
        }

        let differs = match std::fs::read(&factory_path) {
            Ok(original) => std::fs::read(&path)
                .map(|current| current != original)
                .unwrap_or(true),
            // Not in the factory copy at all: a file the user or a package
            // added after the image was built.
            Err(_) => true,
        };
        if differs {
            out.push(format!("/etc/{}", rel.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(name: &str) -> Fixture {
            let dir =
                std::env::temp_dir().join(format!("steelctl-rec-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Fixture(dir)
        }

        fn write(&self, rel: &str, body: &str) {
            let p = self.0.join(rel.trim_start_matches('/'));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }

        fn read(&self, rel: &str) -> Option<String> {
            std::fs::read_to_string(self.0.join(rel.trim_start_matches('/'))).ok()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn manifest(body: &str) -> Manifest {
        Manifest::parse(&format!("[system]\nsnapshot = \"2026-07-20\"\n{body}")).unwrap()
    }

    #[test]
    fn writes_the_files_it_owns() {
        let f = Fixture::new("write");
        let mut r = Reconciler::new(&f.0, false);
        r.apply_immediate(&manifest("[flatpak]\nuser = [\"org.example.App\"]\n"))
            .unwrap();
        let list = f.read("/etc/steelos/flatpak-user.list").unwrap();
        assert!(list.starts_with(MARKER));
        assert!(list.contains("org.example.App"));
        assert_eq!(f.read("/etc/steelos/preset").unwrap().trim(), "balanced");
    }

    #[test]
    fn refuses_to_overwrite_a_file_it_does_not_own() {
        // Resetting all of /etc to the manifest would be more "declarative" and
        // would silently destroy configuration a user needed.
        let f = Fixture::new("nooverwrite");
        f.write("/etc/steelos/backup.conf", "hand written, do not touch\n");
        let mut r = Reconciler::new(&f.0, false);
        r.apply_immediate(&manifest("")).unwrap();
        assert_eq!(
            f.read("/etc/steelos/backup.conf").unwrap(),
            "hand written, do not touch\n"
        );
        assert!(r.actions.iter().any(|a| a.contains("SKIPPED")));
    }

    #[test]
    fn dry_run_changes_nothing_but_reports_everything() {
        let f = Fixture::new("dryrun");
        let mut r = Reconciler::new(&f.0, true);
        r.apply_immediate(&manifest("[services]\nenable = [\"tailscaled\"]\n"))
            .unwrap();
        assert!(f.read("/etc/steelos/flatpak-user.list").is_none());
        assert!(r.actions.iter().any(|a| a.contains("tailscaled.service")));
    }

    #[test]
    fn rewriting_identical_content_is_a_no_op() {
        // Touching the mtime on every apply makes the /etc delta noisy and the
        // export non-reproducible.
        let f = Fixture::new("idempotent");
        let m = manifest("[flatpak]\nuser = [\"org.example.App\"]\n");
        let mut first = Reconciler::new(&f.0, false);
        first.apply_immediate(&m).unwrap();
        let mut second = Reconciler::new(&f.0, false);
        second.apply_immediate(&m).unwrap();
        assert!(
            !second.actions.iter().any(|a| a.starts_with("write")),
            "second apply rewrote files: {:?}",
            second.actions
        );
    }

    #[test]
    fn bare_service_names_get_a_unit_suffix() {
        assert_eq!(normalise_unit("tailscaled"), "tailscaled.service");
        assert_eq!(normalise_unit("fstrim.timer"), "fstrim.timer");
    }

    #[test]
    fn etc_delta_finds_modified_and_added_files_only() {
        let f = Fixture::new("delta");
        f.write("/usr/share/factory/etc/hosts", "127.0.0.1 localhost\n");
        f.write("/usr/share/factory/etc/hostname", "steelos\n");
        // Unchanged.
        f.write("/etc/hostname", "steelos\n");
        // Modified.
        f.write("/etc/hosts", "127.0.0.1 localhost\n10.0.0.1 nas\n");
        // Added after the image was built.
        f.write("/etc/steelos/backup.conf", "enabled=true\n");

        let r = Reconciler::new(&f.0, true);
        let delta = r.etc_delta().unwrap();
        assert!(delta.contains(&"/etc/hosts".to_string()));
        assert!(delta.contains(&"/etc/steelos/backup.conf".to_string()));
        assert!(!delta.contains(&"/etc/hostname".to_string()));
    }

    #[test]
    fn etc_delta_is_empty_when_there_is_no_factory_copy() {
        // On a plain-Arch install there is no image to compare against; an
        // empty delta is correct, not a failure.
        let f = Fixture::new("nofactory");
        f.write("/etc/hosts", "x\n");
        assert!(Reconciler::new(&f.0, true).etc_delta().unwrap().is_empty());
    }
}
