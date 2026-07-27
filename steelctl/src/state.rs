//! Deployment state on disk, under `/var/lib/steelos`.
//!
//! Everything here is plain text in a flat layout, deliberately. When
//! `steelctl` is the thing that is broken, the recovery environment needs to
//! read this state with `cat` and fix it with a text editor. A binary database
//! would be smaller and faster and would fail exactly when it matters most.
//!
//! Writes go through [`StateDir::write`], which writes to a temporary file and
//! renames. A half-written `active-slot` is a machine that does not know which
//! deployment it is running.

use std::io;
use std::path::{Path, PathBuf};

pub struct StateDir {
    root: PathBuf,
}

impl StateDir {
    pub fn new(root: impl Into<PathBuf>) -> StateDir {
        StateDir { root: root.into() }
    }

    /// The default location, overridable for tests and for operating on a
    /// mounted-but-not-running system from the recovery environment.
    pub fn default_path() -> PathBuf {
        std::env::var_os("STEELCTL_STATE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/steelos"))
    }

    pub fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    pub fn read(&self, relative: &str) -> Option<String> {
        std::fs::read_to_string(self.path(relative))
            .ok()
            .map(|s| s.trim().to_string())
    }

    pub fn exists(&self, relative: &str) -> bool {
        self.path(relative).exists()
    }

    /// Atomic write: temp file, fsync, rename.
    ///
    /// The fsync is not superstition. Without it, a power loss between the
    /// rename and the writeback leaves a zero-length `active-slot` on some
    /// filesystems — and a machine that does not know which slot it booted
    /// cannot be repaired without the recovery environment.
    pub fn write(&self, relative: &str, contents: &str) -> io::Result<()> {
        let target = self.path(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp = target.with_extension("tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&temp)?;
            file.write_all(contents.as_bytes())?;
            if !contents.ends_with('\n') {
                file.write_all(b"\n")?;
            }
            file.sync_all()?;
        }
        std::fs::rename(&temp, &target)?;

        // Also sync the directory, or the rename itself can be lost.
        if let Some(parent) = target.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    pub fn remove(&self, relative: &str) -> io::Result<()> {
        match std::fs::remove_file(self.path(relative)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn list(&self, relative: &str) -> Vec<String> {
        let mut names: Vec<String> = match std::fs::read_dir(self.path(relative)) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names
    }

    /// A lock preventing two `steelctl` invocations from staging at once.
    ///
    /// Two concurrent updates would race on the inactive slot and produce a
    /// generation record describing an image that is half one build and half
    /// another — which would then pass its verity check against neither.
    pub fn lock(&self) -> io::Result<Lock> {
        std::fs::create_dir_all(&self.root)?;
        let path = self.root.join("steelctl.lock");
        // O_EXCL creation is the lock. A stale lock after a crash is reported
        // with the path so a human can remove it deliberately, rather than
        // being cleared automatically — automatic clearing would defeat it.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                let _ = writeln!(file, "pid={}", std::process::id());
                Ok(Lock { path })
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "another steelctl is running (lock: {}).\n\
                     If you are sure it is not, remove that file.",
                    path.display()
                ),
            )),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug)]
pub struct Lock {
    path: PathBuf,
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Is this path on the same filesystem as the device being protected?
///
/// Used to enforce the backup-target rule at run time as well as at parse time.
pub fn is_internal_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    if !s.starts_with('/') {
        return false;
    }
    !(s.starts_with("/run/media/") || s.starts_with("/media/") || s.starts_with("/mnt/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state(name: &str) -> StateDir {
        let dir =
            std::env::temp_dir().join(format!("steelctl-state-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        StateDir::new(dir)
    }

    #[test]
    fn write_then_read_round_trips_and_trims() {
        let s = temp_state("rw");
        s.write("active-slot", "a").unwrap();
        assert_eq!(s.read("active-slot").as_deref(), Some("a"));
        let _ = std::fs::remove_dir_all(&s.root);
    }

    #[test]
    fn write_creates_intermediate_directories() {
        let s = temp_state("mkdir");
        s.write("slots/a/generation", "slot=a\n").unwrap();
        assert!(s.exists("slots/a/generation"));
        let _ = std::fs::remove_dir_all(&s.root);
    }

    #[test]
    fn write_leaves_no_temporary_file_behind() {
        // A stray .tmp in the state directory would show up in `list` and
        // confuse slot enumeration.
        let s = temp_state("notmp");
        s.write("thing", "x").unwrap();
        assert!(!s.exists("thing.tmp"));
        let _ = std::fs::remove_dir_all(&s.root);
    }

    #[test]
    fn reading_something_absent_is_none_not_an_error() {
        let s = temp_state("absent");
        assert_eq!(s.read("nope"), None);
        assert!(!s.exists("nope"));
        let _ = std::fs::remove_dir_all(&s.root);
    }

    #[test]
    fn removing_something_absent_succeeds() {
        let s = temp_state("rm");
        assert!(s.remove("never-existed").is_ok());
        let _ = std::fs::remove_dir_all(&s.root);
    }

    #[test]
    fn the_lock_is_exclusive_and_released_on_drop() {
        // Two concurrent stages would race on the inactive slot and produce a
        // generation record describing an image that is half one build and half
        // another.
        let s = temp_state("lock");
        let held = s.lock().unwrap();
        let second = s.lock();
        assert!(second.is_err());
        assert!(second.unwrap_err().to_string().contains("another steelctl"));
        drop(held);
        assert!(s.lock().is_ok());
        let _ = std::fs::remove_dir_all(&s.root);
    }

    #[test]
    fn internal_path_classification_matches_the_backup_rule() {
        assert!(is_internal_path(Path::new("/var/lib/steelos/backup")));
        assert!(is_internal_path(Path::new("/home/chase/backups")));
        assert!(!is_internal_path(Path::new("/run/media/chase/usb/repo")));
        assert!(!is_internal_path(Path::new("/mnt/external/repo")));
        assert!(!is_internal_path(Path::new("relative/path")));
    }
}
