//! Thin wrappers over the system facts steel-check reads.
//!
//! Everything that touches the filesystem goes through [`Sysroot`] so the whole
//! check suite can be pointed at a fixture tree in tests and in CI. Checks that
//! need to execute a helper binary (`sbctl`, `nft`, `aa-status`) must degrade to
//! `Skip` when the binary is absent rather than failing: a missing tool is a
//! different fact from a failed measure, and conflating them trains people to
//! ignore red output.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Filesystem root for every read. `/` in production; a fixture directory under
/// test, selected by `--sysroot` or `STEEL_CHECK_SYSROOT`.
#[derive(Debug, Clone)]
pub struct Sysroot {
    root: PathBuf,
}

impl Sysroot {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Sysroot { root: root.into() }
    }

    pub fn is_real(&self) -> bool {
        self.root == Path::new("/")
    }

    pub fn path(&self, p: &str) -> PathBuf {
        let trimmed = p.strip_prefix('/').unwrap_or(p);
        self.root.join(trimmed)
    }

    pub fn read(&self, p: &str) -> Option<String> {
        fs::read_to_string(self.path(p)).ok()
    }

    /// Read a file that is expected to hold a single value, trimmed.
    pub fn read_trimmed(&self, p: &str) -> Option<String> {
        self.read(p).map(|s| s.trim().to_string())
    }

    pub fn exists(&self, p: &str) -> bool {
        self.path(p).exists()
    }

    pub fn list_dir(&self, p: &str) -> Vec<String> {
        let mut names: Vec<String> = match fs::read_dir(self.path(p)) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names
    }

    /// The kernel command line the running system actually booted with.
    pub fn kernel_cmdline(&self) -> KernelCmdline {
        KernelCmdline::parse(self.read("/proc/cmdline").unwrap_or_default())
    }

    /// Effective sysctl value, read from `/proc/sys` rather than from the
    /// drop-in files. What is configured and what is in force are different
    /// questions, and only the second one is a security property.
    pub fn sysctl(&self, key: &str) -> Option<String> {
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        self.read(&path).map(|s| normalize_ws(&s))
    }

    pub fn mounts(&self) -> Vec<Mount> {
        self.read("/proc/mounts")
            .unwrap_or_default()
            .lines()
            .filter_map(Mount::parse)
            .collect()
    }

    pub fn mount_for(&self, target: &str) -> Option<Mount> {
        self.mounts().into_iter().find(|m| m.target == target)
    }

    pub fn loaded_modules(&self) -> Vec<String> {
        let mut mods: Vec<String> = self
            .read("/proc/modules")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_whitespace().next().map(str::to_string))
            .collect();
        mods.sort();
        mods
    }

    /// Concatenated contents of every file under a config drop-in directory,
    /// e.g. `/etc/modprobe.d`. Used for "is this configured" questions, which
    /// are always weaker evidence than "is this in force".
    pub fn concat_dir(&self, dir: &str, suffix: &str) -> String {
        let mut out = String::new();
        for name in self.list_dir(dir) {
            if !name.ends_with(suffix) {
                continue;
            }
            if let Some(body) = self.read(&format!("{dir}/{name}")) {
                out.push_str(&body);
                out.push('\n');
            }
        }
        out
    }

    /// Users with a real login shell and a UID in the human range. Used by the
    /// homed and per-user backup checks.
    pub fn human_users(&self) -> Vec<String> {
        let mut users: Vec<String> = self
            .read("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() < 7 {
                    return None;
                }
                let uid: u32 = f[2].parse().ok()?;
                let shell = f[6];
                let nologin = shell.ends_with("nologin") || shell.ends_with("/false");
                if (1000..60000).contains(&uid) && !nologin {
                    Some(f[0].to_string())
                } else {
                    None
                }
            })
            .collect();
        users.sort();
        users.dedup();
        users
    }
}

impl Default for Sysroot {
    fn default() -> Self {
        Sysroot::new("/")
    }
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Debug, Clone, Default)]
pub struct KernelCmdline {
    /// Parameter name -> value. Bare flags map to an empty string. Later
    /// occurrences win, matching the kernel's own last-wins behaviour.
    params: BTreeMap<String, String>,
    raw: String,
}

impl KernelCmdline {
    pub fn parse(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        let mut params = BTreeMap::new();
        for token in raw.split_whitespace() {
            match token.split_once('=') {
                Some((k, v)) => {
                    params.insert(k.to_string(), v.to_string());
                }
                None => {
                    params.insert(token.to_string(), String::new());
                }
            }
        }
        KernelCmdline { params, raw }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(|s| s.as_str())
    }

    pub fn has(&self, key: &str) -> bool {
        self.params.contains_key(key)
    }

    pub fn has_value(&self, key: &str, value: &str) -> bool {
        self.get(key) == Some(value)
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Mount {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub options: Vec<String>,
}

impl Mount {
    fn parse(line: &str) -> Option<Mount> {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            return None;
        }
        Some(Mount {
            source: unescape_mount(f[0]),
            target: unescape_mount(f[1]),
            fstype: f[2].to_string(),
            options: f[3].split(',').map(str::to_string).collect(),
        })
    }

    pub fn has_option(&self, opt: &str) -> bool {
        self.options.iter().any(|o| o == opt)
    }

    pub fn is_read_only(&self) -> bool {
        self.has_option("ro")
    }
}

/// `/proc/mounts` octal-escapes space, tab, newline and backslash in paths.
fn unescape_mount(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let digits = &s[i + 1..i + 4];
            if let Ok(code) = u8::from_str_radix(digits, 8) {
                out.push(code as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Result of running a helper binary.
pub struct CmdOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn ok(&self) -> bool {
        self.status == 0
    }

    pub fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// Run a helper binary. Returns `None` if it is not installed, which callers
/// must translate into `Skip`, never into `Fail`.
pub fn run<I, S>(program: &str, args: I) -> Option<CmdOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(program).args(args).output().ok()?;
    Some(CmdOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

pub fn have_binary(program: &str) -> bool {
    let path = match std::env::var_os("PATH") {
        Some(p) => p,
        None => return false,
    };
    std::env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmdline_parses_flags_and_values() {
        let c = KernelCmdline::parse("ro quiet lockdown=confidentiality init_on_free=1");
        assert!(c.has("quiet"));
        assert!(c.has_value("lockdown", "confidentiality"));
        assert_eq!(c.get("init_on_free"), Some("1"));
        assert!(!c.has("nosuchflag"));
        assert_eq!(c.get("ro"), Some(""));
    }

    #[test]
    fn cmdline_last_occurrence_wins() {
        // The kernel takes the last value; so must we, or we report on a
        // setting that is not the one in force.
        let c = KernelCmdline::parse("mitigations=off mitigations=auto");
        assert!(c.has_value("mitigations", "auto"));
    }

    #[test]
    fn mount_parses_and_unescapes() {
        let m = Mount::parse("tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0").unwrap();
        assert_eq!(m.target, "/tmp");
        assert_eq!(m.fstype, "tmpfs");
        assert!(m.has_option("noexec"));
        assert!(!m.is_read_only());

        let m = Mount::parse("/dev/sda1 /mnt/my\\040disk ext4 ro 0 0").unwrap();
        assert_eq!(m.target, "/mnt/my disk");
        assert!(m.is_read_only());
    }

    #[test]
    fn sysroot_prefixes_reads() {
        let dir = std::env::temp_dir().join(format!("steel-check-sysroot-{}", std::process::id()));
        let _ = fs::create_dir_all(dir.join("proc/sys/kernel"));
        fs::write(dir.join("proc/sys/kernel/kptr_restrict"), "2\n").unwrap();
        let sys = Sysroot::new(&dir);
        assert!(!sys.is_real());
        assert_eq!(sys.sysctl("kernel.kptr_restrict").as_deref(), Some("2"));
        assert_eq!(sys.sysctl("kernel.nonexistent"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn human_users_excludes_system_and_nologin_accounts() {
        let dir = std::env::temp_dir().join(format!("steel-check-passwd-{}", std::process::id()));
        let _ = fs::create_dir_all(dir.join("etc"));
        fs::write(
            dir.join("etc/passwd"),
            "root:x:0:0::/root:/bin/bash\n\
             bin:x:1:1::/:/usr/bin/nologin\n\
             chase:x:1000:1000::/home/chase:/bin/bash\n\
             svc:x:999:999::/:/usr/bin/nologin\n\
             nobody:x:65534:65534::/:/usr/bin/nologin\n",
        )
        .unwrap();
        let sys = Sysroot::new(&dir);
        assert_eq!(sys.human_users(), vec!["chase".to_string()]);
        let _ = fs::remove_dir_all(&dir);
    }
}
