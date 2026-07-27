//! Application confinement: AppArmor, Flatpak permission defaults, bubblejail,
//! the absence of SUID sandboxes, and USB device authorisation.

use crate::context::Context;
use crate::report::{Category, Check, Outcome, Severity};
use crate::sys;

pub const CHECKS: &[Check] = &[
    Check {
        id: "sandbox.apparmor-enforcing",
        title: "AppArmor is enabled with profiles in enforce mode",
        category: Category::Sandbox,
        severity: Severity::High,
        rationale: "AppArmor is the layer underneath Flatpak and bubblejail: it confines \
                    the processes that escape or never entered a sandbox. Profiles in \
                    complain mode log and permit, which is useful while writing a profile \
                    and worthless as a defence.",
        escape_hatch: "aa-complain <profile> for one program; steel-harden apparmor off \
                       for all of them.",
        run: check_apparmor,
    },
    Check {
        id: "sandbox.flatpak-overrides",
        title: "Flatpak global overrides strip dangerous defaults",
        category: Category::Sandbox,
        severity: Severity::High,
        rationale: "Flatpak's out-of-the-box permissions are generous — many apps ship \
                    with filesystem=home and full device access, which makes the sandbox \
                    decorative. The global override removes them so per-app grants start \
                    from nothing.",
        escape_hatch: "flatpak override --user --filesystem=... per app, or Flatseal, \
                       which is installed by default for exactly this reason.",
        run: check_flatpak_overrides,
    },
    Check {
        id: "sandbox.no-suid-sandbox",
        title: "No SUID-root sandbox is installed",
        category: Category::Sandbox,
        severity: Severity::High,
        rationale: "firejail is SUID root: a bug in the sandbox is a local root \
                    escalation, which inverts the thing it is meant to provide. We use \
                    unprivileged bubblewrap instead, which is why user namespaces are \
                    deliberately enabled.",
        escape_hatch: "None. If you need firejail, this is the wrong distribution.",
        run: check_no_suid_sandbox,
    },
    Check {
        id: "sandbox.bubblejail",
        title: "bubblejail is available for native binaries",
        category: Category::Sandbox,
        severity: Severity::Medium,
        rationale: "Flatpak covers GUI apps from Flathub. Native binaries installed into \
                    the image, and anything run outside a container, need their own \
                    unprivileged confinement.",
        escape_hatch: "Run the binary directly; nothing forces bubblejail.",
        run: check_bubblejail,
    },
    Check {
        id: "sandbox.usbguard",
        title: "USBGuard authorises new USB devices",
        category: Category::Sandbox,
        severity: Severity::Medium,
        rationale: "A USB port is an unauthenticated peripheral bus. USBGuard turns \
                    plugging something in into a decision rather than an event. Strict \
                    preset only, because the prompts are intrusive.",
        escape_hatch: "steel-harden usbguard off, or usbguard allow-device for one device.",
        run: check_usbguard,
    },
];

fn check_apparmor(ctx: &Context) -> Outcome {
    let enabled = ctx
        .sys
        .read_trimmed("/sys/module/apparmor/parameters/enabled")
        .map(|v| v == "Y")
        .unwrap_or(false);

    if !enabled {
        return Outcome::fail("AppArmor is not enabled")
            .evidence("/sys/module/apparmor/parameters/enabled is not Y")
            .remedy(
                "Add lsm=landlock,lockdown,yama,integrity,apparmor and \
                 apparmor=1 security=apparmor to the kernel command line, then reboot.",
            );
    }

    // /sys/kernel/security/apparmor/profiles lists each profile and its mode.
    let profiles = ctx
        .sys
        .read("/sys/kernel/security/apparmor/profiles")
        .unwrap_or_default();

    if profiles.trim().is_empty() {
        return Outcome::fail("AppArmor is enabled but no profiles are loaded")
            .evidence("An enabled LSM with no profiles confines nothing.")
            .remedy("pacman -S steel-apparmor && systemctl enable --now apparmor");
    }

    let mut enforce = 0usize;
    let mut complain = 0usize;
    let mut other = Vec::new();
    for line in profiles.lines() {
        let mode = line
            .rsplit_once('(')
            .map(|(_, m)| m.trim_end_matches(')'))
            .unwrap_or("");
        match mode {
            "enforce" => enforce += 1,
            "complain" => {
                complain += 1;
                if let Some((name, _)) = line.rsplit_once('(') {
                    other.push(name.trim().to_string());
                }
            }
            _ => {}
        }
    }
    let total = enforce + complain;

    if complain == 0 {
        return Outcome::pass(format!("{enforce} profiles, all enforcing"));
    }

    // Complain-mode profiles are a normal part of writing a new profile, so
    // this warns rather than fails — but it names them, because "some profiles
    // are in complain mode" that nobody can enumerate is how they stay there.
    let mut outcome = Outcome::warn(format!(
        "{enforce}/{total} profiles enforcing, {complain} in complain mode"
    ));
    for name in other.iter().take(10) {
        outcome = outcome.evidence(format!("complain: {name}"));
    }
    if other.len() > 10 {
        outcome = outcome.evidence(format!("... and {} more", other.len() - 10));
    }
    outcome.remedy(
        "aa-enforce <profile> once the profile is complete, or finish it with \
                    `steel-profile refine <program>`.",
    )
}

/// Flatpak permissions that must be removed globally, with the reason each one
/// matters. The override file shipped by `steel-sandbox` is checked against this
/// list by a test.
pub const FLATPAK_GLOBAL_DENIES: &[(&str, &str, &str)] = &[
    ("filesystems", "!home", "an app with home access can read your SSH keys, browser profile, and documents regardless of what its sandbox otherwise says"),
    ("filesystems", "!host", "host access is no sandbox at all"),
    ("devices", "!all", "device access includes /dev/video, /dev/snd and raw USB"),
    ("sockets", "!x11", "X11 has no input isolation: any client can keylog every other client"),
    ("sockets", "!fallback-x11", "fallback-x11 silently reintroduces X11 whenever Wayland negotiation fails"),
    ("shared", "!network", "granted back per app; most apps do not need it"),
];

fn check_flatpak_overrides(ctx: &Context) -> Outcome {
    if !ctx.sys.exists("/usr/bin/flatpak") && !ctx.sys.exists("/var/lib/flatpak") {
        return Outcome::skip("flatpak is not installed");
    }

    let global = ctx
        .sys
        .read("/var/lib/flatpak/overrides/global")
        .or_else(|| ctx.sys.read("/etc/flatpak/overrides/global"))
        .unwrap_or_default();

    if global.trim().is_empty() {
        return Outcome::fail("no global Flatpak override is installed")
            .evidence(
                "Apps run with whatever permissions their manifest requested, which \
                       for many popular apps includes the whole home directory.",
            )
            .remedy(
                "pacman -S steel-sandbox, or apply the overrides by hand with \
                     `flatpak override --filesystem='!home' ...`.",
            );
    }

    let mut missing = Vec::new();
    for (section, value, _why) in FLATPAK_GLOBAL_DENIES {
        // The override file is INI-style: `filesystems=!home;!host;`
        let present = global.lines().any(|line| {
            let line = line.trim();
            line.starts_with(&format!("{section}=")) && line.contains(value)
        });
        if !present {
            missing.push(format!("{section}={value}"));
        }
    }

    if missing.is_empty() {
        Outcome::pass(format!(
            "{} dangerous defaults revoked globally",
            FLATPAK_GLOBAL_DENIES.len()
        ))
    } else {
        Outcome::fail(format!("{} global Flatpak denials missing", missing.len()))
            .evidence_all(missing)
            .remedy("Reinstall steel-sandbox to restore /var/lib/flatpak/overrides/global.")
    }
}

fn check_no_suid_sandbox(ctx: &Context) -> Outcome {
    let mut found = Vec::new();
    for path in [
        "/usr/bin/firejail",
        "/usr/bin/firejail-x11",
        "/usr/local/bin/firejail",
    ] {
        if ctx.sys.exists(path) {
            found.push(path.to_string());
        }
    }
    if found.is_empty() {
        Outcome::pass("firejail is not installed")
    } else {
        Outcome::fail("a SUID-root sandbox is installed")
            .evidence_all(found)
            .evidence(
                "firejail runs SUID root, so a sandbox escape is a root escalation. \
                       This contradicts the threat model rather than serving it.",
            )
            .remedy("pacman -Rns firejail and use bubblejail or Flatpak instead.")
    }
}

fn check_bubblejail(ctx: &Context) -> Outcome {
    if !ctx.sys.exists("/usr/bin/bubblejail") {
        return Outcome::warn("bubblejail is not installed")
            .evidence("Native binaries run unconfined except for AppArmor.")
            .remedy("pacman -S steel-sandbox");
    }
    let profiles = ctx.sys.list_dir("/usr/share/bubblejail/profiles");
    let steel_profiles = ctx.sys.list_dir("/usr/share/steel-sandbox/bubblejail");
    let count = profiles.len() + steel_profiles.len();
    if count == 0 {
        Outcome::warn("bubblejail is installed but no profiles are present")
            .remedy("pacman -S steel-sandbox")
    } else {
        Outcome::pass(format!("installed with {count} profiles"))
    }
}

fn check_usbguard(ctx: &Context) -> Outcome {
    let installed = ctx.sys.exists("/usr/bin/usbguard");
    if !ctx.preset.is_strict() {
        return if installed {
            Outcome::pass(format!(
                "installed (not required by the {} preset)",
                ctx.preset.as_str()
            ))
        } else {
            Outcome::skip(format!(
                "USBGuard is a strict-preset measure; this system is {}",
                ctx.preset.as_str()
            ))
        };
    }

    if !installed {
        return Outcome::fail("USBGuard is not installed but the preset is strict")
            .remedy("pacman -S usbguard steel-sandbox");
    }

    // Installed is not running; the daemon is what enforces the policy.
    if ctx.sys.is_real() && sys::have_binary("systemctl") {
        if let Some(out) = sys::run("systemctl", ["is-active", "usbguard.service"]) {
            let state = out.stdout.trim().to_string();
            if state != "active" {
                return Outcome::fail(format!("usbguard.service is {state}"))
                    .evidence("The policy is only enforced while the daemon runs.")
                    .remedy("systemctl enable --now usbguard.service");
            }
        }
    }

    let rules = ctx.sys.read("/etc/usbguard/rules.conf").unwrap_or_default();
    if rules.trim().is_empty() {
        Outcome::warn("USBGuard is running with an empty policy")
            .evidence(
                "With no rules and the default target, currently-connected devices \
                       may be blocked on next boot, including the keyboard.",
            )
            .remedy(
                "usbguard generate-policy > /etc/usbguard/rules.conf while your \
                     normal devices are connected.",
            )
    } else {
        Outcome::pass(format!(
            "active with {} rules",
            rules.lines().filter(|l| !l.trim().is_empty()).count()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Deployment, Preset};
    use crate::sys::{KernelCmdline, Sysroot};
    use std::fs;
    use std::path::PathBuf;

    struct Fx(PathBuf);
    impl Fx {
        fn new(n: &str) -> Fx {
            let d = std::env::temp_dir().join(format!("steel-check-sb-{n}-{}", std::process::id()));
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
        fn ctx(&self, preset: Preset) -> Context {
            Context {
                sys: Sysroot::new(&self.0),
                preset,
                deployment: Deployment::Arch,
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

    use crate::report::Status;

    #[test]
    fn apparmor_enabled_with_no_profiles_fails() {
        let f = Fx::new("aa-empty");
        f.write("/sys/module/apparmor/parameters/enabled", "Y\n");
        f.write("/sys/kernel/security/apparmor/profiles", "");
        assert_eq!(
            check_apparmor(&f.ctx(Preset::Balanced)).status,
            Status::Fail
        );
    }

    #[test]
    fn complain_mode_profiles_warn_and_are_named() {
        let f = Fx::new("aa-complain");
        f.write("/sys/module/apparmor/parameters/enabled", "Y\n");
        f.write(
            "/sys/kernel/security/apparmor/profiles",
            "/usr/bin/firefox (enforce)\n/usr/bin/thunderbird (complain)\n",
        );
        let out = check_apparmor(&f.ctx(Preset::Balanced));
        assert_eq!(out.status, Status::Warn);
        assert!(out.evidence.iter().any(|e| e.contains("thunderbird")));
    }

    #[test]
    fn all_enforcing_passes() {
        let f = Fx::new("aa-ok");
        f.write("/sys/module/apparmor/parameters/enabled", "Y\n");
        f.write(
            "/sys/kernel/security/apparmor/profiles",
            "/usr/bin/firefox (enforce)\n",
        );
        assert_eq!(
            check_apparmor(&f.ctx(Preset::Balanced)).status,
            Status::Pass
        );
    }

    #[test]
    fn flatpak_check_skips_when_flatpak_is_absent() {
        let f = Fx::new("fp-absent");
        assert_eq!(
            check_flatpak_overrides(&f.ctx(Preset::Balanced)).status,
            Status::Skip
        );
    }

    #[test]
    fn flatpak_partial_override_fails_and_names_the_gaps() {
        let f = Fx::new("fp-partial");
        f.write("/usr/bin/flatpak", "");
        f.write(
            "/var/lib/flatpak/overrides/global",
            "[Context]\nfilesystems=!home;!host;\n",
        );
        let out = check_flatpak_overrides(&f.ctx(Preset::Balanced));
        assert_eq!(out.status, Status::Fail);
        assert!(out.evidence.iter().any(|e| e.contains("devices=!all")));
    }

    #[test]
    fn firejail_presence_is_a_failure() {
        let f = Fx::new("firejail");
        f.write("/usr/bin/firejail", "");
        assert_eq!(
            check_no_suid_sandbox(&f.ctx(Preset::Balanced)).status,
            Status::Fail
        );
    }

    #[test]
    fn usbguard_is_skipped_outside_the_strict_preset() {
        let f = Fx::new("usbguard");
        assert_eq!(
            check_usbguard(&f.ctx(Preset::Balanced)).status,
            Status::Skip
        );
        assert_eq!(check_usbguard(&f.ctx(Preset::Strict)).status, Status::Fail);
    }
}
