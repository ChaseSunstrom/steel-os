//! Kernel-level hardening: sysctl baseline, boot parameters, lockdown, module
//! signature enforcement, module blacklists, and the deliberate exception for
//! user namespaces.

use crate::context::{Context, Deployment, Preset};
use crate::report::{Category, Check, Outcome, Severity, Status};

/// How to compare an effective sysctl value against what we intend.
#[derive(Debug, Clone, Copy)]
pub enum Expect {
    Exact(&'static str),
    /// Numerically at least this. Used where a higher value is strictly more
    /// restrictive and where kernels differ in the maximum they accept.
    AtLeast(i64),
}

impl Expect {
    fn satisfied_by(&self, actual: &str) -> bool {
        match self {
            Expect::Exact(want) => actual == *want,
            Expect::AtLeast(min) => actual.parse::<i64>().map(|v| v >= *min).unwrap_or(false),
        }
    }

    fn describe(&self) -> String {
        match self {
            Expect::Exact(want) => (*want).to_string(),
            Expect::AtLeast(min) => format!(">={min}"),
        }
    }
}

/// The sysctl baseline, and the single source of truth for it.
///
/// `steel-kernel-hardening` ships drop-in files that must set exactly these
/// values; `tests::sysctl_dropin_matches_baseline` parses the packaged drop-in
/// and fails the build if the two drift apart. Without that test, the packages
/// and the auditor would eventually disagree and the auditor would be wrong —
/// which is worse than having no auditor.
pub const SYSCTL_BASELINE: &[(&str, Expect, &str)] = &[
    // --- Kernel information leaks -------------------------------------------
    ("kernel.kptr_restrict", Expect::Exact("2"), "hide kernel pointers from all users, defeating KASLR-defeating info leaks"),
    ("kernel.dmesg_restrict", Expect::Exact("1"), "restrict dmesg to CAP_SYSLOG; the ring buffer leaks addresses and hardware detail"),
    ("kernel.printk", Expect::Exact("3 3 3 3"), "keep kernel messages off the console, where they are readable over the shoulder"),
    ("kernel.perf_event_paranoid", Expect::AtLeast(2), "deny unprivileged perf access; perf has a long history of LPE bugs"),
    // --- Attack surface reduction -------------------------------------------
    ("kernel.kexec_load_disabled", Expect::Exact("1"), "prevent loading a replacement kernel at runtime, which would bypass verified boot"),
    ("kernel.sysrq", Expect::Exact("176"), "allow only sync/remount-ro/reboot via SysRq; the debug and signal functions are a console-attacker LPE"),
    ("kernel.unprivileged_bpf_disabled", Expect::Exact("1"), "unprivileged BPF is a recurring source of kernel LPE"),
    ("net.core.bpf_jit_harden", Expect::Exact("2"), "blind JIT constants so BPF cannot be used to spray attacker-controlled instructions"),
    ("dev.tty.ldisc_autoload", Expect::Exact("0"), "line discipline autoload has produced several LPEs and no desktop needs it"),
    ("vm.unprivileged_userfaultfd", Expect::Exact("0"), "userfaultfd is the standard primitive for winning kernel use-after-free races"),
    // --- Process and memory -------------------------------------------------
    ("kernel.randomize_va_space", Expect::Exact("2"), "full ASLR including the heap"),
    ("kernel.yama.ptrace_scope", Expect::AtLeast(2), "stop one compromised process from reading another's memory, including keys"),
    ("fs.suid_dumpable", Expect::Exact("0"), "never dump core for privileged binaries"),
    ("kernel.core_pattern", Expect::Exact("|/bin/false"), "discard core dumps; they contain keys and land in world-readable places"),
    // --- Filesystem races ---------------------------------------------------
    ("fs.protected_symlinks", Expect::Exact("1"), "block the classic symlink-in-/tmp privilege escalation"),
    ("fs.protected_hardlinks", Expect::Exact("1"), "block the hardlink variant of the same attack"),
    ("fs.protected_fifos", Expect::Exact("2"), "block FIFO-based races in world-writable directories"),
    ("fs.protected_regular", Expect::Exact("2"), "block regular-file variants of the same races"),
    // --- Network ------------------------------------------------------------
    ("net.ipv4.tcp_syncookies", Expect::Exact("1"), "survive SYN floods without dropping legitimate connections"),
    ("net.ipv4.tcp_rfc1337", Expect::Exact("1"), "drop RST packets for sockets in TIME-WAIT, closing a hijacking window"),
    ("net.ipv4.conf.all.accept_redirects", Expect::Exact("0"), "ICMP redirects let a local network attacker reroute traffic"),
    ("net.ipv4.conf.default.accept_redirects", Expect::Exact("0"), "same, for interfaces that appear later"),
    ("net.ipv4.conf.all.secure_redirects", Expect::Exact("0"), "accepting redirects from gateways is still accepting redirects"),
    ("net.ipv4.conf.all.send_redirects", Expect::Exact("0"), "a desktop is not a router"),
    ("net.ipv4.conf.all.accept_source_route", Expect::Exact("0"), "source routing lets an attacker choose the return path"),
    ("net.ipv4.conf.all.rp_filter", Expect::Exact("1"), "drop packets whose source address is not reachable via the receiving interface"),
    ("net.ipv4.icmp_ignore_bogus_error_responses", Expect::Exact("1"), "keep the log clean so real events are visible"),
    ("net.ipv6.conf.all.accept_redirects", Expect::Exact("0"), "IPv6 equivalent of the redirect attack"),
    ("net.ipv6.conf.default.accept_redirects", Expect::Exact("0"), "same, for interfaces that appear later"),
    ("net.ipv6.conf.all.accept_source_route", Expect::Exact("-1"), "IPv6 source routing, disabled as the kernel expects (-1)"),
    ("net.ipv6.conf.all.use_tempaddr", Expect::Exact("2"), "prefer IPv6 privacy addresses so the interface identifier is not a stable tracker"),
    ("net.ipv6.conf.default.use_tempaddr", Expect::Exact("2"), "same, for interfaces that appear later"),
];

/// Sysctls that are stricter under the `strict` preset than under `balanced`.
const SYSCTL_STRICT_OVERRIDES: &[(&str, Expect)] = &[
    // ptrace_scope=3 disables ptrace entirely and cannot be relaxed without a
    // reboot. It breaks debuggers, so it is strict-only.
    ("kernel.yama.ptrace_scope", Expect::AtLeast(3)),
    ("kernel.perf_event_paranoid", Expect::AtLeast(3)),
];

/// Kernel command-line parameters required at balanced and above.
///
/// `mitigations=auto` rather than `=auto,nosmt`: disabling SMT costs roughly a
/// third of the machine's throughput to defend against cross-thread side
/// channels that need local code execution, which the sandboxing layer is
/// already meant to prevent. Users who want it get `steel-harden smt off`.
pub const CMDLINE_BASELINE: &[(&str, &str, &str)] = &[
    (
        "slab_nomerge",
        "",
        "stop similarly-sized slab caches merging, which makes heap grooming much harder",
    ),
    (
        "init_on_alloc",
        "1",
        "zero pages on allocation, killing a large class of uninitialised-memory leaks",
    ),
    (
        "init_on_free",
        "1",
        "zero pages on free, shortening the window for use-after-free exploitation",
    ),
    (
        "page_alloc.shuffle",
        "1",
        "randomise the page allocator freelist",
    ),
    (
        "randomize_kstack_offset",
        "on",
        "randomise the kernel stack offset per syscall",
    ),
    (
        "vsyscall",
        "none",
        "remove the last fixed-address executable region in userspace",
    ),
    (
        "debugfs",
        "off",
        "debugfs exposes broad kernel internals and nothing on a desktop needs it",
    ),
    (
        "mitigations",
        "auto",
        "keep CPU vulnerability mitigations enabled",
    ),
];

const CMDLINE_STRICT: &[(&str, &str, &str)] = &[
    (
        "oops=panic",
        "",
        "treat a kernel oops as fatal, so an attacker cannot retry a technique that oopses",
    ),
    (
        "ia32_emulation",
        "0",
        "remove the 32-bit syscall interface, historically a rich source of LPE",
    ),
];

pub const CHECKS: &[Check] = &[
    Check {
        id: "kernel.sysctl-baseline",
        title: "Hardening sysctls are in force",
        category: Category::Kernel,
        severity: Severity::High,
        rationale: "Reads the effective values from /proc/sys, not the drop-in files. \
                    What is configured and what is in force are different questions, and \
                    only the second one defends anything.",
        escape_hatch: "steel-harden sysctl <key> off, or drop a file in \
                       /etc/sysctl.d/ that sorts after 99-steel-hardening.conf",
        run: check_sysctl_baseline,
    },
    Check {
        id: "kernel.variant",
        title: "Running a hardened kernel",
        category: Category::Kernel,
        severity: Severity::Medium,
        rationale: "linux-hardened carries upstream-rejected but worthwhile patches \
                    (stricter ASLR, extra allocator checks). We do not build our own \
                    kernel: maintaining one means owning its security updates.",
        escape_hatch: "Set kernel = \"linux\" in the manifest, or install a different \
                       kernel package on a plain-Arch install.",
        run: check_kernel_variant,
    },
    Check {
        id: "kernel.cmdline-baseline",
        title: "Hardening boot parameters are active",
        category: Category::Kernel,
        severity: Severity::High,
        rationale: "These are exploit mitigations that can only be set at boot. On an \
                    image deployment they live inside the signed UKI, so they cannot be \
                    edited without invalidating the signature.",
        escape_hatch: "Edit /etc/kernel/cmdline.d/ and rebuild the UKI, or boot the \
                       alternate entry that omits them.",
        run: check_cmdline_baseline,
    },
    Check {
        id: "kernel.lockdown",
        title: "Kernel lockdown mode",
        category: Category::Kernel,
        severity: Severity::High,
        rationale: "Lockdown severs the paths by which root modifies the running kernel \
                    (/dev/mem, kexec, unsigned modules, some debug interfaces). Without \
                    it, root and kernel are the same privilege level, and the immutable \
                    root filesystem buys much less.",
        escape_hatch: "lockdown=integrity (compatible preset) or steel-harden lockdown off.",
        run: check_lockdown,
    },
    Check {
        id: "kernel.module-signatures",
        title: "Unsigned kernel modules are rejected",
        category: Category::Kernel,
        severity: Severity::High,
        rationale: "Loading an unsigned module is the simplest way to defeat everything \
                    above it. Because modules are built and signed in CI at image build \
                    time, this can be a default without breaking out-of-tree drivers such \
                    as NVIDIA — which is a direct advantage of the image model.",
        escape_hatch: "Build a custom image with your module signed, or use steel-devmode.",
        run: check_module_signatures,
    },
    Check {
        id: "kernel.module-blacklist",
        title: "Attack-surface modules are blacklisted and not loaded",
        category: Category::Kernel,
        severity: Severity::Medium,
        rationale: "Rare filesystems and legacy network protocols are large, lightly \
                    audited kernel code reachable from removable media or the network. \
                    A desktop needs none of them.",
        escape_hatch: "steel-harden module <name> allow, or an /etc/modprobe.d file that \
                       sorts after the steel drop-in.",
        run: check_module_blacklist,
    },
    Check {
        id: "kernel.userns",
        title: "Unprivileged user namespaces are enabled (deliberate)",
        category: Category::Kernel,
        severity: Severity::Info,
        rationale: "This is a documented, deliberate divergence from most hardening \
                    guides. Unprivileged bwrap/Flatpak sandboxing depends on user \
                    namespaces; the alternative is SUID-root helpers, which is a worse \
                    trade. See docs/rationale/user-namespaces.md for the counterargument.",
        escape_hatch: "steel-harden userns off — expect Flatpak and bubblejail to break.",
        run: check_userns,
    },
];

fn expected_for(ctx: &Context, key: &str, base: Expect) -> Expect {
    if ctx.preset.is_strict() {
        if let Some((_, e)) = SYSCTL_STRICT_OVERRIDES.iter().find(|(k, _)| *k == key) {
            return *e;
        }
    }
    base
}

fn check_sysctl_baseline(ctx: &Context) -> Outcome {
    let mut deviations = Vec::new();
    let mut missing = Vec::new();

    for (key, base, _why) in SYSCTL_BASELINE {
        let expect = expected_for(ctx, key, *base);
        match ctx.sys.sysctl(key) {
            Some(actual) => {
                if !expect.satisfied_by(&actual) {
                    deviations.push(format!("{key} = {actual} (want {})", expect.describe()));
                }
            }
            // An absent knob is a kernel that does not implement it. That is a
            // fact about the kernel, not a misconfiguration, so it is reported
            // separately and does not fail the check.
            None => missing.push(key.to_string()),
        }
    }

    let total = SYSCTL_BASELINE.len();
    if deviations.is_empty() {
        let mut outcome = Outcome::pass(format!(
            "{}/{total} baseline sysctls in force",
            total - missing.len()
        ));
        if !missing.is_empty() {
            outcome = outcome.evidence(format!(
                "not implemented by this kernel: {}",
                missing.join(", ")
            ));
        }
        return outcome;
    }

    let status = if ctx.preset == Preset::Compatible {
        Status::Warn
    } else {
        Status::Fail
    };
    Outcome::new(
        status,
        format!("{} of {total} baseline sysctls deviate", deviations.len()),
    )
    .evidence_all(deviations)
    .remedy(
        "Reinstall or repair steel-kernel-hardening, then `sysctl --system`. \
         If a deviation is intentional, record it with `steel-harden sysctl <key> off` \
         so it is documented rather than silent.",
    )
}

fn check_kernel_variant(ctx: &Context) -> Outcome {
    let release = match ctx.sys.read_trimmed("/proc/sys/kernel/osrelease") {
        Some(r) => r,
        None => return Outcome::skip("cannot read /proc/sys/kernel/osrelease"),
    };
    if release.contains("hardened") {
        Outcome::pass(format!("linux-hardened ({release})"))
    } else {
        Outcome::warn(format!("running {release}, not linux-hardened"))
            .evidence(
                "The sysctl and cmdline baselines still apply, but the extra \
                       upstream-rejected patches are absent.",
            )
            .remedy(
                "Set kernel = \"linux-hardened\" in the manifest and re-apply, or \
                     `pacman -S linux-hardened` on a plain-Arch install.",
            )
    }
}

fn check_cmdline_baseline(ctx: &Context) -> Outcome {
    let mut missing = Vec::new();

    let mut required: Vec<(&str, &str, &str)> = CMDLINE_BASELINE.to_vec();
    if ctx.preset.is_strict() {
        required.extend_from_slice(CMDLINE_STRICT);
    }

    for (key, value, _why) in &required {
        // Bare flags are written into the table with an empty value.
        let (key, value) = match key.split_once('=') {
            Some((k, v)) => (k, v),
            None => (*key, *value),
        };
        let present = if value.is_empty() {
            ctx.cmdline.has(key)
        } else {
            ctx.cmdline.has_value(key, value)
        };
        if !present {
            let actual = ctx
                .cmdline
                .get(key)
                .map(|v| {
                    if v.is_empty() {
                        "present".to_string()
                    } else {
                        v.to_string()
                    }
                })
                .unwrap_or_else(|| "absent".to_string());
            let want = if value.is_empty() {
                key.to_string()
            } else {
                format!("{key}={value}")
            };
            missing.push(format!("{want} (actual: {actual})"));
        }
    }

    if missing.is_empty() {
        return Outcome::pass(format!("{} boot parameters in force", required.len()));
    }

    // On a plain-Arch install the packages ship a cmdline fragment but cannot
    // apply it — that is the bootloader's business, and we do not own the
    // bootloader until Phase 1. Reporting Fail there would punish users for
    // something the package cannot do.
    let (status, remedy) = match ctx.deployment {
        Deployment::Arch => (
            Status::Warn,
            "Append the contents of /usr/share/steel-kernel-hardening/cmdline to your \
             bootloader entry, then reboot. On an image deployment these parameters live \
             inside the signed UKI and are applied for you.",
        ),
        Deployment::DevMode => (
            Status::Warn,
            "This is a devmode boot; the hardened cmdline is deliberately not applied. \
             Reboot into the normal deployment.",
        ),
        Deployment::Image => (
            Status::Fail,
            "The UKI was built without the hardening fragment. Run `steelctl apply` to \
             rebuild it, or `steel-boot rebuild-uki`.",
        ),
    };

    Outcome::new(status, format!("{} boot parameters missing", missing.len()))
        .evidence_all(missing)
        .remedy(remedy)
}

fn check_lockdown(ctx: &Context) -> Outcome {
    let raw = match ctx.sys.read_trimmed("/sys/kernel/security/lockdown") {
        Some(r) => r,
        None => {
            return Outcome::warn("lockdown LSM not available")
                .evidence(
                    "/sys/kernel/security/lockdown is absent: either securityfs is \
                           not mounted or the kernel was built without the lockdown LSM",
                )
                .remedy(
                    "Use a kernel with CONFIG_SECURITY_LOCKDOWN_LSM=y (linux and \
                         linux-hardened both have it) and ensure securityfs is mounted.",
                )
        }
    };
    // Format: "none [integrity] confidentiality" — brackets mark the active mode.
    let active = raw
        .split_whitespace()
        .find(|t| t.starts_with('['))
        .map(|t| t.trim_matches(['[', ']']).to_string())
        .unwrap_or_else(|| raw.clone());

    let wanted = if ctx.preset == Preset::Compatible {
        "integrity"
    } else {
        "confidentiality"
    };

    match (active.as_str(), wanted) {
        (a, w) if a == w => Outcome::pass(format!("lockdown={a}")),
        ("confidentiality", "integrity") => {
            Outcome::pass("lockdown=confidentiality (stricter than this preset requires)")
        }
        ("integrity", "confidentiality") => {
            Outcome::warn("lockdown=integrity, want confidentiality")
                .evidence(
                    "integrity blocks modification of the running kernel but still \
                       permits reading it, so kernel memory remains extractable by root",
                )
                .remedy("Set lockdown=confidentiality on the kernel command line.")
        }
        (a, w) => Outcome::fail(format!("lockdown={a}, want {w}"))
            .evidence(format!("/sys/kernel/security/lockdown: {raw}"))
            .remedy(format!(
                "Add lockdown={w} to the kernel command line and reboot."
            )),
    }
}

fn check_module_signatures(ctx: &Context) -> Outcome {
    let enforced = ctx
        .sys
        .read_trimmed("/sys/module/module/parameters/sig_enforce")
        .map(|v| v == "Y")
        .unwrap_or(false);

    // Lockdown at integrity or above enforces module signatures regardless of
    // the sig_enforce knob, so report that rather than a misleading failure.
    let lockdown = ctx
        .sys
        .read_trimmed("/sys/kernel/security/lockdown")
        .unwrap_or_default();
    let lockdown_enforcing =
        lockdown.contains("[integrity]") || lockdown.contains("[confidentiality]");

    if enforced {
        return Outcome::pass("module.sig_enforce=1");
    }
    if lockdown_enforcing {
        return Outcome::pass("enforced via kernel lockdown").evidence(
            "module.sig_enforce is not set, but lockdown is at integrity or \
                       above, which rejects unsigned modules on the same code path",
        );
    }

    match ctx.deployment {
        Deployment::Arch => Outcome::warn("unsigned modules are accepted")
            .evidence(
                "On a plain-Arch install this is expected: DKMS modules are built \
                       locally and are not signed by our key.",
            )
            .remedy(
                "This is fixed by the image model, where modules are built and signed \
                     in CI (Phase 1). Do not set module.sig_enforce=1 on a DKMS system \
                     unless you have enrolled your own signing key.",
            ),
        Deployment::DevMode => Outcome::warn("unsigned modules are accepted (devmode)")
            .evidence("devmode deliberately relaxes this so hardware bring-up is possible"),
        Deployment::Image => Outcome::fail("unsigned modules are accepted")
            .evidence(format!("lockdown state: {lockdown}"))
            .remedy("Add module.sig_enforce=1 to the UKI cmdline and rebuild."),
    }
}

/// Modules blacklisted by `steel-kernel-hardening`.
///
/// Kept in sync with the packaged modprobe drop-in by a test, for the same
/// reason as the sysctl table.
pub const BLACKLISTED_MODULES: &[(&str, &str)] = &[
    // Legacy/rare filesystems, reachable by plugging in a USB stick.
    (
        "cramfs",
        "rare filesystem, auto-mounted from removable media",
    ),
    (
        "freevxfs",
        "rare filesystem, auto-mounted from removable media",
    ),
    (
        "jffs2",
        "rare filesystem, auto-mounted from removable media",
    ),
    ("hfs", "rare filesystem, auto-mounted from removable media"),
    (
        "hfsplus",
        "rare filesystem, auto-mounted from removable media",
    ),
    ("udf", "rare filesystem, auto-mounted from removable media"),
    (
        "ksmbd",
        "in-kernel SMB server; a desktop should not run one",
    ),
    // Legacy network protocols, reachable by an unprivileged socket() call.
    (
        "dccp",
        "legacy network protocol with a history of remotely triggerable bugs",
    ),
    (
        "sctp",
        "legacy network protocol with a history of remotely triggerable bugs",
    ),
    (
        "rds",
        "legacy network protocol with a history of remotely triggerable bugs",
    ),
    (
        "tipc",
        "legacy network protocol with a history of remotely triggerable bugs",
    ),
    (
        "n-hdlc",
        "legacy network protocol with a history of remotely triggerable bugs",
    ),
    ("ax25", "amateur radio stack, unused on a desktop"),
    ("netrom", "amateur radio stack, unused on a desktop"),
    ("x25", "legacy WAN protocol, unused on a desktop"),
    ("rose", "amateur radio stack, unused on a desktop"),
    ("decnet", "obsolete protocol"),
    ("econet", "obsolete protocol"),
    ("af_802154", "unused radio stack"),
    ("ipx", "obsolete protocol"),
    ("appletalk", "obsolete protocol"),
    ("psnap", "obsolete protocol"),
    ("p8023", "obsolete protocol"),
    ("p8022", "obsolete protocol"),
    ("can", "vehicle bus, unused on a desktop"),
    ("atm", "obsolete protocol"),
    // Direct DMA to physical memory over an external port.
    (
        "firewire-core",
        "FireWire grants DMA to host memory over an external port",
    ),
    (
        "firewire-ohci",
        "FireWire grants DMA to host memory over an external port",
    ),
    (
        "firewire-sbp2",
        "FireWire grants DMA to host memory over an external port",
    ),
    (
        "thunderbolt",
        "strict preset only; blocks DMA-capable external ports at the cost of docks",
    ),
    // Miscellaneous.
    (
        "vivid",
        "test driver, repeatedly a source of LPE, never needed in production",
    ),
    (
        "msr",
        "direct model-specific register access from userspace",
    ),
];

/// Modules blacklisted only under the strict preset, because blacklisting them
/// costs real functionality.
const STRICT_ONLY_MODULES: &[&str] = &["thunderbolt"];

fn check_module_blacklist(ctx: &Context) -> Outcome {
    let modprobe_conf = ctx.sys.concat_dir("/etc/modprobe.d", ".conf");
    let loaded = ctx.sys.loaded_modules();

    let mut unconfigured = Vec::new();
    let mut loaded_anyway = Vec::new();

    for (module, _why) in BLACKLISTED_MODULES {
        if STRICT_ONLY_MODULES.contains(module) && !ctx.preset.is_strict() {
            continue;
        }
        let alias = module.replace('-', "_");
        // Match the module name as a whole token. A substring match would report
        // `can` as blacklisted because some other line mentions `vcan`, which is
        // the failure mode where the auditor is confidently wrong.
        let configured = modprobe_conf.lines().any(|line| {
            let mut tokens = line.split_whitespace();
            match tokens.next() {
                Some("blacklist") | Some("install") => {
                    matches!(tokens.next(), Some(name) if name == *module || name == alias)
                }
                _ => false,
            }
        });
        if !configured {
            unconfigured.push(module.to_string());
        }
        if loaded.iter().any(|m| *m == alias || m == module) {
            loaded_anyway.push(module.to_string());
        }
    }

    // A blacklisted-but-loaded module is the serious finding: the config is
    // present and something loaded it anyway, or it was loaded before the
    // config applied.
    if !loaded_anyway.is_empty() {
        return Outcome::fail(format!(
            "{} blacklisted modules are loaded",
            loaded_anyway.len()
        ))
        .evidence(format!("loaded: {}", loaded_anyway.join(", ")))
        .remedy(
            "Identify what loaded them (`journalctl -b | grep -i modprobe`), then \
                     unload with `rmmod` and reboot to confirm they stay out.",
        );
    }
    if !unconfigured.is_empty() {
        return Outcome::fail(format!(
            "{} modules are not blacklisted",
            unconfigured.len()
        ))
        .evidence(format!(
            "missing from /etc/modprobe.d: {}",
            unconfigured.join(", ")
        ))
        .remedy("Reinstall steel-kernel-hardening.");
    }
    Outcome::pass("blacklist configured and no blacklisted module is loaded")
}

fn check_userns(ctx: &Context) -> Outcome {
    let max = ctx
        .sys
        .sysctl("user.max_user_namespaces")
        .and_then(|v| v.parse::<i64>().ok());

    match max {
        Some(0) => Outcome::warn("unprivileged user namespaces are disabled")
            .evidence(
                "Flatpak, bubblejail, steel-shell and every other unprivileged \
                       sandbox depend on this. With it off, sandboxing is not available \
                       and the only alternative is SUID-root helpers.",
            )
            .remedy(
                "steel-harden userns on — unless you disabled this on purpose, in \
                     which case expect sandboxed apps not to launch.",
            ),
        Some(n) => Outcome::pass(format!("enabled (user.max_user_namespaces={n})")),
        None => Outcome::skip("user.max_user_namespaces not implemented by this kernel"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        // tools/steel-check -> repo root
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    #[test]
    fn expect_comparison_semantics() {
        assert!(Expect::Exact("2").satisfied_by("2"));
        assert!(!Expect::Exact("2").satisfied_by("1"));
        assert!(Expect::AtLeast(2).satisfied_by("3"));
        assert!(!Expect::AtLeast(2).satisfied_by("1"));
        // Non-numeric values never satisfy AtLeast rather than silently passing.
        assert!(!Expect::AtLeast(2).satisfied_by("yes"));
    }

    #[test]
    fn strict_preset_tightens_ptrace_scope() {
        for (key, expect) in SYSCTL_STRICT_OVERRIDES {
            let base = SYSCTL_BASELINE
                .iter()
                .find(|(k, _, _)| k == key)
                .unwrap_or_else(|| panic!("strict override for unknown sysctl {key}"))
                .1;
            // Every strict override must actually be stricter than the base.
            match (base, expect) {
                (Expect::AtLeast(b), Expect::AtLeast(s)) => assert!(*s > b, "{key} not stricter"),
                _ => panic!("{key}: strict overrides are only meaningful for AtLeast"),
            }
        }
    }

    #[test]
    fn baseline_has_no_duplicate_keys() {
        let mut keys: Vec<&str> = SYSCTL_BASELINE.iter().map(|(k, _, _)| *k).collect();
        let before = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(before, keys.len(), "duplicate sysctl key in the baseline");
    }

    #[test]
    fn every_baseline_entry_has_a_rationale() {
        // Design principle 7: if we cannot say why, it does not ship.
        for (key, _, why) in SYSCTL_BASELINE {
            assert!(why.len() > 20, "{key} has no meaningful rationale");
        }
        for (key, _, why) in CMDLINE_BASELINE {
            assert!(why.len() > 20, "{key} has no meaningful rationale");
        }
        for (module, why) in BLACKLISTED_MODULES {
            assert!(why.len() > 10, "{module} has no meaningful rationale");
        }
    }

    /// The packaged drop-in and this table must not drift apart. If they do,
    /// steel-check reports on a baseline the system was never configured with.
    #[test]
    fn sysctl_dropin_matches_baseline() {
        let path =
            repo_root().join("packages/steel-kernel-hardening/src/sysctl/99-steel-hardening.conf");
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

        let mut configured = std::collections::BTreeMap::new();
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("bad line: {line}"));
            configured.insert(k.trim().to_string(), v.trim().to_string());
        }

        for (key, expect, _) in SYSCTL_BASELINE {
            let actual = configured
                .get(*key)
                .unwrap_or_else(|| panic!("{key} is in the baseline but not in the drop-in"));
            assert!(
                expect.satisfied_by(actual),
                "{key}: drop-in sets {actual}, baseline wants {}",
                expect.describe()
            );
        }
        for key in configured.keys() {
            assert!(
                SYSCTL_BASELINE.iter().any(|(k, _, _)| k == key),
                "{key} is set by the drop-in but not audited by steel-check"
            );
        }
    }

    /// Same argument for the modprobe blacklist, across both drop-ins: a
    /// strict-only module must be in the strict file and nowhere else, so that
    /// a balanced install does not silently lose its Thunderbolt dock.
    #[test]
    fn modprobe_dropins_match_blacklist() {
        let read = |rel: &str| -> Vec<String> {
            let path = repo_root().join(rel);
            let body = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            body.lines()
                .filter_map(|l| l.trim().strip_prefix("install "))
                .filter_map(|rest| rest.split_whitespace().next())
                .map(str::to_string)
                .collect()
        };

        let base = read("packages/steel-kernel-hardening/src/modprobe/99-steel-blacklist.conf");
        let strict =
            read("packages/steel-kernel-hardening/src/modprobe/99-steel-blacklist-strict.conf");

        for (module, _) in BLACKLISTED_MODULES {
            let expected = if STRICT_ONLY_MODULES.contains(module) {
                &strict
            } else {
                &base
            };
            let other = if STRICT_ONLY_MODULES.contains(module) {
                &base
            } else {
                &strict
            };
            assert!(
                expected.iter().any(|c| c == module),
                "{module} is in the blacklist table but not in the drop-in for its preset"
            );
            assert!(
                !other.iter().any(|c| c == module),
                "{module} appears in the wrong preset's drop-in"
            );
        }
        for module in base.iter().chain(strict.iter()) {
            assert!(
                BLACKLISTED_MODULES.iter().any(|(m, _)| m == module),
                "{module} is blacklisted by a drop-in but not audited by steel-check"
            );
        }
    }

    /// The cmdline fragment shipped by the package must match what we audit.
    #[test]
    fn cmdline_fragment_matches_baseline() {
        let path = repo_root().join("packages/steel-kernel-hardening/src/cmdline/hardening");
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let fragment: Vec<&str> = body
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .flat_map(|l| l.split_whitespace())
            .collect();

        for (key, value, _) in CMDLINE_BASELINE {
            let want = if value.is_empty() {
                (*key).to_string()
            } else {
                format!("{key}={value}")
            };
            assert!(
                fragment.contains(&want.as_str()),
                "{want} is audited but not in the packaged cmdline fragment"
            );
        }
    }
}
