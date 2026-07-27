//! Allocator hardening, CPU memory encryption, and DMA containment.

use crate::context::{Context, Deployment, Preset};
use crate::report::{Category, Check, Outcome, Severity};

pub const CHECKS: &[Check] = &[
    Check {
        id: "memory.hardened-malloc",
        title: "hardened_malloc is preloaded",
        category: Category::Memory,
        severity: Severity::Medium,
        rationale: "A hardened allocator turns many heap corruption bugs into crashes \
                    instead of exploits: guard pages, randomised placement, and \
                    metadata kept out of band. This is the single highest-value \
                    userspace mitigation for browser and document-viewer bugs.",
        escape_hatch: "steel-malloc exempt <binary> for one program, or the \
                       'no hardened_malloc' boot entry to disable it system-wide.",
        run: check_hardened_malloc,
    },
    Check {
        id: "memory.hardened-malloc-variant",
        title: "hardened_malloc variant matches the preset",
        category: Category::Memory,
        severity: Severity::Info,
        rationale: "The light variant is the default because the full variant breaks \
                    games and several proprietary applications, and an OS people stop \
                    using protects nobody (design principle 8).",
        escape_hatch: "steel-malloc variant light|full",
        run: check_malloc_variant,
    },
    Check {
        id: "memory.cpu-encryption",
        title: "CPU memory encryption is active",
        category: Category::Memory,
        severity: Severity::Medium,
        rationale: "AMD SME/TSME and Intel TME encrypt DRAM against an attacker with \
                    physical access to the bus or the DIMMs: cold-boot and DMA \
                    attacks. It does NOT defend against software reading memory \
                    through the kernel, and docs must not imply that it does.",
        escape_hatch: "Firmware setting; nothing to disable in the OS.",
        run: check_cpu_memory_encryption,
    },
    Check {
        id: "memory.iommu",
        title: "IOMMU is enabled",
        category: Category::Memory,
        severity: Severity::High,
        rationale: "Without an IOMMU, any Thunderbolt or PCIe peripheral can read and \
                    write all of system memory, which defeats every software measure \
                    on this list. This is the control that makes a hostile dock or \
                    charging cable survivable.",
        escape_hatch: "steel-harden iommu off — only for hardware that will not boot \
                       with it, and it is a large loss.",
        run: check_iommu,
    },
];

fn check_hardened_malloc(ctx: &Context) -> Outcome {
    let preload = ctx.sys.read("/etc/ld.so.preload").unwrap_or_default();
    let configured: Vec<&str> = preload
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let malloc_line = configured.iter().find(|l| l.contains("hardened_malloc"));

    match malloc_line {
        Some(line) => {
            // Configured is not the same as working: a preload pointing at a
            // missing library is silently ignored by the loader, which would
            // leave the user believing they are protected.
            if ctx.sys.exists(line) {
                Outcome::pass(format!("preloaded from {line}"))
            } else {
                Outcome::fail("ld.so.preload references a library that does not exist")
                    .evidence(format!("{line} is listed but not present on disk"))
                    .evidence(
                        "The dynamic loader ignores missing preloads silently, so \
                               nothing is protected and nothing warned you.",
                    )
                    .remedy("Reinstall steel-malloc, or run `steel-malloc repair`.")
            }
        }
        None if ctx.preset == Preset::Compatible => {
            Outcome::skip("compatible preset does not preload hardened_malloc")
        }
        None => Outcome::fail("hardened_malloc is not preloaded")
            .evidence(if configured.is_empty() {
                "/etc/ld.so.preload is empty or absent".to_string()
            } else {
                format!("/etc/ld.so.preload contains: {}", configured.join(", "))
            })
            .remedy("pacman -S steel-malloc, or `steel-malloc enable`."),
    }
}

fn check_malloc_variant(ctx: &Context) -> Outcome {
    let preload = ctx.sys.read("/etc/ld.so.preload").unwrap_or_default();
    let line = match preload
        .lines()
        .map(str::trim)
        .find(|l| l.contains("hardened_malloc"))
    {
        Some(l) => l,
        None => return Outcome::skip("hardened_malloc is not preloaded"),
    };
    // Upstream ships libhardened_malloc.so and libhardened_malloc-light.so.
    let variant = if line.contains("-light") {
        "light"
    } else {
        "full"
    };
    let expected = if ctx.preset.is_strict() {
        "full"
    } else {
        "light"
    };

    if variant == expected {
        Outcome::pass(format!(
            "{variant} variant, matching the {} preset",
            ctx.preset.as_str()
        ))
    } else {
        Outcome::warn(format!(
            "{variant} variant, but the {} preset expects {expected}",
            ctx.preset.as_str()
        ))
        .evidence(format!("preload line: {line}"))
        .remedy(format!("steel-malloc variant {expected}"))
    }
}

fn check_cpu_memory_encryption(ctx: &Context) -> Outcome {
    let cpuinfo = ctx.sys.read("/proc/cpuinfo").unwrap_or_default();
    let flags: Vec<&str> = cpuinfo
        .lines()
        .find(|l| l.starts_with("flags"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.split_whitespace().collect())
        .unwrap_or_default();

    let supports_sme = flags.contains(&"sme");
    let supports_tme = flags.contains(&"tme");

    // The kernel reports active memory encryption in /sys on AMD; on Intel TME
    // it is transparent and only visible as the CPU flag plus firmware state.
    let sme_active = ctx
        .sys
        .read("/sys/kernel/mm/mem_encrypt/active")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
        || ctx.cmdline.has_value("mem_encrypt", "on");

    match (supports_sme, supports_tme, sme_active) {
        (_, _, true) => Outcome::pass("AMD SME/TSME active").evidence(
            "Defends the DRAM bus and powered-off DIMMs. It does not defend \
                       against software reads through the kernel.",
        ),
        (true, _, false) => Outcome::warn("CPU supports SME but it is not active")
            .evidence("cpuinfo advertises 'sme'; the kernel does not report it active")
            .remedy(
                "Enable TSME (or 'Secure Memory Encryption') in firmware setup. On \
                     some boards the setting is under Advanced > AMD CBS > UMC.",
            ),
        (false, true, false) => Outcome::warn("CPU supports TME but it is not reported active")
            .evidence(
                "Intel TME is configured by firmware before the OS runs and is not \
                       reliably visible from the OS; treat this as 'unknown', not 'off'.",
            )
            .remedy("Enable 'Total Memory Encryption' in firmware setup if present."),
        (false, false, false) => Outcome::skip("CPU does not advertise SME or TME").evidence(
            "Cold-boot and DMA attacks are correspondingly easier on this hardware. \
                 The IOMMU check is the remaining defence.",
        ),
    }
}

fn check_iommu(ctx: &Context) -> Outcome {
    let groups = ctx.sys.list_dir("/sys/kernel/iommu_groups");
    let group_count = groups.len();

    if group_count > 0 {
        let mut outcome = Outcome::pass(format!("active, {group_count} IOMMU groups"));
        // Passthrough mode leaves the IOMMU enabled but not translating, which
        // provides no protection at all — a distinction that is easy to miss.
        if ctx.cmdline.has_value("iommu.passthrough", "1") || ctx.cmdline.has_value("iommu", "pt") {
            outcome = Outcome::warn("IOMMU is in passthrough mode")
                .evidence(
                    "Groups exist but translation is bypassed, so peripherals still \
                           reach all of memory. This is equivalent to having no IOMMU.",
                )
                .remedy("Remove iommu.passthrough=1 / iommu=pt from the kernel command line.");
        }
        return outcome;
    }

    let is_vm = ctx
        .sys
        .read("/sys/class/dmi/id/sys_vendor")
        .map(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("qemu") || v.contains("innotek") || v.contains("vmware")
        })
        .unwrap_or(false);

    let outcome = Outcome::fail("no IOMMU groups present")
        .evidence(format!("kernel cmdline: {}", ctx.cmdline.raw()))
        .remedy(
            "Enable VT-d / AMD-Vi in firmware and add intel_iommu=on or \
             amd_iommu=force_isolation to the kernel command line.",
        );

    match (is_vm, ctx.deployment) {
        // A VM without a virtual IOMMU is a test artefact, not a finding.
        (true, _) => Outcome::skip("no IOMMU groups; running in a VM without a virtual IOMMU"),
        (_, Deployment::DevMode) => Outcome::warn("no IOMMU groups (devmode)"),
        _ => outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Context, Deployment, Preset};
    use crate::report::Status;
    use crate::sys::{KernelCmdline, Sysroot};
    use std::fs;
    use std::path::PathBuf;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(name: &str) -> Fixture {
            let dir =
                std::env::temp_dir().join(format!("steel-check-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Fixture(dir)
        }

        fn write(&self, rel: &str, body: &str) -> &Fixture {
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

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn preload_pointing_at_a_missing_library_is_a_failure_not_a_pass() {
        // The loader ignores a missing preload silently. Reporting this as a
        // pass would be the worst kind of wrong: confidently false.
        let f = Fixture::new("malloc-missing");
        f.write(
            "/etc/ld.so.preload",
            "/usr/lib/libhardened_malloc-light.so\n",
        );
        let out = check_hardened_malloc(&f.ctx(Preset::Balanced));
        assert_eq!(out.status, Status::Fail);
        assert!(out.detail.contains("does not exist"));
    }

    #[test]
    fn preload_present_and_library_exists_passes() {
        let f = Fixture::new("malloc-ok");
        f.write("/usr/lib/libhardened_malloc-light.so", "");
        f.write(
            "/etc/ld.so.preload",
            "/usr/lib/libhardened_malloc-light.so\n",
        );
        assert_eq!(
            check_hardened_malloc(&f.ctx(Preset::Balanced)).status,
            Status::Pass
        );
    }

    #[test]
    fn compatible_preset_skips_rather_than_fails() {
        let f = Fixture::new("malloc-compat");
        f.write("/etc/ld.so.preload", "");
        assert_eq!(
            check_hardened_malloc(&f.ctx(Preset::Compatible)).status,
            Status::Skip
        );
    }

    #[test]
    fn variant_mismatch_warns_in_both_directions() {
        let f = Fixture::new("malloc-variant");
        f.write(
            "/etc/ld.so.preload",
            "/usr/lib/libhardened_malloc-light.so\n",
        );
        assert_eq!(
            check_malloc_variant(&f.ctx(Preset::Balanced)).status,
            Status::Pass
        );
        assert_eq!(
            check_malloc_variant(&f.ctx(Preset::Strict)).status,
            Status::Warn
        );

        let g = Fixture::new("malloc-variant-full");
        g.write("/etc/ld.so.preload", "/usr/lib/libhardened_malloc.so\n");
        assert_eq!(
            check_malloc_variant(&g.ctx(Preset::Strict)).status,
            Status::Pass
        );
        assert_eq!(
            check_malloc_variant(&g.ctx(Preset::Balanced)).status,
            Status::Warn
        );
    }

    #[test]
    fn iommu_passthrough_is_reported_as_no_protection() {
        let f = Fixture::new("iommu-pt");
        f.write("/sys/kernel/iommu_groups/0/type", "DMA\n");
        let mut ctx = f.ctx(Preset::Balanced);
        ctx.cmdline = KernelCmdline::parse("intel_iommu=on iommu.passthrough=1");
        let out = check_iommu(&ctx);
        assert_eq!(out.status, Status::Warn);
        assert!(out.detail.contains("passthrough"));
    }
}
