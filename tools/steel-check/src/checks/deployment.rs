//! Generations, A/B slots, boot counting, and runtime system extensions.

use crate::context::Context;
use crate::report::{Category, Check, Outcome, Severity};

pub const CHECKS: &[Check] = &[
    Check {
        id: "deployment.generation",
        title: "The running generation is recorded and matches a known manifest",
        category: Category::Deployment,
        severity: Severity::Medium,
        rationale: "The system is a build artefact, not a history of commands. If the \
                    running deployment cannot be traced back to a manifest hash, that \
                    claim is not true of this machine.",
        escape_hatch: "n/a",
        run: check_generation,
    },
    Check {
        id: "deployment.slot-health",
        title: "Both A/B slots are populated and the inactive slot is bootable",
        category: Category::Deployment,
        severity: Severity::High,
        rationale: "Rollback is only real if the previous deployment is still there. A \
                    single populated slot means a bad update has nowhere to fall back to, \
                    which is precisely when rollback is needed.",
        escape_hatch: "n/a",
        run: check_slots,
    },
    Check {
        id: "deployment.boot-counting",
        title: "Boot counting is armed and the current boot is blessed",
        category: Category::Deployment,
        severity: Severity::High,
        rationale: "Automatic demotion of a deployment that cannot reach a healthy state \
                    is what makes a bad update survivable unattended. CLAUDE.md requires \
                    this before any update mechanism ships.",
        escape_hatch: "n/a",
        run: check_boot_counting,
    },
    Check {
        id: "deployment.sysext-signed",
        title: "All loaded system extensions are signed",
        category: Category::Deployment,
        severity: Severity::High,
        rationale: "sysexts layer onto /usr at runtime. An unsigned one is an unverified \
                    write into the verified root, which is the exact property the design \
                    exists to prevent.",
        escape_hatch: "Sign your extension with the machine's key, or build a custom image.",
        run: check_sysext_signed,
    },
    Check {
        id: "deployment.no-unexpected-layering",
        title: "Nothing has been layered into the verified root",
        category: Category::Deployment,
        severity: Severity::High,
        rationale: "CLAUDE.md gotcha 2: any runtime modification of a verity-backed /usr \
                    makes the system unbootable, and tools that historically edited system \
                    files will try. Failing loudly here is cheaper than discovering it at \
                    the next boot.",
        escape_hatch: "steel-devmode for deliberate modification.",
        run: check_layering,
    },
];

fn check_generation(ctx: &Context) -> Outcome {
    if !ctx.deployment.is_image() {
        return Outcome::skip(ctx.not_image_reason());
    }
    let id = ctx.sys.read_trimmed("/usr/lib/steelos/image-id");
    let manifest_hash = ctx.sys.read_trimmed("/usr/lib/steelos/manifest-hash");

    match (id, manifest_hash) {
        (Some(id), Some(hash)) if !id.is_empty() && !hash.is_empty() => {
            Outcome::pass(format!("generation {id}")).evidence(format!("manifest hash: {hash}"))
        }
        (Some(id), _) => Outcome::warn(format!("generation {id} has no recorded manifest hash"))
            .evidence(
                "The image cannot be traced back to the manifest that produced it, \
                       so reproducibility cannot be verified for this machine.",
            )
            .remedy("Rebuild with `steelctl apply`; the build records the hash."),
        _ => Outcome::fail("no generation identity recorded").remedy(
            "The image was not built by our tooling, or /usr/lib/steelos is \
                     missing. Reinstall or roll back.",
        ),
    }
}

fn check_slots(ctx: &Context) -> Outcome {
    if !ctx.deployment.is_image() {
        return Outcome::skip(ctx.not_image_reason());
    }
    let slots: Vec<String> = ctx
        .sys
        .list_dir("/var/lib/steelos/slots")
        .into_iter()
        .filter(|s| s == "a" || s == "b")
        .collect();

    match slots.len() {
        2 => Outcome::pass("slots a and b are both populated"),
        1 => Outcome::warn(format!("only slot {} is populated", slots[0]))
            .evidence(
                "There is no previous generation to roll back to. This is normal \
                       immediately after a first install and should resolve on the first \
                       update.",
            )
            .remedy("steelctl update"),
        _ => Outcome::fail("no slot metadata found").remedy(
            "The deployment state is damaged. Boot the recovery entry and run \
                     `steelctl repair`.",
        ),
    }
}

fn check_boot_counting(ctx: &Context) -> Outcome {
    if !ctx.deployment.is_image() {
        return Outcome::skip(ctx.not_image_reason());
    }

    // systemd-bless-boot renames the entry to strip the counter once
    // boot-complete.target is reached. An entry still carrying a counter means
    // this boot has not been blessed.
    let entries = ctx.sys.list_dir("/efi/loader/entries");
    let counted: Vec<&String> = entries.iter().filter(|e| e.contains('+')).collect();

    if entries.is_empty() {
        return Outcome::skip("cannot read /efi/loader/entries (ESP not mounted here?)");
    }

    // A healthy machine has a blessed current entry; a staged update legitimately
    // carries a counter until it boots successfully.
    let blessed = entries.iter().any(|e| !e.contains('+'));

    match (blessed, counted.len()) {
        (true, 0) => Outcome::pass("current boot is blessed, no pending counted entries"),
        (true, n) => Outcome::pass(format!(
            "current boot is blessed, {n} staged entry(ies) pending"
        )),
        (false, _) => Outcome::warn("no blessed boot entry")
            .evidence(format!("entries: {}", entries.join(", ")))
            .evidence(
                "If this boot never reaches boot-complete.target the counter will \
                       run out and the previous generation will boot — which is working \
                       as designed, but you should know why.",
            )
            .remedy(
                "Check `systemctl status boot-complete.target` and whatever it \
                     depends on.",
            ),
    }
}

fn check_sysext_signed(ctx: &Context) -> Outcome {
    let loaded = ctx.sys.list_dir("/run/extensions");
    if loaded.is_empty() {
        return Outcome::pass("no system extensions are loaded");
    }
    // The image build records which extensions it signed. Anything loaded that
    // is not in that set arrived some other way.
    let allowed = ctx
        .sys
        .read("/usr/lib/steelos/signed-sysexts")
        .unwrap_or_default();
    let unsigned: Vec<String> = loaded
        .iter()
        .filter(|e| !allowed.lines().any(|a| a.trim() == e.as_str()))
        .cloned()
        .collect();

    if unsigned.is_empty() {
        Outcome::pass(format!("{} signed extension(s) loaded", loaded.len()))
    } else {
        Outcome::fail(format!("{} unsigned extension(s) loaded", unsigned.len()))
            .evidence_all(unsigned)
            .remedy("systemd-sysext unmerge, then sign the extension or remove it.")
    }
}

fn check_layering(ctx: &Context) -> Outcome {
    if !ctx.deployment.is_image() {
        return Outcome::skip(ctx.not_image_reason());
    }
    // An overlay or a writable bind on /usr is the shape every "just let me
    // install one package" workaround takes.
    let offenders: Vec<String> = ctx
        .sys
        .mounts()
        .into_iter()
        .filter(|m| m.target.starts_with("/usr") || m.target == "/etc/ld.so.preload")
        .filter(|m| m.fstype == "overlay" || !m.is_read_only())
        .map(|m| format!("{} ({}, {})", m.target, m.fstype, m.options.join(",")))
        .collect();

    if offenders.is_empty() {
        Outcome::pass("no writable or overlay mounts over the verified root")
    } else {
        Outcome::fail(format!("{} writable mount(s) over /usr", offenders.len()))
            .evidence_all(offenders)
            .remedy(
                "Unmount them. If you need extra software, use Flatpak, steel-shell, \
                     or a signed sysext — see docs/escape-hatches.md.",
            )
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

    fn ctx(dir: &PathBuf, deployment: Deployment) -> Context {
        Context {
            sys: Sysroot::new(dir),
            preset: Preset::Balanced,
            deployment,
            cmdline: KernelCmdline::parse(""),
            real_volume_unlocked: false,
        }
    }

    #[test]
    fn single_slot_warns_because_rollback_has_no_target() {
        let dir = std::env::temp_dir().join(format!("steel-check-dep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("var/lib/steelos/slots/a")).unwrap();
        let out = check_slots(&ctx(&dir, Deployment::Image));
        assert_eq!(out.status, Status::Warn);

        fs::create_dir_all(dir.join("var/lib/steelos/slots/b")).unwrap();
        assert_eq!(
            check_slots(&ctx(&dir, Deployment::Image)).status,
            Status::Pass
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn overlay_over_usr_is_a_failure() {
        let dir = std::env::temp_dir().join(format!("steel-check-dep2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("proc")).unwrap();
        fs::write(
            dir.join("proc/mounts"),
            "overlay /usr overlay rw,lowerdir=/usr,upperdir=/var/usr 0 0\n",
        )
        .unwrap();
        let out = check_layering(&ctx(&dir, Deployment::Image));
        assert_eq!(out.status, Status::Fail);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_sysexts_loaded_is_a_pass_not_a_skip() {
        let dir = std::env::temp_dir().join(format!("steel-check-dep3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            check_sysext_signed(&ctx(&dir, Deployment::Image)).status,
            Status::Pass
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
