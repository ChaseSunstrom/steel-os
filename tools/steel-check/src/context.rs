//! What the checks are allowed to know about the machine before they run.

use crate::sys::{KernelCmdline, Sysroot};

/// The hardening preset the system was installed with. Checks consult this to
/// decide whether a measure is required, optional, or deliberately absent —
/// `compatible` exists precisely so that problem hardware can run SteelOS with
/// less protection, and reporting that as failure would be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Balanced,
    Strict,
    Compatible,
}

impl Preset {
    pub fn as_str(self) -> &'static str {
        match self {
            Preset::Balanced => "balanced",
            Preset::Strict => "strict",
            Preset::Compatible => "compatible",
        }
    }

    pub fn parse(s: &str) -> Option<Preset> {
        Some(match s.trim() {
            "balanced" => Preset::Balanced,
            "strict" => Preset::Strict,
            "compatible" => Preset::Compatible,
            _ => return None,
        })
    }

    pub fn is_strict(self) -> bool {
        self == Preset::Strict
    }
}

/// How this system was deployed. Phase 0 ships the hardening packages on stock
/// Arch, where the image-based measures do not exist yet; those checks report
/// `Skip` with a reason rather than pretending to pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deployment {
    /// SteelOS packages layered on a normal, mutable Arch install (Phase 0).
    Arch,
    /// A verity-protected A/B image deployment (Phase 1+).
    Image,
    /// A `steel-devmode` boot: verity disabled, `/usr` writable. Deliberately
    /// reduced protection; checks say so loudly rather than reporting failures
    /// the user already opted into.
    DevMode,
}

impl Deployment {
    pub fn as_str(self) -> &'static str {
        match self {
            Deployment::Arch => "arch",
            Deployment::Image => "image",
            Deployment::DevMode => "devmode",
        }
    }

    pub fn is_image(self) -> bool {
        self == Deployment::Image
    }
}

pub struct Context {
    pub sys: Sysroot,
    pub preset: Preset,
    pub deployment: Deployment,
    pub cmdline: KernelCmdline,
    /// True when steel-check is running inside an unlocked real profile.
    ///
    /// The duress checks are the only consumers. When false they must emit a
    /// fixed result identical on every machine — see `checks::duress`.
    pub real_volume_unlocked: bool,
}

impl Context {
    pub fn detect(sys: Sysroot, preset_override: Option<Preset>) -> Context {
        let cmdline = sys.kernel_cmdline();
        let deployment = detect_deployment(&sys, &cmdline);
        let preset = preset_override
            .or_else(|| {
                sys.read_trimmed("/etc/steelos/preset")
                    .and_then(|p| Preset::parse(&p))
            })
            .unwrap_or(Preset::Balanced);
        let real_volume_unlocked = detect_real_volume_unlocked(&sys);
        Context {
            sys,
            preset,
            deployment,
            cmdline,
            real_volume_unlocked,
        }
    }

    /// `Skip` reason used by every measure that only exists on image
    /// deployments. Centralised so the wording is identical everywhere, which
    /// matters for output stability.
    pub fn not_image_reason(&self) -> String {
        format!(
            "image-based measure, not applicable on {} deployments (Phase 1+)",
            self.deployment.as_str()
        )
    }
}

fn detect_deployment(sys: &Sysroot, cmdline: &KernelCmdline) -> Deployment {
    if cmdline.has("steelos.devmode") || sys.exists("/run/steelos/devmode") {
        return Deployment::DevMode;
    }
    // The image identity file is written into the image at build time; it
    // cannot exist on a package-layered install.
    if sys.exists("/usr/lib/steelos/image-id") || cmdline.has("roothash") {
        return Deployment::Image;
    }
    Deployment::Arch
}

/// Whether the caller is inside an unlocked real profile.
///
/// Deliberately conservative: the marker is created by the real volume's own
/// units after unlock and lives on a tmpfs, so a decoy or maintenance boot
/// never sees it. Getting this wrong in the permissive direction would make
/// steel-check reveal duress configuration from a decoy session, which is the
/// exact failure the deniability design cannot tolerate.
fn detect_real_volume_unlocked(sys: &Sysroot) -> bool {
    sys.exists("/run/steelos/real-volume-unlocked")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_parsing_rejects_unknown_values() {
        assert_eq!(Preset::parse("strict"), Some(Preset::Strict));
        assert_eq!(Preset::parse(" balanced\n"), Some(Preset::Balanced));
        assert_eq!(Preset::parse("paranoid"), None);
    }

    #[test]
    fn devmode_wins_over_image_detection() {
        // A devmode boot of an image deployment must report devmode: it has
        // verity disabled, and reporting it as a normal image deployment would
        // make every verity check a false failure.
        let cmdline = KernelCmdline::parse("roothash=abc steelos.devmode");
        let sys = Sysroot::new("/nonexistent-sysroot");
        assert_eq!(detect_deployment(&sys, &cmdline), Deployment::DevMode);
    }

    #[test]
    fn plain_arch_is_the_default_deployment() {
        let cmdline = KernelCmdline::parse("ro quiet");
        let sys = Sysroot::new("/nonexistent-sysroot");
        assert_eq!(detect_deployment(&sys, &cmdline), Deployment::Arch);
    }

    #[test]
    fn roothash_on_cmdline_implies_image_deployment() {
        let cmdline = KernelCmdline::parse("roothash=deadbeef ro");
        let sys = Sysroot::new("/nonexistent-sysroot");
        assert_eq!(detect_deployment(&sys, &cmdline), Deployment::Image);
    }
}
