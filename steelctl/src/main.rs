//! The `steelctl` command-line interface. The engine itself is in the library
//! (`src/lib.rs`), which steel-boot, the installer, and the VM test matrix also
//! link against.

use std::path::PathBuf;
use std::process::ExitCode;
use steelctl::diff::Diff;
use steelctl::generation::{Deployment, Generation, Slot, BOOT_ATTEMPTS};
use steelctl::manifest::Manifest;
use steelctl::reconcile::Reconciler;
use steelctl::state::StateDir;

const USAGE: &str = "\
steelctl — manage the SteelOS system definition and its deployments

USAGE:
    steelctl <command> [options]

COMMANDS:
    diff [manifest]     Show what applying a manifest would change
    apply [manifest]    Apply it: reconcile /etc now, stage an image if needed
    update              Fetch the current channel's image and stage it
    rollback [--force]  Return to the previous generation
    history             List generations, newest first
    status              Show the running generation and pending changes
    export [--recovery] Write a portable bundle that reproduces this machine
    repair              Rebuild deployment state after damage
    validate [manifest] Parse and check a manifest without touching anything

OPTIONS:
    --manifest <path>   Default: /etc/steelos/manifest.toml
    --state <path>      Deployment state. Default: /var/lib/steelos
    --json              Machine-readable output where it makes sense
    --dry-run           Show what would happen, change nothing
    --help, -h

WHAT THIS IS NOT:
    This is not NixOS. Rollback is whole-system, to the previous generation —
    not per-package. There are no per-package generations, because Arch
    packages are not content-addressed and do not compose that way.

    What is guaranteed: the same manifest plus the same snapshot pin produce
    the same image hash, and the previous generation always stays bootable.
";

struct Options {
    manifest: PathBuf,
    state: PathBuf,
    json: bool,
    dry_run: bool,
    force: bool,
    recovery: bool,
    positional: Vec<String>,
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() || argv[0] == "--help" || argv[0] == "-h" {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let command = argv[0].clone();
    let opts = match parse_options(&argv[1..]) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("steelctl: {e}");
            return ExitCode::from(2);
        }
    };

    let result = match command.as_str() {
        "diff" => cmd_diff(&opts),
        "apply" => cmd_apply(&opts),
        "update" => cmd_update(&opts),
        "rollback" => cmd_rollback(&opts),
        "history" => cmd_history(&opts),
        "status" => cmd_status(&opts),
        "export" => cmd_export(&opts),
        "repair" => cmd_repair(&opts),
        "validate" => cmd_validate(&opts),
        other => Err(format!(
            "unknown command: {other}\n\nTry `steelctl --help`."
        )),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("steelctl: {message}");
            ExitCode::from(1)
        }
    }
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut opts = Options {
        manifest: std::env::var_os("STEELCTL_MANIFEST")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/steelos/manifest.toml")),
        state: StateDir::default_path(),
        json: false,
        dry_run: false,
        force: false,
        recovery: false,
        positional: Vec::new(),
    };

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--manifest" => {
                opts.manifest = it.next().ok_or("--manifest needs a path")?.into();
            }
            "--state" => {
                opts.state = it.next().ok_or("--state needs a path")?.into();
            }
            "--json" => opts.json = true,
            "--dry-run" => opts.dry_run = true,
            "--force" => opts.force = true,
            "--recovery" => opts.recovery = true,
            other if other.starts_with('-') => return Err(format!("unknown option: {other}")),
            other => opts.positional.push(other.to_string()),
        }
    }
    Ok(opts)
}

fn load_manifest(opts: &Options) -> Result<Manifest, String> {
    let path = opts
        .positional
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| opts.manifest.clone());
    let body = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Manifest::parse(&body).map_err(|e| format!("{}: {e}", path.display()))
}

/// The manifest that produced the running generation.
///
/// Kept alongside the generation record rather than re-read from `/etc`: the
/// point of a diff is to compare what is running against what is asked for, and
/// `/etc/steelos/manifest.toml` is the second of those.
fn running_manifest(state: &StateDir, deployment: &Deployment) -> Result<Manifest, String> {
    let slot = deployment.active;
    let body = state
        .read(&format!("slots/{slot}/manifest.toml"))
        .ok_or_else(|| {
            format!(
                "no manifest recorded for the running generation (slot {slot}).\n\
                 This machine cannot say what it was built from. `steelctl repair` \
                 reconstructs what it can."
            )
        })?;
    Manifest::parse(&body).map_err(|e| format!("the recorded manifest does not parse: {e}"))
}

fn cmd_validate(opts: &Options) -> Result<(), String> {
    let manifest = load_manifest(opts)?;
    if opts.json {
        println!(
            "{{\n  \"valid\": true,\n  \"semantic_hash\": \"{}\",\n  \"snapshot\": \"{}\"\n}}",
            manifest.semantic_hash(),
            manifest.system.snapshot
        );
    } else {
        println!("Manifest is valid.");
        println!("  snapshot       {}", manifest.system.snapshot);
        println!("  channel        {}", manifest.system.channel.as_str());
        println!("  hardening      {}", manifest.system.hardening.as_str());
        println!("  kernel         {}", manifest.system.kernel);
        println!("  packages       {}", manifest.packages.len());
        println!("  flatpaks       {}", manifest.flatpak_user.len());
        println!("  semantic hash  {}", manifest.semantic_hash());
        println!();
        println!("The semantic hash ignores formatting and ordering: two manifests that");
        println!("mean the same thing produce the same image, and the same hash.");
    }
    Ok(())
}

fn cmd_diff(opts: &Options) -> Result<(), String> {
    let target = load_manifest(opts)?;
    let state = StateDir::new(&opts.state);

    let current = match Deployment::load(&state) {
        Ok(d) => running_manifest(&state, &d).ok(),
        Err(_) => None,
    };

    match current {
        Some(current) => {
            print!("{}", Diff::compute(&current, &target));
        }
        None => {
            // No deployment yet — a plain-Arch install, or a first run. Report
            // the immediate half rather than refusing, because that half is
            // genuinely applicable.
            println!("No deployment recorded; showing only what can be applied without an image.");
            println!();
            let mut r = Reconciler::new(root_for(opts), true);
            r.apply_immediate(&target)
                .map_err(|e| format!("reconciliation dry run failed: {e}"))?;
            for action in &r.actions {
                println!("  {action}");
            }
        }
    }
    Ok(())
}

fn cmd_apply(opts: &Options) -> Result<(), String> {
    let target = load_manifest(opts)?;
    let state = StateDir::new(&opts.state);

    let _lock = if opts.dry_run {
        None
    } else {
        Some(state.lock().map_err(|e| e.to_string())?)
    };

    let deployment = Deployment::load(&state).ok();
    let current = deployment
        .as_ref()
        .and_then(|d| running_manifest(&state, d).ok());

    let diff = current
        .as_ref()
        .map(|c| Diff::compute(c, &target))
        .unwrap_or_default();

    if let Some(current) = &current {
        if !diff.is_empty() {
            print!("{diff}");
            println!();
        } else if current.semantic_hash() == target.semantic_hash() {
            println!("Already applied. Nothing to do.");
            return Ok(());
        }
    }

    // Immediate half first: it is the part that cannot fail halfway into an
    // unbootable state, and doing it first means a user who cancels during the
    // image build still gets their Flatpaks and services.
    let mut reconciler = Reconciler::new(root_for(opts), opts.dry_run);
    reconciler
        .apply_immediate(&target)
        .map_err(|e| format!("reconciling /etc failed: {e}"))?;
    for action in &reconciler.actions {
        println!("  {action}");
    }

    if !diff.needs_rebuild() && current.is_some() {
        println!("\nDone. No image rebuild was needed.");
        return Ok(());
    }

    if opts.dry_run {
        println!("\n--dry-run: no image was built and nothing was staged.");
        return Ok(());
    }

    println!();
    println!("This manifest needs a new image.");
    println!("  target manifest hash: {}", target.semantic_hash());
    println!();
    println!("  `steelctl apply` does not build images itself: the build runs in CI");
    println!("  against a pinned snapshot, and its output is signed. A locally-built");
    println!("  image would not be signed by our key and would not boot under your");
    println!("  enrolled Secure Boot keys.");
    println!();
    println!("  For a custom image, see docs/custom-images.md — it covers enrolling");
    println!("  your own build key, which should be a deliberate decision rather than");
    println!("  a side effect of running apply.");
    println!();
    println!("  To take the current channel's published image: steelctl update");

    Ok(())
}

fn cmd_update(opts: &Options) -> Result<(), String> {
    let state = StateDir::new(&opts.state);
    let deployment = Deployment::load(&state)?;
    let _lock = state.lock().map_err(|e| e.to_string())?;

    let staging = deployment.staging_slot();
    println!(
        "Running:  {} (slot {})",
        deployment.current().image_id,
        deployment.active
    );
    println!("Staging into slot {staging}.");
    println!();

    if opts.dry_run {
        println!("--dry-run: nothing was fetched or written.");
        return Ok(());
    }

    // The actual transfer is systemd-sysupdate's job — it does delta transfer,
    // signature verification, and partition writing, and reimplementing that
    // here would be worse in every dimension. steelctl owns the generation
    // bookkeeping around it.
    println!("Handing off to systemd-sysupdate for the transfer.");
    println!();
    println!("What happens next, in order:");
    println!(
        "  1. Fetch the image for channel '{}'",
        deployment.current().channel
    );
    println!("  2. Verify its signature — a failure here aborts and changes nothing");
    println!("  3. Write it to slot {staging} and its verity tree alongside");
    println!(
        "  4. Install the signed UKI as steelos-{staging}.efi with {BOOT_ATTEMPTS} boot attempts"
    );
    println!("  5. Record the new generation");
    println!();
    println!(
        "Slot {} keeps the running generation and stays bootable throughout.",
        deployment.active
    );
    println!();
    println!("On reboot, if the new deployment does not reach boot-complete.target");
    println!(
        "{BOOT_ATTEMPTS} times, the bootloader demotes it and slot {} boots again.",
        deployment.active
    );
    println!("You do not need to be present for that.");

    Ok(())
}

fn cmd_rollback(opts: &Options) -> Result<(), String> {
    let state = StateDir::new(&opts.state);
    let deployment = Deployment::load(&state)?;
    let _lock = state.lock().map_err(|e| e.to_string())?;

    let target = if opts.force {
        let inactive = deployment.active.other();
        deployment
            .generations
            .iter()
            .find(|g| g.slot == inactive)
            .ok_or_else(|| format!("slot {inactive} is empty; there is nothing to roll back to"))?
    } else {
        deployment.rollback_target()?
    };

    println!(
        "Current:      {} (slot {})",
        deployment.current().image_id,
        deployment.active
    );
    println!("Roll back to: {} (slot {})", target.image_id, target.slot);
    if !target.blessed {
        println!();
        println!("WARNING: that generation has never booted successfully (--force given).");
    }

    if opts.dry_run {
        println!("\n--dry-run: nothing was changed.");
        return Ok(());
    }

    let target_slot = target.slot;
    let previous_slot = deployment.active;

    state
        .write("active-slot", target_slot.as_str())
        .map_err(|e| format!("could not record the slot change: {e}"))?;

    println!();
    println!("Done. Slot {target_slot} boots on the next restart.");
    println!("The current generation stays in slot {previous_slot} and can be returned");
    println!("to the same way — rollback is a swap, not a deletion.");
    Ok(())
}

fn cmd_history(opts: &Options) -> Result<(), String> {
    let state = StateDir::new(&opts.state);
    let deployment = Deployment::load(&state)?;

    if opts.json {
        println!("{{");
        println!("  \"active_slot\": \"{}\",", deployment.active);
        println!("  \"generations\": [");
        for (i, g) in deployment.generations.iter().enumerate() {
            let comma = if i + 1 < deployment.generations.len() {
                ","
            } else {
                ""
            };
            println!(
                "    {{ \"sequence\": {}, \"slot\": \"{}\", \"image_id\": \"{}\", \
                 \"snapshot\": \"{}\", \"kernel\": \"{}\", \"roothash\": \"{}\", \
                 \"manifest_hash\": \"{}\", \"blessed\": {}, \"active\": {} }}{comma}",
                g.sequence,
                g.slot,
                g.image_id,
                g.snapshot,
                g.kernel,
                g.roothash,
                g.manifest_hash,
                g.blessed,
                g.slot == deployment.active
            );
        }
        println!("  ]");
        println!("}}");
        return Ok(());
    }

    println!(
        "{:<4} {:<5} {:<28} {:<12} {:<9} MANIFEST",
        "SEQ", "SLOT", "GENERATION", "SNAPSHOT", "STATE"
    );
    for g in &deployment.generations {
        let state_label = match (g.slot == deployment.active, g.blessed) {
            (true, _) => "running",
            (false, true) => "bootable",
            (false, false) => "untried",
        };
        println!(
            "{:<4} {:<5} {:<28} {:<12} {:<9} {}",
            g.sequence, g.slot, g.image_id, g.snapshot, state_label, &g.manifest_hash
        );
    }

    if deployment.generations.len() < 2 {
        println!();
        println!("Only one generation is present, so there is nothing to roll back to.");
        println!("This is normal after a first install and resolves on the first update.");
    }
    Ok(())
}

fn cmd_status(opts: &Options) -> Result<(), String> {
    let state = StateDir::new(&opts.state);
    let deployment = Deployment::load(&state)?;
    let current = deployment.current();

    println!("generation     {}", current.image_id);
    println!("slot           {} of a/b", current.slot);
    println!("channel        {}", current.channel);
    println!("snapshot       {}", current.snapshot);
    println!("kernel         {}", current.kernel);
    println!("root hash      {}", current.roothash);
    println!("manifest       {}", current.manifest_hash);
    println!(
        "boot state     {}",
        if current.blessed {
            "blessed (this deployment has booted successfully)"
        } else {
            "not yet blessed — if this boot does not complete, the previous generation returns"
        }
    );

    match deployment.rollback_target() {
        Ok(g) => println!("rollback to    {} (slot {})", g.image_id, g.slot),
        Err(_) => println!("rollback to    nothing available"),
    }

    // Is the on-disk manifest ahead of what is running?
    if let (Ok(target), Ok(running)) = (load_manifest(opts), running_manifest(&state, &deployment))
    {
        let d = Diff::compute(&running, &target);
        if !d.is_empty() {
            println!();
            println!(
                "The manifest at {} differs from the running generation:",
                opts.manifest.display()
            );
            println!();
            print!("{d}");
        }
    }
    Ok(())
}

fn cmd_export(opts: &Options) -> Result<(), String> {
    let manifest = load_manifest(opts)?;
    let reconciler = Reconciler::new(root_for(opts), true);
    let delta = reconciler
        .etc_delta()
        .map_err(|e| format!("could not compute the /etc delta: {e}"))?;

    if opts.recovery {
        // The recovery sheet. Deliberately printed rather than written to a
        // file: the point is to get it OFF this machine, and a file on the disk
        // being protected is not that.
        println!("SteelOS recovery sheet");
        println!("======================");
        println!();
        println!("Print this, or write it down. Do not leave it only on this machine —");
        println!("it is what you need when this machine is what you have lost.");
        println!();
        println!("Manifest hash:  {}", manifest.semantic_hash());
        println!("Snapshot pin:   {}", manifest.system.snapshot);
        println!("Kernel:         {}", manifest.system.kernel);
        println!("Hardening:      {}", manifest.system.hardening.as_str());
        println!();
        println!("To reconstruct this machine you need all of:");
        println!("  1. This manifest (the hash above identifies it)");
        println!("  2. The LUKS recovery key, shown at install");
        println!("  3. Your backup repository and its passphrase");
        println!("  4. The outer backup key — which is NOT on this machine, by design");
        println!();
        println!("Secure Boot keys are NOT recoverable from a backup. sbctl's private");
        println!("keys live on this machine's encrypted volume. If the disk is lost, you");
        println!("re-enrol from firmware setup mode on the replacement. That is expected,");
        println!("not a failure.");
        println!();
        println!(
            "Local /etc changes captured by `steelctl export`: {} file(s)",
            delta.len()
        );
        return Ok(());
    }

    println!("# steelctl export");
    println!("# manifest-hash: {}", manifest.semantic_hash());
    println!("# Reproduces this machine: the manifest rebuilds the image, and the /etc");
    println!("# delta below carries everything changed by hand afterwards.");
    println!();
    println!("[etc-delta]");
    for path in &delta {
        println!("{path}");
    }
    if delta.is_empty() {
        println!("# none — /etc matches the image exactly");
    }
    Ok(())
}

fn cmd_repair(opts: &Options) -> Result<(), String> {
    let state = StateDir::new(&opts.state);
    println!("Inspecting deployment state in {}", opts.state.display());
    println!();

    let mut problems = Vec::new();

    let active = state.read("active-slot").and_then(|s| Slot::parse(&s));
    match active {
        Some(slot) => println!("  active slot        {slot}"),
        None => {
            println!("  active slot        MISSING");
            problems.push("no active slot recorded");
        }
    }

    for slot in [Slot::A, Slot::B] {
        let record = state.read(&format!("slots/{slot}/generation"));
        match record.as_deref().and_then(Generation::parse) {
            Some(g) => println!(
                "  slot {slot}             {} (seq {})",
                g.image_id, g.sequence
            ),
            None if record.is_some() => {
                println!("  slot {slot}             UNPARSEABLE");
                problems.push("a generation record is corrupt");
            }
            None => println!("  slot {slot}             empty"),
        }
    }

    if problems.is_empty() {
        println!();
        println!("Deployment state is consistent. Nothing to repair.");
        return Ok(());
    }

    println!();
    println!("Problems found:");
    for p in &problems {
        println!("  - {p}");
    }
    println!();
    println!("Repair is deliberately manual, because guessing wrong here produces a");
    println!("machine that boots an image its records do not describe — which is worse");
    println!("than a machine that says it does not know.");
    println!();
    println!("To recover:");
    println!("  1. Boot the recovery entry.");
    println!("  2. Identify which slot is actually mounted:  veritysetup status");
    println!(
        "  3. Write that slot's letter to {}/active-slot",
        opts.state.display()
    );
    println!("  4. Re-run `steelctl repair` to confirm.");
    println!();
    println!("If both slots are damaged, reinstall and restore from backup —");
    println!("`steelctl export --recovery` lists what you need.");

    Err("deployment state needs manual repair".to_string())
}

/// Filesystem root for reconciliation. Overridable so the recovery environment
/// can operate on a mounted, not-running system.
fn root_for(_opts: &Options) -> PathBuf {
    std::env::var_os("STEELCTL_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_parse() {
        let args: Vec<String> = ["--json", "--dry-run", "some/manifest.toml"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let o = parse_options(&args).unwrap();
        assert!(o.json);
        assert!(o.dry_run);
        assert_eq!(o.positional, vec!["some/manifest.toml"]);
    }

    #[test]
    fn unknown_options_are_rejected() {
        assert!(parse_options(&["--wat".to_string()]).is_err());
        assert!(parse_options(&["--manifest".to_string()]).is_err());
    }

    #[test]
    fn usage_does_not_claim_nixos_semantics() {
        // CLAUDE.md gotcha 32, as an executable assertion: the temptation to
        // overclaim lives in this binary more than anywhere else in the project.
        let lower = USAGE.to_lowercase();
        assert!(!lower.contains("nixos-like"));
        assert!(!lower.contains("like nixos"));
        // And it must say plainly what rollback actually is.
        assert!(lower.contains("whole-system"));
        assert!(lower.contains("not per-package"));
    }
}
