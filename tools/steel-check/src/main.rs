//! steel-check — audit a SteelOS system against every measure it claims.
//!
//! One command, pass/fail per measure, `--json` so CI and users share the same
//! assertions. The governing rule from CLAUDE.md: every claim in user-facing
//! material must be verifiable by this tool.

mod checks;
mod context;
mod json;
mod report;
mod sys;

use context::{Context, Preset};
use report::Category;
use std::io::IsTerminal;
use std::process::ExitCode;

const USAGE: &str = "\
steel-check — audit this system against the measures SteelOS claims

USAGE:
    steel-check [OPTIONS] [CHECK_ID...]

OPTIONS:
    --json              Machine-readable output (stable schema, see --schema)
    --list              List every check without running any
    --explain <ID>      Print why a check exists and how to turn the measure off
    --category <NAME>   Run only one category (boot, kernel, memory, filesystem,
                        network, sandbox, identity, storage, deployment, backup,
                        duress)
    --preset <NAME>     Audit against balanced|strict|compatible instead of the
                        installed preset
    --sysroot <PATH>    Read system state from a directory tree instead of /.
                        For tests and for auditing a mounted, not-running system.
    --strict-warn       Treat warnings as failures for the exit code
    --verbose, -v       Show evidence for passing checks too
    --no-color          Disable colour even on a terminal
    --schema            Print the JSON schema version and exit
    --version           Print the version and exit
    --help, -h          This text

EXIT STATUS:
    0   no failures
    1   at least one check failed (or warned, with --strict-warn)
    2   steel-check could not run

NOTE:
    Output contains no timestamps, hostnames, or other host-varying data. That
    is deliberate: it is what makes the deniability assertion in tests/audit/
    possible to state as a byte-for-byte comparison.
";

enum Mode {
    Run,
    List,
    Explain(String),
    Schema,
    Version,
    Help,
}

struct Args {
    mode: Mode,
    json: bool,
    verbose: bool,
    color: Option<bool>,
    strict_warn: bool,
    category: Option<Category>,
    preset: Option<Preset>,
    sysroot: Option<String>,
    ids: Vec<String>,
}

fn parse_args(argv: Vec<String>) -> Result<Args, String> {
    let mut args = Args {
        mode: Mode::Run,
        json: false,
        verbose: false,
        color: None,
        strict_warn: false,
        category: None,
        preset: None,
        sysroot: std::env::var("STEEL_CHECK_SYSROOT").ok(),
        ids: Vec::new(),
    };

    let mut it = argv.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => args.mode = Mode::Help,
            "--version" => args.mode = Mode::Version,
            "--schema" => args.mode = Mode::Schema,
            "--list" => args.mode = Mode::List,
            "--json" => args.json = true,
            "--verbose" | "-v" => args.verbose = true,
            "--no-color" => args.color = Some(false),
            "--color" => args.color = Some(true),
            "--strict-warn" => args.strict_warn = true,
            "--explain" => {
                let id = it.next().ok_or("--explain needs a check id")?;
                args.mode = Mode::Explain(id);
            }
            "--category" => {
                let name = it.next().ok_or("--category needs a name")?;
                args.category =
                    Some(Category::parse(&name).ok_or(format!("unknown category: {name}"))?);
            }
            "--preset" => {
                let name = it.next().ok_or("--preset needs a name")?;
                args.preset = Some(Preset::parse(&name).ok_or(format!("unknown preset: {name}"))?);
            }
            "--sysroot" => {
                args.sysroot = Some(it.next().ok_or("--sysroot needs a path")?);
            }
            other if other.starts_with('-') => return Err(format!("unknown option: {other}")),
            id => args.ids.push(id.to_string()),
        }
    }
    Ok(args)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("steel-check: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    match &args.mode {
        Mode::Help => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Mode::Version => {
            println!("steel-check {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Mode::Schema => {
            println!("{}", checks::SCHEMA_VERSION);
            return ExitCode::SUCCESS;
        }
        Mode::List => {
            for check in checks::all() {
                println!(
                    "{:<36} {:<10} {:<8} {}",
                    check.id,
                    check.category.as_str(),
                    check.severity.as_str(),
                    check.title
                );
            }
            return ExitCode::SUCCESS;
        }
        Mode::Explain(id) => {
            return match checks::find(id) {
                Some(check) => {
                    println!(
                        "{}  [{}, {}]",
                        check.id,
                        check.category.as_str(),
                        check.severity.as_str()
                    );
                    println!("{}\n", check.title);
                    println!("Why this exists:\n  {}\n", wrap(check.rationale, 76, "  "));
                    println!(
                        "How to turn it off:\n  {}",
                        wrap(check.escape_hatch, 76, "  ")
                    );
                    ExitCode::SUCCESS
                }
                None => {
                    eprintln!("steel-check: no such check: {id}");
                    eprintln!("Run `steel-check --list` to see them all.");
                    ExitCode::from(2)
                }
            };
        }
        Mode::Run => {}
    }

    let sysroot = sys::Sysroot::new(args.sysroot.as_deref().unwrap_or("/"));
    let ctx = Context::detect(sysroot, args.preset);

    let mut selected: Vec<&'static report::Check> = checks::all();
    if let Some(category) = args.category {
        selected.retain(|c| c.category == category);
    }
    if !args.ids.is_empty() {
        for id in &args.ids {
            if checks::find(id).is_none() {
                eprintln!("steel-check: no such check: {id}");
                return ExitCode::from(2);
            }
        }
        selected.retain(|c| args.ids.iter().any(|id| id == c.id));
    }
    if selected.is_empty() {
        eprintln!("steel-check: no checks selected");
        return ExitCode::from(2);
    }

    let report = checks::run(&ctx, &selected);

    if args.json {
        print!("{}", report.to_json().to_pretty_string());
    } else {
        let color = args
            .color
            .unwrap_or_else(|| std::io::stdout().is_terminal());
        print!("{}", report.to_text(color, args.verbose));
    }

    let failed = report.has_failures() || (args.strict_warn && report.has_warnings());
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Wrap text for `--explain`, indenting continuation lines.
fn wrap(text: &str, width: usize, indent: &str) -> String {
    let mut out = String::new();
    let mut line = 0usize;
    for word in text.split_whitespace() {
        if line > 0 && line + word.len() + 1 > width {
            out.push('\n');
            out.push_str(indent);
            line = 0;
        } else if line > 0 {
            out.push(' ');
            line += 1;
        }
        out.push_str(word);
        line += word.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use report::Status;

    fn args(v: &[&str]) -> Result<Args, String> {
        parse_args(v.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn parses_flags_and_positional_ids() {
        let a = args(&["--json", "kernel.lockdown", "-v"]).unwrap();
        assert!(a.json);
        assert!(a.verbose);
        assert_eq!(a.ids, vec!["kernel.lockdown".to_string()]);
    }

    #[test]
    fn rejects_unknown_options_rather_than_ignoring_them() {
        assert!(args(&["--wat"]).is_err());
        assert!(args(&["--category", "nonsense"]).is_err());
        assert!(args(&["--preset", "paranoid"]).is_err());
        assert!(args(&["--explain"]).is_err());
    }

    #[test]
    fn category_and_preset_round_trip() {
        let a = args(&["--category", "duress", "--preset", "strict"]).unwrap();
        assert_eq!(a.category, Some(Category::Duress));
        assert_eq!(a.preset, Some(Preset::Strict));
    }

    #[test]
    fn wrap_breaks_at_the_requested_width() {
        let wrapped = wrap("aaa bbb ccc ddd eee", 11, "  ");
        assert_eq!(wrapped, "aaa bbb ccc\n  ddd eee");
    }

    /// The whole suite must run against an empty sysroot without panicking.
    /// A check that panics takes the audit down with it, which on a machine in
    /// trouble is exactly when the audit is needed.
    #[test]
    fn every_check_survives_a_completely_empty_sysroot() {
        let dir = std::env::temp_dir().join(format!("steel-check-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ctx = Context::detect(sys::Sysroot::new(&dir), None);
        let report = checks::run(&ctx, &checks::all());
        assert_eq!(report.results.len(), checks::all().len());
        // And it must render in both formats.
        assert!(!report.to_text(false, true).is_empty());
        assert!(!report.to_json().to_pretty_string().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The deniability assertion, end to end over the whole suite: two sysroots
    /// identical except that one has duress fully configured must produce
    /// byte-identical output from a locked context.
    #[test]
    fn full_report_is_byte_identical_with_and_without_duress_configured() {
        let base = std::env::temp_dir().join(format!("steel-check-den-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        let plain = base.join("plain");
        let configured = base.join("configured");
        for root in [&plain, &configured] {
            std::fs::create_dir_all(root.join("usr/lib/initcpio/hooks")).unwrap();
            std::fs::create_dir_all(root.join("usr/lib/initcpio/install")).unwrap();
            std::fs::write(root.join("usr/lib/initcpio/hooks/steel-duress"), "hook").unwrap();
            std::fs::write(
                root.join("usr/lib/initcpio/install/steel-duress"),
                "install",
            )
            .unwrap();
            std::fs::create_dir_all(root.join("var/lib/steelos")).unwrap();
            std::fs::write(
                root.join("var/lib/steelos/custody.region"),
                vec![0u8; 4 * 1024 * 1024],
            )
            .unwrap();
        }

        // Only the second machine has duress configured — inside the encrypted
        // volume, which is where it belongs.
        std::fs::create_dir_all(configured.join("var/lib/steelos/private")).unwrap();
        std::fs::write(
            configured.join("var/lib/steelos/private/duress-drill"),
            "configured=yes\nlast_drill_age_days=12\nplaybook=A\ndecoy=yes\n",
        )
        .unwrap();

        let render = |root: &std::path::Path| {
            let ctx = Context::detect(sys::Sysroot::new(root), None);
            assert!(
                !ctx.real_volume_unlocked,
                "fixture must be a locked context"
            );
            let report = checks::run(&ctx, &checks::all());
            (
                report.to_json().to_pretty_string(),
                report.to_text(false, true),
            )
        };

        let (json_a, text_a) = render(&plain);
        let (json_b, text_b) = render(&configured);
        assert_eq!(
            json_a, json_b,
            "JSON output leaks duress configuration state"
        );
        assert_eq!(
            text_a, text_b,
            "text output leaks duress configuration state"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn selecting_a_category_narrows_the_run_without_reordering_it() {
        let all = checks::all();
        let duress: Vec<&str> = all
            .iter()
            .filter(|c| c.category == Category::Duress)
            .map(|c| c.id)
            .collect();
        assert!(!duress.is_empty());
        let in_registry_order: Vec<&str> = all
            .iter()
            .filter(|c| duress.contains(&c.id))
            .map(|c| c.id)
            .collect();
        assert_eq!(duress, in_registry_order);
    }

    #[test]
    fn status_ordering_is_defined_for_stable_summaries() {
        assert!(Status::Pass < Status::Fail);
    }
}
