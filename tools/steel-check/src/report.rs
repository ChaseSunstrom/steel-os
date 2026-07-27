//! Check definitions, results, and rendering.
//!
//! ## The byte-identical-output rule
//!
//! CLAUDE.md requires that `steel-check` produce byte-identical output on a
//! machine with duress configured and one without, when run from a context that
//! has not unlocked the real volume. Two consequences are enforced here rather
//! than left to the individual checks:
//!
//!  1. **No volatile fields.** The report contains no timestamps, hostnames,
//!     serial numbers, or run identifiers. If you are tempted to add one, add it
//!     to a separate command instead — a single volatile byte turns the
//!     deniability assertion into an unrunnable test.
//!  2. **Fixed check set and fixed order.** Every check in the registry runs and
//!     is reported on every machine. Checks are never added or removed based on
//!     configuration state; they resolve to `Skip` with a reason that is itself
//!     identical across machines in the same class.
//!
//! `tests/audit/` turns this into an executable assertion.

use crate::json::Value;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// The measure is in force. Verified against running state where possible.
    Pass,
    /// The measure is claimed but not in force. Always actionable.
    Fail,
    /// In force but weaker than the preset intends, or unverifiable in a way
    /// the user should know about.
    Warn,
    /// Not applicable to this system, or not verifiable without privileges the
    /// current context lacks. Never used to paper over a failure.
    Skip,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Warn => "warn",
            Status::Skip => "skip",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Warn => "WARN",
            Status::Skip => "SKIP",
        }
    }

    fn ansi(self) -> &'static str {
        match self {
            Status::Pass => "\x1b[32m",
            Status::Fail => "\x1b[31m",
            Status::Warn => "\x1b[33m",
            Status::Skip => "\x1b[90m",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// A failure invalidates a core threat-model claim (verified boot, root
    /// immutability, encryption at rest).
    Critical,
    /// A failure removes a defence the preset promises.
    High,
    /// Defence in depth; a failure degrades but does not remove a guarantee.
    Medium,
    /// Reported for completeness; not a hardening measure on its own.
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    Boot,
    Kernel,
    Memory,
    Filesystem,
    Network,
    Sandbox,
    Identity,
    Storage,
    Deployment,
    Backup,
    Duress,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Boot => "boot",
            Category::Kernel => "kernel",
            Category::Memory => "memory",
            Category::Filesystem => "filesystem",
            Category::Network => "network",
            Category::Sandbox => "sandbox",
            Category::Identity => "identity",
            Category::Storage => "storage",
            Category::Deployment => "deployment",
            Category::Backup => "backup",
            Category::Duress => "duress",
        }
    }

    pub fn parse(s: &str) -> Option<Category> {
        Some(match s {
            "boot" => Category::Boot,
            "kernel" => Category::Kernel,
            "memory" => Category::Memory,
            "filesystem" => Category::Filesystem,
            "network" => Category::Network,
            "sandbox" => Category::Sandbox,
            "identity" => Category::Identity,
            "storage" => Category::Storage,
            "deployment" => Category::Deployment,
            "backup" => Category::Backup,
            "duress" => Category::Duress,
            _ => return None,
        })
    }

    pub const ALL: [Category; 11] = [
        Category::Boot,
        Category::Kernel,
        Category::Memory,
        Category::Filesystem,
        Category::Network,
        Category::Sandbox,
        Category::Identity,
        Category::Storage,
        Category::Deployment,
        Category::Backup,
        Category::Duress,
    ];
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of running one check.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub status: Status,
    /// One line, present tense, stating what is true. Not advice.
    pub detail: String,
    /// The raw facts the verdict rests on, so a reader can disagree with us.
    pub evidence: Vec<String>,
    /// What to do about a Fail or Warn. Omitted for Pass and Skip.
    pub remedy: Option<String>,
}

impl Outcome {
    pub fn new(status: Status, detail: impl Into<String>) -> Outcome {
        Outcome {
            status,
            detail: detail.into(),
            evidence: Vec::new(),
            remedy: None,
        }
    }

    pub fn pass(detail: impl Into<String>) -> Outcome {
        Outcome::new(Status::Pass, detail)
    }

    pub fn fail(detail: impl Into<String>) -> Outcome {
        Outcome::new(Status::Fail, detail)
    }

    pub fn warn(detail: impl Into<String>) -> Outcome {
        Outcome::new(Status::Warn, detail)
    }

    pub fn skip(detail: impl Into<String>) -> Outcome {
        Outcome::new(Status::Skip, detail)
    }

    pub fn evidence(mut self, line: impl Into<String>) -> Outcome {
        self.evidence.push(line.into());
        self
    }

    pub fn evidence_all<I: IntoIterator<Item = String>>(mut self, lines: I) -> Outcome {
        self.evidence.extend(lines);
        self
    }

    pub fn remedy(mut self, remedy: impl Into<String>) -> Outcome {
        self.remedy = Some(remedy.into());
        self
    }
}

/// A single auditable claim.
///
/// Every hardening measure SteelOS ships must have exactly one of these, and
/// every user-facing claim must be traceable to one (`CLAUDE.md`: "every claim
/// in user-facing material must be verifiable by this tool").
pub struct Check {
    /// Stable identifier. Referenced by docs, CI, and `--explain`; changing one
    /// is a breaking change to the JSON contract.
    pub id: &'static str,
    pub title: &'static str,
    pub category: Category,
    pub severity: Severity,
    /// Why this measure exists, in terms of the threat model. Shown by
    /// `--explain`. If you cannot write this line, the measure is theatre and
    /// should not ship (design principle 7).
    pub rationale: &'static str,
    /// How to turn the measure off, because principle 6 requires every measure
    /// to have a documented, discoverable escape hatch.
    pub escape_hatch: &'static str,
    pub run: fn(&crate::context::Context) -> Outcome,
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub id: &'static str,
    pub title: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub outcome: Outcome,
}

impl CheckResult {
    fn to_json(&self) -> Value {
        let mut fields = vec![
            ("id", Value::str(self.id)),
            ("title", Value::str(self.title)),
            ("category", Value::str(self.category.as_str())),
            ("severity", Value::str(self.severity.as_str())),
            ("status", Value::str(self.outcome.status.as_str())),
            ("detail", Value::str(&self.outcome.detail)),
            (
                "evidence",
                Value::array(self.outcome.evidence.iter().map(Value::str)),
            ),
        ];
        fields.push((
            "remedy",
            match &self.outcome.remedy {
                Some(r) => Value::str(r),
                None => Value::Null,
            },
        ));
        Value::object(fields)
    }
}

pub struct Report {
    pub schema_version: u32,
    pub preset: String,
    pub deployment: String,
    pub results: Vec<CheckResult>,
}

impl Report {
    pub fn counts(&self) -> BTreeMap<Status, usize> {
        let mut counts = BTreeMap::new();
        for status in [Status::Pass, Status::Fail, Status::Warn, Status::Skip] {
            counts.insert(status, 0);
        }
        for r in &self.results {
            *counts.entry(r.outcome.status).or_insert(0) += 1;
        }
        counts
    }

    pub fn has_failures(&self) -> bool {
        self.results
            .iter()
            .any(|r| r.outcome.status == Status::Fail)
    }

    pub fn has_warnings(&self) -> bool {
        self.results
            .iter()
            .any(|r| r.outcome.status == Status::Warn)
    }

    pub fn to_json(&self) -> Value {
        let counts = self.counts();
        Value::object([
            ("schema_version", Value::Int(self.schema_version as i64)),
            ("tool", Value::str("steel-check")),
            ("tool_version", Value::str(env!("CARGO_PKG_VERSION"))),
            ("preset", Value::str(&self.preset)),
            ("deployment", Value::str(&self.deployment)),
            (
                "summary",
                Value::object([
                    ("pass", Value::Int(counts[&Status::Pass] as i64)),
                    ("fail", Value::Int(counts[&Status::Fail] as i64)),
                    ("warn", Value::Int(counts[&Status::Warn] as i64)),
                    ("skip", Value::Int(counts[&Status::Skip] as i64)),
                ]),
            ),
            (
                "checks",
                Value::array(self.results.iter().map(CheckResult::to_json)),
            ),
        ])
    }

    /// Human-readable rendering, grouped by category, ordered deterministically.
    pub fn to_text(&self, color: bool, verbose: bool) -> String {
        let mut out = String::new();
        let (c_reset, c_bold, c_dim) = if color {
            ("\x1b[0m", "\x1b[1m", "\x1b[90m")
        } else {
            ("", "", "")
        };

        out.push_str(&format!(
            "{c_bold}steel-check{c_reset} {}  preset={}  deployment={}\n\n",
            env!("CARGO_PKG_VERSION"),
            self.preset,
            self.deployment
        ));

        for category in Category::ALL {
            let in_cat: Vec<&CheckResult> = self
                .results
                .iter()
                .filter(|r| r.category == category)
                .collect();
            if in_cat.is_empty() {
                continue;
            }
            out.push_str(&format!("{c_bold}{}{c_reset}\n", category.as_str()));
            for r in in_cat {
                let (sc, se) = if color {
                    (r.outcome.status.ansi(), c_reset)
                } else {
                    ("", "")
                };
                out.push_str(&format!(
                    "  {sc}{:<4}{se}  {:<34}  {}\n",
                    r.outcome.status.label(),
                    r.id,
                    r.outcome.detail
                ));
                let show_detail =
                    verbose || matches!(r.outcome.status, Status::Fail | Status::Warn);
                if show_detail {
                    for line in &r.outcome.evidence {
                        out.push_str(&format!("        {c_dim}{line}{c_reset}\n"));
                    }
                    if let Some(remedy) = &r.outcome.remedy {
                        out.push_str(&format!("        {c_dim}fix: {remedy}{c_reset}\n"));
                    }
                }
            }
            out.push('\n');
        }

        let counts = self.counts();
        out.push_str(&format!(
            "{} passed, {} failed, {} warnings, {} skipped\n",
            counts[&Status::Pass],
            counts[&Status::Fail],
            counts[&Status::Warn],
            counts[&Status::Skip]
        ));
        if self.has_failures() {
            out.push_str(
                "\nRun `steel-check --explain <id>` for the rationale and the off-switch.\n",
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(id: &'static str, status: Status) -> CheckResult {
        CheckResult {
            id,
            title: "t",
            category: Category::Kernel,
            severity: Severity::High,
            outcome: Outcome::new(status, "detail"),
        }
    }

    fn report(results: Vec<CheckResult>) -> Report {
        Report {
            schema_version: 1,
            preset: "balanced".into(),
            deployment: "arch".into(),
            results,
        }
    }

    #[test]
    fn counts_every_status_even_when_zero() {
        let r = report(vec![result("a", Status::Pass)]);
        let counts = r.counts();
        assert_eq!(counts[&Status::Pass], 1);
        assert_eq!(counts[&Status::Fail], 0);
        assert_eq!(counts[&Status::Warn], 0);
        assert_eq!(counts[&Status::Skip], 0);
    }

    #[test]
    fn failure_and_warning_detection() {
        assert!(!report(vec![result("a", Status::Pass)]).has_failures());
        assert!(report(vec![result("a", Status::Fail)]).has_failures());
        assert!(report(vec![result("a", Status::Warn)]).has_warnings());
        // A skip is not a failure. It is also not a pass.
        assert!(!report(vec![result("a", Status::Skip)]).has_failures());
    }

    #[test]
    fn json_output_contains_no_volatile_fields() {
        // Guards the byte-identical-output rule at the type level: if someone
        // adds a timestamp or hostname to the report, this fails.
        let r = report(vec![result("a", Status::Pass)]);
        let s = r.to_json().to_pretty_string();
        for banned in [
            "timestamp",
            "date",
            "time",
            "hostname",
            "host",
            "machine_id",
            "uuid",
        ] {
            assert!(
                !s.contains(banned),
                "report JSON must not contain volatile field `{banned}`:\n{s}"
            );
        }
    }

    #[test]
    fn text_output_is_stable_across_renders() {
        let r = report(vec![result("a", Status::Pass), result("b", Status::Fail)]);
        assert_eq!(r.to_text(false, false), r.to_text(false, false));
    }
}
