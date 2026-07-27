//! The check registry.
//!
//! Order is fixed and the set is complete: every check runs on every machine,
//! and none is added or removed based on configuration state. See
//! `report.rs` for why that matters.

pub mod backup;
pub mod boot;
pub mod deployment;
pub mod duress;
pub mod filesystem;
pub mod identity;
pub mod kernel;
pub mod memory;
pub mod network;
pub mod sandbox;
pub mod storage;

use crate::context::Context;
use crate::report::{Check, CheckResult, Report};

/// Bumped when the JSON shape changes in a way consumers must notice.
/// Adding a check is not a schema change; renaming a field is.
pub const SCHEMA_VERSION: u32 = 1;

pub fn all() -> Vec<&'static Check> {
    let mut checks: Vec<&'static Check> = Vec::new();
    for group in [
        boot::CHECKS,
        storage::CHECKS,
        kernel::CHECKS,
        memory::CHECKS,
        filesystem::CHECKS,
        network::CHECKS,
        sandbox::CHECKS,
        identity::CHECKS,
        deployment::CHECKS,
        backup::CHECKS,
        duress::CHECKS,
    ] {
        checks.extend(group.iter());
    }
    checks
}

pub fn find(id: &str) -> Option<&'static Check> {
    all().into_iter().find(|c| c.id == id)
}

pub fn run(ctx: &Context, selected: &[&'static Check]) -> Report {
    let results = selected
        .iter()
        .map(|check| CheckResult {
            id: check.id,
            title: check.title,
            category: check.category,
            severity: check.severity,
            outcome: (check.run)(ctx),
        })
        .collect();

    Report {
        schema_version: SCHEMA_VERSION,
        preset: ctx.preset.as_str().to_string(),
        deployment: ctx.deployment.as_str().to_string(),
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_ids_are_unique() {
        let mut ids: Vec<&str> = all().iter().map(|c| c.id).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate check id in the registry");
    }

    #[test]
    fn check_ids_are_namespaced_by_category() {
        // The id prefix is what lets `--category` and the docs stay in sync.
        for check in all() {
            let prefix = check.id.split('.').next().unwrap();
            assert_eq!(
                prefix,
                check.category.as_str(),
                "{} is in category {} but its id says {prefix}",
                check.id,
                check.category
            );
        }
    }

    #[test]
    fn every_check_has_a_rationale_and_an_escape_hatch() {
        // Design principles 6 and 7, enforced rather than remembered: every
        // measure needs a stated reason and a documented off-switch.
        for check in all() {
            assert!(
                check.rationale.len() > 40,
                "{} has no meaningful rationale",
                check.id
            );
            assert!(
                !check.escape_hatch.is_empty(),
                "{} has no escape hatch, not even 'None'",
                check.id
            );
        }
    }

    #[test]
    fn registry_order_is_stable() {
        let a: Vec<&str> = all().iter().map(|c| c.id).collect();
        let b: Vec<&str> = all().iter().map(|c| c.id).collect();
        assert_eq!(a, b);
    }
}
