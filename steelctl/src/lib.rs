//! SteelOS deployment and manifest engine.
//!
//! Exposed as a library as well as a binary because three other things need it:
//! `steel-boot` when it stages a UKI and manages boot counters, the installer
//! when it writes the first generation record, and the VM test matrix when it
//! asserts what a deployment looks like after an update. Reimplementing slot
//! and generation handling in shell for each of those is how the copies drift
//! apart, and a drifted copy of this logic is an unbootable machine.
//!
//! What this delivers, stated accurately because the temptation to overclaim
//! lives here more than anywhere else in the project:
//!
//! **Image-level declarative configuration with whole-system generation
//! rollback.** Not NixOS semantics. Arch packages are not content-addressed and
//! do not compose that way, so there are no per-package generations and no
//! rolling back a single package. Any user-facing string that implies otherwise
//! is a bug.

pub mod diff;
pub mod generation;
pub mod hash;
pub mod manifest;
pub mod reconcile;
pub mod state;
pub mod toml;
