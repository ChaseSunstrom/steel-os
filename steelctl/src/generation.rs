//! Generations and A/B slots.
//!
//! A generation is a deployed image plus the manifest that produced it. The
//! machine holds at most two, one per slot, and `steelctl rollback` swaps which
//! one boots.
//!
//! # Why rollback needs both slots populated
//!
//! A machine with one populated slot has no rollback target — which is exactly
//! the state rollback exists for. That is why both slots are allocated at
//! install time and why `deployment.slot-health` warns when only one is filled.
//!
//! # Why boot counting comes before updates
//!
//! CLAUDE.md is explicit that boot counting must ship before any update
//! mechanism. Without it, an image that boots to a black screen is
//! unrecoverable for every user who took it: they cannot see the boot menu
//! because there is no display, and they cannot run `steelctl rollback` because
//! there is no session. Automatic demotion is what makes a bad update
//! survivable unattended, and it is the only thing that does.

use crate::state::StateDir;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn as_str(self) -> &'static str {
        match self {
            Slot::A => "a",
            Slot::B => "b",
        }
    }

    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    pub fn parse(s: &str) -> Option<Slot> {
        match s.trim() {
            "a" | "A" => Some(Slot::A),
            "b" | "B" => Some(Slot::B),
            _ => None,
        }
    }

    pub fn root_device(self) -> String {
        format!("/dev/disk/by-partlabel/steelos-root-{}", self.as_str())
    }

    pub fn verity_device(self) -> String {
        format!("/dev/disk/by-partlabel/steelos-verity-{}", self.as_str())
    }

    /// UKI filename on the ESP. Fixed and identical on every install — the ESP
    /// is unencrypted and is the first thing an examiner reads, so nothing here
    /// may vary between machines.
    pub fn uki_name(self) -> String {
        format!("steelos-{}.efi", self.as_str())
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One deployed generation.
///
/// Stored as a flat key=value file so the recovery environment can read it with
/// `cat` when `steelctl` itself is what is broken.
#[derive(Debug, Clone, PartialEq)]
pub struct Generation {
    pub slot: Slot,
    /// Human-meaningful identity, e.g. `steelos-20260720-0f1e2d3c`.
    pub image_id: String,
    pub channel: String,
    pub snapshot: String,
    pub kernel: String,
    /// dm-verity root hash. The value sealed into this generation's signed UKI.
    pub roothash: String,
    /// Semantic hash of the manifest that produced it.
    pub manifest_hash: String,
    /// Sequence number. Monotonic, so `history` can order generations without a
    /// timestamp — and the report stays free of volatile fields.
    pub sequence: u64,
    /// Has this generation ever booted successfully?
    pub blessed: bool,
}

impl Generation {
    pub fn serialise(&self) -> String {
        // Fixed field order: this file is compared between machines when
        // verifying the "same manifest => same image" claim.
        format!(
            "slot={}\nimage-id={}\nchannel={}\nsnapshot={}\nkernel={}\nroothash={}\n\
             manifest-hash={}\nsequence={}\nblessed={}\n",
            self.slot,
            self.image_id,
            self.channel,
            self.snapshot,
            self.kernel,
            self.roothash,
            self.manifest_hash,
            self.sequence,
            if self.blessed { "yes" } else { "no" },
        )
    }

    pub fn parse(body: &str) -> Option<Generation> {
        let mut fields = std::collections::BTreeMap::new();
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                fields.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        Some(Generation {
            slot: Slot::parse(fields.get("slot")?)?,
            image_id: fields.get("image-id")?.clone(),
            channel: fields.get("channel").cloned().unwrap_or_default(),
            snapshot: fields.get("snapshot").cloned().unwrap_or_default(),
            kernel: fields.get("kernel").cloned().unwrap_or_default(),
            roothash: fields.get("roothash")?.clone(),
            manifest_hash: fields.get("manifest-hash").cloned().unwrap_or_default(),
            sequence: fields
                .get("sequence")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            blessed: fields.get("blessed").map(|b| b == "yes").unwrap_or(false),
        })
    }
}

/// The deployment state: which slot is active, which is staged, what is in each.
#[derive(Debug, Clone)]
pub struct Deployment {
    pub active: Slot,
    pub generations: Vec<Generation>,
}

impl Deployment {
    pub fn load(state: &StateDir) -> Result<Deployment, String> {
        let active = state
            .read("active-slot")
            .and_then(|s| Slot::parse(&s))
            .ok_or_else(|| {
                "no active slot recorded. This machine's deployment state is damaged; \
                 boot the recovery entry and run `steelctl repair`."
                    .to_string()
            })?;

        let mut generations = Vec::new();
        for slot in [Slot::A, Slot::B] {
            if let Some(body) = state.read(&format!("slots/{slot}/generation")) {
                match Generation::parse(&body) {
                    Some(g) => generations.push(g),
                    None => {
                        return Err(format!(
                            "slot {slot} has a generation record that cannot be parsed. \
                             Run `steelctl repair`."
                        ))
                    }
                }
            }
        }

        if !generations.iter().any(|g| g.slot == active) {
            return Err(format!(
                "the active slot ({active}) has no generation record. \
                 The running system cannot be identified; run `steelctl repair`."
            ));
        }

        // Newest first, so `history` reads the way people expect.
        generations.sort_by_key(|g| std::cmp::Reverse(g.sequence));
        Ok(Deployment {
            active,
            generations,
        })
    }

    pub fn current(&self) -> &Generation {
        self.generations
            .iter()
            .find(|g| g.slot == self.active)
            .expect("load() guarantees the active slot has a generation")
    }

    /// The generation `rollback` would switch to.
    ///
    /// Deliberately requires it to be blessed: rolling back to a generation
    /// that has never booted successfully swaps a known-bad system for an
    /// unknown one, which is not what the user asked for.
    pub fn rollback_target(&self) -> Result<&Generation, String> {
        let inactive = self.active.other();
        match self.generations.iter().find(|g| g.slot == inactive) {
            None => Err(format!(
                "slot {inactive} is empty — there is nothing to roll back to.\n\
                 This is normal immediately after a first install and resolves on the \
                 first update."
            )),
            Some(g) if !g.blessed => Err(format!(
                "slot {inactive} holds {} which has never booted successfully.\n\
                 Rolling back to it would swap a known-bad system for an unknown one.\n\
                 If you want it anyway: steelctl rollback --force",
                g.image_id
            )),
            Some(g) => Ok(g),
        }
    }

    pub fn next_sequence(&self) -> u64 {
        self.generations
            .iter()
            .map(|g| g.sequence)
            .max()
            .unwrap_or(0)
            + 1
    }

    /// The slot an update should be written into.
    pub fn staging_slot(&self) -> Slot {
        self.active.other()
    }
}

/// Boot-counting state, as systemd-boot and systemd-bless-boot see it.
///
/// systemd-boot renames an entry `name+3-0.efi` -> `name+2-1.efi` on each
/// attempt; `systemd-bless-boot` strips the counter once `boot-complete.target`
/// is reached. An entry that runs out of tries is skipped, and the previous
/// generation boots.
#[derive(Debug, Clone, PartialEq)]
pub struct BootCounter {
    pub name: String,
    pub tries_left: u32,
    pub tries_done: u32,
}

impl BootCounter {
    /// Parse a boot-counting filename. Returns `None` for an entry with no
    /// counter, which means it has been blessed.
    pub fn parse(filename: &str) -> Option<BootCounter> {
        let stem = filename.strip_suffix(".efi").unwrap_or(filename);
        let (name, counter) = stem.rsplit_once('+')?;
        let (left, done) = match counter.split_once('-') {
            Some((l, d)) => (l, d),
            None => (counter, "0"),
        };
        Some(BootCounter {
            name: name.to_string(),
            tries_left: left.parse().ok()?,
            tries_done: done.parse().ok()?,
        })
    }

    pub fn filename(&self) -> String {
        format!("{}+{}-{}.efi", self.name, self.tries_left, self.tries_done)
    }

    pub fn is_exhausted(&self) -> bool {
        self.tries_left == 0
    }
}

/// How many boots a new deployment gets before it is demoted.
///
/// Three, not one. A single failure can be a fluke — a hardware hiccup, a
/// half-written ESP, a user hitting reset. Three consecutive failures to reach
/// `boot-complete.target` is a real signal. Much more than three and a genuinely
/// broken image wastes a lot of the user's time before it gives up.
pub const BOOT_ATTEMPTS: u32 = 3;

// A design constraint, checked at compile time: one attempt would demote on a
// fluke, and many would waste a lot of a user's time on a genuinely broken
// image before giving up.
const _: () = assert!(BOOT_ATTEMPTS >= 2 && BOOT_ATTEMPTS <= 5);

pub fn esp_entry_path(esp: &std::path::Path, slot: Slot) -> PathBuf {
    esp.join("EFI/Linux").join(slot.uki_name())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(slot: Slot, sequence: u64, blessed: bool) -> Generation {
        Generation {
            slot,
            image_id: format!("steelos-20260720-{sequence:08x}"),
            channel: "stable".into(),
            snapshot: "2026-07-20".into(),
            kernel: "linux-hardened".into(),
            roothash: "d".repeat(64),
            manifest_hash: "sha256:abc".into(),
            sequence,
            blessed,
        }
    }

    #[test]
    fn generation_round_trips_through_its_on_disk_form() {
        let g = generation(Slot::A, 7, true);
        let parsed = Generation::parse(&g.serialise()).unwrap();
        assert_eq!(g, parsed);
    }

    #[test]
    fn generation_parsing_tolerates_comments_and_whitespace() {
        // The recovery environment may have had a human edit this file.
        let body = "# written by steelctl\n slot = b \nimage-id=x\nroothash=y\n\n";
        let g = Generation::parse(body).unwrap();
        assert_eq!(g.slot, Slot::B);
        assert_eq!(g.image_id, "x");
        assert!(!g.blessed);
    }

    #[test]
    fn generation_parsing_fails_without_the_fields_that_identify_it() {
        assert!(Generation::parse("image-id=x\n").is_none());
        assert!(Generation::parse("slot=a\n").is_none());
        assert!(Generation::parse("slot=q\nimage-id=x\nroothash=y\n").is_none());
    }

    #[test]
    fn slots_alternate() {
        assert_eq!(Slot::A.other(), Slot::B);
        assert_eq!(Slot::B.other(), Slot::A);
        assert_eq!(Slot::A.other().other(), Slot::A);
    }

    fn deployment(active: Slot, gens: Vec<Generation>) -> Deployment {
        let mut gens = gens;
        gens.sort_by_key(|g| std::cmp::Reverse(g.sequence));
        Deployment {
            active,
            generations: gens,
        }
    }

    #[test]
    fn rollback_refuses_when_the_other_slot_is_empty() {
        let d = deployment(Slot::A, vec![generation(Slot::A, 1, true)]);
        let e = d.rollback_target().unwrap_err();
        assert!(e.contains("nothing to roll back to"));
    }

    #[test]
    fn rollback_refuses_an_unblessed_target_but_says_how_to_force_it() {
        // Rolling back to something that has never booted swaps a known-bad
        // system for an unknown one.
        let d = deployment(
            Slot::A,
            vec![generation(Slot::A, 2, true), generation(Slot::B, 1, false)],
        );
        let e = d.rollback_target().unwrap_err();
        assert!(e.contains("never booted successfully"));
        assert!(e.contains("--force"));
    }

    #[test]
    fn rollback_target_is_the_inactive_slot() {
        let d = deployment(
            Slot::A,
            vec![generation(Slot::A, 2, true), generation(Slot::B, 1, true)],
        );
        assert_eq!(d.rollback_target().unwrap().slot, Slot::B);
        assert_eq!(d.staging_slot(), Slot::B);
        assert_eq!(d.current().slot, Slot::A);
        assert_eq!(d.next_sequence(), 3);
    }

    #[test]
    fn boot_counter_parsing() {
        let c = BootCounter::parse("steelos-a+3-0.efi").unwrap();
        assert_eq!(c.name, "steelos-a");
        assert_eq!(c.tries_left, 3);
        assert_eq!(c.tries_done, 0);
        assert!(!c.is_exhausted());
        assert_eq!(c.filename(), "steelos-a+3-0.efi");

        // systemd-boot writes the short form for a fresh entry.
        let c = BootCounter::parse("steelos-b+3.efi").unwrap();
        assert_eq!(c.tries_left, 3);
        assert_eq!(c.tries_done, 0);

        // An exhausted entry is skipped by the bootloader.
        assert!(BootCounter::parse("steelos-a+0-3.efi")
            .unwrap()
            .is_exhausted());

        // No counter means blessed.
        assert!(BootCounter::parse("steelos-a.efi").is_none());
    }

    #[test]
    fn esp_entry_names_are_fixed_and_slot_derived() {
        // The ESP is unencrypted and is the first thing an examiner reads.
        // Nothing in these names may vary between machines.
        assert_eq!(Slot::A.uki_name(), "steelos-a.efi");
        assert_eq!(Slot::B.uki_name(), "steelos-b.efi");
        let p = esp_entry_path(std::path::Path::new("/efi"), Slot::A);
        assert_eq!(p, std::path::Path::new("/efi/EFI/Linux/steelos-a.efi"));
    }
}
