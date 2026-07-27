# tests/vm/ — Phase 1 onwards

Not yet implemented. QEMU + OVMF + swtpm test matrix, gating every publish:
unattended install of each preset, boot, `steel-check` green, update to a newer
image, roll back, restore from backup.

A preset that fails to boot fails the release.

## The tests that must exist before the features they cover ship

- **Boot counting demotion.** Ship a deliberately broken image and assert the
  machine boots the previous generation unattended, with no console access.
  Required before any update mechanism.
- **Restore drill.** Install, write data, back up, wipe, reinstall from the
  manifest, restore, assert equality. `CLAUDE.md`: if this test does not exist,
  the backup feature is not done.
- **Duress drill.** `steel-duress test` against scratch volumes, both decoy
  credentials exercised separately. A wipe feature that has never been tested
  does not work.
- **Timing indistinguishability.** A harness measuring the unlock paths for
  real, decoy-maintenance, decoy-duress, and wrong passphrases. This has to be
  measured, not inspected — the whole point is a difference too small to see by
  reading the code.

`tests/audit/run.sh` runs today and covers the suite-level properties that do
not need a VM.
