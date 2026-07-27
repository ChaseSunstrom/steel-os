# steelctl/ — Phase 2 and 3

Not yet implemented. The manifest engine and deployment tool, in Rust:
`steelctl apply | diff | update | rollback | history | export`.

**Milestone (Phase 2):** deliberately ship a broken image; the machine demotes
and boots the previous generation unattended.

**Milestone (Phase 3):** two machines from the same manifest produce identical
image hashes.

## What this must not claim

`CLAUDE.md` is explicit, and it is worth repeating here because this is the
component where the temptation lives: we are not building NixOS semantics. Arch
packages are not content-addressed and do not compose that way. What `steelctl`
delivers is image-level declarative configuration with whole-system generation
rollback — not per-package generations, and not the ability to roll back a
single package. Any user-facing string in this directory that implies otherwise
is a bug.
