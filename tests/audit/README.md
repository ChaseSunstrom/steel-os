# tests/audit

Assertions about the check suite as a whole, shared by `steel-check` and CI.

The unit tests inside `steel-check` verify individual checks against fixture
sysroots. This verifies properties that only exist at the level of the whole
suite:

1. **A fully-configured system audits green.** If the suite cannot pass even in
   principle, it is a list of complaints rather than a definition of done, and
   people stop reading it. `make_green_sysroot()` is also a readable
   specification of what "configured" means — a check that needs something the
   fixture does not provide will not pass on a real machine either.

2. **The deniability requirement holds end to end.** Two sysroots identical
   except that one has duress fully configured must produce byte-identical
   output in every format, including verbose. `CLAUDE.md` states this as a
   requirement on `steel-check` and says the assertion is itself a CI test.
   This is that test.

3. **The output contract holds.** Repeated runs are identical (no volatile
   fields), every check appears in every report, and every check documents a
   rationale and an escape hatch.

4. **Presets change what is required**, rather than being cosmetic.

```
cargo build --release
tests/audit/run.sh
```
