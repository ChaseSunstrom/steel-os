# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Email `security@steelos.invalid` with the details. If you want to encrypt,
the key fingerprint is published in [docs/keys.md](docs/keys.md) and on the
project site — check it against both, because a fingerprint published only on
the site that serves the software verifies nothing.

Include, if you can: what you did, what happened, what you expected, and the
output of `steel-check --json`. That output contains no hostname, timestamp, or
other identifying data by design, so it is safe to paste.

We will acknowledge within 72 hours and give you an assessment within seven
days. If we disagree that something is a vulnerability we will say so and
explain why, rather than going quiet.

## What we consider a vulnerability

The threat model in [docs/threat-model.md](docs/threat-model.md) is the
reference. Anything that defeats an in-scope defence is in scope. In
particular, we want to hear about:

- **Anything that makes `steel-check` report a measure as active when it is
  not.** An auditor that is confidently wrong is worse than no auditor, because
  people act on it.
- **Any way to distinguish a machine with duress configured from one without**,
  from a context that has not unlocked the real volume — timing, file presence,
  size, journal contents, ESP contents, anything. The deniability design rests
  entirely on this and we would rather hear it from you.
- **Any path that modifies the verified root without invalidating the UKI
  signature.**
- **Any way to reach a keyslot check before the duress credential comparison**,
  or to make that comparison non-constant-time.
- **Backup targets or outer key material leaking onto the protected device.**

## What we do not consider a vulnerability

Stated plainly so nobody spends time on them:

- Anything the threat model lists as out of scope: compromised UEFI firmware,
  Intel ME, AMD PSP, hardware implants, an attacker with your unlock password,
  full anonymity, or a kernel 0-day escaping every sandbox layer.
- The fact that `compatible` provides less protection. That is what it is for.
- The fact that devmode disables verity. It requires physical presence at boot
  and announces itself in Plymouth and in the session.
- The fact that a decoy is not confidential against someone holding the
  hardware. Its key is TPM-sealed so unattended sessions can run; this is
  documented, and `steel-decoy` refuses to import real data for this reason.
- The fact that `steel-custody` does not prevent coerced unlock. It delays,
  witnesses, and records. That is the whole claim.

## Disclosure

We publish an advisory when a fix ships, naming the reporter unless they prefer
otherwise. If a fix will take longer than 90 days we will tell you why and agree
a date rather than letting it drift.

Critical issues take the expedited release path: out of cycle, with the VM
matrix still run on the balanced preset. Expedited, not skipped — skipping tests
to ship a security fix faster is how a security fix becomes an outage, and the
release notes say which coverage was traded for speed.

## Verifying what you are running

```
steel-check                 # every measure, pass/fail, with the reason
steel-check --json          # the same, machine-readable
steelctl status             # generation, root hash, manifest hash
```

Every claim in our user-facing material must be verifiable by `steel-check`. If
you find one that is not, that is a bug — either the check is missing or the
claim is, and we want to know which.
