# tools/

| Tool | Purpose |
|---|---|
| `steel-check` | Audit the system against every measure it claims. Rust, no dependencies. |
| `steel-harden` | Turn individual measures on and off, recording each override. |

`steel-profile` (AppArmor), `steel-malloc`, `steel-network`, and `steel-shell`
ship inside their respective packages rather than here, because each one is
useless without the configuration its package installs.

## The relationship between these two

`steel-check` reports what is true. `steel-harden` changes it, and writes a
record to `/etc/steelos/overrides/` that `steel-check` then reports.

That loop is the point. A measure someone deliberately disabled and a measure
that quietly stopped working look identical in an audit six months later, and
only one of them was a decision.
