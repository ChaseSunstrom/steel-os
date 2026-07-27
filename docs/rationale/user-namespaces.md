# Why unprivileged user namespaces are enabled

Most Linux hardening guides disable unprivileged user namespaces. `linux-hardened`
disables them by default. SteelOS enables them, deliberately, and this is the
argument for and against.

## The case against (which is real)

Unprivileged user namespaces let an unprivileged process obtain `CAP_SYS_ADMIN`
inside a new namespace, which makes a large amount of kernel code — mount,
network, and filesystem paths that were previously root-only — reachable by any
local user. This has produced a long run of local privilege escalations, and
will produce more.

Disabling them removes that reachability in one line. It is one of the highest
value-per-effort hardening changes available on a general Linux system.

## Why we enable them anyway

Because on this system, disabling them removes the sandboxing layer entirely.

Every unprivileged sandbox here depends on user namespaces: Flatpak, bubblejail,
`steel-shell`, rootless Podman. With namespaces off, none of them run. The
alternative mechanism is a SUID-root helper — which is what firejail does, and
which means a bug in the sandbox is a *root escalation* rather than a sandbox
escape. That inverts the property the sandbox exists to provide.

So the choice is not "user namespaces or not". It is:

| Option | Kernel attack surface | Application confinement |
|---|---|---|
| userns enabled, unprivileged bwrap | larger | yes |
| userns disabled, SUID sandbox | smaller | yes, but escapes are root |
| userns disabled, no sandbox | smaller | none |

The threat model settles it. The primary threat to a desktop is a malicious
document or website exploiting a browser or viewer — which is exactly what
sandboxing contains, and exactly what an unconfined application does not. Taking
away confinement of the most-exposed processes to reduce kernel surface reachable
by an attacker who *already has local code execution* is trading the common case
for the rarer one.

## What reduces the cost of this decision

Enabling namespaces is not the end of the argument; several other measures exist
partly to bound what it exposes:

- **AppArmor enforcing** confines processes regardless of namespace, and profiles
  apply inside namespaces too.
- **`vm.unprivileged_userfaultfd = 0`** removes the standard primitive for
  winning the use-after-free races that userns bugs are usually exploited
  through.
- **`kernel.unprivileged_bpf_disabled = 1`** and **`net.core.bpf_jit_harden = 2`**
  close the other main road from local code execution to kernel compromise.
- **`linux-hardened`** carries additional allocator and copy checks that raise
  the difficulty of the exploits this decision leaves reachable.
- **Immutability** bounds what a successful escalation can persist, though not
  what it can do in the session.

## How to disagree

The counterargument is respectable, and if your threat model is different — a
multi-user machine, a kiosk, a server, anything where local users are the
adversary rather than the person being protected — you should act on it:

```
steel-harden userns off
```

This will break every Flatpak, bubblejail, and `steel-shell` immediately and
completely. That is not a bug; it is the trade being made visible. The command
records the override in `/etc/steelos/overrides/` so `steel-check` reports it as
a deliberate choice rather than a broken measure.

`steel-check`'s `kernel.userns` check has severity `info` rather than `high` for
this reason: it reports the state and explains the decision, and it does not
treat either answer as a failure.
