# image/ — Phase 1

Not yet implemented. This will hold the mkosi build definitions that produce a
rootfs image, its dm-verity hash tree, and a signed UKI whose embedded cmdline
carries the verity root hash.

**Milestone:** the image boots in QEMU with Secure Boot and verity enforcing,
and `/usr` is provably read-only.

The order matters. `CLAUDE.md` puts the boot chain first because everything else
depends on it, and puts A/B deployment with boot counting (Phase 2) before any
update mechanism ships — automatic demotion of a deployment that cannot reach a
healthy state is what makes a bad update survivable, and shipping updates
without it means the first bad image is unrecoverable for everyone who took it.

Until then, `packages/` works on plain Arch and `steel-check` reports the
image-based measures as `Skip` with a reason rather than pretending they pass.
