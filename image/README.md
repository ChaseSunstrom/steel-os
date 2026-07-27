# image/ — Phase 1: the image build

Produces, from a pinned Arch snapshot: a read-only erofs root image, a dm-verity
hash tree over it, and a UKI whose embedded command line carries that tree's
root hash — then signs the UKI.

## Why the ordering is the design

```
1. build the root filesystem      (from a PINNED snapshot)
2. compute the verity hash tree   -> root hash
3. build the UKI                  (root hash goes INSIDE the cmdline)
4. sign the UKI
```

Because the root hash is inside the thing being signed, **signing the kernel
signs the identity of the entire root filesystem**. Change any block of `/usr`
and the root hash changes, the UKI changes, and the signature is invalid.

Doing steps 2 and 3 the other way round produces something that looks identical
and guarantees nothing. `steel-check`'s
`storage.verity-roothash-matches-uki` is the runtime check for exactly this
property: verity with an attacker-chosen root hash verifies the attacker's image
perfectly, so "verity is on" is not the property that matters — "the root hash
came from the signed UKI" is.

## Building

```
export STEELOS_SB_KEY=/path/to/db.key
export STEELOS_SB_CERT=/path/to/db.pem
export STEELOS_VERITY_KEY=/path/to/verity.key
export STEELOS_VERITY_CERT=/path/to/verity.pem

image/build.sh
```

Without keys it builds and warns. The unsigned result will not boot under our
enrolled Secure Boot keys, which is the intended behaviour rather than a
limitation.

Artefacts land in `image/out/`: `steelos.root.raw`, `steelos.verity.raw`,
`steelos.roothash`, `steelos.efi`, `steelos.metadata`, and `steelos.sha256`.

## Reproducibility

The claim is *same manifest + same snapshot pin => same image hash*, and it is
checkable — CI builds twice and compares, and `steelctl history` records the
manifest hash alongside every generation.

Four things would break it, and each is handled:

| Source of variance | Handling |
|---|---|
| Timestamps | `SOURCE_DATE_EPOCH` derived from the snapshot date, not the clock |
| Machine identity | No `machine-id` in the image; generated per machine at first boot |
| Caches and indexes | Rebuilt with a fixed locale and sorted input in `mkosi.postinst` |
| Verity salt | Fixed, not random — the data being hashed is public, so the salt adds nothing and a random one would defeat the whole claim |

`build.sh` **refuses to build** without a snapshot pin. Building against
`current` makes reproducibility a lie, and Arch moves every day.

## Two build-time guards

- **UKI size.** Some firmware refuses PE binaries over a certain size, and an
  initrd with `linux-hardened`, NVIDIA firmware, and Plymouth is not small. The
  build fails over 60 MiB rather than shipping an image that boots in QEMU and
  not on a laptop.
- **Universal duress components.** `mkosi.postinst` fails the build if the
  initramfs hook or the maintenance boot path is missing. These must exist in
  *every* image or their presence identifies the machines that have them.

## Module signing

Out-of-tree modules are signed during the build with the same key that signs the
UKI. This is what lets `lockdown=confidentiality` and `module.sig_enforce=1` be
defaults without breaking NVIDIA: there is no DKMS-at-runtime path to break.
It is a direct advantage of the image model over a mutable one, and it is why
those two settings are audited but deliberately *not* applied by the Phase 0
packages on plain Arch.

## Layout

```
mkosi.conf              base configuration
mkosi.conf.d/           packages, reproducibility, layout
mkosi.repart/           BUILD output: one root + verity + signature
mkosi.postinst          runs inside the image before sealing
device-layout/          INSTALLED machine partition table, including A/B
build.sh                the four steps above
manifest.default.toml   the manifest producing the stock image
```

`mkosi.repart/` and `device-layout/` are different things. The build produces
**one** root image; the A/B duplication lives on the device, and an update
writes that one image into whichever slot is inactive. Building two identical
images would only create the opportunity for them to differ.
