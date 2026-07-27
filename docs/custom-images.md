# Building your own images

`steelctl apply` deliberately does not build images. This page is the supported
path for people who need one, and it is a longer path on purpose.

## Why apply does not just build it

The UKI's command line contains the dm-verity root hash. Signing the UKI is
therefore what pins the identity of the entire root filesystem — that is the
crux of the whole design.

A locally built image would carry a root hash the local machine computed, signed
by a local key. That is exactly the substitution the signature exists to
prevent, and having `apply` do it quietly would mean the guarantee silently
weakens the first time someone edits a manifest.

So it is a deliberate decision with its own steps, not a side effect.

## What you are taking on

Enrolling your own build key means:

- **You own the security updates for everything in your image.** The published
  channel rebuilds against a tested Arch snapshot and publishes only after the
  VM matrix passes. Your image gets whatever you build, when you build it.
- **Your machines trust your key.** Anyone who obtains it can produce an image
  your machines will boot.
- **The reproducibility claim becomes yours to keep.** Same manifest, same
  snapshot pin, same hash — verify it, because nobody else will.

If what you need is a package, check first that it genuinely cannot be a
Flatpak, a `steel-shell` container, or a signed sysext. Image rebuilds are for
the kernel, drivers, the base system, and hardening posture. Getting that
boundary wrong is what makes an immutable OS feel hostile.

## Building

```
# Generate a build key. Offline, on a machine you trust.
openssl req -newkey rsa:4096 -nodes -keyout build.key \
  -new -x509 -sha256 -days 3650 -subj "/CN=your-org SteelOS build/" -out build.pem

# Enroll it alongside ours, or instead of ours.
sbctl enroll-keys --microsoft --custom-cert build.pem

export STEELOS_SB_KEY=$PWD/build.key
export STEELOS_SB_CERT=$PWD/build.pem
export STEELOS_VERITY_KEY=$PWD/build.key
export STEELOS_VERITY_CERT=$PWD/build.pem
export STEELOS_MANIFEST=$PWD/my-manifest.toml

image/build.sh
```

`build.sh` refuses to run without a snapshot pin, and refuses one that is not a
real date. Building against `current` makes reproducibility a lie and Arch moves
every day, so that is a hard failure rather than a warning.

## Installing what you built

```
steel-boot stage image/out/steelos.efi
steel-boot activate b        # or whichever slot it went to
```

`stage` verifies the signature before installing. An unsigned UKI on the ESP
produces a machine that will not boot and cannot say why, and that is entirely
avoidable at this step.

## Verify before you trust it

```
steel-check storage.verity-roothash-matches-uki
steel-check boot.uki-signed
steelctl status
```

And build it twice. If the two hashes differ, something non-deterministic got
into your image, and you have lost the property that makes two machines the same
machine.
