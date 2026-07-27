# Installed-machine partition layout

`systemd-repart` definitions for the disk as it exists on an installed machine.
The installer applies these; `steelctl` and `systemd-sysupdate` rely on the
labels they produce.

This is separate from `image/mkosi.repart/`, which describes the *build output*
— one root image plus its verity tree. The A/B duplication is here, on the
device, because an update writes the single built image into whichever slot is
inactive. Building two identical images would only create the opportunity for
them to differ.

## The layout

| Partition | Size | Contents |
|---|---|---|
| ESP | 1 GiB | UKIs for both slots, recovery, maintenance |
| `steelos-root-a` | 6 GiB | Root image, slot A |
| `steelos-verity-a` | ~48 MiB | Verity hash tree, slot A |
| `steelos-root-b` | 6 GiB | Root image, slot B |
| `steelos-verity-b` | ~48 MiB | Verity hash tree, slot B |
| `steelos-custody` | 4 MiB | Custody region — random fill on most machines |
| `steelos-decoy` | 20% | Decoy volume — random fill on most machines |
| `steelos-var` | rest | LUKS2, all writable state and `/home` |

Minimum disk: **64 GiB**. Below that the decoy allocation and two root slots
leave too little for `/var`, and the installer refuses rather than producing a
machine that cannot take its first update.

## Two partitions that are usually empty, and must be

`steelos-custody` and `steelos-decoy` are allocated on **every** install, decoy
or not, custody or not, and filled with random data when unused.

This is the highest-value item in the deniability design and it cannot be
retrofitted. If the decoy partition only existed on machines with a decoy, its
presence would be the evidence — and a machine that later added one would have a
partition table visibly different from the one it shipped with. Allocating
always means a second LUKS volume occupies space that already looked like
high-entropy random data on every other SteelOS machine.

The same argument applies to the custody region: the initramfs needs wrapped key
material before anything is decrypted, so it cannot live inside the encrypted
volume, so it must exist everywhere or its existence is the tell.

Every partition table is therefore identical in shape across installs of the
same disk size. `steel-check`'s `duress.custody-region` verifies the region is
present and exactly the standard size — a region whose size differs from every
other install is itself a distinguishing feature.

## Free space

The installer allocates the **entire disk** and fills unallocated space with
random data. Unallocated regions with high-entropy data are a forensic signal;
having none is better than having some, and a disk that is fully allocated on
every install gives an examiner nothing to compare.
