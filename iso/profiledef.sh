#!/usr/bin/env bash
# shellcheck disable=SC2034

# Every variable here is read by mkarchiso after it sources this file, hence the
# blanket SC2034 above: shellcheck cannot see any of them being used.
#
# archiso profile for the SteelOS live installer.
#
# The live environment's job is narrow: boot on the widest possible range of
# hardware, run the installer, and get out of the way. It is deliberately NOT a
# hardened environment — hardening the installer medium would make it fail to
# boot on exactly the machines that most need to be installed onto, and the
# installed system is where the guarantees live.
#
# One thing it must get right: the live session runs as an unprivileged user
# with no network services, because a live ISO with an open port is a machine
# on someone else's network with no firewall configured yet.

iso_name="steelos"
iso_label="STEELOS_$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y%m)"
iso_publisher="SteelOS <https://github.com/ChaseSunstrom/steel-os>"
iso_application="SteelOS Installer"
iso_version="$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y.%m.%d)"
install_dir="steelos"

buildmodes=('iso')
# 'bios.syslinux' covers both the isohybrid MBR and El Torito paths, and
# 'uefi.systemd-boot' covers x64 and ia32, from the ESP and from El Torito.
# The per-path names archiso used to take are deprecated and now warn.
bootmodes=(
  'bios.syslinux'
  'uefi.systemd-boot'
)

arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'zstd' '-Xcompression-level' '19' '-b' '1M')

# Reproducible: same inputs, same ISO. Published hashes are only meaningful if
# someone else can produce the same bytes.
airootfs_image_tool_options+=('-no-exports' '-noappend')

file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/etc/gshadow"]="0:0:400"
  ["/etc/sudoers.d/10-steelos-live"]="0:0:440"
  ["/root"]="0:0:750"
  ["/home/live"]="1000:1000:750"
  ["/usr/local/bin/steelos-install"]="0:0:755"
  ["/usr/local/bin/steelos-check-hardware"]="0:0:755"
  ["/usr/local/bin/steelos-live-probe"]="0:0:755"
)
