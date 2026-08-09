#!/usr/bin/env python3
"""Assertions about the archiso profile that do not require building an ISO.

Every check here corresponds to a way mkarchiso fails late and expensively. The
ISO build takes the better part of an hour — Plasma pacstrapped, Calamares
compiled, a gigabyte of squashfs — and all of that runs before the profile's
shape is ever exercised. Finding a one-line mistake at the end of it is the
worst possible place to find it.

The first test is the one that already caught us: mkarchiso checks each
`file_permissions` path with `realpath -q` before pacstrap, against the copied
airootfs and nothing else. A missing final component is a warning; a missing
PARENT makes realpath fail, which mkarchiso reports as "Outside of valid path"
and treats as fatal. And because git does not track empty directories, a path
whose parent is an empty directory exists in a working tree and not in a fresh
checkout — so the build passes locally and fails in CI, which is exactly what
happened.
"""

import re
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ISO = REPO / "iso"
AIROOTFS = ISO / "airootfs"


def profiledef():
    return (ISO / "profiledef.sh").read_text()


def representable(directory: Path) -> bool:
    """Can git carry this directory to a fresh checkout?

    Not the same question as "does it exist". Git stores files, not
    directories, so a directory survives a clone exactly when something inside
    it does. Deliberately checked against the filesystem rather than against
    `git ls-files`, which would also flag a file that is simply not staged yet
    and turn every new page into a failure.
    """
    return any(child.is_file() or child.is_symlink()
               for child in directory.rglob("*"))


def ignored(path: Path) -> bool:
    """Would git refuse to add this? An ignored file is not carried either."""
    return subprocess.run(
        ["git", "check-ignore", "-q", str(path.relative_to(REPO))],
        cwd=REPO, capture_output=True, check=False,
    ).returncode == 0


class TestFilePermissions(unittest.TestCase):
    def paths(self):
        return re.findall(r'\["(/[^"]*)"\]', profiledef())

    def test_there_are_some(self):
        self.assertTrue(self.paths(), "no file_permissions entries were parsed")

    def test_every_path_is_shipped_by_the_profile(self):
        for entry in self.paths():
            target = AIROOTFS / entry.lstrip("/")
            self.assertTrue(
                target.exists(),
                f"profiledef.sh sets permissions on {entry}, which this profile "
                f"does not ship. mkarchiso applies file_permissions before "
                f"pacstrap, so a path that only appears once packages are "
                f"installed is never there when it looks.",
            )

    def test_every_parent_directory_is_tracked_by_git(self):
        # The fatal case. realpath needs every component but the last to exist.
        for entry in self.paths():
            parent = (AIROOTFS / entry.lstrip("/")).parent
            self.assertTrue(
                parent.is_dir(),
                f"{entry}: its parent {parent.relative_to(REPO)} does not exist",
            )
            self.assertTrue(
                representable(parent),
                f"{entry}: its parent {parent.relative_to(REPO)} is an empty "
                f"directory, which git does not carry. This builds here and "
                f"fails on a fresh checkout with 'Outside of valid path'.",
            )


class TestNoEmptyDirectories(unittest.TestCase):
    def test_the_profile_has_no_untrackable_directories(self):
        # Any empty directory in the profile is a difference between this
        # working tree and a clone of it, and differences like that only ever
        # show up in someone else's build.
        for directory in sorted(p for p in AIROOTFS.rglob("*") if p.is_dir()):
            self.assertTrue(
                representable(directory),
                f"{directory.relative_to(REPO)} is empty; git cannot carry it. "
                f"Ship a file in it, or create it at boot with tmpfiles.d.",
            )

    def test_nothing_in_the_profile_is_git_ignored(self):
        # An ignored file is as absent from a clone as an empty directory is.
        for path in sorted(AIROOTFS.rglob("*")):
            if path.is_file() or path.is_symlink():
                self.assertFalse(
                    ignored(path),
                    f"{path.relative_to(REPO)} matches a .gitignore rule and "
                    f"will not reach a fresh checkout",
                )


class TestBootModes(unittest.TestCase):
    """Each declared boot mode needs its configuration present in the profile."""

    def modes(self):
        block = re.search(r"bootmodes=\(([^)]*)\)", profiledef()).group(1)
        return re.findall(r"'([^']+)'", block)

    def test_bios_syslinux_has_configuration(self):
        if "bios.syslinux" not in self.modes():
            self.skipTest("no BIOS boot mode declared")
        self.assertTrue(list((ISO / "syslinux").glob("*.cfg")),
                        "bios.syslinux needs at least one syslinux/*.cfg")

    def test_uefi_systemd_boot_has_configuration(self):
        if "uefi.systemd-boot" not in self.modes():
            self.skipTest("no UEFI boot mode declared")
        self.assertTrue((ISO / "efiboot/loader/loader.conf").exists())
        self.assertTrue(list((ISO / "efiboot/loader/entries").glob("*.conf")),
                        "uefi.systemd-boot needs at least one loader entry")

    def test_bios_syslinux_requires_the_syslinux_package(self):
        packages = (ISO / "packages.x86_64").read_text().split()
        if "bios.syslinux" in self.modes():
            self.assertIn("syslinux", packages,
                          "mkarchiso validates this and refuses to build")

    def test_no_deprecated_boot_mode_names(self):
        # The per-path names warn on every build and are scheduled to go.
        for mode in self.modes():
            self.assertNotRegex(
                mode, r"\.(mbr|eltorito|esp)$",
                f"{mode} is deprecated; use bios.syslinux or uefi.systemd-boot",
            )


class TestInitramfs(unittest.TestCase):
    """Without these the live medium builds and does not boot."""

    def test_the_mkinitcpio_preset_is_shipped(self):
        preset = AIROOTFS / "etc/mkinitcpio.d/linux.preset"
        self.assertTrue(preset.exists(),
                        "no linux.preset: mkinitcpio's pacman hook produces no "
                        "initramfs and the ISO has nothing to boot")
        self.assertIn("archiso", preset.read_text())

    def test_the_archiso_hooks_are_configured(self):
        conf = AIROOTFS / "etc/mkinitcpio.conf.d/archiso.conf"
        self.assertTrue(conf.exists())
        hooks = conf.read_text()
        for hook in ("archiso", "block", "filesystems"):
            self.assertIn(hook, hooks, f"the {hook} hook is missing")

    def test_the_archiso_hook_package_is_installed(self):
        packages = (ISO / "packages.x86_64").read_text().split()
        self.assertIn("mkinitcpio-archiso", packages,
                      "the archiso hook comes from this package")


class TestPacmanConfiguration(unittest.TestCase):
    def test_the_local_repository_is_a_placeholder(self):
        body = (ISO / "pacman.conf").read_text()
        self.assertIn("@STEELOS_REPO@", body,
                      "iso/build.sh substitutes this; a hard-coded path here "
                      "would only work on the machine it was written on")

    def test_the_local_repository_comes_last(self):
        body = (ISO / "pacman.conf").read_text()
        self.assertGreater(body.index("[steelos]"), body.index("[extra]"),
                           "a local build shadowing an official package is the "
                           "kind of surprise that only shows up in the ISO")

    def test_profiledef_points_at_it(self):
        self.assertIn('pacman_conf="pacman.conf"', profiledef())


class TestPackageList(unittest.TestCase):
    def packages(self):
        return [line.strip() for line in
                (ISO / "packages.x86_64").read_text().splitlines()
                if line.strip() and not line.startswith("#")]

    def test_every_steel_package_has_a_pkgbuild(self):
        for package in self.packages():
            if not package.startswith("steel-"):
                continue
            self.assertTrue(
                (REPO / "packages" / package / "PKGBUILD").exists(),
                f"{package} is in the ISO package list with no PKGBUILD, so "
                f"pacstrap will not find it in the local repository",
            )

    def test_every_steel_package_is_built_by_the_build_script(self):
        build = (ISO / "build.sh").read_text()
        listed = re.search(r"PACKAGES=\(([^)]*)\)", build).group(1).split()
        for package in self.packages():
            if not package.startswith("steel-"):
                continue
            self.assertIn(package, listed,
                          f"{package} is installed onto the ISO but never built")

    def test_the_installer_is_present(self):
        packages = self.packages()
        self.assertIn("calamares", packages)
        self.assertIn("steel-installer", packages)

    def test_qml_and_svg_runtime_is_present(self):
        # The pages are QML and the mark is an SVG. Without these the installer
        # starts and shows empty pages, which is worse than not starting.
        packages = self.packages()
        for required in ("qt6-declarative", "qt6-svg"):
            self.assertIn(required, packages)

    def test_a_font_is_present(self):
        # A live medium with no font renders every page as boxes, which looks
        # like a broken ISO rather than a missing package.
        packages = self.packages()
        self.assertTrue(
            any(p.startswith(("noto-fonts", "ttf-")) for p in packages),
            "no font in the package list",
        )


class TestLiveSession(unittest.TestCase):
    def test_the_live_user_exists_in_passwd_group_and_shadow(self):
        for name in ("passwd", "group", "shadow"):
            body = (AIROOTFS / "etc" / name).read_text()
            self.assertIn("live", body, f"the live user is missing from {name}")

    def test_the_live_home_is_created_at_boot(self):
        conf = AIROOTFS / "etc/tmpfiles.d/steelos-live.conf"
        self.assertTrue(conf.exists(),
                        "nothing creates /home/live; autologin will fail")
        # assertRegex takes a message third, not flags — compile for MULTILINE.
        self.assertRegex(conf.read_text(),
                         re.compile(r"^d\s+/home/live\s", re.M))

    def test_the_session_autologins(self):
        conf = AIROOTFS / "etc/sddm.conf.d/10-steelos-live.conf"
        self.assertTrue(conf.exists())
        body = conf.read_text()
        self.assertIn("User=live", body)
        self.assertIn("[Autologin]", body)

    def test_the_display_server_and_the_session_agree(self):
        # Setting DisplayServer=x11 while naming a Wayland session file (or the
        # reverse) fails at login with nothing useful on screen. The two names
        # are set in different sections of the same file and nothing else
        # cross-checks them.
        body = (AIROOTFS / "etc/sddm.conf.d/10-steelos-live.conf").read_text()
        server = re.search(r"^DisplayServer=(\S+)", body, re.M).group(1)
        session = re.search(r"^Session=(\S+)", body, re.M).group(1)
        if server == "x11":
            self.assertIn("x11", session,
                          "an X11 display server needs an X11 session file")
        else:
            self.assertNotIn("x11", session,
                             "a Wayland display server needs a Wayland session")

    def test_the_session_package_is_installed(self):
        # Plasma's X11 session lives in its own package; plasma-workspace alone
        # provides only the Wayland one. Naming a session file whose package is
        # absent gives SDDM nothing to start.
        body = (AIROOTFS / "etc/sddm.conf.d/10-steelos-live.conf").read_text()
        session = re.search(r"^Session=(\S+)", body, re.M).group(1)
        packages = (ISO / "packages.x86_64").read_text().split()
        if "x11" in session:
            self.assertIn("plasma-x11-session", packages)
        else:
            self.assertIn("plasma-workspace", packages)

    def test_the_launcher_does_not_depend_on_a_gpu(self):
        # Qt's hardware paths are the most common way a Qt application comes up
        # as a black window on a virtual machine or an unfamiliar graphics
        # stack, and a black window cannot be diagnosed from the inside. The
        # pages are forms; nothing here needs a GPU.
        body = (AIROOTFS / "usr/local/bin/steelos-install").read_text()
        self.assertIn("QT_QUICK_BACKEND", body)
        self.assertIn("software", body)

    def test_the_launcher_leaves_a_log(self):
        # Launched from an autostart entry there is no terminal. Without a log,
        # a failure is indistinguishable from the installer never having been
        # asked to start.
        body = (AIROOTFS / "usr/local/bin/steelos-install").read_text()
        self.assertIn("install.log", body)
        self.assertIn("report_failure", body,
                      "a failure must reach the screen, not only the log")

    def test_a_dialog_tool_is_available_for_failures(self):
        # report_failure falls back to xmessage. plasma-workspace depends on
        # xorg-xmessage, so it is present transitively — but if the desktop ever
        # changes, the fallback silently stops working.
        packages = (ISO / "packages.x86_64").read_text().split()
        self.assertTrue(
            "plasma-workspace" in packages or "xorg-xmessage" in packages,
            "nothing on the medium can put an error on screen",
        )

    def test_the_installer_can_be_started_three_ways(self):
        # Autostart, the application menu, and an icon on the desktop. An
        # autostart entry that fails leaves no trace on screen, and "there is no
        # way to start the installer" is the worst thing a live medium can be.
        self.assertTrue((AIROOTFS / "etc/xdg/autostart/steelos-install.desktop").exists())
        self.assertTrue((AIROOTFS / "usr/share/applications/steelos-install.desktop").exists())
        tmpfiles = (AIROOTFS / "etc/tmpfiles.d/steelos-live.conf").read_text()
        self.assertIn("/home/live/Desktop", tmpfiles)

    def test_the_display_manager_is_enabled(self):
        link = AIROOTFS / "etc/systemd/system/display-manager.service"
        self.assertTrue(link.is_symlink(),
                        "without this symlink nothing starts the desktop")

    def test_sudo_names_the_launcher_and_not_calamares(self):
        # The launcher is where the installer's environment is set up. Running
        # calamares directly produces pages that silently cannot read the
        # machine's facts, so it must not be reachable through sudo.
        body = (AIROOTFS / "etc/sudoers.d/10-steelos-live").read_text()
        self.assertIn("/usr/local/bin/steelos-install", body)
        self.assertNotIn("/usr/bin/calamares", body)

    def test_the_launcher_allows_qml_to_read_local_files(self):
        # QML refuses local file reads through XMLHttpRequest unless this is
        # set, and the pages read the probe's output that way. Without it they
        # come up empty with only a line in the log.
        body = (AIROOTFS / "usr/local/bin/steelos-install").read_text()
        self.assertIn("QML_XHR_ALLOW_FILE_READ", body)

    def test_the_probe_runs_before_the_desktop(self):
        unit = AIROOTFS / "etc/systemd/system/steelos-live-probe.service"
        self.assertTrue(unit.exists())
        self.assertIn("Before=display-manager.service", unit.read_text())
        wants = (AIROOTFS
                 / "etc/systemd/system/multi-user.target.wants"
                 / "steelos-live-probe.service")
        self.assertTrue(wants.is_symlink(), "the probe unit is not enabled")


if __name__ == "__main__":
    unittest.main(verbosity=2)
