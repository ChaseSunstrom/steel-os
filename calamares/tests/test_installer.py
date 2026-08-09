#!/usr/bin/env python3
"""Tests for the installer: the comprehension check, the refusals, and the wiring.

Two kinds of thing are checked here.

The first is the logic that decides whether someone read the limits before
configuring something irreversible. That is the entire point of the
threatened-user step, so the code deciding it needs to be correct, and the
questions themselves need to be un-guessable.

The second is the wiring. The installer is assembled from a settings file, a
set of QML pages in the branding directory, a set of Python job modules and a
config file per page. Any one of those referring to something that does not
exist produces an installer that fails at run time, on someone's machine, with
a Calamares error rather than a useful one. These tests are cheap and catch all
of it before the ISO is built.
"""

import json
import re
import sys
import types
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CALAMARES = REPO / "calamares"
BRANDING = CALAMARES / "branding" / "steelos"
MODULES = CALAMARES / "modules"
MODULE_CONFIGS = CALAMARES / "modules-config"
VIEWMODULE = CALAMARES / "viewmodule"

# Stub Calamares so the job modules import outside the installer.
libcalamares = types.ModuleType("libcalamares")
libcalamares.globalstorage = types.SimpleNamespace(
    value=lambda k: None, insert=lambda k, v: None, keys=lambda: []
)
libcalamares.utils = types.SimpleNamespace(
    warning=lambda m: None,
    debug=lambda m: None,
    check_target_env_call=lambda *a, **k: None,
    host_env_process_output=lambda *a, **k: "",
)
libcalamares.job = types.SimpleNamespace(configuration={}, working_path="")
sys.modules.setdefault("libcalamares", libcalamares)
sys.modules.setdefault("libcalamares.utils", libcalamares.utils)

sys.path.insert(0, str(MODULES / "steelos_threatened"))
import main as threatened  # noqa: E402

LIMITS_JSON = json.loads((BRANDING / "threatened-limits.json").read_text())
LIMITS = LIMITS_JSON["limits"]
PLAYBOOKS = LIMITS_JSON["playbooks"]

BACKUP_OK = {"enabled": True, "targetKind": "remote", "remoteUrl": "rest:https://h/r"}


class TestComprehension(unittest.TestCase):
    def test_all_correct_answers_pass(self):
        answers = {limit["id"]: limit["correct"] for limit in LIMITS}
        self.assertEqual(threatened.check_comprehension(answers, LIMITS), [])

    def test_a_wrong_answer_returns_its_explanation(self):
        answers = {limit["id"]: limit["correct"] for limit in LIMITS}
        limit = next(l for l in LIMITS if l["id"] == "multiple-snapshot")
        # Derive a wrong index rather than hard-coding one: hard-coding is how
        # this test silently stopped testing anything when the options moved.
        answers["multiple-snapshot"] = (limit["correct"] + 1) % len(limit["options"])
        wrong = threatened.check_comprehension(answers, LIMITS)
        self.assertEqual(len(wrong), 1)
        self.assertEqual(wrong[0]["id"], "multiple-snapshot")
        self.assertIn("repeated physical access", wrong[0]["explanation"])

    def test_no_answers_fails_everything(self):
        # Bypassing the page must not read as having understood it.
        self.assertEqual(len(threatened.check_comprehension({}, LIMITS)), len(LIMITS))

    def test_every_limit_is_well_formed(self):
        for limit in LIMITS:
            self.assertIn(limit["correct"], range(len(limit["options"])),
                          f"{limit['id']}: correct index out of range")
            self.assertGreaterEqual(len(limit["options"]), 3,
                                    f"{limit['id']}: needs distractors")
            self.assertTrue(limit["on_wrong"].strip(),
                            f"{limit['id']}: no explanation for a wrong answer")
            self.assertGreater(len(limit["body"]), 200,
                               f"{limit['id']}: body too short to have taught anything")

    def test_the_correct_answer_is_not_always_in_the_same_position(self):
        # If every correct answer sat at index 0, someone could pass the check
        # by picking the first option each time — which measures nothing and
        # would make the whole step theatre.
        positions = {limit["correct"] for limit in LIMITS}
        self.assertGreater(
            len(positions), 1,
            "correct answers are all in the same position; the check is guessable"
        )


class TestValidation(unittest.TestCase):
    def test_wiping_without_a_backup_is_refused(self):
        problems = threatened.validate_configuration(
            {"duress_action": "wipe-keys", "playbook": "A"}, {})
        self.assertTrue(any("append-only backup" in p for p in problems))

    def test_wiping_with_a_backup_is_allowed(self):
        problems = threatened.validate_configuration(
            {"duress_action": "wipe-keys", "playbook": "A"}, BACKUP_OK)
        self.assertFalse(any("append-only backup" in p for p in problems))

    def test_a_local_backup_does_not_count_as_off_device(self):
        problems = threatened.validate_configuration(
            {"duress_action": "wipe-keys", "playbook": "A"},
            {"enabled": True, "targetKind": "removable"})
        self.assertTrue(any("append-only backup" in p for p in problems))

    def test_a_wiping_decoy_needs_a_decoy(self):
        problems = threatened.validate_configuration(
            {"duress_action": "decoy-and-wipe", "playbook": "A"}, BACKUP_OK)
        self.assertTrue(any("TWO credentials" in p for p in problems))

    def test_playbook_c_requires_a_rehearsed_collision_answer(self):
        problems = threatened.validate_configuration(
            {"playbook": "C", "duress_action": "alert-only"}, {})
        self.assertTrue(any("contradictory" in p for p in problems))

    def test_the_vault_requires_amplification_to_have_been_shown(self):
        problems = threatened.validate_configuration(
            {"playbook": "A", "duress_action": "alert-only", "vault": True}, {})
        self.assertTrue(any("write amplification" in p for p in problems))

    def test_attempt_limit_wiping_must_be_acknowledged(self):
        problems = threatened.validate_configuration(
            {"playbook": "A", "duress_action": "alert-only",
             "attempt_limit_wipe": True}, {})
        self.assertTrue(any("self-destruct" in p for p in problems))

    def test_no_playbook_is_refused(self):
        problems = threatened.validate_configuration({"duress_action": "alert-only"}, {})
        self.assertTrue(any("No playbook" in p for p in problems))

    def test_a_clean_configuration_has_no_problems(self):
        self.assertEqual(threatened.validate_configuration({
            "playbook": "A",
            "duress_action": "decoy",
            "decoy": True,
        }, BACKUP_OK), [])


class TestPlaybooks(unittest.TestCase):
    def test_playbook_c_carries_the_contradiction_warning(self):
        self.assertIn("undermine each other", PLAYBOOKS["C"]["warning"])

    def test_a_and_b_do_not_both_claim_custody_and_deniability(self):
        # The two coherent postures must stay coherent.
        self.assertNotIn("custody", PLAYBOOKS["A"]["enables"])
        self.assertNotIn("decoy", PLAYBOOKS["B"]["enables"])


class TestBackupRefusals(unittest.TestCase):
    """The outer backup key must never be the private half."""

    def setUp(self):
        sys.path.insert(0, str(MODULES / "steelos_backup"))
        import importlib
        self.backup = importlib.import_module("main")
        importlib.reload(self.backup)

    def test_an_age_private_key_is_recognised(self):
        self.assertTrue(self.backup.looks_like_private_key(
            "AGE-SECRET-KEY-1QQPQ8N9..."))

    def test_a_pem_private_key_is_recognised(self):
        self.assertTrue(self.backup.looks_like_private_key(
            "-----BEGIN OPENSSH PRIVATE KEY-----"))

    def test_a_public_key_is_accepted(self):
        self.assertFalse(self.backup.looks_like_private_key(
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"))

    def test_nothing_is_accepted(self):
        self.assertFalse(self.backup.looks_like_private_key(""))


class TestWiring(unittest.TestCase):
    """The installer refers only to things that exist."""

    # Calamares' own modules, which we use as-is, plus our one compiled view
    # module. Anything else in the sequence must be a Python job module of ours.
    STOCK = {"welcome", "locale", "keyboard", "summary", "finished",
             "localecfg", "hwclock", "machineid"}
    VIEWMODULE = "steelospage"

    def setUp(self):
        self.settings = (CALAMARES / "settings.conf").read_text()

    def sequence_entries(self):
        entries = []
        for line in self.settings.splitlines():
            match = re.match(r"^\s{2,}-\s+([a-z0-9_@]+)\s*$", line)
            if match:
                entries.append(match.group(1))
        return entries

    def test_every_sequence_entry_resolves(self):
        for entry in self.sequence_entries():
            module = entry.split("@")[0]
            if module in self.STOCK:
                continue
            if module == self.VIEWMODULE:
                self.assertTrue((VIEWMODULE / "module.desc").exists(),
                                "the steelospage view module is missing")
                continue
            self.assertTrue(
                (MODULES / module / "module.desc").exists(),
                f"{entry} in the sequence has no module in calamares/modules/",
            )

    def test_every_instance_has_a_config_and_a_qml_page(self):
        instances = re.findall(
            r"-\s+id:\s+(\S+)\s*\n\s+module:\s+(\S+)\s*\n\s+config:\s+(\S+)",
            self.settings,
        )
        self.assertTrue(instances, "no instances parsed out of settings.conf")
        for instance_id, module, config in instances:
            path = MODULE_CONFIGS / config
            self.assertTrue(path.exists(), f"{config} is missing")
            body = path.read_text()
            filename = re.search(r"qmlFilename:\s+(\S+)", body)
            self.assertIsNotNone(filename, f"{config} sets no qmlFilename")
            qml = BRANDING / f"{filename.group(1)}.qml"
            self.assertTrue(qml.exists(), f"{config} points at a missing {qml.name}")
            # SteelPageViewStep reads the sidebar label from qmlLabel.name and
            # falls back to a generic string when it is absent, which would put
            # eight identically-named steps in the sidebar.
            self.assertRegex(body, r"qmlLabel:\s*\n\s+name:",
                             f"{config} must set qmlLabel.name")
            self.assertIn(f"@{instance_id}", self.settings,
                          f"instance {instance_id} is declared but never used")

    def test_every_job_module_is_in_the_sequence(self):
        # A module that exists but is never run is dead weight that reads as
        # implemented.
        entries = set(self.sequence_entries())
        for module in sorted(p.name for p in MODULES.iterdir() if p.is_dir()):
            self.assertIn(module, entries,
                          f"{module} is packaged but never runs")

    def test_every_module_declares_itself_a_job(self):
        # Calamares 3.4 has no Python view modules. A `type: view` Python module
        # fails to load at run time with a message that does not say why.
        for desc in MODULES.glob("*/module.desc"):
            body = desc.read_text()
            self.assertIn('type:       "job"', body,
                          f"{desc.parent.name} is not declared as a job module")
            self.assertIn(f'name:       "{desc.parent.name}"', body,
                          f"{desc.parent.name}: module.desc name does not match "
                          "its directory, which is how Calamares resolves it")

    def test_the_view_module_is_declared_as_a_view(self):
        body = (VIEWMODULE / "module.desc").read_text()
        self.assertIn('type:       "view"', body)
        self.assertIn('interface:  "qtplugin"', body)
        # module.desc's `load` and the library CMake produces have to agree, or
        # Calamares reports the module as missing with no further explanation.
        cmake = (VIEWMODULE / "CMakeLists.txt").read_text()
        load = re.search(r'load:\s+"(\S+)"', body).group(1)
        self.assertIn(load.removesuffix(".so"), cmake,
                      "module.desc load= does not match the CMake OUTPUT_NAME")

    def test_a_page_that_can_block_next_explains_why(self):
        # A greyed-out Next whose cause is three screens down reads as a broken
        # installer. Any page whose `valid` is not a constant must set
        # `blocker`, which SteelPage pins above the scrolling body.
        for page in BRANDING.glob("steelos-*.qml"):
            body = page.read_text()
            # `\s*` before a negative lookahead backtracks to zero width and
            # matches anything; compare the whole line instead.
            valid_lines = [line.strip() for line in body.splitlines()
                           if line.strip().startswith("valid:")]
            gated = any(line != "valid: true" for line in valid_lines)
            if gated:
                self.assertIn("blocker:", body,
                              f"{page.name} can block Next but never says why")

    def test_pages_gate_next_through_the_config_object(self):
        # A page that never sets config.valid can be walked past with empty
        # input, and the first thing that notices is a job writing to a disk.
        state = (BRANDING / "SteelState.qml").read_text()
        self.assertIn("config.valid", state)
        for page in BRANDING.glob("steelos-*.qml"):
            self.assertIn("SteelState", page.read_text(),
                          f"{page.name} has no SteelState and so cannot gate Next")

    def test_workspace_consumers_match_their_pkgbuilds(self):
        # Every package whose source=() names the workspace tarball must be in
        # prepare-workspace-source.sh's list, or its build fails at source
        # retrieval on a machine where a stale tarball is not lying around.
        script = (REPO / "packages" / "prepare-workspace-source.sh").read_text()
        listed = set(re.search(r"CONSUMERS=\(([^)]*)\)", script).group(1).split())
        expected = {p.parent.name for p in (REPO / "packages").glob("*/PKGBUILD")
                    if "steel-os-$pkgver.tar.gz" in p.read_text()}
        self.assertEqual(listed, expected)

    def test_branding_images_exist(self):
        branding = (BRANDING / "branding.desc").read_text()
        # [ \t] rather than \s: \s matches newlines and would run the match on
        # past the blank line into the style block.
        images = re.search(r"^images:\n((?:[ \t]+\S+:.*\n)+)", branding, re.M)
        self.assertIsNotNone(images, "branding.desc declares no images")
        names = re.findall(r":\s+\"([^\"]+)\"", images.group(1))
        self.assertTrue(names)
        for name in names:
            self.assertTrue((BRANDING / name).exists(),
                            f"branding.desc names a missing image: {name}")

    def test_the_slideshow_exists(self):
        branding = (BRANDING / "branding.desc").read_text()
        show = re.search(r"^slideshow:\s+\"(\S+)\"", branding, re.M)
        self.assertIsNotNone(show)
        self.assertTrue((BRANDING / show.group(1)).exists())

    def test_qml_pages_only_use_shared_components_that_exist(self):
        available = {p.stem for p in BRANDING.glob("Steel*.qml")}
        self.assertIn("SteelPage", available)
        # Instantiations only — `SteelChoice {` at the start of a statement.
        # Matching the bare word would also hit "SteelOS" in the prose.
        pattern = re.compile(r"(?:^|[\s:{(])(Steel[A-Z]\w+)\s*\{", re.M)
        for page in BRANDING.glob("steelos-*.qml"):
            for used in set(pattern.findall(page.read_text())):
                self.assertIn(used, available,
                              f"{page.name} uses {used}, which does not exist")


if __name__ == "__main__":
    unittest.main(verbosity=2)
