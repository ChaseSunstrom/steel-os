#!/usr/bin/env python3
"""Tests for the comprehension check and configuration validation.

These run without Calamares. The module's entire purpose is that people read
the limits before configuring something irreversible, so the logic deciding
whether they did needs to be correct.
"""

import sys
import types
import unittest
from pathlib import Path

# Stub out Calamares so the module imports outside the installer.
libcalamares = types.ModuleType("libcalamares")
libcalamares.globalstorage = types.SimpleNamespace(value=lambda k: None)
libcalamares.utils = types.SimpleNamespace(
    warning=lambda m: None, check_target_env_call=lambda *a, **k: None
)
sys.modules["libcalamares"] = libcalamares
sys.modules["libcalamares.utils"] = libcalamares.utils

sys.path.insert(0, str(Path(__file__).parent))
import main  # noqa: E402


class TestComprehension(unittest.TestCase):
    def test_all_correct_answers_pass(self):
        answers = {limit["id"]: limit["correct"] for limit in main.LIMITS}
        self.assertEqual(main.check_comprehension(answers), [])

    def test_a_wrong_answer_returns_its_explanation(self):
        answers = {limit["id"]: limit["correct"] for limit in main.LIMITS}
        limit = next(l for l in main.LIMITS if l["id"] == "multiple-snapshot")
        # Derive a wrong index rather than hard-coding one: hard-coding is how
        # this test silently stopped testing anything when the options moved.
        answers["multiple-snapshot"] = (limit["correct"] + 1) % len(limit["options"])
        wrong = main.check_comprehension(answers)
        self.assertEqual(len(wrong), 1)
        self.assertEqual(wrong[0]["id"], "multiple-snapshot")
        self.assertIn("repeated physical access", wrong[0]["explanation"])

    def test_no_answers_fails_everything(self):
        # Bypassing the view must not read as having understood it.
        self.assertEqual(len(main.check_comprehension({})), len(main.LIMITS))

    def test_every_limit_is_well_formed(self):
        for limit in main.LIMITS:
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
        positions = {limit["correct"] for limit in main.LIMITS}
        self.assertGreater(
            len(positions), 1,
            "correct answers are all in the same position; the check is guessable"
        )


class TestValidation(unittest.TestCase):
    def test_wiping_without_a_backup_is_refused(self):
        problems = main.validate_configuration({"duress_action": "wipe-keys"})
        self.assertTrue(any("append-only backup" in p for p in problems))

    def test_wiping_with_a_backup_is_allowed(self):
        problems = main.validate_configuration({
            "duress_action": "wipe-keys",
            "backup_target": "restic:sftp:host:/repo",
        })
        self.assertFalse(any("append-only backup" in p for p in problems))

    def test_a_decoy_needs_two_credentials(self):
        problems = main.validate_configuration({"decoy": True})
        self.assertTrue(any("TWO credentials" in p for p in problems))

    def test_playbook_c_requires_a_rehearsed_collision_answer(self):
        problems = main.validate_configuration({"playbook": "C"})
        self.assertTrue(any("contradictory" in p for p in problems))

    def test_the_vault_requires_amplification_to_have_been_shown(self):
        problems = main.validate_configuration({"vault": True})
        self.assertTrue(any("write amplification" in p for p in problems))

    def test_a_clean_configuration_has_no_problems(self):
        self.assertEqual(main.validate_configuration({
            "playbook": "A",
            "duress_action": "alert-only",
            "decoy": True,
            "decoy_maintenance_credential": "set",
            "backup_target": "restic:sftp:host:/repo",
        }), [])


class TestPlaybooks(unittest.TestCase):
    def test_playbook_c_carries_the_contradiction_warning(self):
        self.assertIn("undermine each other", main.PLAYBOOKS["C"]["warning"])

    def test_a_and_b_do_not_both_claim_custody_and_deniability(self):
        # The two coherent postures must stay coherent.
        self.assertNotIn("custody", main.PLAYBOOKS["A"]["enables"])
        self.assertNotIn("decoy", main.PLAYBOOKS["B"]["enables"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
