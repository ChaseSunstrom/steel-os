#!/usr/bin/env python3
"""The optional threatened-user setup.

CLAUDE.md: this step "enables it and walks through the limits above with a
comprehension confirmation, not just an 'I agree' box."

The UI does the walking through; this module does the refusing. It re-checks
everything the page checked, because the page is not the last word — global
storage can be reached by any earlier module, and what gets configured here
destroys data irreversibly.

The limits, questions and playbooks live in threatened-limits.json alongside the
QML that renders them. One file, read by both, so the text someone answered
questions about is the text that is enforced.
"""

import json
import os

import libcalamares

LIMITS_FILE = "/usr/share/calamares/branding/steelos/threatened-limits.json"


def load_limits(path=LIMITS_FILE):
    with open(path) as handle:
        return json.load(handle)


def check_comprehension(answers, limits):
    """Return the limits answered incorrectly.

    Deliberately not a pass/fail gate that locks anyone out — in the UI a wrong
    answer returns them to the paragraph it came from. Reaching this function
    with wrong answers means the page was bypassed rather than failed, which is
    a different thing and is refused.
    """
    wrong = []
    for limit in limits:
        given = answers.get(limit["id"])
        if given != limit["correct"]:
            wrong.append({
                "id": limit["id"],
                "title": limit["title"],
                "explanation": limit["on_wrong"],
            })
    return wrong


def validate_configuration(config, backup):
    """Refuse combinations that cannot work, before anything is written."""
    problems = []

    action = config.get("duress_action")
    has_offdevice_backup = bool(
        backup.get("enabled") and backup.get("targetKind") == "remote"
        and backup.get("remoteUrl")
    )

    if action in ("wipe-keys", "decoy-and-wipe") and not has_offdevice_backup:
        problems.append(
            "A wiping duress action needs an off-device, append-only backup. "
            "Without one the destruction is permanent and total, including for "
            "you. Configure a backup target first, or choose alert-only."
        )

    if action == "decoy-and-wipe" and not config.get("decoy"):
        problems.append(
            "decoy-and-wipe needs a decoy, and a decoy needs TWO credentials: "
            "decoy-maintenance (yours, never disclosed, used to age the decoy) "
            "and decoy-duress (the one you disclose). Shipping only a wiping "
            "decoy guarantees you destroy your own data and makes credible "
            "aging impossible."
        )

    if config.get("attempt_limit_wipe") and not config.get("attempt_limit_acknowledged"):
        problems.append(
            "Attempt-limit wiping has not been acknowledged. It is a "
            "self-destruct that anyone with physical access can trigger."
        )

    if config.get("playbook") == "C" and not config.get("collision_rehearsed"):
        problems.append(
            "Playbook C claims both custody and deniability, which are "
            "contradictory stories. You must have a rehearsed answer for an "
            "examiner who finds evidence of both."
        )

    if config.get("vault") and not config.get("vault_amplification_shown"):
        problems.append(
            "steel-vault's write amplification must be shown and acknowledged "
            "before enabling. Users who skip this enable it for their home "
            "directory and conclude the OS is broken."
        )

    if config.get("playbook") not in ("A", "B", "C"):
        problems.append(
            "No playbook was chosen. Enabling these features without one "
            "produces a story that contradicts itself under examination."
        )

    return problems


def _run(argv, root):
    libcalamares.utils.debug("steelos_threatened: run " + " ".join(argv[:3]) + " ...")
    return libcalamares.utils.host_env_process_output(argv, None)


def pretty_name():
    return "Configuring duress and deniability"


def run():
    gs = libcalamares.globalstorage
    config = gs.value("steelos.threatened") or {}
    root = gs.value("rootMountPoint")

    if not config.get("enabled"):
        return None

    if not os.path.exists(LIMITS_FILE):
        return (
            "The threatened-user limits are missing",
            f"{LIMITS_FILE} does not exist, so the comprehension check cannot "
            "be verified. Refusing to configure irreversible features without "
            "it.",
        )

    data = load_limits()
    wrong = check_comprehension(config.get("comprehension_answers", {}), data["limits"])
    if wrong:
        return (
            "Threatened-user setup was not completed",
            "The comprehension check was not passed:\n\n"
            + "\n\n".join(f"{w['title']}\n{w['explanation']}" for w in wrong),
        )

    problems = validate_configuration(config, gs.value("steelos.backup") or {})
    if problems:
        return ("Configuration cannot be applied", "\n\n".join(problems))

    playbook = config["playbook"]
    device = gs.value("luksDevice")

    _run(["steel-duress", "--root", root, "configure",
          "--playbook", playbook,
          "--action", config.get("duress_action", "alert-only")], root)

    if config.get("decoy"):
        _run(["steel-decoy", "--root", root, "create"], root)
        _run(["steel-decoy", "--root", root, "schedule", "enable"], root)

    if config.get("custody"):
        _run(["steel-custody", "--root", root, "enroll", device], root)
        # The drill is part of enrolment, not a follow-up task. Custody that has
        # never been reassembled is a data-loss event waiting to happen.
        _run(["steel-custody", "--root", root, "drill"], root)

    if config.get("vault"):
        _run(["steel-vault", "--root", root, "create",
              str(config.get("vault_gb", 8))], root)

    if config.get("attempt_limit_wipe"):
        _run(["steel-duress", "--root", root, "attempt-limit",
              "--action", "wipe-keys", "--count", "10"], root)

    # Rehearse now, while the user is still in front of the machine. A playbook
    # that has never been performed will be performed badly under stress, which
    # is the only time it matters.
    _run(["steel-duress", "--root", root, "drill", "--unattended"], root)
    return None
