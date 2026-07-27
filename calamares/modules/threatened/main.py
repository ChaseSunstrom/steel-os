#!/usr/bin/env python3
"""The optional "Threatened-user setup" step.

CLAUDE.md: this step "enables it and walks through the limits above with a
comprehension confirmation, not just an 'I agree' box."

That distinction is the whole module. An "I agree" checkbox measures whether
someone can find a checkbox. The failure modes here are irreversible — a wiped
volume with no backup, a decoy that was never aged, a 2-of-3 quorum that was
never reassembled — and several are legal rather than technical. So the user
answers questions about what they just read, and a wrong answer sends them back
to the relevant paragraph rather than blocking them permanently.

This module is also where the installer refuses combinations that cannot work,
rather than letting someone assemble them and find out later.
"""

import libcalamares
from libcalamares.utils import check_target_env_call

# ---------------------------------------------------------------------------
# The limits, in the order they must be read.
# ---------------------------------------------------------------------------

LIMITS = [
    {
        "id": "capability-vs-use",
        "title": "This hides whether you used it, not that it exists",
        "body": (
            "An examiner who identifies this OS as SteelOS knows every install "
            "has decoy capability. That is the point of shipping it universally "
            "— a machine without it would be the anomaly — and it is also the "
            "ceiling on what this achieves.\n\n"
            "They cannot prove from the disk that you configured one. They can "
            "simply demand another passphrase anyway, indefinitely. No "
            "cryptographic construction distinguishes 'there is nothing more' "
            "from 'I refuse', and neither can they — which is why an adversary "
            "willing to keep asking is not defeated by any of this."
        ),
        "question": (
            "If an examiner identifies this machine as running SteelOS, what "
            "can they conclude about whether you have configured a decoy?"
        ),
        "options": [
            "Nothing — every install has the capability",
            "That a decoy exists, because the software is present",
            "That no decoy exists unless they find one",
        ],
        "correct": 0,
        "on_wrong": (
            "Re-read the paragraph above. The capability is universal, so its "
            "presence says nothing about you. What it also means is that they "
            "know to ask."
        ),
    },
    {
        "id": "multiple-snapshot",
        "title": "An adversary who images your disk twice defeats a decoy",
        "body": (
            "If your adversary can image the disk on more than one occasion — a "
            "repeated border crossing, a seized-and-returned laptop, a "
            "compromised backup target — then blocks that changed between "
            "images, while the decoy claims to have been idle, are direct "
            "evidence that a hidden volume exists.\n\n"
            "Defending against this needs ORAM-style oblivious writes at severe "
            "performance cost. steel-vault implements it for a small documents "
            "volume. The main volume does not have it and will not."
        ),
        "question": (
            "Your laptop is taken at a border crossing, examined, and returned. "
            "Two months later you cross the same border and it is taken again. "
            "Does a decoy protect you?"
        ),
        "options": [
            "Yes, as long as the decoy has been used in between",
            "No — two images of the same disk expose the hidden volume",
            "Yes, decoys are designed for exactly this",
        ],
        "correct": 1,
        "on_wrong": (
            "This is the case where decoys fail, and it is a common real "
            "situation rather than an exotic one. If your adversary has repeated "
            "physical access, assume decoys do not work for you."
        ),
    },
    {
        "id": "decoy-not-confidential",
        "title": "The decoy is not confidential",
        "body": (
            "Something has to open the decoy volume with nobody present, so the "
            "unattended aging sessions can run. The decoy key is therefore "
            "TPM-sealed and released automatically on a dedicated maintenance "
            "boot path.\n\n"
            "That means anyone holding the hardware can open the decoy. It "
            "provides NO confidentiality against the person you are surrendering "
            "it to.\n\n"
            "This is acceptable only because surrendering it is the plan — and "
            "it turns 'the decoy should contain nothing real' from advice into a "
            "hard requirement. steel-decoy refuses to import your data."
        ),
        "question": "What may be stored in the decoy profile?",
        "options": [
            "Nothing real — anyone with the hardware can open it",
            "Anything not sensitive, since it is still encrypted",
            "Real but old data, as that makes it more credible",
        ],
        "correct": 0,
        "on_wrong": (
            "The decoy's key is released by the machine itself. Encryption that "
            "the holder of the device can undo is not protecting anything from "
            "them."
        ),
    },
    {
        "id": "wipe-needs-backup",
        "title": "Key destruction without an off-device backup is permanent",
        "body": (
            "Duress actions work by destroying key material, which makes the "
            "ciphertext permanently unreadable in milliseconds. That is the "
            "point, and it is also the risk.\n\n"
            "If there is no off-device, append-only backup, the destruction is "
            "total and includes you. The installer will refuse to configure a "
            "wiping action without one."
        ),
        "question": (
            "You enable a wiping duress action and have no remote backup. Your "
            "duress passphrase is entered. What is recoverable?"
        ),
        "options": [
            "The data, using the LUKS recovery key",
            "The data, from the local btrfs snapshots",
            "Nothing, ever, by anyone including you",
        ],
        "correct": 2,
        "on_wrong": (
            "The recovery key is itself a keyslot, and the wipe destroys the "
            "keyslots. Local snapshots are on the disk being destroyed. Neither "
            "survives, which is why the off-device backup is not optional."
        ),
    },
    {
        "id": "attempt-limits",
        "title": "Attempt-limit wiping is a self-destruct anyone can trigger",
        "body": (
            "Count-based auto-wipe can be triggered by anyone with physical "
            "access: a child, a roommate, a coworker, a thief who only wants to "
            "resell the hardware, or you on a bad day with the wrong keyboard "
            "layout.\n\n"
            "GrapheneOS deliberately does not enable count-based auto-wipe as a "
            "default for exactly this reason. Escalating delays give most of the "
            "anti-brute-force benefit with none of the self-destruct risk, and a "
            "40-character passphrase makes brute force irrelevant regardless.\n\n"
            "We recommend delays. We offer wiping. It is OFF by default."
        ),
        "question": (
            "Who can trigger an attempt-limit wipe on your machine?"
        ),
        "options": [
            "Anyone with physical access, including by accident",
            "Only someone who knows it is configured",
            "Only an attacker deliberately brute-forcing it",
        ],
        "correct": 0,
        "on_wrong": (
            "The counter does not know who is typing or why. A toddler at a "
            "keyboard reaches the limit the same way an attacker does."
        ),
    },
    {
        "id": "wiping-can-escalate",
        "title": "Wiping can make your situation worse",
        "body": (
            "Destroying data in front of someone who was going to let you go can "
            "turn a search into an arrest. In several jurisdictions destroying "
            "data during an investigation, or at a border, is itself an offence "
            "— sometimes a more serious one than whatever was being protected.\n\n"
            "This is why `alert-only` exists as a duress action and why it is "
            "the recommended default for anyone whose adversary might react "
            "badly to discovering data was destroyed.\n\n"
            "If you are facing real legal jeopardy, get advice from a lawyer in "
            "your jurisdiction. This software is not a legal strategy."
        ),
        "question": "When is wiping NOT the right duress action?",
        "options": [
            "Never — wiping is always the safest response",
            "When discovering the destruction would escalate your situation",
            "Only when you have no backup",
        ],
        "correct": 1,
        "on_wrong": (
            "Destruction is a response to one threat that can create another. "
            "alert-only exists because that trade is not always worth making."
        ),
    },
    {
        "id": "off-device-evidence",
        "title": "Off-device evidence usually dominates",
        "body": (
            "Cloud backups, ISP records, purchase history, phone contents, VPN "
            "account records, and your own backup remote all testify about what "
            "this machine actually did. A decoy on the disk does nothing about "
            "any of them.\n\n"
            "This is usually the largest hole and the one people think about "
            "least. For most people at risk, NOT CARRYING THE DATA AT ALL — a "
            "clean device, restored from a remote backup afterwards — is "
            "dramatically more effective than every on-device measure combined. "
            "`steelctl export` and a remote repository make that a supported "
            "workflow."
        ),
        "question": (
            "What is usually the most effective protection for someone crossing "
            "a border with sensitive data?"
        ),
        "options": [
            "A well-aged decoy profile",
            "A duress passphrase that wipes the volume",
            "Not carrying the data — travel clean, restore afterwards",
        ],
        "correct": 2,
        "on_wrong": (
            "Every on-device measure is an attempt to survive an examination. "
            "Not having the data is an attempt to make the examination "
            "pointless, and it works far more reliably."
        ),
    },
]

# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------

PLAYBOOKS = {
    "A": {
        "name": "Deniable",
        "description": (
            "Decoy plus duress credentials, no visible custody. The story is an "
            "ordinary machine belonging to a privacy-conscious person."
        ),
        "best_for": "Searches where the goal is for examination to end early.",
        "enables": ["decoy", "duress-credentials"],
    },
    "B": {
        "name": "Openly locked",
        "description": (
            "Custody enabled and not hidden. The story is 'this device is under "
            "a key-management policy; I physically cannot open it here, and "
            "release needs a delay and a second party.' No decoy claimed."
        ),
        "best_for": (
            "A professional carrying work data under an organisational policy — "
            "a journalist, an auditor, a lawyer — where being SEEN to have a "
            "policy is normal and protective."
        ),
        "enables": ["custody"],
    },
    "C": {
        "name": "Layered",
        "description": (
            "Both, with custody enrollment concealed in the universal custody "
            "region, and a rehearsed answer for the moment the two stories "
            "collide."
        ),
        "best_for": (
            "Only people who have thought hard about their specific adversary."
        ),
        "enables": ["decoy", "duress-credentials", "custody"],
        "warning": (
            "Custody says 'I cannot open this'. Deniability says 'there is "
            "nothing here to open'. Claimed together they undermine each other: "
            "an examiner who finds evidence of split-key enrollment on a machine "
            "you present as ordinary has caught the contradiction. Choose this "
            "only if you have a rehearsed answer for that moment."
        ),
    },
}


def check_comprehension(answers):
    """Return the limits the user answered incorrectly.

    Deliberately NOT a pass/fail gate that locks someone out. A wrong answer
    returns them to the paragraph it came from. The purpose is to make sure the
    text was read, not to administer an exam — someone who genuinely needs
    these features and fails a question needs the explanation, not a refusal.
    """
    wrong = []
    for limit in LIMITS:
        given = answers.get(limit["id"])
        if given != limit["correct"]:
            wrong.append({
                "id": limit["id"],
                "title": limit["title"],
                "explanation": limit["on_wrong"],
            })
    return wrong


def validate_configuration(config):
    """Refuse combinations that cannot work, before anything is written."""
    problems = []

    action = config.get("duress_action")
    if action in ("wipe-keys", "decoy-and-wipe") and not config.get("backup_target"):
        problems.append(
            "A wiping duress action needs an off-device, append-only backup. "
            "Without one the destruction is permanent and total, including for "
            "you. Configure a backup target first, or choose alert-only."
        )

    if config.get("decoy") and not config.get("decoy_maintenance_credential"):
        problems.append(
            "A decoy needs TWO credentials: decoy-maintenance (yours, never "
            "disclosed, used to age the decoy) and decoy-duress (the one you "
            "disclose). Shipping only a wiping decoy guarantees you destroy your "
            "own data and makes credible aging impossible."
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

    return problems


def run():
    gs = libcalamares.globalstorage

    if not gs.value("steelosThreatenedSetup"):
        return None

    config = gs.value("steelosThreatenedConfig") or {}

    wrong = check_comprehension(config.get("comprehension_answers", {}))
    if wrong:
        # The UI loops back before reaching exec; reaching here with wrong
        # answers means the view was bypassed, so fail rather than configure
        # irreversible things for someone who has not read the limits.
        return (
            "Threatened-user setup was not completed",
            "The comprehension check was not passed. These features destroy "
            "data irreversibly and cannot be configured without it.",
        )

    problems = validate_configuration(config)
    if problems:
        return ("Configuration cannot be applied", "\n\n".join(problems))

    playbook = config.get("playbook")
    check_target_env_call(["steel-duress", "configure", "--playbook", playbook])

    if config.get("decoy"):
        check_target_env_call(["steel-decoy", "create"])
        check_target_env_call(["steel-decoy", "schedule", "enable"])

    if config.get("custody"):
        check_target_env_call(["steel-custody", "enroll", gs.value("luksDevice")])
        # The drill is part of enrollment, not a follow-up task. Custody that
        # has never been reassembled is a data-loss event waiting to happen.
        check_target_env_call(["steel-custody", "drill"])

    if config.get("vault"):
        check_target_env_call(["steel-vault", "create", str(config.get("vault_gb", 8))])

    # And rehearse, here, while the user is still in front of the machine.
    check_target_env_call(["steel-duress", "drill"])
    return None
