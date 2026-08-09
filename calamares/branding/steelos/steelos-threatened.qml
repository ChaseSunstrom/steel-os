/* The optional threatened-user step.
 *
 * CLAUDE.md requires "a comprehension confirmation, not just an 'I agree' box",
 * and that distinction is the entire page. An agreement checkbox measures
 * whether someone can find a checkbox. What is configured here destroys data
 * irreversibly, and several of the failure modes are legal rather than
 * technical — so the user reads seven limits and answers a question about each.
 *
 * A wrong answer returns them to the paragraph it came from. It does not lock
 * them out: someone who genuinely needs these features and misses a question
 * needs the explanation, not a refusal.
 *
 * The limits, questions and playbooks are read from threatened-limits.json,
 * which is the same file the install job validates against. One source — a
 * second copy would eventually disagree, and the copy the user read is not
 * necessarily the one that gets enforced.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import io.calamares.core 1.0

SteelPage {
    id: root

    title: qsTr("Duress, decoys and custody")
    subtitle: qsTr("Optional, and off unless you turn it on. Read the limits before deciding — this is the part of SteelOS most likely to give false confidence, and false confidence here gets people hurt.")
    blocker: optedIn && problems.length > 0 ? problems[0] : ""

    property bool optedIn: false
    property var limits: []
    property var playbooks: ({})
    property var answers: ({})
    property string playbook: ""
    property string duressAction: "alert-only"
    property bool decoy: false
    property bool custody: false
    property bool vault: false
    property bool vaultAmplificationShown: false
    property bool collisionRehearsed: false
    property bool attemptLimitWipe: false
    property bool attemptLimitAcknowledged: false

    SteelFacts { id: facts }

    readonly property int answeredCorrectly: {
        var n = 0;
        for (var i = 0; i < limits.length; ++i) {
            if (answers[limits[i].id] === limits[i].correct) {
                n++;
            }
        }
        return n;
    }
    readonly property bool comprehensionPassed:
        limits.length > 0 && answeredCorrectly === limits.length

    /* The same refusals the install job applies, applied here so they are seen
     * while they can still be fixed rather than at the point of writing. */
    readonly property var problems: {
        var out = [];
        if (!optedIn) {
            return out;
        }
        if (!comprehensionPassed) {
            out.push(qsTr("The comprehension check is not complete."));
        }
        if (playbook.length === 0) {
            out.push(qsTr("No playbook chosen. Enabling these features without one produces a story that contradicts itself."));
        }
        if ((duressAction === "wipe-keys" || duressAction === "decoy-and-wipe")
            && !(Global.contains("steelos.backup")
                 && Global.value("steelos.backup").enabled === true
                 && Global.value("steelos.backup").targetKind === "remote")) {
            out.push(qsTr("A wiping duress action needs an off-device, append-only backup. Without one the destruction is permanent and total, including for you. Go back and configure a remote backup, or choose alert-only."));
        }
        if (duressAction === "decoy-and-wipe" && !decoy) {
            out.push(qsTr("decoy-and-wipe needs a decoy, and a decoy needs two credentials — one for your own routine use and one to disclose. Shipping only a wiping decoy guarantees you destroy your own data."));
        }
        if (playbook === "C" && !collisionRehearsed) {
            out.push(qsTr("Playbook C claims both custody and deniability, which are contradictory stories. Confirm you have a rehearsed answer for an examiner who finds evidence of both."));
        }
        if (vault && !vaultAmplificationShown) {
            out.push(qsTr("steel-vault's write amplification has not been acknowledged."));
        }
        if (attemptLimitWipe && !attemptLimitAcknowledged) {
            out.push(qsTr("Attempt-limit wiping has not been acknowledged."));
        }
        return out;
    }

    SteelState {
        id: state
        key: "steelos.threatened"
        valid: !root.optedIn || root.problems.length === 0
    }

    function commit() {
        state.set({
            enabled: root.optedIn,
            playbook: root.playbook,
            duress_action: root.duressAction,
            decoy: root.decoy,
            custody: root.custody,
            vault: root.vault,
            vault_amplification_shown: root.vaultAmplificationShown,
            collision_rehearsed: root.collisionRehearsed,
            attempt_limit_wipe: root.attemptLimitWipe,
            attempt_limit_acknowledged: root.attemptLimitAcknowledged,
            comprehension_answers: root.answers,
            comprehension_passed: root.comprehensionPassed
        });
    }

    function answer(limitId, index) {
        var next = {};
        for (var k in answers) {
            next[k] = answers[k];
        }
        next[limitId] = index;
        answers = next;
        commit();
    }

    function onActivate() { state.applyGate(); }

    Component.onCompleted: {
        state.load({ enabled: false });
        facts.readFile("file:///usr/share/calamares/branding/steelos/threatened-limits.json",
                       function(body) {
            if (body.length === 0) {
                return;
            }
            try {
                var parsed = JSON.parse(body);
                root.limits = parsed.limits;
                root.playbooks = parsed.playbooks;
            } catch (e) {
                root.limits = [];
            }
        });
    }

    SteelNote {
        severity: "info"
        heading: qsTr("Consider not carrying the data at all")
        text: qsTr("For most people at risk, travelling with a clean machine and restoring from a remote backup afterwards is dramatically more effective than every on-device measure here combined. <tt>steelctl export</tt> and a remote repository make that a supported workflow, and it is the honest first recommendation.")
    }

    SteelSwitch {
        label: qsTr("Set up duress, decoy or custody features")
        detail: qsTr("The code for all of this ships on every SteelOS machine whether or not you use it — that is deliberate, and it is why finding it on your disk proves only that you run SteelOS. What you decide here is stored inside the encrypted volume it protects and is not visible to anyone who has not unlocked it.")
        checked: root.optedIn
        onToggled: function(v) { root.optedIn = v; root.commit(); }
    }

    /* --- Comprehension ---------------------------------------------------- */

    Rectangle {
        visible: root.optedIn
        Layout.fillWidth: true
        Layout.preferredHeight: 1
        color: root.theme.border
    }

    RowLayout {
        visible: root.optedIn
        Layout.fillWidth: true

        Text {
            text: qsTr("The limits")
            color: root.theme.text
            font.pixelSize: root.theme.bodySize + 1
            font.weight: Font.DemiBold
            Layout.fillWidth: true
        }

        Text {
            text: qsTr("%1 of %2 answered").arg(root.answeredCorrectly).arg(root.limits.length)
            color: root.comprehensionPassed ? root.theme.ok : root.theme.textMuted
            font.pixelSize: root.theme.smallSize
        }
    }

    Repeater {
        model: root.optedIn ? root.limits : []

        Rectangle {
            id: limitCard
            required property var modelData
            required property int index

            readonly property bool answered: root.answers[modelData.id] !== undefined
            readonly property bool correct: root.answers[modelData.id] === modelData.correct

            Layout.fillWidth: true
            implicitHeight: limitLayout.implicitHeight + 2 * root.theme.gap
            radius: root.theme.radius
            color: root.theme.surface
            border.width: 1
            border.color: !answered ? root.theme.border
                        : correct ? root.theme.ok : root.theme.danger

            ColumnLayout {
                id: limitLayout
                anchors.fill: parent
                anchors.margins: root.theme.gap
                spacing: 8

                Text {
                    text: (limitCard.index + 1) + ". " + limitCard.modelData.title
                    color: root.theme.text
                    font.pixelSize: root.theme.bodySize + 1
                    font.weight: Font.DemiBold
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                Text {
                    text: limitCard.modelData.body
                    color: root.theme.textMuted
                    font.pixelSize: root.theme.bodySize
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                Text {
                    text: limitCard.modelData.question
                    color: root.theme.accent
                    font.pixelSize: root.theme.bodySize
                    font.weight: Font.DemiBold
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                    Layout.topMargin: 4
                }

                Repeater {
                    model: limitCard.modelData.options

                    RadioButton {
                        id: option
                        required property int index
                        required property string modelData

                        Layout.fillWidth: true
                        text: modelData
                        checked: root.answers[limitCard.modelData.id] === index
                        onClicked: root.answer(limitCard.modelData.id, index)

                        // Addressed by id rather than through `parent`. A
                        // contentItem is reparented to its control, so `parent`
                        // does resolve at run time — but only at run time:
                        // statically it is a bare Item, so nothing checks these
                        // two properties exist, and a typo here would show up as
                        // an unlabelled radio button rather than an error.
                        contentItem: Text {
                            text: option.text
                            color: root.theme.text
                            font.pixelSize: root.theme.bodySize
                            wrapMode: Text.WordWrap
                            leftPadding: option.indicator.width + 6
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                }

                SteelNote {
                    visible: limitCard.answered && !limitCard.correct
                    severity: "danger"
                    heading: qsTr("Not quite — read the paragraph again")
                    text: limitCard.modelData.on_wrong
                }
            }
        }
    }

    /* --- Playbook --------------------------------------------------------- */

    Rectangle {
        visible: root.optedIn && root.comprehensionPassed
        Layout.fillWidth: true
        Layout.preferredHeight: 1
        color: root.theme.border
    }

    Text {
        visible: root.optedIn && root.comprehensionPassed
        text: qsTr("Choose a playbook")
        color: root.theme.text
        font.pixelSize: root.theme.bodySize + 1
        font.weight: Font.DemiBold
        Layout.fillWidth: true
    }

    Text {
        visible: root.optedIn && root.comprehensionPassed
        text: qsTr("Custody says \"I cannot open this\". Deniability says \"there is nothing here to open\". Claimed together without preparation they undermine each other, so you pick one story and rehearse it rather than enabling everything and hoping.")
        color: root.theme.textMuted
        font.pixelSize: root.theme.bodySize
        wrapMode: Text.WordWrap
        Layout.fillWidth: true
    }

    SteelChoice {
        visible: root.optedIn && root.comprehensionPassed
        label: qsTr("A — Deniable")
        summary: qsTr("Decoy plus duress credentials, no visible custody.")
        detail: qsTr("The story is an ordinary machine belonging to a privacy-conscious person, which is also a true description of most SteelOS users. Best against searches where the goal is for examination to end early.")
        selected: root.playbook === "A"
        onPicked: { root.playbook = "A"; root.decoy = true; root.custody = false; root.commit(); }
    }

    SteelChoice {
        visible: root.optedIn && root.comprehensionPassed
        label: qsTr("B — Openly locked")
        badge: qsTr("STRONGEST")
        summary: qsTr("Split-key custody, not hidden. No decoy claimed.")
        detail: qsTr("The real volume's key is split 2-of-3 between a hardware token you leave at home, a release service with a delay, and a trusted second party. On the road the machine physically cannot be decrypted by anyone, including you — and \"I cannot\" is a materially different position from \"I will not\". Best for a professional carrying work data under an organisational policy, where being seen to have one is normal and protective.")
        selected: root.playbook === "B"
        onPicked: { root.playbook = "B"; root.custody = true; root.decoy = false; root.commit(); }
    }

    SteelChoice {
        visible: root.optedIn && root.comprehensionPassed
        label: qsTr("C — Layered")
        badge: qsTr("ADVANCED")
        badgeColor: root.theme.caution
        summary: qsTr("Both, with custody enrolment concealed. Rehearsal required.")
        detail: qsTr("Only appropriate if you have thought hard about your specific adversary and have an answer ready for the moment an examiner finds evidence of split-key enrolment on a machine you are presenting as ordinary.")
        selected: root.playbook === "C"
        onPicked: { root.playbook = "C"; root.custody = true; root.decoy = true; root.commit(); }
    }

    SteelSwitch {
        visible: root.optedIn && root.playbook === "C"
        label: qsTr("I have a rehearsed answer for the moment the two stories collide")
        detail: qsTr("Required for playbook C. <tt>steel-duress drill</tt> walks through it end to end on scratch volumes after installation.")
        checked: root.collisionRehearsed
        onToggled: function(v) { root.collisionRehearsed = v; root.commit(); }
    }

    /* --- Duress action ---------------------------------------------------- */

    Text {
        visible: root.optedIn && root.playbook.length > 0
        text: qsTr("What a duress credential does")
        color: root.theme.text
        font.pixelSize: root.theme.bodySize + 1
        font.weight: Font.DemiBold
        Layout.fillWidth: true
        Layout.topMargin: root.theme.gap
    }

    SteelChoice {
        visible: root.optedIn && root.playbook.length > 0
        label: qsTr("alert-only")
        badge: qsTr("RECOMMENDED")
        summary: qsTr("Unlocks normally and fires a signal. Destroys nothing.")
        detail: qsTr("Marks a canary file and, if the network is up, sends a pre-configured message. The right default for anyone whose adversary might escalate on discovering data was destroyed — which is most people, and is why this is not the wiping option.")
        selected: root.duressAction === "alert-only"
        onPicked: { root.duressAction = "alert-only"; root.commit(); }
    }

    SteelChoice {
        visible: root.optedIn && root.playbook.length > 0
        label: qsTr("decoy")
        summary: qsTr("Unlocks the decoy volume only. The real one stays sealed.")
        detail: qsTr("Nothing is destroyed. The decoy has its own home, its own /var, its own backup repository that genuinely receives backups, and a byte-identical /usr — so its system reveals nothing, because it is the same system.")
        selected: root.duressAction === "decoy"
        onPicked: { root.duressAction = "decoy"; root.decoy = true; root.commit(); }
    }

    SteelChoice {
        visible: root.optedIn && root.playbook.length > 0
        label: qsTr("decoy-and-wipe")
        badge: qsTr("IRREVERSIBLE")
        badgeColor: root.theme.danger
        summary: qsTr("Unlocks the decoy and silently destroys the real volume's keys.")
        detail: qsTr("Requires two decoy credentials that are indistinguishable to an examiner: one you use routinely so the decoy ages credibly, and one you disclose. Requires a remote append-only backup, because the destruction is otherwise total and includes you.")
        selected: root.duressAction === "decoy-and-wipe"
        onPicked: { root.duressAction = "decoy-and-wipe"; root.decoy = true; root.commit(); }
    }

    SteelChoice {
        visible: root.optedIn && root.playbook.length > 0
        label: qsTr("wipe-keys")
        badge: qsTr("IRREVERSIBLE")
        badgeColor: root.theme.danger
        summary: qsTr("Destroys all key material, then powers off.")
        detail: qsTr("The screen shows a normal-looking wrong-passphrase failure, never \"wipe complete\". Requires a remote append-only backup. Read limit 6 again before choosing this: destroying data in front of someone who was going to let you go can turn a search into an arrest, and in several jurisdictions is itself an offence.")
        selected: root.duressAction === "wipe-keys"
        onPicked: { root.duressAction = "wipe-keys"; root.commit(); }
    }

    /* --- Extras ----------------------------------------------------------- */

    Rectangle {
        visible: root.optedIn && root.playbook.length > 0
        Layout.fillWidth: true
        Layout.preferredHeight: 1
        color: root.theme.border
        Layout.topMargin: root.theme.gap
    }

    SteelSwitch {
        visible: root.optedIn && root.playbook.length > 0
        label: qsTr("Attempt-limit wiping")
        detail: qsTr("<b>Off by default and recommended off.</b> This is a self-destruct that anyone with physical access can trigger — a child, a roommate, a coworker, a thief who only wants the hardware, or you on a bad day with the wrong keyboard layout. Escalating delays are applied from the third attempt regardless of this setting, and give most of the anti-brute-force benefit with none of the risk.")
        checked: root.attemptLimitWipe
        onToggled: function(v) { root.attemptLimitWipe = v; root.attemptLimitAcknowledged = false; root.commit(); }
    }

    SteelSwitch {
        visible: root.optedIn && root.attemptLimitWipe
        label: qsTr("I understand anyone with physical access can trigger this")
        detail: qsTr("Including by accident.")
        checked: root.attemptLimitAcknowledged
        onToggled: function(v) { root.attemptLimitAcknowledged = v; root.commit(); }
    }

    SteelSwitch {
        visible: root.optedIn && root.playbook.length > 0
        label: qsTr("steel-vault — deniable document volume")
        detail: qsTr("A small write-only-ORAM volume for sensitive files, and the only thing here that resists an adversary who images your disk more than once. It is for documents, not for the OS and not for your home directory.")
        checked: root.vault
        onToggled: function(v) { root.vault = v; root.vaultAmplificationShown = false; root.commit(); }
    }

    SteelNote {
        visible: root.optedIn && root.vault
        severity: "caution"
        heading: qsTr("Roughly 4x write amplification, and worse on an SSD")
        text: qsTr("Oblivious writes mean every real write becomes several. That is tolerable for a few gigabytes of documents and intolerable for a home directory — people who enable it for one conclude the OS is broken. It is also weaker on an SSD than on a mechanical disk, because the drive's own translation layer remaps blocks in ways no software can see or control.")
    }

    SteelSwitch {
        visible: root.optedIn && root.vault
        label: qsTr("I have read the write-amplification cost")
        detail: qsTr("Required before the vault is created.")
        checked: root.vaultAmplificationShown
        onToggled: function(v) { root.vaultAmplificationShown = v; root.commit(); }
    }

    /* --- Refusals --------------------------------------------------------- */

    Repeater {
        model: root.optedIn ? root.problems : []

        SteelNote {
            required property string modelData
            severity: "danger"
            heading: qsTr("Cannot continue")
            text: modelData
        }
    }
}
