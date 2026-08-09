/* Boot security: Secure Boot keys, TPM binding, and the recovery key.
 *
 * Three rules this page exists to enforce, from calamares/README.md:
 *
 *  - Microsoft's keys are included by default. Some firmware needs them to run
 *    option ROMs — a discrete GPU's, most commonly — and a machine that enrols
 *    only our keys can fail to POST. Removing them is an explicit expert
 *    choice, not a default.
 *
 *  - TPM enrolment without a PIN is not offered at all. Not defaulted off:
 *    absent. A TPM-sealed key with no PIN unlocks for whoever is holding the
 *    machine, which turns full-disk encryption into a speed bump against
 *    exactly the attacker it exists to stop.
 *
 *  - The recovery key confirmation asks for one segment at random rather than
 *    the whole key. Asking for the whole thing invites copy-paste off the
 *    screen, which proves nothing.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import io.calamares.core 1.0

SteelPage {
    id: root

    title: qsTr("Boot security")
    subtitle: qsTr("What the firmware will trust, how the disk unlocks, and how you get back in if that fails.")
    blocker: !challengeOk
             ? qsTr("Write down the recovery key at the bottom of this page and type back the group it asks for.")
             : !tpmOk
               ? qsTr("The TPM PIN must be at least 6 characters and both entries must match.")
               : ""

    property int challengeIndex: 0
    property string challengeAnswer: ""
    property bool enrollKeys: true
    property bool includeMicrosoft: true
    property bool useTpm: false
    property string tpmPin: ""
    property string tpmPinAgain: ""

    SteelFacts { id: facts }

    readonly property var keySegments: facts.recoveryKey.length > 0
                                       ? facts.recoveryKey.split("-") : []
    readonly property bool challengeOk:
        keySegments.length === 0
        || challengeAnswer.toUpperCase() === keySegments[challengeIndex]
    readonly property bool tpmOk:
        !useTpm || (tpmPin.length >= 6 && tpmPin === tpmPinAgain)

    SteelState {
        id: state
        key: "steelos.bootsec"
        valid: root.challengeOk && root.tpmOk
    }

    function onActivate() {
        state.applyGate();
    }

    Component.onCompleted: {
        // A segment chosen at random, fixed for the session. Always asking for
        // the first one teaches people to only read the first one.
        challengeIndex = Math.floor(Math.random() * 8);
        state.load({
            enrollKeys: true,
            includeMicrosoft: true,
            tpm: false,
            tpmPin: "",
            recoveryKeyConfirmed: false
        });
    }

    SteelNote {
        severity: facts.firmware === "uefi" ? "info" : "danger"
        heading: facts.firmware === "uefi" ? qsTr("UEFI firmware detected")
                                           : qsTr("This machine booted in BIOS mode")
        text: facts.firmware === "uefi"
              ? qsTr("Secure Boot state: <b>%1</b>. Setup mode: <b>%2</b>.")
                .arg(facts.secureBoot).arg(facts.setupMode ? qsTr("yes") : qsTr("no"))
              : qsTr("SteelOS seals the dm-verity root hash inside a signed UKI, which requires UEFI. Reboot the installer in UEFI mode, or this machine cannot run a verified boot chain.")
    }

    /* --- Secure Boot ---------------------------------------------------- */

    Text {
        text: qsTr("Secure Boot")
        color: root.theme.text
        font.pixelSize: root.theme.bodySize + 1
        font.weight: Font.DemiBold
        Layout.fillWidth: true
    }

    SteelSwitch {
        label: qsTr("Enrol our own Secure Boot keys")
        detail: qsTr("Generates a key pair on this machine with sbctl, enrols it, and signs the UKI with it. This is what makes the signature on the kernel — and therefore on the root hash it carries — mean something to <i>your</i> firmware rather than to a vendor's.")
        disabledReason: qsTr("Firmware is not in setup mode. The installer will show you how to enter it; keys can be enrolled afterwards with <tt>steel-boot enroll</tt>.")
        enabled: facts.setupMode || !facts.loaded
        checked: root.enrollKeys
        onToggled: function(v) { root.enrollKeys = v; state.set({ enrollKeys: v }); }
    }

    SteelSwitch {
        label: qsTr("Keep Microsoft's keys enrolled")
        detail: qsTr("Recommended. Some firmware needs them to run option ROMs — a discrete GPU's, most commonly — and a machine that trusts only our key can fail to POST. That is hard to diagnose and, on some hardware, hard to recover from.")
        enabled: root.enrollKeys
        checked: root.includeMicrosoft
        onToggled: function(v) { root.includeMicrosoft = v; state.set({ includeMicrosoft: v }); }
    }

    SteelNote {
        visible: root.enrollKeys && !root.includeMicrosoft
        severity: "danger"
        heading: qsTr("Expert choice")
        text: qsTr("Removing Microsoft's keys can leave this machine unable to POST with its current graphics card. Have a way to reset the firmware's key store before you reboot.")
    }

    /* --- TPM ------------------------------------------------------------ */

    Rectangle { Layout.fillWidth: true; height: 1; color: root.theme.border; Layout.topMargin: root.theme.gap }

    Text {
        text: qsTr("Unlocking")
        color: root.theme.text
        font.pixelSize: root.theme.bodySize + 1
        font.weight: Font.DemiBold
        Layout.fillWidth: true
    }

    SteelSwitch {
        label: qsTr("Bind the disk key to this machine's TPM, with a PIN")
        detail: qsTr("Sealed to PCR 7 and PCR 11, so the key is released only when the firmware's Secure Boot state and the measured UKI both match. Pull the drive and it yields ciphertext; swap in a tampered OS to capture the passphrase and the measurements change and the TPM refuses.<br><br>A PIN is mandatory. TPM alone unlocks for whoever is holding the machine.")
        disabledReason: facts.tpm === "tpm1"
                        ? qsTr("This machine has a TPM 1.2, which cannot do PCR-sealed unlock the way this design needs.")
                        : qsTr("No TPM 2.0 was detected. The passphrase remains the way in, which is a perfectly good answer.")
        enabled: facts.hasTpm2
        checked: root.useTpm
        onToggled: function(v) { root.useTpm = v; state.set({ tpm: v }); }
    }

    SteelField {
        visible: root.useTpm
        label: qsTr("TPM PIN")
        placeholder: qsTr("at least 6 characters")
        secret: true
        hint: root.tpmPin.length > 0 && root.tpmPin.length < 6
              ? qsTr("At least 6 characters.") : ""
        hintSeverity: "danger"
        onEdited: function(v) { root.tpmPin = v; state.set({ tpmPin: v }); }
    }

    SteelField {
        visible: root.useTpm
        label: qsTr("TPM PIN again")
        secret: true
        hint: root.tpmPinAgain.length > 0 && root.tpmPin !== root.tpmPinAgain
              ? qsTr("The two entries do not match.") : ""
        hintSeverity: "danger"
        onEdited: function(v) { root.tpmPinAgain = v; }
    }

    SteelNote {
        visible: root.useTpm
        severity: "caution"
        heading: qsTr("A firmware update will break this")
        text: qsTr("Updating the BIOS changes PCR 7, and automatic unlock stops working until you run <tt>steel-boot reseal</tt>. The recovery key below is what gets you in when that happens, so it is not optional.")
    }

    /* --- Recovery key --------------------------------------------------- */

    Rectangle { Layout.fillWidth: true; height: 1; color: root.theme.border; Layout.topMargin: root.theme.gap }

    Text {
        text: qsTr("Recovery key")
        color: root.theme.text
        font.pixelSize: root.theme.bodySize + 1
        font.weight: Font.DemiBold
        Layout.fillWidth: true
    }

    Text {
        text: qsTr("Write this down now, on paper, and keep it somewhere other than with this machine. It is generated once and shown once.")
        color: root.theme.textMuted
        font.pixelSize: root.theme.bodySize
        wrapMode: Text.WordWrap
        Layout.fillWidth: true
    }

    Rectangle {
        Layout.fillWidth: true
        implicitHeight: keyText.implicitHeight + 2 * root.theme.gapLarge
        radius: root.theme.radius
        color: root.theme.surface
        border.width: 1
        border.color: root.theme.accent

        Text {
            id: keyText
            anchors.centerIn: parent
            width: parent.width - 2 * root.theme.gapLarge
            horizontalAlignment: Text.AlignHCenter
            text: facts.recoveryKey.length > 0
                  ? facts.recoveryKey
                  : qsTr("unavailable — the live probe did not run")
            color: facts.recoveryKey.length > 0 ? root.theme.accent : root.theme.caution
            font.family: "monospace"
            font.pixelSize: root.theme.titleSize
            font.letterSpacing: 2
            wrapMode: Text.WrapAnywhere
        }
    }

    SteelField {
        visible: root.keySegments.length > 0
        label: qsTr("Type group %1 of 8 to confirm you wrote it down").arg(root.challengeIndex + 1)
        placeholder: qsTr("5 characters")
        monospace: true
        hint: root.challengeAnswer.length === 0 ? ""
              : root.challengeOk ? qsTr("Matches.") : qsTr("That is not group %1.").arg(root.challengeIndex + 1)
        hintSeverity: root.challengeOk ? "ok" : "danger"
        onEdited: function(v) {
            root.challengeAnswer = v;
            state.set({ recoveryKeyConfirmed: root.challengeOk });
        }
    }

    /* --- Things the user must do in firmware ---------------------------- */

    SteelNote {
        visible: facts.memoryEncryptionSupported && !facts.memoryEncryptionActive
        severity: "caution"
        heading: qsTr("Memory encryption is supported but switched off")
        text: qsTr("This CPU supports SME/TME and the firmware has it disabled. Enable it in firmware setup after installing — it defends against cold-boot and DMA attacks. It does not defend against software reading memory through the kernel, and nothing claims it does.")
    }

    SteelNote {
        visible: facts.loaded && !facts.iommu
        severity: "caution"
        heading: qsTr("No IOMMU is active")
        text: qsTr("Without it, a Thunderbolt or PCIe peripheral can read system memory directly. The installed system requests it on the kernel command line; if it is disabled in firmware, enable it there.")
    }
}
