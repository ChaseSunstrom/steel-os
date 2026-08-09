/* Disk and encryption.
 *
 * SteelOS takes the whole disk. That is not a simplification for the
 * installer's benefit: unallocated regions with high-entropy data are a
 * forensic signal, and a partition table whose shape varies between installs
 * weakens the deniability design for everyone, not just the person who chose
 * it. So there is no "install alongside" and no free space — the layout is
 * identical on every SteelOS machine, and the space not in use is filled with
 * random data.
 *
 * The passphrase is the only thing standing between a stolen machine and the
 * data on it. Length beats complexity, and the meter says so rather than
 * demanding a symbol.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import io.calamares.core 1.0

SteelPage {
    id: root

    title: qsTr("Disk")
    subtitle: qsTr("SteelOS allocates the entire disk and fills what it does not use with random data. Everything on the selected disk is destroyed.")
    blocker: selectedIndex < 0
             ? qsTr("Choose a disk to continue.")
             : passphrase.length < 12
               ? qsTr("Enter an encryption passphrase of at least 12 characters — the fields are further down this page.")
               : passphrase !== passphraseAgain
                 ? qsTr("The two passphrase entries do not match.")
                 : ""

    property int selectedIndex: -1
    property string passphrase: ""
    property string passphraseAgain: ""

    SteelFacts { id: facts }

    SteelState {
        id: state
        key: "steelos.disk"
        valid: root.selectedIndex >= 0
               && root.passphrase.length >= 12
               && root.passphrase === root.passphraseAgain
    }

    function humanSize(bytes) {
        var gb = bytes / 1000000000;
        if (gb >= 1000) {
            return (gb / 1000).toFixed(1) + " TB";
        }
        return Math.round(gb) + " GB";
    }

    /* Length, not character classes. A 12-character passphrase of four words is
     * stronger than an 8-character one with a symbol in it, and telling people
     * otherwise is how "P@ssw0rd1" became universal. */
    function strengthOf(p) {
        if (p.length === 0) return { text: "", severity: "info" };
        if (p.length < 12) return {
            text: qsTr("Too short. At least 12 characters; four or five unrelated words is the easiest way to get there."),
            severity: "danger" };
        if (p.length < 20) return {
            text: qsTr("Workable. Every additional character is worth more than any symbol you could add."),
            severity: "caution" };
        if (p.length < 30) return {
            text: qsTr("Good. Long enough that brute force is not the way in."),
            severity: "ok" };
        return { text: qsTr("Strong."), severity: "ok" };
    }

    function pick(index) {
        root.selectedIndex = index;
        var disk = facts.disks[index];
        state.set({ device: disk.path, model: disk.model, bytes: disk.bytes });
    }

    function onActivate() {
        state.applyGate();
    }

    Component.onCompleted: {
        state.load({ device: "", model: "", bytes: 0, passphrase: "", wholeDisk: true });
    }

    SteelNote {
        severity: "danger"
        heading: qsTr("This erases the selected disk")
        text: qsTr("There is no dual-boot option and no way to keep an existing partition. Back up anything on the target disk before continuing.")
    }

    SteelNote {
        visible: !facts.loaded
        severity: "caution"
        heading: qsTr("Hardware facts are unavailable")
        text: qsTr("The live probe did not run, so no disks can be listed. This installer is meant to be run from the SteelOS live medium.")
    }

    Text {
        visible: facts.loaded
        text: qsTr("Available disks")
        color: root.theme.textMuted
        font.pixelSize: root.theme.smallSize
        Layout.fillWidth: true
    }

    Repeater {
        model: facts.disks

        SteelChoice {
            required property int index
            required property var modelData

            readonly property bool tooSmall: modelData.bytes < facts.minimumDiskBytes
            readonly property bool isLive: modelData.live === true

            label: modelData.path + "  —  " + root.humanSize(modelData.bytes)
            summary: modelData.model
                     + (modelData.rotational ? qsTr("  ·  rotational") : qsTr("  ·  solid state"))
                     + (modelData.removable ? qsTr("  ·  removable") : "")
            badge: isLive ? qsTr("LIVE MEDIUM")
                 : tooSmall ? qsTr("TOO SMALL") : ""
            badgeColor: root.theme.danger
            detail: isLive
                    ? qsTr("This is the disk the installer booted from. It cannot be the target.")
                    : tooSmall
                      ? qsTr("SteelOS needs at least 64 GB: two root slots, two verity trees, the always-allocated custody and decoy regions, and /var. A smaller disk installs and then cannot take an update.")
                      : qsTr("A solid-state drive cannot be reliably overwritten, so nothing here relies on overwriting — the duress features destroy key material instead. This matters if you plan to use them.")
            enabled: !isLive && !tooSmall
            selected: root.selectedIndex === index
            onPicked: root.pick(index)
        }
    }

    Rectangle {
        Layout.fillWidth: true
        Layout.topMargin: root.theme.gap
        height: 1
        color: root.theme.border
    }

    Text {
        text: qsTr("Encryption passphrase")
        color: root.theme.text
        font.pixelSize: root.theme.bodySize + 1
        font.weight: Font.DemiBold
        Layout.fillWidth: true
    }

    Text {
        text: qsTr("Unlocks /var and every profile's home at boot. It is not recoverable — if it is lost, the recovery key on the next page is the only way back in.")
        color: root.theme.textMuted
        font.pixelSize: root.theme.bodySize
        wrapMode: Text.WordWrap
        Layout.fillWidth: true
    }

    SteelField {
        id: passField
        label: qsTr("Passphrase")
        placeholder: qsTr("four or five unrelated words")
        secret: true
        hint: root.strengthOf(root.passphrase).text
        hintSeverity: root.strengthOf(root.passphrase).severity
        onEdited: function(value) {
            root.passphrase = value;
            state.set({ passphrase: value });
        }
    }

    SteelField {
        label: qsTr("Passphrase again")
        secret: true
        hint: root.passphraseAgain.length > 0 && root.passphrase !== root.passphraseAgain
              ? qsTr("The two entries do not match.") : ""
        hintSeverity: "danger"
        onEdited: function(value) { root.passphraseAgain = value; }
    }
}
