/* Backups.
 *
 * Two rules are enforced in the UI rather than documented, because both of them
 * silently void the rest of the design if they are broken:
 *
 *  - No backup target may live on the device being protected. A local snapshot
 *    is a convenience rollback and is labelled as one; it is never counted as a
 *    backup. This is what resolves the recoverable-versus-destroyable tension:
 *    local key material can be destroyed under duress precisely because
 *    recovery lives somewhere else.
 *
 *  - The target must be append-only. Without that, an adversary with the
 *    running machine deletes the backups and then the local wipe is total —
 *    and so does ransomware.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import io.calamares.core 1.0

SteelPage {
    id: root

    title: qsTr("Backups")
    subtitle: qsTr("A backup system that has never restored is not a backup system, so this one verifies itself on a schedule.")
    blocker: backupEnabled && targetKind === "remote" && remoteUrl.length === 0
             ? qsTr("Enter the backup repository, or switch the target to a removable drive.")
             : ""

    property bool backupEnabled: true
    property string targetKind: "remote"
    property string remoteUrl: ""
    property string outerKey: ""

    SteelState {
        id: state
        key: "steelos.backup"
        valid: !root.backupEnabled
               || (root.targetKind === "removable")
               || (root.targetKind === "remote" && root.remoteUrl.length > 0)
    }

    function onActivate() { state.applyGate(); }

    Component.onCompleted: {
        state.load({
            enabled: true,
            targetKind: "remote",
            remoteUrl: "",
            outerKeyRecipient: "",
            appendOnly: true,
            schedule: "daily",
            retention: "7d 4w 6m"
        });
        root.backupEnabled = state.values.enabled;
        root.targetKind = state.values.targetKind;
        root.remoteUrl = state.values.remoteUrl;
        root.outerKey = state.values.outerKeyRecipient;
    }

    SteelSwitch {
        label: qsTr("Set up backups now")
        detail: qsTr("Per profile, from inside the session while the home is unlocked. Backing up a locked homed home at block level produces a blob that can only be restored wholesale and cannot be verified — so this is the only correct way to do it, and it has to be configured per profile.")
        checked: root.backupEnabled
        onToggled: function(v) { root.backupEnabled = v; state.set({ enabled: v }); }
    }

    Text {
        visible: root.backupEnabled
        text: qsTr("Where")
        color: root.theme.text
        font.pixelSize: root.theme.bodySize + 1
        font.weight: Font.DemiBold
        Layout.fillWidth: true
    }

    SteelChoice {
        visible: root.backupEnabled
        label: qsTr("Remote server")
        badge: qsTr("RECOMMENDED")
        summary: qsTr("restic or borg over SSH, append-only.")
        detail: qsTr("Configured with a credential that can add but cannot delete or prune — a rest-server in <tt>--append-only</tt> mode, or a forced SSH command for borg. Pruning happens from a different, trusted machine. This is what makes the duress design real rather than decorative.")
        selected: root.targetKind === "remote"
        onPicked: { root.targetKind = "remote"; state.set({ targetKind: "remote" }); }
    }

    SteelChoice {
        visible: root.backupEnabled
        label: qsTr("Removable drive")
        summary: qsTr("A drive that is not attached during normal operation.")
        detail: qsTr("Acceptable, with one condition that is on you rather than on the software: it has to actually be detached. A backup drive left plugged in is on the same machine as the data, and an attacker with the running system reaches both.")
        selected: root.targetKind === "removable"
        onPicked: { root.targetKind = "removable"; state.set({ targetKind: "removable" }); }
    }

    SteelField {
        visible: root.backupEnabled && root.targetKind === "remote"
        label: qsTr("Repository")
        placeholder: qsTr("rest:https://backup.example.org/steelos  ·  ssh://borg@host/./repo")
        text: root.remoteUrl
        hint: qsTr("Credentials are collected on first run inside the profile's session, not here — this installer should not hold them.")
        onEdited: function(v) { root.remoteUrl = v; state.set({ remoteUrl: v }); }
    }

    SteelField {
        visible: root.backupEnabled
        label: qsTr("Outer encryption recipient (age public key)")
        placeholder: qsTr("age1... — public key only")
        text: root.outerKey
        monospace: true
        hint: root.outerKey.length > 0 && root.outerKey.indexOf("AGE-SECRET-KEY") === 0
              ? qsTr("That is a PRIVATE key. Only the public key may ever be on this machine.")
              : qsTr("Optional but strongly recommended. Leave empty to use restic's own encryption alone.")
        hintSeverity: root.outerKey.indexOf("AGE-SECRET-KEY") === 0 ? "danger" : "info"
        onEdited: function(v) { root.outerKey = v; state.set({ outerKeyRecipient: v }); }
    }

    SteelNote {
        visible: root.backupEnabled
        severity: "caution"
        heading: qsTr("The outer private key must never touch this machine")
        text: qsTr("Each archive is encrypted twice with independent key material: restic's own key, and an <tt>age</tt> layer keyed by a recipient <b>public</b> key. Because only the public half is here, a seized or fully compromised machine cannot decrypt its own history. If that private key lands in the keyring for convenience, the entire benefit is gone — <tt>steel-check</tt> verifies that only a public key is present, and will fail if it is not.")
    }

    SteelNote {
        visible: root.backupEnabled
        severity: "danger"
        heading: qsTr("Lose the outer private key and the backups are gone")
        text: qsTr("There is no recovery path and there cannot be one; that is the same property that makes this useful. Store it on a hardware token, on paper, or with someone you trust — off this machine — before you rely on it.")
    }

    SteelNote {
        severity: "info"
        heading: qsTr("The LUKS header backup lives only in the remote repository")
        text: qsTr("Never on this device and never on the ESP. That is what lets a duress wipe be genuinely destructive to whoever is holding the hardware while remaining recoverable by you afterwards. Header backup and duress wiping are opposing properties, and this is how both are kept true at once.")
    }
}
