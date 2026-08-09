/* Profiles.
 *
 * A profile is a systemd-homed user with a LUKS-backed home, its own Flatpak
 * app set, its own sandbox strictness and its own backup configuration. It is
 * deliberately not a bespoke concept — they are just users, so every existing
 * tool works on them.
 *
 * The honest limit, stated on the page and not only in the docs: profiles share
 * one kernel. This separates data and confines applications. It does not defend
 * against a kernel exploit, and anyone who needs that wants Qubes.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import io.calamares.core 1.0

SteelPage {
    id: root

    title: qsTr("Profiles")
    subtitle: qsTr("Each profile's home is independently encrypted. One profile cannot read another's data at rest, even as root.")
    blocker: allValid
             ? ""
             : qsTr("Every profile needs a valid user name and a password of at least 8 characters, entered twice.")

    SteelState {
        id: state
        key: "steelos.profiles"
        valid: root.allValid
    }

    ListModel {
        id: profiles
        ListElement {
            name: ""
            password: ""
            passwordAgain: ""
            sandbox: "balanced"
            homeSizeGb: 64
        }
    }

    readonly property bool allValid: {
        if (profiles.count === 0) {
            return false;
        }
        var seen = {};
        for (var i = 0; i < profiles.count; ++i) {
            var p = profiles.get(i);
            if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(p.name)) {
                return false;
            }
            if (seen[p.name]) {
                return false;
            }
            seen[p.name] = true;
            if (p.password.length < 8 || p.password !== p.passwordAgain) {
                return false;
            }
        }
        return true;
    }

    onAllValidChanged: commitProfiles()

    function commitProfiles() {
        var list = [];
        for (var i = 0; i < profiles.count; ++i) {
            var p = profiles.get(i);
            list.push({
                name: p.name,
                password: p.password,
                sandbox: p.sandbox,
                homeSizeGb: p.homeSizeGb
            });
        }
        state.set({ profiles: list });
    }

    function onActivate() { state.applyGate(); }

    Component.onCompleted: state.load({ profiles: [] })

    SteelNote {
        severity: "info"
        heading: qsTr("Homes do not shrink easily")
        text: qsTr("A systemd-homed home is a LUKS image sized at creation. Growing one is routine; shrinking one is not. Size it for what this profile will hold, not for what it holds on day one.")
    }

    Repeater {
        model: profiles

        Rectangle {
            id: card
            required property int index
            required property string name
            required property string password
            required property string passwordAgain
            required property string sandbox

            Layout.fillWidth: true
            implicitHeight: cardLayout.implicitHeight + 2 * root.theme.gap
            radius: root.theme.radius
            color: root.theme.surface
            border.width: 1
            border.color: root.theme.border

            ColumnLayout {
                id: cardLayout
                anchors.fill: parent
                anchors.margins: root.theme.gap
                spacing: root.theme.gap

                RowLayout {
                    Layout.fillWidth: true

                    Text {
                        text: qsTr("Profile %1").arg(card.index + 1)
                        color: root.theme.textMuted
                        font.pixelSize: root.theme.smallSize
                        font.weight: Font.DemiBold
                        Layout.fillWidth: true
                    }

                    Button {
                        text: qsTr("Remove")
                        visible: profiles.count > 1
                        flat: true
                        onClicked: { profiles.remove(card.index); root.commitProfiles(); }
                    }
                }

                SteelField {
                    label: qsTr("User name")
                    placeholder: qsTr("lowercase, no spaces")
                    text: card.name
                    hint: card.name.length > 0 && !/^[a-z_][a-z0-9_-]{0,31}$/.test(card.name)
                          ? qsTr("Lowercase letters, digits, dash and underscore; must not start with a digit.")
                          : ""
                    hintSeverity: "danger"
                    onEdited: function(v) {
                        profiles.setProperty(card.index, "name", v);
                        root.commitProfiles();
                    }
                }

                SteelField {
                    label: qsTr("Password")
                    secret: true
                    text: card.password
                    hint: card.password.length > 0 && card.password.length < 8
                          ? qsTr("At least 8 characters. This unlocks the home, so length matters here too.")
                          : ""
                    hintSeverity: "danger"
                    onEdited: function(v) {
                        profiles.setProperty(card.index, "password", v);
                        root.commitProfiles();
                    }
                }

                SteelField {
                    label: qsTr("Password again")
                    secret: true
                    text: card.passwordAgain
                    hint: card.passwordAgain.length > 0 && card.password !== card.passwordAgain
                          ? qsTr("The two entries do not match.") : ""
                    hintSeverity: "danger"
                    onEdited: function(v) {
                        profiles.setProperty(card.index, "passwordAgain", v);
                        root.commitProfiles();
                    }
                }

                Text {
                    text: qsTr("Sandbox strictness")
                    color: root.theme.textMuted
                    font.pixelSize: root.theme.smallSize
                    Layout.fillWidth: true
                }

                ComboBox {
                    Layout.fillWidth: true
                    model: [
                        qsTr("Balanced — Flatpak default-deny, portals for file access"),
                        qsTr("Strict — no host filesystem at all, no device access, per-app grants only"),
                        qsTr("Permissive — closer to a normal desktop; for a profile that runs awkward software")
                    ]
                    currentIndex: card.sandbox === "strict" ? 1
                                : card.sandbox === "permissive" ? 2 : 0
                    onActivated: function(i) {
                        var v = i === 1 ? "strict" : i === 2 ? "permissive" : "balanced";
                        profiles.setProperty(card.index, "sandbox", v);
                        root.commitProfiles();
                    }
                }
            }
        }
    }

    Button {
        text: qsTr("Add another profile")
        Layout.fillWidth: true
        onClicked: {
            profiles.append({
                name: "", password: "", passwordAgain: "",
                sandbox: "balanced", homeSizeGb: 64
            });
            root.commitProfiles();
        }
    }

    SteelNote {
        severity: "caution"
        heading: qsTr("Profiles share one kernel")
        text: qsTr("This defends against data leakage and application compromise. A kernel exploit crosses profiles, and nothing in this design prevents that. If that is your threat model, Qubes OS is the honest answer and this is not.")
    }
}
