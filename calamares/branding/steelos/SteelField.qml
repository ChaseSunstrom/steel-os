/* A labelled text field, with room under it for the reason it is wrong.
 *
 * The hint slot is used for live validation rather than a dialog on Next. A
 * passphrase that is too short should say so while it is being typed, not four
 * pages later.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ColumnLayout {
    id: field

    property string label: ""
    property string placeholder: ""
    property string hint: ""
    property string hintSeverity: "info"    // info | caution | danger | ok
    property bool secret: false
    property alias text: input.text
    property bool monospace: false

    signal edited(string value)

    readonly property SteelTheme theme: fieldTheme
    SteelTheme { id: fieldTheme }

    Layout.fillWidth: true
    spacing: 4

    Text {
        text: field.label
        visible: field.label.length > 0
        color: fieldTheme.textMuted
        font.pixelSize: fieldTheme.smallSize
        Layout.fillWidth: true
    }

    TextField {
        id: input
        Layout.fillWidth: true
        placeholderText: field.placeholder
        echoMode: field.secret ? TextInput.Password : TextInput.Normal
        color: fieldTheme.text
        placeholderTextColor: fieldTheme.textFaint
        font.family: field.monospace ? "monospace" : font.family
        font.pixelSize: fieldTheme.bodySize
        selectByMouse: true
        onTextChanged: field.edited(text)

        background: Rectangle {
            color: fieldTheme.surface
            radius: 4
            border.width: 1
            border.color: input.activeFocus ? fieldTheme.accent : fieldTheme.border
        }
    }

    Text {
        text: field.hint
        visible: field.hint.length > 0
        color: field.hintSeverity === "danger"  ? fieldTheme.danger
             : field.hintSeverity === "caution" ? fieldTheme.caution
             : field.hintSeverity === "ok"      ? fieldTheme.ok
                                                : fieldTheme.textFaint
        font.pixelSize: fieldTheme.smallSize
        wrapMode: Text.WordWrap
        Layout.fillWidth: true
    }
}
