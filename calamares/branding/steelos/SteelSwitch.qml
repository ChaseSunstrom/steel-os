/* A labelled toggle with its consequence written next to it.
 *
 * `detail` says what turning it on actually does. Several of these switches
 * enable things that cannot be undone later without reinstalling, so "what does
 * this do" has to be answerable without leaving the page.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: row

    property string label: ""
    property string detail: ""
    property bool checked: false
    property string disabledReason: ""

    signal toggled(bool value)

    readonly property SteelTheme theme: switchTheme
    SteelTheme { id: switchTheme }

    Layout.fillWidth: true
    implicitHeight: layout.implicitHeight + 2 * switchTheme.gap
    radius: switchTheme.radius
    color: switchTheme.surface
    border.width: 1
    border.color: row.checked ? switchTheme.accent : switchTheme.border
    opacity: row.enabled ? 1.0 : 0.45

    RowLayout {
        id: layout
        anchors.fill: parent
        anchors.margins: switchTheme.gap
        spacing: switchTheme.gap

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 3

            Text {
                text: row.label
                color: switchTheme.text
                font.pixelSize: switchTheme.bodySize + 1
                font.weight: Font.DemiBold
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }

            Text {
                text: row.enabled || row.disabledReason.length === 0
                      ? row.detail : row.disabledReason
                visible: text.length > 0
                color: row.enabled ? switchTheme.textMuted : switchTheme.caution
                font.pixelSize: switchTheme.smallSize
                wrapMode: Text.WordWrap
                textFormat: Text.StyledText
                Layout.fillWidth: true
            }
        }

        Switch {
            checked: row.checked
            enabled: row.enabled
            onToggled: row.toggled(checked)
        }
    }
}
