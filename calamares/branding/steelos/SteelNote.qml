/* A callout.
 *
 * Severity is meaningful: `info` explains, `caution` marks a choice that gives
 * something up, `danger` marks one that can destroy data or lock someone out
 * permanently. Nothing here is styled for emphasis alone.
 */
import QtQuick
import QtQuick.Layouts

Rectangle {
    id: note

    property string severity: "info"   // info | caution | danger | ok
    property string text: ""
    property string heading: ""

    readonly property SteelTheme theme: noteTheme
    SteelTheme { id: noteTheme }

    readonly property color tone: severity === "danger"  ? noteTheme.danger
                                : severity === "caution" ? noteTheme.caution
                                : severity === "ok"      ? noteTheme.ok
                                                         : noteTheme.accent

    Layout.fillWidth: true
    implicitHeight: noteLayout.implicitHeight + 2 * noteTheme.gap
    radius: noteTheme.radius
    color: noteTheme.surface
    border.width: 1
    border.color: noteTheme.border

    Rectangle {
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        width: 3
        radius: noteTheme.radius
        color: note.tone
    }

    ColumnLayout {
        id: noteLayout
        anchors.fill: parent
        anchors.margins: noteTheme.gap
        anchors.leftMargin: noteTheme.gap + 6
        spacing: 4

        Text {
            visible: note.heading.length > 0
            text: note.heading
            color: note.tone
            font.pixelSize: noteTheme.bodySize
            font.weight: Font.DemiBold
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }

        Text {
            text: note.text
            color: noteTheme.textMuted
            font.pixelSize: noteTheme.bodySize
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
            textFormat: Text.StyledText
        }
    }
}
