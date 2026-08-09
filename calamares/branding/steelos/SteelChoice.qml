/* A selectable card.
 *
 * Every option on every page states what it costs as well as what it gives.
 * `detail` is not optional in practice — a preset that hides what it changes is
 * how people end up running a system they did not choose, and then disable all
 * of it at once the first time something breaks.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: choice

    property string label: ""
    property string summary: ""
    property string detail: ""
    property string badge: ""
    property color badgeColor: theme.accent
    property bool selected: false

    signal picked()

    readonly property SteelTheme theme: choiceTheme
    SteelTheme { id: choiceTheme }

    Layout.fillWidth: true
    implicitHeight: inner.implicitHeight + 2 * choiceTheme.gap
    radius: choiceTheme.radius
    color: selected ? choiceTheme.accentWash
                    : (hover.hovered ? choiceTheme.surfaceHover : choiceTheme.surface)
    border.width: selected ? 2 : 1
    border.color: selected ? choiceTheme.accent : choiceTheme.border
    opacity: enabled ? 1.0 : 0.45

    HoverHandler { id: hover; enabled: choice.enabled }
    TapHandler {
        enabled: choice.enabled
        onTapped: choice.picked()
    }

    RowLayout {
        id: inner
        anchors.fill: parent
        anchors.margins: choiceTheme.gap
        spacing: choiceTheme.gap

        Rectangle {
            Layout.alignment: Qt.AlignTop
            width: 16; height: 16; radius: 8
            color: "transparent"
            border.width: 2
            border.color: choice.selected ? choiceTheme.accent : choiceTheme.borderStrong

            Rectangle {
                anchors.centerIn: parent
                width: 8; height: 8; radius: 4
                color: choiceTheme.accent
                visible: choice.selected
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 4

            RowLayout {
                Layout.fillWidth: true
                spacing: 8

                Text {
                    text: choice.label
                    color: choiceTheme.text
                    font.pixelSize: choiceTheme.bodySize + 1
                    font.weight: Font.DemiBold
                }

                Rectangle {
                    visible: choice.badge.length > 0
                    radius: 3
                    color: "transparent"
                    border.width: 1
                    border.color: choice.badgeColor
                    implicitWidth: badgeText.implicitWidth + 10
                    implicitHeight: badgeText.implicitHeight + 4

                    Text {
                        id: badgeText
                        anchors.centerIn: parent
                        text: choice.badge
                        color: choice.badgeColor
                        font.pixelSize: choiceTheme.smallSize - 1
                        font.weight: Font.DemiBold
                    }
                }

                Item { Layout.fillWidth: true }
            }

            Text {
                text: choice.summary
                visible: choice.summary.length > 0
                color: choiceTheme.textMuted
                font.pixelSize: choiceTheme.bodySize
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            Text {
                text: choice.detail
                visible: choice.detail.length > 0 && choice.selected
                color: choiceTheme.textFaint
                font.pixelSize: choiceTheme.smallSize
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
                textFormat: Text.StyledText
            }
        }
    }
}
