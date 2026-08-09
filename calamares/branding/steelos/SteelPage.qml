/* The scaffold every SteelOS installer page uses: a title, one line saying what
 * the page decides, and a scrolling body.
 *
 * The subtitle is not decoration. Each of these pages changes something that is
 * hard or impossible to undo after the install, and a user who has to infer
 * from the controls what the page is for will infer wrong.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: page

    property string title: ""
    property string subtitle: ""

    /** Why Next is disabled, in one line.
     *
     * Pinned above the scrolling body on purpose. These pages are long, and the
     * field that is blocking progress is often below the fold — a greyed-out
     * Next with the reason three screens down reads as a broken installer, and
     * the next thing someone does is reboot.
     */
    property string blocker: ""

    default property alias content: bodyLayout.data
    readonly property SteelTheme theme: pageTheme

    color: pageTheme.background

    SteelTheme { id: pageTheme }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: pageTheme.gapLarge
        spacing: pageTheme.gap

        Text {
            text: page.title
            color: pageTheme.text
            font.pixelSize: pageTheme.titleSize
            font.weight: Font.DemiBold
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }

        Text {
            text: page.subtitle
            visible: page.subtitle.length > 0
            color: pageTheme.textMuted
            font.pixelSize: pageTheme.bodySize
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }

        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: pageTheme.border
        }

        Rectangle {
            visible: page.blocker.length > 0
            Layout.fillWidth: true
            implicitHeight: blockerText.implicitHeight + 16
            radius: 4
            color: pageTheme.surface
            border.width: 1
            border.color: pageTheme.caution

            Row {
                anchors.fill: parent
                anchors.margins: 8
                spacing: 8

                Text {
                    text: "▸"
                    color: pageTheme.caution
                    font.pixelSize: pageTheme.bodySize
                }

                Text {
                    id: blockerText
                    width: parent.width - 20
                    text: page.blocker
                    color: pageTheme.caution
                    font.pixelSize: pageTheme.bodySize
                    wrapMode: Text.WordWrap
                }
            }
        }

        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentWidth: availableWidth

            ColumnLayout {
                id: bodyLayout
                width: parent.width
                spacing: pageTheme.gap
            }
        }
    }
}
