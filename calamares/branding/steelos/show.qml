/* Shown while the install runs.
 *
 * Not marketing. The install phase is where the machine is being partitioned,
 * filled with random data and written to, and the honest thing to do with a
 * captive audience is explain what the system they chose actually does — and,
 * on the last slide, what it does not.
 */
import QtQuick
import calamares.slideshow 1.0

Presentation {
    id: presentation

    property int slideSeconds: 11

    function nextSlide() {
        presentation.goToNextSlide();
    }

    function onActivate() {
        advanceTimer.running = true;
    }

    function onLeave() {
        advanceTimer.running = false;
    }

    Timer {
        id: advanceTimer
        interval: presentation.slideSeconds * 1000
        repeat: true
        running: false
        onTriggered: nextSlide()
    }

    Component {
        id: slideBody

        Item {}
    }

    Slide {
        Column {
            anchors.centerIn: parent
            width: parent.width * 0.72
            spacing: 18

            Image {
                source: "logo.svg"
                width: 96
                height: 96
                sourceSize.width: 96
                sourceSize.height: 96
                fillMode: Image.PreserveAspectFit
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Text {
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                text: "The root filesystem is sealed"
                color: "#E6EAEE"
                font.pixelSize: 24
                font.weight: Font.DemiBold
                wrapMode: Text.WordWrap
            }

            Text {
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                text: "/usr is read-only and every block is verified against a dm-verity hash tree as it is read. The root hash lives inside the signed kernel image, so signing the kernel signs the identity of the entire filesystem. Change one block and the signature no longer matches."
                color: "#93A1AE"
                font.pixelSize: 15
                wrapMode: Text.WordWrap
                lineHeight: 1.3
            }
        }
    }

    Slide {
        Column {
            anchors.centerIn: parent
            width: parent.width * 0.72
            spacing: 18

            Text {
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                text: "Installing software still works"
                color: "#E6EAEE"
                font.pixelSize: 24
                font.weight: Font.DemiBold
                wrapMode: Text.WordWrap
            }

            Text {
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                text: "Desktop applications come from Flatpak, per profile, sandboxed by default. Command-line work happens in steel-shell — a mutable container where pacman works exactly as you expect and nothing escapes into the verified root. Neither needs a rebuild or a reboot."
                color: "#93A1AE"
                font.pixelSize: 15
                wrapMode: Text.WordWrap
                lineHeight: 1.3
            }
        }
    }

    Slide {
        Column {
            anchors.centerIn: parent
            width: parent.width * 0.72
            spacing: 18

            Text {
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                text: "Every update is reversible"
                color: "#E6EAEE"
                font.pixelSize: 24
                font.weight: Font.DemiBold
                wrapMode: Text.WordWrap
            }

            Text {
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                text: "There are two root slots. An update is written to the one you are not running and takes effect at the next boot. If a deployment fails to reach a healthy desktop, the boot loader counts the attempts, gives up, and boots the previous generation on its own. steelctl rollback does the same on demand."
                color: "#93A1AE"
                font.pixelSize: 15
                wrapMode: Text.WordWrap
                lineHeight: 1.3
            }
        }
    }

    Slide {
        Column {
            anchors.centerIn: parent
            width: parent.width * 0.72
            spacing: 18

            Text {
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                text: "What this does not protect you from"
                color: "#E0A33E"
                font.pixelSize: 24
                font.weight: Font.DemiBold
                wrapMode: Text.WordWrap
            }

            Text {
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                text: "Compromised firmware. A kernel exploit that escapes every sandbox — profiles share one kernel, and Qubes is the honest answer if that is your threat model. Anyone who has both your machine and your passphrase. And an adversary who simply keeps demanding another passphrase, which no cryptography answers.\n\nThere is no hardware root of trust on a PC. This is verified boot without one, and the README says exactly that rather than rounding it up."
                color: "#93A1AE"
                font.pixelSize: 15
                wrapMode: Text.WordWrap
                lineHeight: 1.3
            }
        }
    }

    Slide {
        Column {
            anchors.centerIn: parent
            width: parent.width * 0.72
            spacing: 18

            Text {
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                text: "When it finishes"
                color: "#E6EAEE"
                font.pixelSize: 24
                font.weight: Font.DemiBold
                wrapMode: Text.WordWrap
            }

            Text {
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                text: "Run steel-check. It audits every measure this system claims, one line each, pass or fail, and it is the same tool CI runs before an image is allowed to publish. Every claim made during this install is something you can verify yourself afterwards."
                color: "#93A1AE"
                font.pixelSize: 15
                wrapMode: Text.WordWrap
                lineHeight: 1.3
            }
        }
    }
}
