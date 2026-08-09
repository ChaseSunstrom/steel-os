/* Graphics.
 *
 * On a mutable distribution this page would install a driver package. Here
 * /usr is sealed, so the driver either is in the image or it is not, and a
 * missing one is a wrong-image error rather than something the user can fix
 * after the first reboot. They need to know that now, not after booting into a
 * black screen.
 *
 * The good news, and it is worth saying on this page: out-of-tree modules are
 * built and signed in CI at image build time, so NVIDIA's modules ship signed
 * inside the verified image. lockdown=confidentiality and module.sig_enforce=1
 * are defaults here without breaking NVIDIA, which is the opposite of the usual
 * trade.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import io.calamares.core 1.0

SteelPage {
    id: root

    title: qsTr("Graphics")
    subtitle: qsTr("Which driver has to be inside the image, and whether the one you are about to install has it.")

    property string channel: "stable"

    SteelFacts { id: facts }

    SteelState {
        id: state
        key: "steelos.graphics"
        valid: true
    }

    readonly property string vendorName:
        facts.gpuVendor === "nvidia" ? "NVIDIA"
      : facts.gpuVendor === "amd"    ? "AMD"
      : facts.gpuVendor === "intel"  ? "Intel"
                                     : qsTr("not identified")

    function onActivate() { state.applyGate(); }

    Component.onCompleted: {
        state.load({ vendor: facts.gpuVendor, channel: "stable" });
        root.channel = state.values.channel;
    }

    SteelNote {
        severity: facts.gpuVendor === "other" ? "caution" : "ok"
        heading: qsTr("Detected: %1").arg(root.vendorName)
        text: facts.data.gpus && facts.data.gpus.length > 0
              ? facts.data.gpus.join("<br>")
              : qsTr("No display controller was reported. If this machine has one, the installed system may still drive it with a generic modesetting driver.")
    }

    SteelNote {
        visible: facts.gpuVendor === "nvidia"
        severity: "info"
        heading: qsTr("NVIDIA is not a conflict here")
        text: qsTr("The open kernel modules are built and signed during the image build with the same key that signs the UKI, so they load under <tt>module.sig_enforce=1</tt>. There is no DKMS step at runtime, and there cannot be — that is a consequence of the sealed root, and on this one point it is an advantage.")
    }

    SteelNote {
        visible: facts.gpuVendor === "nvidia"
        severity: "caution"
        heading: qsTr("Very new cards need a newer channel")
        text: qsTr("If this GPU was released in the last few months, the stable channel's kernel may not drive it. Testing tracks a newer snapshot. If the installed system boots to a black screen, the basic-graphics entry on the boot menu will get you back in.")
    }

    Rectangle { Layout.fillWidth: true; height: 1; color: root.theme.border; Layout.topMargin: root.theme.gap }

    Text {
        text: qsTr("Update channel")
        color: root.theme.text
        font.pixelSize: root.theme.bodySize + 1
        font.weight: Font.DemiBold
        Layout.fillWidth: true
    }

    SteelChoice {
        label: qsTr("Stable")
        badge: qsTr("DEFAULT")
        summary: qsTr("Images publish only after the full VM matrix passes on every preset.")
        detail: qsTr("Our CI rebuilds against a pinned Arch snapshot and publishes only after unattended install, boot, <tt>steel-check</tt>, update, rollback and a restore drill all pass. You are never exposed to an untested Arch state — that is the reason the snapshot pin exists, and it is the real advantage over rolling Arch.")
        selected: root.channel === "stable"
        onPicked: { root.channel = "stable"; state.set({ channel: "stable" }); }
    }

    SteelChoice {
        label: qsTr("Testing")
        summary: qsTr("A newer snapshot, for hardware the stable kernel does not drive yet.")
        detail: qsTr("Same pipeline, less soak time. Choose it if this machine needs a kernel or firmware that stable does not have yet. You can move back with <tt>steelctl</tt> later; the previous generation always stays bootable.")
        selected: root.channel === "testing"
        onPicked: { root.channel = "testing"; state.set({ channel: "testing" }); }
    }
}
