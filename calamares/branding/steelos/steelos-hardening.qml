/* Hardening preset.
 *
 * The details under each preset are the point of the page. A preset that hides
 * what it changes is how people end up running a system they did not choose,
 * and then turn all of it off at once the first time something breaks. Every
 * measure named here has an off-switch and a rationale in the installed docs.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import io.calamares.core 1.0

SteelPage {
    id: root

    title: qsTr("Hardening")
    subtitle: qsTr("Balanced is the default because a system that gets uninstalled protects nobody. Every measure here can be turned off individually afterwards with steel-harden.")

    property string preset: "balanced"

    SteelState {
        id: state
        key: "steelos.hardening"
        valid: true
    }

    function choose(name) {
        root.preset = name;
        state.set({ preset: name });
    }

    function onActivate() { state.applyGate(); }

    Component.onCompleted: {
        state.load({ preset: "balanced", kernel: "linux-hardened" });
        root.preset = state.values.preset;
    }

    SteelChoice {
        label: qsTr("Balanced")
        badge: qsTr("DEFAULT")
        summary: qsTr("Everything that does not routinely break normal desktop use.")
        detail: qsTr("Verified immutable root (dm-verity, root hash sealed in the signed UKI) · linux-hardened · sysctl and module-blacklist baseline · hardened_malloc, light variant · AppArmor enforcing · Flatpak default-deny permissions and bubblejail for native binaries · nftables input drop · DNS over TLS · systemd-homed per-user encryption · <tt>lockdown=confidentiality</tt> and <tt>module.sig_enforce=1</tt> · IOMMU on · user namespaces enabled, because unprivileged sandboxing depends on them.")
        selected: root.preset === "balanced"
        onPicked: root.choose("balanced")
    }

    SteelChoice {
        label: qsTr("Strict")
        summary: qsTr("Adds measures that will get in your way. Choose it deliberately.")
        detail: qsTr("Everything in Balanced, plus: hardened_malloc strict variant, which breaks some games and proprietary applications · USBGuard, so a newly plugged USB device needs approval before it works · <tt>noexec</tt> on every writable mount · stricter Flatpak defaults · additional module blacklists, including Thunderbolt · <b>no devmode boot entry</b>, which means hardware bring-up on this machine requires reinstalling.")
        selected: root.preset === "strict"
        onPicked: root.choose("strict")
    }

    SteelChoice {
        label: qsTr("Compatible")
        badge: qsTr("REDUCED PROTECTION")
        badgeColor: root.theme.caution
        summary: qsTr("For hardware that will not boot the other two.")
        detail: qsTr("<tt>lockdown=integrity</tt> instead of confidentiality · no hardened_malloc preload · devmode boot entry available · relaxed module blacklists. The verified root, the encryption and the sandboxing are still there — this trades away the exploit-mitigation layer, not the architecture. Use it to get a problem machine running, then move to Balanced once you know what was failing.")
        selected: root.preset === "compatible"
        onPicked: root.choose("compatible")
    }

    SteelNote {
        visible: root.preset === "strict"
        severity: "caution"
        heading: qsTr("Strict removes the escape hatch")
        text: qsTr("Without a devmode entry there is no way to boot this machine with a writable /usr. If a driver problem appears later, the fix is a custom image build or a reinstall.")
    }

    SteelNote {
        visible: root.preset === "compatible"
        severity: "caution"
        heading: qsTr("This is a fallback, not a preference")
        text: qsTr("Nothing in Compatible is secret and nothing about it is dishonest — it is just less. <tt>steel-check</tt> will report the gap on every run so it does not quietly become permanent.")
    }

    Rectangle { Layout.fillWidth: true; height: 1; color: root.theme.border; Layout.topMargin: root.theme.gap }

    SteelNote {
        severity: "info"
        heading: qsTr("What none of these presets change")
        text: qsTr("<tt>/usr</tt> is read-only and verified on every read, in all three. <tt>pacman -S</tt> at runtime is impossible by construction, not by policy. Applications come from Flatpak, command-line work happens in <tt>steel-shell</tt> containers where pacman works normally, and the system itself is defined by <tt>/etc/steelos/manifest.toml</tt>.")
    }
}
