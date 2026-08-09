/* Network privacy.
 *
 * Captive-portal handling is on this page and not buried in a settings app for
 * a specific reason: if hotel wifi appears broken because DNS-over-TLS cannot
 * reach the resolver, people turn DNS security off permanently and never turn
 * it back on. A usability failure here is a security failure.
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import io.calamares.core 1.0

SteelPage {
    id: root

    title: qsTr("Network privacy")
    subtitle: qsTr("Default-deny inbound, encrypted DNS, and a hardware address that does not follow you between networks.")
    blocker: provider === "custom" && customServer.length === 0
             ? qsTr("Enter the custom resolver, or choose one of the three above.")
             : ""

    property string provider: "quad9"
    property string customServer: ""

    SteelState {
        id: state
        key: "steelos.network"
        valid: root.provider !== "custom" || root.customServer.length > 0
    }

    function choose(name) {
        root.provider = name;
        state.set({ dnsProvider: name });
    }

    function onActivate() { state.applyGate(); }

    Component.onCompleted: {
        state.load({
            dnsProvider: "quad9",
            dnsCustom: "",
            dnsMode: "strict",
            macRandomization: true,
            killSwitch: false,
            captivePortalHelper: true
        });
        root.provider = state.values.dnsProvider;
        root.customServer = state.values.dnsCustom;
    }

    Text {
        text: qsTr("DNS over TLS")
        color: root.theme.text
        font.pixelSize: root.theme.bodySize + 1
        font.weight: Font.DemiBold
        Layout.fillWidth: true
    }

    Text {
        text: qsTr("Your resolver sees every name you look up. Choosing one is choosing who that is.")
        color: root.theme.textMuted
        font.pixelSize: root.theme.bodySize
        wrapMode: Text.WordWrap
        Layout.fillWidth: true
    }

    SteelChoice {
        label: qsTr("Quad9")
        badge: qsTr("DEFAULT")
        summary: qsTr("Swiss foundation, no logging of client IPs, filters known-malicious domains.")
        detail: qsTr("9.9.9.9 · dns.quad9.net. The malware filtering is a real benefit and also a real behaviour: it means Quad9 decides some names do not resolve for you.")
        selected: root.provider === "quad9"
        onPicked: root.choose("quad9")
    }

    SteelChoice {
        label: qsTr("Cloudflare")
        summary: qsTr("Fast almost everywhere. No filtering.")
        detail: qsTr("1.1.1.1 · cloudflare-dns.com. A large commercial network that already terminates a substantial share of the web's TLS; consider whether concentrating your DNS there as well is what you want.")
        selected: root.provider === "cloudflare"
        onPicked: root.choose("cloudflare")
    }

    SteelChoice {
        label: qsTr("Mullvad")
        summary: qsTr("Privacy-focused, no logging, funded by a paid VPN product rather than by data.")
        detail: qsTr("194.242.2.2 · dns.mullvad.net. No account is needed to use the public resolver.")
        selected: root.provider === "mullvad"
        onPicked: root.choose("mullvad")
    }

    SteelChoice {
        label: qsTr("Custom")
        summary: qsTr("Your own resolver, or your organisation's.")
        detail: qsTr("Must speak DNS over TLS on port 853 and present a certificate matching the name you give.")
        selected: root.provider === "custom"
        onPicked: root.choose("custom")
    }

    SteelField {
        visible: root.provider === "custom"
        label: qsTr("Resolver")
        placeholder: qsTr("203.0.113.10#dns.example.org")
        text: root.customServer
        hint: qsTr("Address, then # and the name on its certificate.")
        onEdited: function(v) { root.customServer = v; state.set({ dnsCustom: v }); }
    }

    Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: root.theme.border; Layout.topMargin: root.theme.gap }

    SteelSwitch {
        label: qsTr("Randomise the hardware address")
        detail: qsTr("A new MAC per network, and a random one while scanning. Without it, the same address is broadcast in every café and airport you open the laptop in, which is a durable identifier tied to a device you carry.")
        checked: state.values.macRandomization === true
        onToggled: function(v) { state.set({ macRandomization: v }); }
    }

    SteelSwitch {
        label: qsTr("Captive portal helper")
        detail: qsTr("When a network hijacks DNS, this opens the portal page in a disposable browser profile, with a bounded window of plaintext DNS, and restores strict DNS afterwards whether or not you finish signing in. Without it, hotel wifi looks broken.")
        checked: state.values.captivePortalHelper === true
        onToggled: function(v) { state.set({ captivePortalHelper: v }); }
    }

    SteelSwitch {
        label: qsTr("Outbound kill switch")
        detail: qsTr("Drops outbound traffic that is not going through a configured tunnel. Useful if you always use one. It will make an unconfigured machine look like it has no network at all, which is the intended behaviour and a common support question.")
        checked: state.values.killSwitch === true
        onToggled: function(v) { state.set({ killSwitch: v }); }
    }

    SteelNote {
        severity: "info"
        heading: qsTr("What is already decided")
        text: qsTr("Inbound is dropped, forwarding is dropped, loopback is allowed and ICMP is rate-limited. There are no listening ports and <tt>sshd</tt> is not installed. None of that is a choice on this page because none of it has a cost worth offering.")
    }
}
