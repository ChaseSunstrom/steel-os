#!/usr/bin/env python3
"""Network defaults: encrypted DNS, MAC randomisation, firewall policy.

The captive-portal helper is enabled here rather than left to the user for a
specific reason: if hotel wifi appears broken because DNS-over-TLS cannot reach
the resolver, people turn DNS security off permanently and never turn it back
on. A usability failure is a security failure.
"""

import os

import libcalamares

RESOLVERS = {
    "quad9":      ("9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net", "Quad9"),
    "cloudflare": ("1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com", "Cloudflare"),
    "mullvad":    ("194.242.2.2#dns.mullvad.net", "Mullvad"),
}

RESOLVED_DROPIN = """# Written by the SteelOS installer.
#
# DNSOverTLS=opportunistic would silently fall back to plaintext, which is
# indistinguishable from not having configured it at all. Strict means a
# resolver that cannot be reached over TLS is an error you find out about.
[Resolve]
DNS={servers}
DNSOverTLS=yes
DNSSEC=allow-downgrade
FallbackDNS=
Domains=~.
MulticastDNS=no
LLMNR=no
"""

NM_PRIVACY = """# Written by the SteelOS installer.
#
# Without randomisation the same hardware address is broadcast in every cafe and
# airport the machine is opened in: a durable identifier attached to a device a
# person carries.
[device]
wifi.scan-rand-mac-address={scan}

[connection]
wifi.cloned-mac-address={connection}
ethernet.cloned-mac-address={connection}
connection.stable-id=${{CONNECTION}}/${{BOOT}}
"""


def pretty_name():
    return "Configuring network privacy"


def run():
    gs = libcalamares.globalstorage
    config = gs.value("steelos.network") or {}
    root = gs.value("rootMountPoint")

    if not root:
        return ("Nothing is mounted",
                "The deployment step did not set a root mount point.")

    provider = config.get("dnsProvider", "quad9")
    if provider == "custom":
        servers = config.get("dnsCustom", "").strip()
        if not servers:
            return ("No resolver was given",
                    "The custom DNS option was chosen without a server.")
    else:
        if provider not in RESOLVERS:
            return ("Unknown DNS provider", f"{provider!r}")
        servers = RESOLVERS[provider][0]

    dropin_dir = os.path.join(root, "etc/systemd/resolved.conf.d")
    os.makedirs(dropin_dir, exist_ok=True)
    with open(os.path.join(dropin_dir, "99-steel.conf"), "w") as handle:
        handle.write(RESOLVED_DROPIN.format(servers=servers))

    randomize = config.get("macRandomization", True)
    nm_dir = os.path.join(root, "etc/NetworkManager/conf.d")
    os.makedirs(nm_dir, exist_ok=True)
    with open(os.path.join(nm_dir, "99-steel-privacy.conf"), "w") as handle:
        handle.write(NM_PRIVACY.format(
            scan="yes" if randomize else "no",
            connection="stable" if randomize else "preserve",
        ))

    # The captive-portal helper needs NetworkManager's connectivity check to be
    # on, which is the one outbound request the installed system makes by
    # default. Turning the helper off turns the check off with it.
    connectivity = os.path.join(nm_dir, "98-steel-connectivity.conf")
    if config.get("captivePortalHelper", True):
        with open(connectivity, "w") as handle:
            handle.write(
                "# Written by the SteelOS installer.\n"
                "#\n"
                "# The only outbound request the installed system makes on its\n"
                "# own. It is what lets the captive-portal helper notice a\n"
                "# hijacked network instead of the user concluding that wifi is\n"
                "# broken and disabling DNS security for good.\n"
                "[connectivity]\n"
                "uri=http://networkcheck.steelos.invalid/check\n"
                "interval=300\n"
            )
    elif os.path.exists(connectivity):
        os.unlink(connectivity)

    # The kill switch is a flag rather than a rule set: steel-network owns the
    # nftables ruleset, and having two writers to one policy is how a firewall
    # ends up in a state nobody intended.
    steelos_etc = os.path.join(root, "etc/steelos")
    os.makedirs(steelos_etc, exist_ok=True)
    with open(os.path.join(steelos_etc, "network"), "w") as handle:
        handle.write(
            f"dns_provider={provider}\n"
            f"mac_randomization={'yes' if randomize else 'no'}\n"
            f"kill_switch={'yes' if config.get('killSwitch') else 'no'}\n"
            f"captive_portal_helper="
            f"{'yes' if config.get('captivePortalHelper', True) else 'no'}\n"
        )
    return None
