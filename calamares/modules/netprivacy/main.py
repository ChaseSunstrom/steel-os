#!/usr/bin/env python3
"""DNS provider, MAC randomisation, optional per-app tunnels."""

import libcalamares
from libcalamares.utils import check_target_env_call

DNS_PROVIDERS = {
    "quad9": {
        "label": "Quad9 (default)",
        "servers": "9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net",
        "note": "Swiss non-profit, no logging, filters known-malicious domains.",
    },
    "cloudflare": {
        "label": "Cloudflare",
        "servers": "1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com",
        "note": "Fast and widely available. A large US company sees your lookups.",
    },
    "mullvad": {
        "label": "Mullvad",
        "servers": "194.242.2.2#dns.mullvad.net",
        "note": "Privacy-focused, no logging, no account required for DNS.",
    },
}

MAC_MODES = {
    "stable": (
        "Per-network stable address (default). Different networks cannot "
        "correlate you; captive portals and MAC-based authentication keep "
        "working."
    ),
    "random": (
        "New address on every connection. Stronger, and it BREAKS captive "
        "portal logins and any network that authenticates on MAC address."
    ),
    "permanent": (
        "Use the hardware address. This is a permanent identifier broadcast to "
        "every network in range."
    ),
}


def run():
    gs = libcalamares.globalstorage
    provider = gs.value("steelosDnsProvider") or "quad9"
    mac_mode = gs.value("steelosMacMode") or "stable"

    check_target_env_call(["steel-network", "dns", "strict"])
    check_target_env_call(["steel-network", "mac", mac_mode])

    root = gs.value("rootMountPoint")
    servers = DNS_PROVIDERS[provider]["servers"]
    conf = f"{root}/etc/systemd/resolved.conf.d/99-steel.conf"
    with open(conf) as handle:
        body = handle.read()
    body = "\n".join(
        f"DNS={servers}" if line.startswith("DNS=") else line
        for line in body.splitlines()
    )
    with open(conf, "w") as handle:
        handle.write(body + "\n")

    # The firewall is applied but the ruleset is validated first: a rejected
    # ruleset leaves the previous one in place, which is the safe failure. A
    # half-applied default-deny policy on a fresh install is not.
    check_target_env_call(["steel-network", "apply"])
    return None
