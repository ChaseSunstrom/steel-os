//! Firewall policy, listening services, encrypted DNS, and MAC randomisation.

use crate::context::Context;
use crate::report::{Category, Check, Outcome, Severity};
use crate::sys;

pub const CHECKS: &[Check] = &[
    Check {
        id: "network.nftables-policy",
        title: "nftables default policy is drop for input and forward",
        category: Category::Network,
        severity: Severity::High,
        rationale: "Threat model: local network attacker. A default-deny inbound policy \
                    means an accidentally-started service on hotel wifi is not reachable, \
                    which is the difference between a mistake and a compromise.",
        escape_hatch: "steel-network allow <port>, or edit /etc/nftables.d/ — the \
                       generated ruleset has a documented include point for local rules.",
        run: check_nftables_policy,
    },
    Check {
        id: "network.no-listening-ports",
        title: "No unexpected listening ports",
        category: Category::Network,
        severity: Severity::Medium,
        rationale: "The firewall is the enforcement layer, but a listening service is \
                    still attack surface reachable from localhost by any compromised \
                    application, and it is the thing that breaks when the firewall does.",
        escape_hatch: "Expected listeners are declared in /etc/steelos/expected-listeners; \
                       add yours there so the exception is recorded rather than ignored.",
        run: check_listening_ports,
    },
    Check {
        id: "network.dns-over-tls",
        title: "DNS-over-TLS is active",
        category: Category::Network,
        severity: Severity::Medium,
        rationale: "Plaintext DNS tells every hop on the path what you are doing and lets \
                    them lie about it. DoT with strict mode fails closed rather than \
                    silently downgrading, which is the only setting that means anything.",
        escape_hatch: "steel-network dns opportunistic, or set DNSOverTLS=no in \
                       /etc/systemd/resolved.conf.d/.",
        run: check_dns_over_tls,
    },
    Check {
        id: "network.captive-portal-support",
        title: "Captive portal detection is configured",
        category: Category::Network,
        severity: Severity::Info,
        rationale: "Not a hardening measure — a prerequisite for one. Without captive \
                    portal handling, hotel wifi appears broken and users permanently \
                    disable DNS security to fix it (design principle 8). CLAUDE.md calls \
                    this out explicitly.",
        escape_hatch: "n/a — this is a usability guard, disable it only if you know why.",
        run: check_captive_portal,
    },
    Check {
        id: "network.mac-randomization",
        title: "MAC address randomisation is enabled",
        category: Category::Network,
        severity: Severity::Medium,
        rationale: "A stable MAC address is a permanent, passively-observable identifier \
                    that follows the machine across every network it touches. Randomising \
                    both scanning and connection addresses breaks that correlation.",
        escape_hatch: "steel-network mac stable — required by some captive portals and \
                       by networks that authenticate on MAC address.",
        run: check_mac_randomization,
    },
];

fn check_nftables_policy(ctx: &Context) -> Outcome {
    if !ctx.sys.is_real() {
        return Outcome::skip("live ruleset cannot be read from a fixture sysroot");
    }
    if !sys::have_binary("nft") {
        return Outcome::skip("nft is not installed")
            .evidence("nftables is required to enforce the network policy");
    }

    let out = match sys::run("nft", ["-t", "list", "ruleset"]) {
        Some(o) if o.ok() => o.stdout,
        Some(o) => {
            return Outcome::skip("cannot read the nftables ruleset")
                .evidence(format!("nft exited {}: {}", o.status, o.stderr.trim()))
                .evidence("This usually means steel-check is not running as root.")
        }
        None => return Outcome::skip("nft could not be executed"),
    };

    let input_drop = hook_policy_is_drop(&out, "input");
    let forward_drop = hook_policy_is_drop(&out, "forward");

    match (input_drop, forward_drop) {
        (true, true) => Outcome::pass("input drop, forward drop"),
        (false, true) => Outcome::fail("input policy is not drop")
            .evidence("Any service listening on any interface is reachable from the network.")
            .remedy("systemctl enable --now nftables, or `steel-network apply`."),
        (true, false) => Outcome::warn("forward policy is not drop")
            .evidence(
                "Container runtimes set this deliberately. If you do not run \
                       containers, it should be drop.",
            )
            .remedy("steel-network apply, then verify your containers still have network."),
        (false, false) => Outcome::fail("no default-deny policy is in force")
            .evidence(if out.trim().is_empty() {
                "the ruleset is empty".to_string()
            } else {
                format!(
                    "ruleset has {} lines but no drop policy on input",
                    out.lines().count()
                )
            })
            .remedy("pacman -S steel-network && systemctl enable --now nftables"),
    }
}

/// Parse `nft list ruleset` for a base chain's policy.
///
/// Chain declarations look like:
///   `chain input { type filter hook input priority filter; policy drop; }`
/// spread over several lines.
fn hook_policy_is_drop(ruleset: &str, hook: &str) -> bool {
    let needle = format!("hook {hook} ");
    let mut lines = ruleset.lines();
    while let Some(line) = lines.next() {
        if !line.contains(&needle) {
            continue;
        }
        // The policy is on the same line as the hook declaration, or on the
        // next one depending on nft's output width.
        if line.contains("policy drop") {
            return true;
        }
        if let Some(next) = lines.next() {
            if next.contains("policy drop") {
                return true;
            }
            if next.contains("policy accept") {
                return false;
            }
        }
    }
    false
}

fn check_listening_ports(ctx: &Context) -> Outcome {
    if !ctx.sys.is_real() {
        return Outcome::skip("listening sockets cannot be read from a fixture sysroot");
    }
    if !sys::have_binary("ss") {
        return Outcome::skip("ss is not installed (iproute2)");
    }
    let out = match sys::run("ss", ["-tulnH"]) {
        Some(o) if o.ok() => o.stdout,
        _ => return Outcome::skip("could not enumerate listening sockets"),
    };

    let expected = ctx
        .sys
        .read("/etc/steelos/expected-listeners")
        .unwrap_or_default();
    let expected: Vec<String> = expected
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let mut unexpected = Vec::new();
    for line in out.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let local = fields[4];
        // Loopback-only listeners are not reachable from the network. They are
        // still reachable by a compromised local application, but that is the
        // sandbox layer's problem, not the firewall's.
        if local.starts_with("127.") || local.starts_with("[::1]") {
            continue;
        }
        let port = local.rsplit(':').next().unwrap_or("");
        if expected.iter().any(|e| e == port || e == local) {
            continue;
        }
        unexpected.push(format!("{} {}", fields[0], local));
    }

    if unexpected.is_empty() {
        Outcome::pass("no unexpected listeners on non-loopback addresses")
    } else {
        Outcome::warn(format!("{} unexpected listener(s)", unexpected.len()))
            .evidence_all(unexpected)
            .remedy(
                "Stop the service, or record it in /etc/steelos/expected-listeners \
                 (one port or address:port per line) so the exception is explicit.",
            )
    }
}

fn check_dns_over_tls(ctx: &Context) -> Outcome {
    let conf = ctx.sys.concat_dir("/etc/systemd/resolved.conf.d", ".conf");
    let base = ctx
        .sys
        .read("/etc/systemd/resolved.conf")
        .unwrap_or_default();
    let combined = format!("{base}\n{conf}");

    let setting = combined
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix("DNSOverTLS="))
        // Last wins: drop-ins are read in order and a later file overrides an
        // earlier one, so the final occurrence is the effective setting.
        .next_back()
        .map(|v| v.trim().to_string());

    // Prefer the live state: resolvectl reports what is actually in force,
    // including per-link overrides pushed by NetworkManager.
    let live = if ctx.sys.is_real() && sys::have_binary("resolvectl") {
        sys::run("resolvectl", ["status"])
            .filter(|o| o.ok())
            .map(|o| o.stdout)
    } else {
        None
    };

    let live_dot = live.as_ref().map(|s| {
        s.lines()
            .filter_map(|l| l.trim().strip_prefix("+DNSOverTLS"))
            .count()
            > 0
            || s.contains("DNSOverTLS setting: yes")
    });

    match (setting.as_deref(), live_dot) {
        (Some("yes"), Some(false)) => Outcome::warn("DoT is configured but not in force")
            .evidence(
                "resolved.conf.d sets DNSOverTLS=yes, but resolvectl does not report \
                       it active on any link — a link-level setting is overriding it",
            )
            .remedy(
                "Check `resolvectl status` per link; NetworkManager can override the \
                     global setting per connection.",
            ),
        (Some("yes"), _) => Outcome::pass("DNSOverTLS=yes (strict: fails closed)"),
        (Some("opportunistic"), _) => Outcome::warn("DoT is opportunistic")
            .evidence(
                "Opportunistic mode silently falls back to plaintext when the \
                       server does not answer on 853, so an on-path attacker who blocks \
                       853 gets exactly what they wanted.",
            )
            .remedy("Set DNSOverTLS=yes."),
        (Some(other), _) => Outcome::fail(format!("DNSOverTLS={other}"))
            .remedy("Set DNSOverTLS=yes in /etc/systemd/resolved.conf.d/."),
        (None, _) => Outcome::fail("DNSOverTLS is not configured")
            .evidence("DNS queries are sent in plaintext to whoever DHCP nominated.")
            .remedy(
                "pacman -S steel-network, or set DNSOverTLS=yes and a DNS= line \
                     with a server that supports it.",
            ),
    }
}

fn check_captive_portal(ctx: &Context) -> Outcome {
    let nm = ctx.sys.concat_dir("/etc/NetworkManager/conf.d", ".conf");
    let connectivity_configured = nm.contains("[connectivity]") && nm.contains("uri=");
    let helper = ctx.sys.exists("/usr/lib/steelos/captive-portal-helper");

    match (connectivity_configured, helper) {
        (true, true) => Outcome::pass("connectivity check and portal helper are configured"),
        (true, false) => Outcome::warn("connectivity checking is on, but no portal helper")
            .evidence(
                "Users will see 'limited connectivity' with no way to reach the \
                       portal page, and will disable DNS security to work around it.",
            )
            .remedy("pacman -S steel-network."),
        (false, _) => Outcome::warn("no captive portal handling is configured")
            .evidence(
                "With DoT enforced and no portal handling, hotel and airport wifi \
                       simply does not work. CLAUDE.md flags this as a security failure, \
                       not a convenience gap.",
            )
            .remedy("pacman -S steel-network."),
    }
}

fn check_mac_randomization(ctx: &Context) -> Outcome {
    let nm = ctx.sys.concat_dir("/etc/NetworkManager/conf.d", ".conf");

    let scan_random = nm.contains("wifi.scan-rand-mac-address=yes")
        || !nm.contains("wifi.scan-rand-mac-address=no");
    let wifi_cloned = nm
        .lines()
        .any(|l| l.trim().starts_with("wifi.cloned-mac-address=") && l.contains("random"));
    let eth_cloned = nm
        .lines()
        .any(|l| l.trim().starts_with("ethernet.cloned-mac-address=") && l.contains("random"));

    let mut missing = Vec::new();
    if !wifi_cloned {
        missing.push("wifi.cloned-mac-address=random");
    }
    if !eth_cloned {
        missing.push("ethernet.cloned-mac-address=random");
    }
    if !scan_random {
        missing.push("wifi.scan-rand-mac-address=yes");
    }

    if missing.is_empty() {
        Outcome::pass("scan and connection MAC addresses are randomised")
    } else if missing.len() == 3 {
        Outcome::fail("MAC randomisation is not configured")
            .evidence(
                "The hardware address is broadcast to every network in range and is \
                       a stable identifier for the device across all of them.",
            )
            .remedy("pacman -S steel-network.")
    } else {
        Outcome::warn(format!(
            "MAC randomisation is partial: missing {}",
            missing.join(", ")
        ))
        .remedy(
            "pacman -S steel-network, or add the missing keys to \
                     /etc/NetworkManager/conf.d/.",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULESET: &str = "\
table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}";

    #[test]
    fn parses_drop_policies_from_nft_output() {
        assert!(hook_policy_is_drop(RULESET, "input"));
        assert!(hook_policy_is_drop(RULESET, "forward"));
        assert!(!hook_policy_is_drop(RULESET, "output"));
    }

    #[test]
    fn policy_on_the_following_line_is_recognised() {
        // nft wraps chain declarations depending on terminal width; missing
        // that would report a correctly-configured firewall as absent.
        let wrapped = "\ttable inet filter {\n\t\tchain input {\n\t\t\ttype filter hook input priority filter;\n\t\t\tpolicy drop;\n";
        assert!(hook_policy_is_drop(wrapped, "input"));
    }

    #[test]
    fn absent_chain_is_not_treated_as_drop() {
        assert!(!hook_policy_is_drop("", "input"));
        assert!(!hook_policy_is_drop("table inet filter {}", "input"));
    }
}
