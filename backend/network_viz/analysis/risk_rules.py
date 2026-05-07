from collections import defaultdict
from ipaddress import ip_address, ip_network
from uuid import UUID

from network_viz.normalizer.model import (
    Confidence,
    Finding,
    FirewallRule,
    NatRule,
    NatType,
    NormalizedConfig,
    RawReference,
    RuleAction,
    Severity,
)

SENSITIVE_PORTS = {"22", "3389", "5900", "5432", "3306", "6379", "9200", "8080", "8443"}
WAN_INTERFACES = {"wan"}
MANAGEMENT_PORTS = {"22", "80", "443", "8443"}


def analyze_risks(config: NormalizedConfig) -> NormalizedConfig:
    findings: list[Finding] = []
    findings.extend(_wan_allow_from_any(config.firewall_rules))
    findings.extend(_wan_allow_to_private_destination(config.firewall_rules))
    findings.extend(_sensitive_port_forwards(config.nat_rules))
    findings.extend(_management_exposure(config.firewall_rules))
    findings.extend(_broad_vpn_to_lan(config.firewall_rules))
    findings.extend(_any_to_any_allows(config.firewall_rules))
    findings.extend(_disabled_risky_rules(config.firewall_rules))
    findings.extend(_rules_without_description(config.firewall_rules))
    findings.extend(_internet_allows_without_logging(config.firewall_rules))
    findings.extend(_duplicate_rules(config.firewall_rules))
    findings.extend(_shadowed_rules(config.firewall_rules))
    findings.extend(_nat_without_restrictive_firewall_rule(config.nat_rules, config.firewall_rules))
    config.findings = findings
    return config


def _wan_allow_from_any(rules: list[FirewallRule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        if rule.enabled and _is_allow(rule) and _is_wan(rule.interface) and rule.source == "any":
            findings.append(
                _finding(
                    Severity.HIGH,
                    "WAN allow from any source",
                    "An enabled WAN allow rule accepts traffic from any source. Review whether the "
                    "destination and service are intentionally public.",
                    [rule.id],
                    [rule.raw_reference],
                    Confidence.HIGH,
                )
            )
    return findings


def _wan_allow_to_private_destination(rules: list[FirewallRule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        if (
            rule.enabled
            and _is_allow(rule)
            and _is_wan(rule.interface)
            and _selector_contains_private_address(rule.destination)
        ):
            findings.append(
                _finding(
                    Severity.HIGH,
                    "WAN allow to private destination",
                    "A WAN allow rule targets a private or internal address. This may expose an "
                    "internal service directly or indicate missing NAT context.",
                    [rule.id],
                    [rule.raw_reference],
                    Confidence.HIGH,
                )
            )
    return findings


def _sensitive_port_forwards(nat_rules: list[NatRule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in nat_rules:
        sensitive_ports = sorted(set(rule.service.ports) & SENSITIVE_PORTS)
        if rule.enabled and rule.nat_type == NatType.PORT_FORWARD and sensitive_ports:
            severity = Severity.HIGH if _is_wan(rule.interface) else Severity.MEDIUM
            confidence = Confidence.HIGH if _is_wan(rule.interface) else Confidence.MEDIUM
            findings.append(
                _finding(
                    severity,
                    "Sensitive port-forward",
                    "A port-forward includes sensitive service port(s): "
                    f"{', '.join(sensitive_ports)}.",
                    [rule.id],
                    [rule.raw_reference],
                    confidence,
                )
            )
    return findings


def _management_exposure(rules: list[FirewallRule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        exposed_ports = sorted(set(rule.service.ports) & MANAGEMENT_PORTS)
        if (
            rule.enabled
            and _is_allow(rule)
            and _is_external_interface(rule.interface)
            and exposed_ports
        ):
            findings.append(
                _finding(
                    Severity.HIGH,
                    "Firewall management port exposed",
                    "An external-facing allow rule exposes common management port(s): "
                    f"{', '.join(exposed_ports)}.",
                    [rule.id],
                    [rule.raw_reference],
                    Confidence.MEDIUM,
                )
            )
    return findings


def _broad_vpn_to_lan(rules: list[FirewallRule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        if (
            rule.enabled
            and _is_allow(rule)
            and _is_vpn_interface(rule.interface)
            and _is_lan_destination(rule.destination)
            and not rule.service.ports
        ):
            findings.append(
                _finding(
                    Severity.MEDIUM,
                    "Broad VPN-to-LAN access",
                    "A VPN-facing rule allows broad access into a LAN destination without service "
                    "restrictions.",
                    [rule.id],
                    [rule.raw_reference],
                    Confidence.MEDIUM,
                )
            )
    return findings


def _any_to_any_allows(rules: list[FirewallRule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        if rule.enabled and _is_allow(rule) and rule.source == "any" and rule.destination == "any":
            severity = Severity.CRITICAL if _is_wan(rule.interface) else Severity.HIGH
            findings.append(
                _finding(
                    severity,
                    "Any-to-any allow rule",
                    "An enabled allow rule permits traffic from any source to any destination.",
                    [rule.id],
                    [rule.raw_reference],
                    Confidence.HIGH,
                )
            )
    return findings


def _disabled_risky_rules(rules: list[FirewallRule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        if not rule.enabled and _is_allow(rule) and _is_broad_rule(rule):
            findings.append(
                _finding(
                    Severity.INFO,
                    "Disabled risky rule retained",
                    "A disabled rule would be broad or externally exposed if re-enabled.",
                    [rule.id],
                    [rule.raw_reference],
                    Confidence.MEDIUM,
                )
            )
    return findings


def _rules_without_description(rules: list[FirewallRule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        if rule.enabled and not rule.description:
            findings.append(
                _finding(
                    Severity.LOW,
                    "Rule without description",
                    "An enabled firewall rule has no description, making future review harder.",
                    [rule.id],
                    [rule.raw_reference],
                    Confidence.HIGH,
                )
            )
    return findings


def _internet_allows_without_logging(rules: list[FirewallRule]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        if rule.enabled and _is_allow(rule) and _is_wan(rule.interface) and not rule.log:
            findings.append(
                _finding(
                    Severity.MEDIUM,
                    "Internet-facing allow rule without logging",
                    "An enabled WAN allow rule does not log matched traffic.",
                    [rule.id],
                    [rule.raw_reference],
                    Confidence.HIGH,
                )
            )
    return findings


def _duplicate_rules(rules: list[FirewallRule]) -> list[Finding]:
    grouped: dict[tuple[object, ...], list[FirewallRule]] = defaultdict(list)
    for rule in rules:
        if not rule.enabled:
            continue
        key = (
            rule.interface,
            rule.action,
            rule.source,
            rule.destination,
            rule.service.protocol,
            tuple(rule.service.ports),
        )
        grouped[key].append(rule)

    findings: list[Finding] = []
    for duplicates in grouped.values():
        if len(duplicates) < 2:
            continue
        findings.append(
            _finding(
                Severity.MEDIUM,
                "Duplicate firewall rules",
                "Multiple enabled firewall rules have the same interface, action, selectors, "
                "protocol, and ports.",
                [rule.id for rule in duplicates],
                [rule.raw_reference for rule in duplicates],
                Confidence.HIGH,
            )
        )
    return findings


def _shadowed_rules(rules: list[FirewallRule]) -> list[Finding]:
    findings: list[Finding] = []
    previous_broad_allows: dict[str, FirewallRule] = {}
    for rule in rules:
        if not rule.enabled or not _is_allow(rule) or not rule.interface:
            continue
        previous = previous_broad_allows.get(rule.interface)
        if previous is not None and rule.id != previous.id:
            findings.append(
                _finding(
                    Severity.LOW,
                    "Rule may be shadowed",
                    "An earlier broad allow rule on the same interface may make this later allow "
                    "rule redundant.",
                    [previous.id, rule.id],
                    [previous.raw_reference, rule.raw_reference],
                    Confidence.LOW,
                )
            )
        if _is_broad_rule(rule):
            previous_broad_allows[rule.interface] = rule
    return findings


def _nat_without_restrictive_firewall_rule(
    nat_rules: list[NatRule], firewall_rules: list[FirewallRule]
) -> list[Finding]:
    findings: list[Finding] = []
    for nat_rule in nat_rules:
        if not nat_rule.enabled or nat_rule.nat_type != NatType.PORT_FORWARD:
            continue
        matching_allows = [
            rule
            for rule in firewall_rules
            if rule.enabled
            and _is_allow(rule)
            and rule.interface == nat_rule.interface
            and _ports_overlap(rule.service.ports, nat_rule.service.ports)
        ]
        if not matching_allows:
            findings.append(
                _finding(
                    Severity.MEDIUM,
                    "NAT without matching firewall allow rule",
                    "A port-forward has no enabled allow rule with matching interface and port. "
                    "The exposure may depend on associated-rule behavior not represented here.",
                    [nat_rule.id],
                    [nat_rule.raw_reference],
                    Confidence.LOW,
                )
            )
            continue
        if any(rule.source == "any" for rule in matching_allows):
            findings.append(
                _finding(
                    Severity.MEDIUM,
                    "NAT paired with broad firewall allow",
                    "A port-forward appears paired with a firewall allow rule that accepts traffic "
                    "from any source.",
                    [nat_rule.id, *[rule.id for rule in matching_allows if rule.source == "any"]],
                    [nat_rule.raw_reference, *[rule.raw_reference for rule in matching_allows]],
                    Confidence.MEDIUM,
                )
            )
    return findings


def _finding(
    severity: Severity,
    title: str,
    explanation: str,
    affected_objects: list[UUID],
    raw_references: list[RawReference | None],
    confidence: Confidence,
) -> Finding:
    return Finding(
        severity=severity,
        title=title,
        explanation=explanation,
        affected_objects=affected_objects,
        confidence=confidence,
        raw_references=[reference for reference in raw_references if reference is not None],
    )


def _is_allow(rule: FirewallRule) -> bool:
    return rule.action == RuleAction.ALLOW


def _is_wan(interface: str | None) -> bool:
    return interface in WAN_INTERFACES


def _is_external_interface(interface: str | None) -> bool:
    return _is_wan(interface) or _is_vpn_interface(interface)


def _is_vpn_interface(interface: str | None) -> bool:
    if interface is None:
        return False
    return interface.startswith("openvpn") or interface.startswith("ovpn") or interface == "enc0"


def _is_lan_destination(destination: str) -> bool:
    return destination == "lan" or destination.startswith("lan:")


def _is_broad_rule(rule: FirewallRule) -> bool:
    return rule.source == "any" and rule.destination == "any" and not rule.service.ports


def _ports_overlap(left: list[str], right: list[str]) -> bool:
    return not left or not right or bool(set(left) & set(right))


def _selector_contains_private_address(selector: str) -> bool:
    value = selector[1:] if selector.startswith("!") else selector
    host_or_network = value.rsplit(":", 1)[0]
    if host_or_network in {"any", "(self)", "lan"}:
        return host_or_network == "lan"
    try:
        if "/" in host_or_network:
            return ip_network(host_or_network, strict=False).is_private
        return ip_address(host_or_network).is_private
    except ValueError:
        return False
