from ipaddress import ip_address, ip_network
from uuid import UUID

from network_viz.normalizer.model import (
    ExplanationStep,
    FirewallRule,
    Flow,
    FlowVerdict,
    Interface,
    NatType,
    NormalizedConfig,
    PortSelector,
    Route,
    RuleAction,
)

MANAGEMENT_PORTS = ("22", "80", "443", "8443")


def analyze_flows(config: NormalizedConfig) -> NormalizedConfig:
    config.flows = generate_representative_flows(config)
    return config


def generate_representative_flows(config: NormalizedConfig) -> list[Flow]:
    flows: list[Flow] = []
    flows.extend(_flows_for_port_forwards(config))
    flows.extend(_flows_for_wan_allows(config))
    flows.extend(_zone_pair_flows(config))
    flows.extend(_management_flows(config))
    flows.extend(_flows_for_broad_allows(config))
    return _deduplicate_flows(flows)


def _flows_for_port_forwards(config: NormalizedConfig) -> list[Flow]:
    flows: list[Flow] = []
    for nat_rule in sorted(config.nat_rules, key=lambda rule: rule.order):
        if not nat_rule.enabled or nat_rule.nat_type != NatType.PORT_FORWARD:
            continue

        source = nat_rule.original_source or "internet"
        original_destination = nat_rule.original_destination or "wan"
        translated_destination = nat_rule.translated_destination or original_destination
        service = nat_rule.service
        firewall_match = _first_matching_rule(
            config.firewall_rules,
            nat_rule.interface,
            source,
            translated_destination,
            service,
            fallback_destination=original_destination,
        )
        verdict = _verdict_from_firewall_rule(firewall_match)
        if firewall_match is None:
            verdict = FlowVerdict.AMBIGUOUS
        elif source == "any" and verdict == FlowVerdict.ALLOWED:
            verdict = FlowVerdict.RISKY

        steps = [
            ExplanationStep(
                order=0,
                title="Representative flow",
                detail=(
                    "Generated from a public port-forward. The inbound destination is "
                    f"{original_destination} before translation."
                ),
                raw_reference=nat_rule.raw_reference,
            ),
            ExplanationStep(
                order=1,
                title="NAT translation",
                detail=f"Destination is translated to {translated_destination}.",
                raw_reference=nat_rule.raw_reference,
            ),
            _route_step(2, translated_destination, config.interfaces, config.routes),
            _firewall_step(3, firewall_match, nat_rule.interface),
        ]
        flows.append(
            Flow(
                source=source,
                destination=translated_destination,
                service=service,
                verdict=verdict,
                path=_path_for_flow(source, translated_destination, nat_rule.interface),
                matched_firewall_rules=_ids([firewall_match]),
                matched_nat_rules=[nat_rule.id],
                explanation=steps,
            )
        )
    return flows


def _flows_for_wan_allows(config: NormalizedConfig) -> list[Flow]:
    flows: list[Flow] = []
    for rule in sorted(config.firewall_rules, key=lambda item: item.order):
        if not rule.enabled or rule.action != RuleAction.ALLOW or rule.interface != "wan":
            continue
        verdict = FlowVerdict.RISKY if rule.source == "any" else FlowVerdict.ALLOWED
        flows.append(
            Flow(
                source=rule.source,
                destination=rule.destination,
                service=rule.service,
                verdict=verdict,
                path=_path_for_flow(rule.source, rule.destination, rule.interface),
                matched_firewall_rules=[rule.id],
                explanation=[
                    ExplanationStep(
                        order=0,
                        title="Representative flow",
                        detail="Generated from an enabled WAN allow rule.",
                        raw_reference=rule.raw_reference,
                    ),
                    _route_step(1, rule.destination, config.interfaces, config.routes),
                    _firewall_step(2, rule, rule.interface),
                ],
            )
        )
    return flows


def _zone_pair_flows(config: NormalizedConfig) -> list[Flow]:
    flows: list[Flow] = []
    pairs = [("lan", "internet"), ("vpn", "lan"), ("vpn", "dmz"), ("dmz", "lan")]
    for source_zone, destination_zone in pairs:
        source_interfaces = _interfaces_for_zone(config.interfaces, source_zone)
        destination_interfaces: list[Interface | None] = [
            *_interfaces_for_zone(config.interfaces, destination_zone)
        ]
        if destination_zone == "internet":
            destination_interfaces = [None]
        if not source_interfaces or not destination_interfaces:
            continue
        source_interface = source_interfaces[0]
        destination_interface = destination_interfaces[0]
        source = source_interface.zone or source_interface.name
        destination = (
            "internet"
            if destination_interface is None
            else destination_interface.zone or destination_interface.name
        )
        service = PortSelector(protocol=None, ports=[])
        firewall_match = _first_matching_rule(
            config.firewall_rules,
            source_interface.name,
            source,
            destination,
            service,
        )
        verdict = _verdict_from_firewall_rule(firewall_match)
        if firewall_match is None:
            verdict = FlowVerdict.UNKNOWN
        flows.append(
            Flow(
                source=source,
                destination=destination,
                service=service,
                verdict=verdict,
                path=_path_for_flow(source, destination, source_interface.name),
                matched_firewall_rules=_ids([firewall_match]),
                explanation=[
                    ExplanationStep(
                        order=0,
                        title="Representative flow",
                        detail=(
                            f"Generated for common {source.upper()} to "
                            f"{destination.upper()} traffic."
                        ),
                    ),
                    _route_step(1, destination, config.interfaces, config.routes),
                    _firewall_step(2, firewall_match, source_interface.name),
                ],
            )
        )
    return flows


def _management_flows(config: NormalizedConfig) -> list[Flow]:
    flows: list[Flow] = []
    for interface in sorted(config.interfaces, key=lambda item: item.name):
        if not interface.enabled:
            continue
        source = interface.zone or interface.name
        for port in MANAGEMENT_PORTS:
            service = PortSelector(protocol="tcp", ports=[port])
            firewall_match = _first_matching_rule(
                config.firewall_rules,
                interface.name,
                source,
                "(self)",
                service,
                fallback_destination="any",
            )
            if firewall_match is None:
                continue
            verdict = _verdict_from_firewall_rule(firewall_match)
            if verdict == FlowVerdict.ALLOWED and _externalish_interface(interface.name):
                verdict = FlowVerdict.RISKY
            flows.append(
                Flow(
                    source=source,
                    destination="firewall",
                    service=service,
                    verdict=verdict,
                    path=[source, "firewall"],
                    matched_firewall_rules=[firewall_match.id],
                    explanation=[
                        ExplanationStep(
                            order=0,
                            title="Representative flow",
                            detail=f"Generated for access to firewall management port {port}.",
                        ),
                        _firewall_step(1, firewall_match, interface.name),
                    ],
                )
            )
    return flows


def _flows_for_broad_allows(config: NormalizedConfig) -> list[Flow]:
    flows: list[Flow] = []
    for rule in sorted(config.firewall_rules, key=lambda item: item.order):
        if (
            not rule.enabled
            or rule.action != RuleAction.ALLOW
            or rule.source != "any"
            or rule.destination != "any"
        ):
            continue
        flows.append(
            Flow(
                source="any",
                destination="any",
                service=rule.service,
                verdict=FlowVerdict.RISKY,
                path=_path_for_flow("any", "any", rule.interface),
                matched_firewall_rules=[rule.id],
                explanation=[
                    ExplanationStep(
                        order=0,
                        title="Representative flow",
                        detail="Generated from an enabled broad allow rule.",
                        raw_reference=rule.raw_reference,
                    ),
                    _firewall_step(1, rule, rule.interface),
                    ExplanationStep(
                        order=2,
                        title="Risk context",
                        detail=(
                            "The rule permits any source to any destination for the "
                            "selected service."
                        ),
                        raw_reference=rule.raw_reference,
                    ),
                ],
            )
        )
    return flows


def _first_matching_rule(
    rules: list[FirewallRule],
    interface: str | None,
    source: str,
    destination: str,
    service: PortSelector,
    *,
    fallback_destination: str | None = None,
) -> FirewallRule | None:
    for rule in sorted(rules, key=lambda item: item.order):
        if not rule.enabled:
            continue
        if interface is not None and rule.interface != interface:
            continue
        if not _selector_matches(rule.source, source):
            continue
        if not (
            _selector_matches(rule.destination, destination)
            or (
                fallback_destination is not None
                and _selector_matches(rule.destination, fallback_destination)
            )
        ):
            continue
        if not _service_matches(rule.service, service):
            continue
        return rule
    return None


def _selector_matches(rule_selector: str, flow_selector: str) -> bool:
    if rule_selector == "any" or flow_selector == "any":
        return True
    if rule_selector == flow_selector:
        return True
    rule_host = _host_part(rule_selector)
    flow_host = _host_part(flow_selector)
    if rule_host == flow_host:
        return True
    if rule_host == "(self)" and flow_host == "firewall":
        return True
    if flow_host == "(self)" and rule_host == "firewall":
        return True
    return _address_contains(rule_host, flow_host)


def _host_part(selector: str) -> str:
    value = selector[1:] if selector.startswith("!") else selector
    if value.count(":") == 1 and "/" not in value:
        return value.rsplit(":", 1)[0]
    return value


def _address_contains(rule_host: str, flow_host: str) -> bool:
    try:
        network = ip_network(rule_host, strict=False)
        return ip_address(flow_host) in network
    except ValueError:
        return False


def _service_matches(rule_service: PortSelector, flow_service: PortSelector) -> bool:
    if (
        rule_service.protocol
        and flow_service.protocol
        and rule_service.protocol != flow_service.protocol
    ):
        return False
    if not rule_service.ports or not flow_service.ports:
        return True
    return bool(set(rule_service.ports) & set(flow_service.ports))


def _verdict_from_firewall_rule(rule: FirewallRule | None) -> FlowVerdict:
    if rule is None:
        return FlowVerdict.UNKNOWN
    if rule.action == RuleAction.ALLOW:
        return FlowVerdict.ALLOWED
    if rule.action in {RuleAction.DENY, RuleAction.REJECT}:
        return FlowVerdict.DENIED
    return FlowVerdict.AMBIGUOUS


def _route_step(
    order: int,
    destination: str,
    interfaces: list[Interface],
    routes: list[Route],
) -> ExplanationStep:
    interface = _interface_for_destination(destination, interfaces)
    if interface is not None:
        return ExplanationStep(
            order=order,
            title="Route decision",
            detail=f"Destination appears to belong to interface {interface.name}.",
            raw_reference=interface.raw_reference,
        )
    route = _route_for_destination(destination, routes)
    if route is not None:
        detail = f"Static route {route.destination}"
        if route.gateway:
            detail = f"{detail} via gateway {route.gateway}"
        if route.interface:
            detail = f"{detail} on interface {route.interface}"
        return ExplanationStep(
            order=order,
            title="Route decision",
            detail=detail + ".",
            raw_reference=route.raw_reference,
        )
    if destination == "internet" or destination == "any":
        return ExplanationStep(
            order=order,
            title="Route decision",
            detail=(
                "Traffic is treated as outbound or broad destination traffic; exact "
                "egress route is not known from static config alone."
            ),
        )
    return ExplanationStep(
        order=order,
        title="Route decision",
        detail=(
            "No matching interface address or static route was found, so route "
            "context is ambiguous."
        ),
    )


def _firewall_step(
    order: int,
    rule: FirewallRule | None,
    interface: str | None,
) -> ExplanationStep:
    if rule is None:
        interface_detail = f" on interface {interface}" if interface else ""
        return ExplanationStep(
            order=order,
            title="Firewall decision",
            detail=(
                "No enabled firewall rule matched"
                f"{interface_detail}. Verdict depends on default policy or "
                "behavior not represented here."
            ),
        )
    return ExplanationStep(
        order=order,
        title="Firewall decision",
        detail=(
            f"Rule {rule.order} on {rule.interface or 'unknown interface'} "
            f"applies action {rule.action}."
        ),
        raw_reference=rule.raw_reference,
    )


def _interface_for_destination(destination: str, interfaces: list[Interface]) -> Interface | None:
    host = _host_part(destination)
    for interface in interfaces:
        if host in {interface.name, interface.zone, interface.display_name}:
            return interface
        for address in interface.addresses:
            if _address_in_interface(host, address):
                return interface
    return None


def _address_in_interface(host: str, network_or_address: str) -> bool:
    if network_or_address in {"dhcp", "dhcp6"}:
        return False
    try:
        network = ip_network(network_or_address, strict=False)
        return ip_address(host) in network
    except ValueError:
        return False


def _route_for_destination(destination: str, routes: list[Route]) -> Route | None:
    host = _host_part(destination)
    for route in routes:
        if route.destination == host:
            return route
        try:
            if ip_address(host) in ip_network(route.destination, strict=False):
                return route
        except ValueError:
            continue
    return None


def _interfaces_for_zone(interfaces: list[Interface], zone: str) -> list[Interface]:
    if zone == "vpn":
        return [
            interface
            for interface in interfaces
            if interface.enabled and _externalish_interface(interface.name)
        ]
    if zone == "dmz":
        return [
            interface
            for interface in interfaces
            if interface.enabled
            and (
                (interface.zone is not None and "dmz" in interface.zone.lower())
                or (interface.display_name is not None and "dmz" in interface.display_name.lower())
            )
        ]
    return [
        interface
        for interface in interfaces
        if interface.enabled and (interface.name == zone or interface.zone == zone)
    ]


def _path_for_flow(source: str, destination: str, interface: str | None) -> list[str]:
    path = [source]
    if interface:
        path.append(interface)
    path.append(destination)
    return path


def _ids(rules: list[FirewallRule | None]) -> list[UUID]:
    return [rule.id for rule in rules if rule is not None]


def _externalish_interface(interface: str | None) -> bool:
    if interface is None:
        return False
    return interface == "wan" or interface.startswith("openvpn") or interface.startswith("ovpn")


type FlowKey = tuple[
    str,
    str,
    str | None,
    tuple[str, ...],
    tuple[UUID, ...],
    tuple[UUID, ...],
]


def _flow_key(flow: Flow) -> FlowKey:
    return (
        flow.source,
        flow.destination,
        flow.service.protocol,
        tuple(flow.service.ports),
        tuple(flow.matched_firewall_rules),
        tuple(flow.matched_nat_rules),
    )


def _deduplicate_flows(flows: list[Flow]) -> list[Flow]:
    deduplicated: list[Flow] = []
    seen: set[FlowKey] = set()
    for flow in flows:
        key = _flow_key(flow)
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(flow)
    return deduplicated
