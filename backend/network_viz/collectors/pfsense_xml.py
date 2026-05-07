from pathlib import Path
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

from network_viz.normalizer.model import (
    Alias,
    ConfigSource,
    FirewallRule,
    Gateway,
    Interface,
    NatRule,
    NatType,
    NormalizedConfig,
    PortSelector,
    RawReference,
    Route,
    RuleAction,
    SourceBackend,
)


def parse_pfsense_xml(path: str | Path) -> NormalizedConfig:
    config_path = Path(path)
    root = ElementTree.parse(config_path).getroot()

    return NormalizedConfig(
        source=ConfigSource(backend=SourceBackend.PFSENSE_XML, name=config_path.name),
        interfaces=_parse_interfaces(root),
        aliases=_parse_aliases(root),
        routes=_parse_routes(root),
        gateways=_parse_gateways(root),
        firewall_rules=_parse_firewall_rules(root),
        nat_rules=_parse_nat_rules(root),
    )


def _parse_interfaces(root: Element) -> list[Interface]:
    interfaces = root.find("interfaces")
    if interfaces is None:
        return []

    normalized: list[Interface] = []
    for element in list(interfaces):
        name = element.tag
        address = _interface_address(element)
        normalized.append(
            Interface(
                name=name,
                display_name=_text(element, "descr") or name.upper(),
                addresses=[address] if address else [],
                zone=name,
                interface_type=_text(element, "if"),
                enabled=element.find("enable") is not None,
                raw_reference=_raw_reference(f"/interfaces/{name}", name),
            )
        )
    return normalized


def _parse_aliases(root: Element) -> list[Alias]:
    aliases = root.find("aliases")
    if aliases is None:
        return []

    normalized: list[Alias] = []
    for index, element in enumerate(aliases.findall("alias")):
        name = _text(element, "name") or f"alias-{index}"
        normalized.append(
            Alias(
                name=name,
                alias_type=_text(element, "type") or "unknown",
                values=_split_values(_text(element, "address")),
                description=_empty_to_none(_text(element, "descr")),
                raw_reference=_raw_reference(f"/aliases/alias[{index}]", name),
            )
        )
    return normalized


def _parse_firewall_rules(root: Element) -> list[FirewallRule]:
    filter_element = root.find("filter")
    if filter_element is None:
        return []

    rules: list[FirewallRule] = []
    for order, element in enumerate(filter_element.findall("rule")):
        raw_id = _text(element, "tracker") or _text(element, "id") or str(order)
        source = _selector(element.find("source"))
        destination = _selector(element.find("destination"))
        ports = _rule_ports(element)

        rules.append(
            FirewallRule(
                source=source,
                destination=destination,
                service=PortSelector(
                    protocol=_empty_to_none(_text(element, "protocol")),
                    ports=ports,
                ),
                action=_rule_action(_text(element, "type")),
                order=order,
                interface=_empty_to_none(_text(element, "interface")),
                enabled=element.find("disabled") is None,
                log=element.find("log") is not None,
                description=_empty_to_none(_text(element, "descr")),
                raw_reference=_raw_reference(f"/filter/rule[{order}]", raw_id),
            )
        )
    return rules


def _parse_nat_rules(root: Element) -> list[NatRule]:
    nat = root.find("nat")
    if nat is None:
        return []

    rules: list[NatRule] = []
    for order, element in enumerate(nat.findall("rule")):
        raw_id = _text(element, "associated-rule-id") or str(order)
        protocol = _empty_to_none(_text(element, "protocol"))
        ports = _nat_ports(element)

        rules.append(
            NatRule(
                nat_type=NatType.PORT_FORWARD,
                original_source=_selector(element.find("source")),
                original_destination=_selector(element.find("destination")),
                translated_destination=_empty_to_none(_text(element, "target")),
                service=PortSelector(protocol=protocol, ports=ports),
                order=order,
                interface=_empty_to_none(_text(element, "interface")),
                enabled=element.find("disabled") is None,
                description=_empty_to_none(_text(element, "descr")),
                raw_reference=_raw_reference(f"/nat/rule[{order}]", raw_id),
            )
        )
    return rules


def _parse_routes(root: Element) -> list[Route]:
    static_routes = root.find("staticroutes")
    if static_routes is None:
        return []

    routes: list[Route] = []
    for order, element in enumerate(static_routes.findall("route")):
        destination = _text(element, "network") or _text(element, "destination")
        if not destination:
            continue
        routes.append(
            Route(
                destination=destination,
                gateway=_empty_to_none(_text(element, "gateway")),
                interface=_empty_to_none(_text(element, "interface")),
                raw_reference=_raw_reference(f"/staticroutes/route[{order}]", str(order)),
            )
        )
    return routes


def _parse_gateways(root: Element) -> list[Gateway]:
    gateways = root.find("gateways")
    if gateways is None:
        return []

    normalized: list[Gateway] = []
    for order, element in enumerate(gateways.findall("gateway_item")):
        name = _text(element, "name")
        address = _text(element, "gateway")
        if not name or not address:
            continue
        normalized.append(
            Gateway(
                name=name,
                address=address,
                interface=_empty_to_none(_text(element, "interface")),
                raw_reference=_raw_reference(f"/gateways/gateway_item[{order}]", name),
            )
        )
    return normalized


def _interface_address(element: Element) -> str | None:
    ip_address = _empty_to_none(_text(element, "ipaddr"))
    subnet = _empty_to_none(_text(element, "subnet"))
    if not ip_address:
        return None
    if ip_address in {"dhcp", "dhcp6"} or not subnet:
        return ip_address
    return f"{ip_address}/{subnet}"


def _selector(element: Element | None) -> str:
    if element is None:
        return "any"
    if element.find("any") is not None:
        return "any"

    parts: list[str] = []
    for tag in ("address", "network"):
        value = _empty_to_none(_text(element, tag))
        if value:
            parts.append(value)

    port = _empty_to_none(_text(element, "port"))
    if port and parts:
        parts[-1] = f"{parts[-1]}:{port}"
    elif port:
        parts.append(f"port:{port}")

    if element.find("not") is not None and parts:
        return f"!{parts[0]}"
    return parts[0] if parts else "any"


def _rule_ports(element: Element) -> list[str]:
    ports: list[str] = []
    destination = element.find("destination")
    source = element.find("source")
    for selector in (destination, source):
        port = _empty_to_none(_text(selector, "port") if selector is not None else None)
        if port:
            ports.append(port)
    return ports


def _nat_ports(element: Element) -> list[str]:
    ports: list[str] = []
    destination = element.find("destination")
    destination_port = _empty_to_none(
        _text(destination, "port") if destination is not None else None
    )
    local_port = _empty_to_none(_text(element, "local-port"))
    if destination_port:
        ports.append(destination_port)
    if local_port and local_port not in ports:
        ports.append(local_port)
    return ports


def _rule_action(value: str | None) -> RuleAction:
    match value:
        case "pass":
            return RuleAction.ALLOW
        case "block":
            return RuleAction.DENY
        case "reject":
            return RuleAction.REJECT
        case _:
            return RuleAction.UNKNOWN


def _text(element: Element | None, tag: str) -> str | None:
    if element is None:
        return None
    child = element.find(tag)
    if child is None or child.text is None:
        return None
    return child.text.strip()


def _empty_to_none(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    return value


def _split_values(value: str | None) -> list[str]:
    if not value:
        return []
    return [item for item in value.split() if item]


def _raw_reference(path: str, raw_id: str | None = None) -> RawReference:
    return RawReference(backend=SourceBackend.PFSENSE_XML, path=path, raw_id=raw_id)
