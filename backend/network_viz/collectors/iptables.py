from pathlib import Path
from shlex import split
from typing import Any

from network_viz.normalizer.model import (
    ConfigSource,
    FirewallRule,
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

SUPPORTED_TABLES = {"raw", "mangle", "nat", "filter"}
SUPPORTED_CHAINS = {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"}
FILTER_TARGETS = {"ACCEPT", "DROP", "REJECT"}
NAT_TARGETS = {"DNAT", "SNAT", "MASQUERADE", "REDIRECT"}


def parse_iptables_bundle(
    iptables_save_path: str | Path,
    *,
    route_path: str | Path | None = None,
    rule_path: str | Path | None = None,
    interface_path: str | Path | None = None,
) -> NormalizedConfig:
    config = parse_iptables_save(iptables_save_path)
    if route_path is not None:
        config.routes = parse_ip_route(route_path)
    if rule_path is not None:
        config.source.metadata["ip_rules"] = parse_ip_rule(rule_path)
    if interface_path is not None:
        config.interfaces = parse_ip_addr(interface_path)
    return config


def parse_iptables_bundle_text(
    iptables_save_content: str,
    *,
    name: str = "uploaded-iptables-save",
    route_content: str | None = None,
    rule_content: str | None = None,
    interface_content: str | None = None,
) -> NormalizedConfig:
    config = parse_iptables_save_text(iptables_save_content, name=name)
    if route_content:
        config.routes = parse_ip_route_text(route_content)
    if rule_content:
        config.source.metadata["ip_rules"] = parse_ip_rule_text(rule_content)
    if interface_content:
        config.interfaces = parse_ip_addr_text(interface_content)
    return config


def parse_iptables_save(path: str | Path) -> NormalizedConfig:
    config_path = Path(path)
    return parse_iptables_save_text(config_path.read_text(), name=config_path.name)


def parse_iptables_save_text(
    content: str,
    name: str = "uploaded-iptables-save",
) -> NormalizedConfig:
    lines = content.splitlines()
    firewall_rules: list[FirewallRule] = []
    nat_rules: list[NatRule] = []
    tables_seen: list[str] = []
    current_table: str | None = None
    rule_orders: dict[tuple[str, str], int] = {}

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:]
            current_table = table if table in SUPPORTED_TABLES else None
            if current_table is not None:
                tables_seen.append(current_table)
            continue
        if line == "COMMIT":
            current_table = None
            continue
        if current_table is None:
            continue
        if line.startswith(":"):
            default_policy = _parse_default_policy(line, current_table, line_number)
            if default_policy is not None:
                firewall_rules.append(default_policy)
            continue
        if not line.startswith("-A "):
            continue

        tokens = split(line)
        if len(tokens) < 3:
            continue
        chain = tokens[1]
        if chain not in SUPPORTED_CHAINS:
            continue
        order_key = (current_table, chain)
        order = rule_orders.get(order_key, 0)
        rule_orders[order_key] = order + 1
        parsed = _parse_rule_tokens(tokens[2:])
        raw_reference = _raw_reference(
            f"/iptables-save/{current_table}/{chain}/rule[{order}]",
            f"{current_table}:{chain}:{order}",
            line,
        )
        if current_table == "nat" and parsed.target in NAT_TARGETS:
            nat_rules.append(_nat_rule(parsed, chain, order, raw_reference))
        elif current_table == "filter" and parsed.target in FILTER_TARGETS:
            firewall_rules.append(_firewall_rule(parsed, chain, order, raw_reference))

    return NormalizedConfig(
        source=ConfigSource(
            backend=SourceBackend.IPTABLES,
            name=name,
            metadata={"tables": tables_seen},
        ),
        firewall_rules=firewall_rules,
        nat_rules=nat_rules,
    )


def parse_ip_route(path: str | Path) -> list[Route]:
    route_path = Path(path)
    return parse_ip_route_text(route_path.read_text())


def parse_ip_route_text(content: str) -> list[Route]:
    routes: list[Route] = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        tokens = split(line)
        if not tokens:
            continue
        routes.append(
            Route(
                destination=tokens[0],
                gateway=_value_after(tokens, "via"),
                interface=_value_after(tokens, "dev"),
                metric=_int_value_after(tokens, "metric"),
                raw_reference=_raw_reference(
                    f"/ip-route/route[{len(routes)}]",
                    str(line_number),
                    line,
                ),
            )
        )
    return routes


def parse_ip_addr(path: str | Path) -> list[Interface]:
    addr_path = Path(path)
    return parse_ip_addr_text(addr_path.read_text())


def parse_ip_addr_text(content: str) -> list[Interface]:
    by_name: dict[str, Interface] = {}
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        tokens = split(line)
        if "inet" not in tokens:
            continue
        inet_index = tokens.index("inet")
        if inet_index + 1 >= len(tokens):
            continue
        name = _interface_name_from_addr_tokens(tokens)
        if name is None:
            continue
        address = tokens[inet_index + 1]
        interface = by_name.get(name)
        if interface is None:
            interface = Interface(
                name=name,
                display_name=name,
                addresses=[],
                zone=name,
                interface_type="linux",
                enabled=True,
                raw_reference=_raw_reference(
                    f"/ip-addr/interface[{len(by_name)}]",
                    str(line_number),
                    line,
                ),
            )
            by_name[name] = interface
        interface.addresses.append(address)
    return list(by_name.values())


def parse_ip_rule(path: str | Path) -> list[dict[str, str]]:
    rule_path = Path(path)
    return parse_ip_rule_text(rule_path.read_text())


def parse_ip_rule_text(content: str) -> list[dict[str, str]]:
    rules: list[dict[str, str]] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        priority, separator, selector = line.partition(":")
        if separator:
            rules.append(
                {
                    "priority": priority.strip(),
                    "selector": selector.strip(),
                    "raw": line,
                }
            )
        else:
            rules.append({"priority": "", "selector": line, "raw": line})
    return rules


class ParsedRule:
    def __init__(self) -> None:
        self.protocol: str | None = None
        self.source = "any"
        self.destination = "any"
        self.in_interface: str | None = None
        self.out_interface: str | None = None
        self.ports: list[str] = []
        self.target: str | None = None
        self.comment: str | None = None
        self.to_destination: str | None = None
        self.to_source: str | None = None
        self.to_ports: str | None = None
        self.extra: dict[str, Any] = {}


def _parse_rule_tokens(tokens: list[str]) -> ParsedRule:
    parsed = ParsedRule()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        value = tokens[index + 1] if index + 1 < len(tokens) else None
        match token:
            case "-p" | "--protocol":
                parsed.protocol = value
                index += 2
            case "-s" | "--source":
                parsed.source = value or "any"
                index += 2
            case "-d" | "--destination":
                parsed.destination = value or "any"
                index += 2
            case "-i" | "--in-interface":
                parsed.in_interface = value
                index += 2
            case "-o" | "--out-interface":
                parsed.out_interface = value
                index += 2
            case "--dport" | "--destination-port" | "--sport" | "--source-port":
                parsed.ports.extend(_split_ports(value))
                index += 2
            case "--dports" | "--sports":
                parsed.ports.extend(_split_ports(value))
                index += 2
            case "-j" | "--jump":
                parsed.target = value
                index += 2
            case "--comment":
                parsed.comment = value
                index += 2
            case "--to-destination":
                parsed.to_destination = value
                index += 2
            case "--to-source":
                parsed.to_source = value
                index += 2
            case "--to-ports":
                parsed.to_ports = value
                index += 2
            case "--to":
                if parsed.target == "DNAT":
                    parsed.to_destination = value
                elif parsed.target == "SNAT":
                    parsed.to_source = value
                else:
                    parsed.to_ports = value
                index += 2
            case _:
                if value is not None and token.startswith("-") and not value.startswith("-"):
                    parsed.extra[token] = value
                    index += 2
                else:
                    index += 1
    return parsed


def _parse_default_policy(
    line: str,
    table: str,
    line_number: int,
) -> FirewallRule | None:
    tokens = line.split()
    if len(tokens) < 2 or table != "filter":
        return None
    chain = tokens[0][1:]
    policy = tokens[1]
    if chain not in SUPPORTED_CHAINS or policy == "-":
        return None
    return FirewallRule(
        source="any",
        destination="any",
        service=PortSelector(),
        action=_target_to_action(policy),
        order=-1,
        chain=chain,
        description=f"Default policy for {table}/{chain}",
        raw_reference=_raw_reference(
            f"/iptables-save/{table}/{chain}/default-policy",
            f"{table}:{chain}:policy",
            line,
        ),
    )


def _firewall_rule(
    parsed: ParsedRule,
    chain: str,
    order: int,
    raw_reference: RawReference,
) -> FirewallRule:
    return FirewallRule(
        source=parsed.source,
        destination=parsed.destination,
        service=PortSelector(protocol=parsed.protocol, ports=parsed.ports),
        action=_target_to_action(parsed.target),
        order=order,
        interface=parsed.in_interface or parsed.out_interface,
        chain=chain,
        description=parsed.comment,
        raw_reference=raw_reference,
    )


def _nat_rule(
    parsed: ParsedRule,
    chain: str,
    order: int,
    raw_reference: RawReference,
) -> NatRule:
    return NatRule(
        nat_type=_target_to_nat_type(parsed.target),
        original_source=parsed.source,
        original_destination=parsed.destination,
        translated_source=parsed.to_source,
        translated_destination=_translated_destination(parsed),
        service=PortSelector(protocol=parsed.protocol, ports=parsed.ports),
        order=order,
        interface=parsed.in_interface or parsed.out_interface,
        description=parsed.comment or f"{chain} {parsed.target}",
        raw_reference=raw_reference,
    )


def _translated_destination(parsed: ParsedRule) -> str | None:
    if parsed.target == "REDIRECT":
        if parsed.to_ports:
            return f"(self):{parsed.to_ports}"
        return "(self)"
    return parsed.to_destination


def _target_to_action(target: str | None) -> RuleAction:
    match target:
        case "ACCEPT":
            return RuleAction.ALLOW
        case "DROP":
            return RuleAction.DENY
        case "REJECT":
            return RuleAction.REJECT
        case _:
            return RuleAction.UNKNOWN


def _target_to_nat_type(target: str | None) -> NatType:
    match target:
        case "DNAT":
            return NatType.DNAT
        case "SNAT":
            return NatType.SNAT
        case "MASQUERADE":
            return NatType.MASQUERADE
        case "REDIRECT":
            return NatType.REDIRECT
        case _:
            return NatType.DNAT


def _split_ports(value: str | None) -> list[str]:
    if not value:
        return []
    return [port for port in value.split(",") if port]


def _value_after(tokens: list[str], key: str) -> str | None:
    if key not in tokens:
        return None
    index = tokens.index(key)
    if index + 1 >= len(tokens):
        return None
    return tokens[index + 1]


def _int_value_after(tokens: list[str], key: str) -> int | None:
    value = _value_after(tokens, key)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _interface_name_from_addr_tokens(tokens: list[str]) -> str | None:
    if len(tokens) < 2:
        return None
    return tokens[1].rstrip(":")


def _raw_reference(path: str, raw_id: str | None, raw: str) -> RawReference:
    return RawReference(
        backend=SourceBackend.IPTABLES,
        path=path,
        raw_id=raw_id,
        raw=raw,
    )
