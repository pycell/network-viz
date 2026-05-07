from pathlib import Path

from network_viz.collectors.iptables import (
    parse_ip_addr,
    parse_ip_route,
    parse_ip_rule,
    parse_iptables_bundle,
    parse_iptables_save,
)
from network_viz.normalizer.model import NatType, RuleAction, SourceBackend

FIXTURE_DIR = Path(__file__).parent


def test_parse_iptables_save_normalizes_filter_rules_and_default_policies() -> None:
    config = parse_iptables_save(FIXTURE_DIR / "iptables-save.fixture")

    assert config.source.backend == SourceBackend.IPTABLES
    assert config.source.metadata["tables"] == ["raw", "mangle", "nat", "filter"]

    default_input = next(rule for rule in config.firewall_rules if rule.chain == "INPUT")
    ssh_rule = next(rule for rule in config.firewall_rules if rule.description == "trusted ssh")
    reject_rule = next(rule for rule in config.firewall_rules if rule.service.ports == ["23"])

    assert default_input.action == RuleAction.DENY
    assert default_input.order == -1
    assert default_input.raw_reference is not None
    assert default_input.raw_reference.raw == ":INPUT DROP [0:0]"
    assert ssh_rule.action == RuleAction.ALLOW
    assert ssh_rule.source == "198.51.100.7/32"
    assert ssh_rule.destination == "any"
    assert ssh_rule.interface == "eth0"
    assert ssh_rule.chain == "INPUT"
    assert ssh_rule.service.protocol == "tcp"
    assert ssh_rule.service.ports == ["22"]
    assert ssh_rule.raw_reference is not None
    assert ssh_rule.raw_reference.raw is not None
    assert reject_rule.action == RuleAction.REJECT


def test_parse_iptables_save_normalizes_nat_targets() -> None:
    config = parse_iptables_save(FIXTURE_DIR / "iptables-save.fixture")

    dnat = next(rule for rule in config.nat_rules if rule.nat_type == NatType.DNAT)
    masquerade = next(rule for rule in config.nat_rules if rule.nat_type == NatType.MASQUERADE)
    snat = next(rule for rule in config.nat_rules if rule.nat_type == NatType.SNAT)
    redirect = next(rule for rule in config.nat_rules if rule.nat_type == NatType.REDIRECT)

    assert dnat.original_source == "any"
    assert dnat.original_destination == "203.0.113.10"
    assert dnat.translated_destination == "10.0.0.10:443"
    assert dnat.service.protocol == "tcp"
    assert dnat.service.ports == ["8443"]
    assert dnat.interface == "eth0"
    assert dnat.description == "public admin"
    assert masquerade.original_source == "10.0.0.0/24"
    assert masquerade.interface == "eth0"
    assert snat.translated_source == "203.0.113.20"
    assert redirect.translated_destination == "(self):80"


def test_parse_ip_route_preserves_gateway_interface_and_metric() -> None:
    routes = parse_ip_route(FIXTURE_DIR / "ip-route.fixture")

    assert routes[0].destination == "default"
    assert routes[0].gateway == "203.0.113.1"
    assert routes[0].interface == "eth0"
    assert routes[0].metric == 100
    assert routes[1].destination == "10.0.0.0/24"
    assert routes[1].gateway is None
    assert routes[2].gateway == "10.0.0.254"
    assert routes[2].metric == 50


def test_parse_ip_addr_preserves_interface_inventory() -> None:
    interfaces = parse_ip_addr(FIXTURE_DIR / "ip-addr.fixture")

    eth0 = next(interface for interface in interfaces if interface.name == "eth0")
    eth1 = next(interface for interface in interfaces if interface.name == "eth1")

    assert eth0.addresses == ["203.0.113.10/24"]
    assert eth0.interface_type == "linux"
    assert eth1.addresses == ["10.0.0.1/24"]


def test_parse_ip_rule_preserves_policy_routing_lines() -> None:
    rules = parse_ip_rule(FIXTURE_DIR / "ip-rule.fixture")

    assert rules[0]["priority"] == "0"
    assert rules[0]["raw"] == "0: from all lookup local"
    assert rules[1]["priority"] == "100"
    assert rules[1]["selector"] == "from 10.0.1.0/24 lookup 100"


def test_parse_iptables_bundle_combines_firewall_routes_and_interfaces() -> None:
    config = parse_iptables_bundle(
        FIXTURE_DIR / "iptables-save.fixture",
        route_path=FIXTURE_DIR / "ip-route.fixture",
        rule_path=FIXTURE_DIR / "ip-rule.fixture",
        interface_path=FIXTURE_DIR / "ip-addr.fixture",
    )

    assert len(config.firewall_rules) >= 8
    assert len(config.nat_rules) == 4
    assert len(config.routes) == 3
    assert len(config.interfaces) == 3
    assert len(config.source.metadata["ip_rules"]) == 4
