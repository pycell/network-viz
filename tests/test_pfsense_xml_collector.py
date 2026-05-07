from pathlib import Path

from network_viz.collectors.pfsense_xml import parse_pfsense_xml
from network_viz.normalizer.model import NatType, RuleAction, SourceBackend

FIXTURE = Path(__file__).parent / "pf_config.xml"


def test_parse_pfsense_xml_core_sections() -> None:
    config = parse_pfsense_xml(FIXTURE)

    assert config.source.backend == SourceBackend.PFSENSE_XML
    assert config.source.name == "pf_config.xml"
    assert len(config.interfaces) == 3
    assert len(config.aliases) == 7
    assert len(config.firewall_rules) >= 10
    assert len(config.nat_rules) == 2


def test_parse_pfsense_xml_interfaces_and_aliases() -> None:
    config = parse_pfsense_xml(FIXTURE)

    lan = next(interface for interface in config.interfaces if interface.name == "lan")
    opt1 = next(interface for interface in config.interfaces if interface.name == "opt1")
    alias = next(item for item in config.aliases if item.name == "Test1")

    assert lan.display_name == "LAN"
    assert lan.addresses == ["192.168.125.1/24"]
    assert lan.enabled is True
    assert opt1.enabled is False
    assert opt1.interface_type == "ovpnc2"
    assert alias.alias_type == "host"
    assert alias.values == ["8.8.4.4"]
    assert alias.raw_reference is not None


def test_parse_pfsense_xml_firewall_rules_preserve_fields() -> None:
    config = parse_pfsense_xml(FIXTURE)

    wan_openvpn_rule = next(
        rule
        for rule in config.firewall_rules
        if rule.interface == "wan" and rule.service.protocol == "udp"
    )
    first_rule = config.firewall_rules[0]

    assert first_rule.order == 0
    assert first_rule.action == RuleAction.DENY
    assert first_rule.source == "pfB_Asia_v4"
    assert first_rule.destination == "any"
    assert first_rule.log is True
    assert first_rule.raw_reference is not None
    assert wan_openvpn_rule.action == RuleAction.ALLOW
    assert wan_openvpn_rule.source == "any"
    assert wan_openvpn_rule.destination == "(self):1194"
    assert wan_openvpn_rule.service.ports == ["1194"]


def test_parse_pfsense_xml_nat_rules_preserve_translation_fields() -> None:
    config = parse_pfsense_xml(FIXTURE)

    first_nat = config.nat_rules[0]

    assert first_nat.order == 0
    assert first_nat.nat_type == NatType.PORT_FORWARD
    assert first_nat.original_source == "any"
    assert first_nat.original_destination == "10.10.10.1:80"
    assert first_nat.translated_destination == "127.0.0.1"
    assert first_nat.service.protocol == "tcp"
    assert first_nat.service.ports == ["80", "8081"]
    assert first_nat.interface == "lan"
    assert first_nat.raw_reference is not None
