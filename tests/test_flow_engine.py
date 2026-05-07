from network_viz.analysis.flow_engine import analyze_flows
from network_viz.normalizer.model import (
    ConfigSource,
    FirewallRule,
    Interface,
    NatRule,
    NatType,
    NormalizedConfig,
    PortSelector,
    RuleAction,
    SourceBackend,
)


def test_port_forward_flow_explains_nat_and_firewall_allow() -> None:
    config = _config(
        nat_rules=[
            NatRule(
                nat_type=NatType.PORT_FORWARD,
                original_source="any",
                original_destination="wan:443",
                translated_destination="10.0.0.10",
                service=PortSelector(protocol="tcp", ports=["443"]),
                order=0,
                interface="wan",
            )
        ],
        firewall_rules=[
            FirewallRule(
                source="any",
                destination="10.0.0.10:443",
                service=PortSelector(protocol="tcp", ports=["443"]),
                action=RuleAction.ALLOW,
                order=0,
                interface="wan",
                description="Published HTTPS",
            )
        ],
    )

    analyzed = analyze_flows(config)

    flow = analyzed.flows[0]
    assert flow.source == "any"
    assert flow.destination == "10.0.0.10"
    assert flow.verdict == "risky"
    assert flow.matched_nat_rules == [config.nat_rules[0].id]
    assert flow.matched_firewall_rules == [config.firewall_rules[0].id]
    assert [step.title for step in flow.explanation] == [
        "Representative flow",
        "NAT translation",
        "Route decision",
        "Firewall decision",
    ]


def test_port_forward_without_firewall_context_is_ambiguous() -> None:
    config = _config(
        nat_rules=[
            NatRule(
                nat_type=NatType.PORT_FORWARD,
                original_source="any",
                original_destination="wan:8443",
                translated_destination="10.0.0.20",
                service=PortSelector(protocol="tcp", ports=["8443"]),
                order=0,
                interface="wan",
            )
        ]
    )

    analyzed = analyze_flows(config)

    assert analyzed.flows[0].verdict == "ambiguous"
    assert analyzed.flows[0].matched_firewall_rules == []
    assert "No enabled firewall rule matched" in analyzed.flows[0].explanation[-1].detail


def test_wan_allow_flow_is_generated_from_matching_rule() -> None:
    config = _config(
        firewall_rules=[
            FirewallRule(
                source="203.0.113.10",
                destination="(self):1194",
                service=PortSelector(protocol="udp", ports=["1194"]),
                action=RuleAction.ALLOW,
                order=0,
                interface="wan",
                description="VPN",
            )
        ]
    )

    analyzed = analyze_flows(config)

    flow = analyzed.flows[0]
    assert flow.source == "203.0.113.10"
    assert flow.destination == "(self):1194"
    assert flow.verdict == "allowed"
    assert flow.matched_firewall_rules == [config.firewall_rules[0].id]
    assert flow.explanation[0].detail == "Generated from an enabled WAN allow rule."


def test_lan_to_internet_flow_matches_lan_rule() -> None:
    config = _config(
        interfaces=[
            Interface(name="lan", addresses=["192.168.1.1/24"], zone="lan"),
            Interface(name="wan", addresses=["dhcp"], zone="wan"),
        ],
        firewall_rules=[
            FirewallRule(
                source="lan",
                destination="any",
                service=PortSelector(),
                action=RuleAction.ALLOW,
                order=0,
                interface="lan",
                description="LAN outbound",
            )
        ],
    )

    analyzed = analyze_flows(config)

    lan_flow = next(flow for flow in analyzed.flows if flow.source == "lan")
    assert lan_flow.destination == "internet"
    assert lan_flow.verdict == "allowed"
    assert lan_flow.matched_firewall_rules == [config.firewall_rules[0].id]


def _config(
    interfaces: list[Interface] | None = None,
    firewall_rules: list[FirewallRule] | None = None,
    nat_rules: list[NatRule] | None = None,
) -> NormalizedConfig:
    return NormalizedConfig(
        source=ConfigSource(backend=SourceBackend.PFSENSE_XML, name="test.xml"),
        interfaces=interfaces or [],
        firewall_rules=firewall_rules or [],
        nat_rules=nat_rules or [],
    )
