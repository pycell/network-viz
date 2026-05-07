from pathlib import Path

from network_viz.analysis.risk_rules import analyze_risks
from network_viz.collectors.pfsense_xml import parse_pfsense_xml
from network_viz.normalizer.model import (
    ConfigSource,
    FirewallRule,
    NatRule,
    NatType,
    NormalizedConfig,
    PortSelector,
    RuleAction,
    SourceBackend,
)

FIXTURE = Path(__file__).parent / "pf_config.xml"


def test_analyze_fixture_generates_findings_with_references() -> None:
    config = analyze_risks(parse_pfsense_xml(FIXTURE))

    titles = {finding.title for finding in config.findings}

    assert "WAN allow from any source" in titles
    assert "Any-to-any allow rule" in titles
    assert "Internet-facing allow rule without logging" in titles
    assert "Rule without description" in titles
    assert "Duplicate firewall rules" in titles
    assert all(finding.raw_references for finding in config.findings)


def test_sensitive_port_forward_finding() -> None:
    config = _config(
        nat_rules=[
            NatRule(
                nat_type=NatType.PORT_FORWARD,
                original_source="any",
                original_destination="wan:22",
                translated_destination="10.0.0.10",
                service=PortSelector(protocol="tcp", ports=["22"]),
                order=0,
                interface="wan",
            )
        ]
    )

    analyzed = analyze_risks(config)

    sensitive_finding = next(
        finding for finding in analyzed.findings if finding.title == "Sensitive port-forward"
    )

    assert sensitive_finding.severity == "high"


def test_wan_allow_to_private_destination_finding() -> None:
    config = _config(
        firewall_rules=[
            FirewallRule(
                source="any",
                destination="10.0.0.10:443",
                service=PortSelector(protocol="tcp", ports=["443"]),
                action=RuleAction.ALLOW,
                order=0,
                interface="wan",
                log=True,
                description="Published internal service",
            )
        ]
    )

    analyzed = analyze_risks(config)

    assert "WAN allow to private destination" in _titles(analyzed)


def test_disabled_risky_rule_finding() -> None:
    config = _config(
        firewall_rules=[
            FirewallRule(
                source="any",
                destination="any",
                action=RuleAction.ALLOW,
                order=0,
                interface="wan",
                enabled=False,
                description="Old broad allow",
            )
        ]
    )

    analyzed = analyze_risks(config)

    assert _titles(analyzed) == {"Disabled risky rule retained"}


def test_nat_without_matching_firewall_rule_finding() -> None:
    config = _config(
        nat_rules=[
            NatRule(
                nat_type=NatType.PORT_FORWARD,
                original_source="any",
                original_destination="wan:8443",
                translated_destination="10.0.0.10",
                service=PortSelector(protocol="tcp", ports=["8443"]),
                order=0,
                interface="wan",
            )
        ],
        firewall_rules=[
            FirewallRule(
                source="trusted_admins",
                destination="10.0.0.10:443",
                service=PortSelector(protocol="tcp", ports=["443"]),
                action=RuleAction.ALLOW,
                order=0,
                interface="wan",
                log=True,
                description="Different service",
            )
        ],
    )

    analyzed = analyze_risks(config)

    assert "NAT without matching firewall allow rule" in _titles(analyzed)


def _config(
    firewall_rules: list[FirewallRule] | None = None,
    nat_rules: list[NatRule] | None = None,
) -> NormalizedConfig:
    return NormalizedConfig(
        source=ConfigSource(backend=SourceBackend.PFSENSE_XML, name="test.xml"),
        firewall_rules=firewall_rules or [],
        nat_rules=nat_rules or [],
    )


def _titles(config: NormalizedConfig) -> set[str]:
    return {finding.title for finding in config.findings}
