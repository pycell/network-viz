from network_viz.normalizer.model import ConfigSource, NormalizedConfig, SourceBackend


def test_normalized_config_defaults() -> None:
    config = NormalizedConfig(
        source=ConfigSource(backend=SourceBackend.PFSENSE_XML, name="sample.xml")
    )

    assert config.interfaces == []
    assert config.firewall_rules == []
    assert config.nat_rules == []
    assert config.findings == []
