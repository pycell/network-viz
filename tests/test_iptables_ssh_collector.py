from network_viz.collectors.iptables_ssh import (
    IptablesSshCollectionError,
    collect_iptables_over_ssh,
)


def test_collect_iptables_over_ssh_parses_remote_outputs() -> None:
    commands: list[str] = []

    def runner(
        host: str,
        username: str,
        port: int,
        command: str,
        timeout_seconds: int,
    ) -> str:
        assert host == "192.168.64.2"
        assert username == "root"
        assert port == 22
        assert timeout_seconds == 20
        commands.append(command)
        match command:
            case "iptables-save":
                return open("tests/iptables-save.fixture").read()
            case "ip route":
                return open("tests/ip-route.fixture").read()
            case "ip rule":
                return open("tests/ip-rule.fixture").read()
            case "ip -o -4 addr show":
                return open("tests/ip-addr.fixture").read()
            case _:
                raise AssertionError(f"Unexpected command: {command}")

    config = collect_iptables_over_ssh("192.168.64.2", "root", runner=runner)

    assert commands == ["iptables-save", "ip route", "ip rule", "ip -o -4 addr show"]
    assert config.source.name == "root@192.168.64.2:iptables-save"
    assert config.source.metadata["collector"] == "ssh"
    assert config.source.metadata["ssh_host"] == "192.168.64.2"
    assert config.firewall_rules
    assert config.nat_rules
    assert config.routes
    assert config.interfaces


def test_collect_iptables_over_ssh_validates_host_and_user() -> None:
    try:
        collect_iptables_over_ssh("", "root")
    except IptablesSshCollectionError as exc:
        assert "host is required" in str(exc)
    else:
        raise AssertionError("Expected host validation error")

    try:
        collect_iptables_over_ssh("192.168.64.2", "")
    except IptablesSshCollectionError as exc:
        assert "username is required" in str(exc)
    else:
        raise AssertionError("Expected username validation error")
