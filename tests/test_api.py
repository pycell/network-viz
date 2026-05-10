from fastapi.testclient import TestClient
from network_viz.api.main import create_app
from network_viz.collectors.iptables import parse_iptables_bundle_text
from network_viz.config import get_settings


def test_health_endpoint() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_summary_without_configured_xml() -> None:
    get_settings.cache_clear()
    client = TestClient(create_app())

    response = client.get("/api/v1/summary")

    assert response.status_code == 200
    assert response.json()["config_source"] is None


def test_summary_with_configured_xml(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("NETWORK_VIZ_PFSENSE_XML_PATH", "tests/pf_config.xml")
    get_settings.cache_clear()
    client = TestClient(create_app())

    response = client.get("/api/v1/summary")

    assert response.status_code == 200
    assert response.json()["config_source"] == "pf_config.xml"
    assert response.json()["interfaces"] == 3
    assert response.json()["flows"] > 0
    assert response.json()["findings"] > 0
    get_settings.cache_clear()


def test_policy_with_configured_xml(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("NETWORK_VIZ_PFSENSE_XML_PATH", "tests/pf_config.xml")
    get_settings.cache_clear()
    client = TestClient(create_app())

    response = client.get("/api/v1/policy")

    assert response.status_code == 200
    assert response.json()["source"]["name"] == "pf_config.xml"
    assert response.json()["flows"]
    assert response.json()["findings"]
    get_settings.cache_clear()


def test_upload_pfsense_xml_policy() -> None:
    get_settings.cache_clear()
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/policy/pfsense/xml",
        json={
            "filename": "manual.xml",
            "content": open("tests/pf_config.xml").read(),
        },
    )

    assert response.status_code == 200
    assert response.json()["source"]["name"] == "manual.xml"
    assert response.json()["findings"]
    assert response.json()["flows"]


def test_upload_iptables_local_policy() -> None:
    get_settings.cache_clear()
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/policy/iptables/local",
        json={
            "filename": "iptables-save.fixture",
            "iptables_save": open("tests/iptables-save.fixture").read(),
            "ip_route": open("tests/ip-route.fixture").read(),
            "ip_rule": open("tests/ip-rule.fixture").read(),
            "ip_addr": open("tests/ip-addr.fixture").read(),
        },
    )

    assert response.status_code == 200
    assert response.json()["source"]["backend"] == "iptables"
    assert response.json()["firewall_rules"]
    assert response.json()["nat_rules"]
    assert response.json()["routes"]
    assert response.json()["interfaces"]


def test_pfsense_api_collector_is_explicitly_not_implemented() -> None:
    get_settings.cache_clear()
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/policy/pfsense/api",
        json={"host": "192.168.64.2", "username": "admin", "api_token": "secret"},
    )

    assert response.status_code == 501


def test_iptables_ssh_policy(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_collect(host: str, username: str, *, port: int = 22):  # type: ignore[no-untyped-def]
        assert host == "192.168.64.2"
        assert username == "root"
        assert port == 22
        return parse_iptables_bundle_text(
            open("tests/iptables-save.fixture").read(),
            name="root@192.168.64.2:iptables-save",
            route_content=open("tests/ip-route.fixture").read(),
            rule_content=open("tests/ip-rule.fixture").read(),
            interface_content=open("tests/ip-addr.fixture").read(),
        )

    monkeypatch.setattr("network_viz.api.main.collect_iptables_over_ssh", fake_collect)
    get_settings.cache_clear()
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/policy/iptables/ssh",
        json={"host": "192.168.64.2", "username": "root", "port": 22},
    )

    assert response.status_code == 200
    assert response.json()["source"]["name"] == "root@192.168.64.2:iptables-save"
    assert response.json()["firewall_rules"]
    assert response.json()["nat_rules"]


def test_iptables_ssh_rejects_password_auth() -> None:
    get_settings.cache_clear()
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/policy/iptables/ssh",
        json={"host": "192.168.64.2", "username": "root", "password": "secret"},
    )

    assert response.status_code == 400
    assert "Password SSH is not supported" in response.json()["detail"]
