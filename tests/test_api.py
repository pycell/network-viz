from fastapi.testclient import TestClient
from network_viz.api.main import create_app
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
    assert response.json()["findings"] > 0
    get_settings.cache_clear()


def test_policy_with_configured_xml(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("NETWORK_VIZ_PFSENSE_XML_PATH", "tests/pf_config.xml")
    get_settings.cache_clear()
    client = TestClient(create_app())

    response = client.get("/api/v1/policy")

    assert response.status_code == 200
    assert response.json()["source"]["name"] == "pf_config.xml"
    assert response.json()["findings"]
    get_settings.cache_clear()
