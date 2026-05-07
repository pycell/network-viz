from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from network_viz import __version__
from network_viz.analysis.flow_engine import analyze_flows
from network_viz.analysis.risk_rules import analyze_risks
from network_viz.collectors.iptables import parse_iptables_bundle_text
from network_viz.collectors.pfsense_xml import parse_pfsense_xml, parse_pfsense_xml_text
from network_viz.config import get_settings
from network_viz.normalizer.model import NormalizedConfig


class PfsenseXmlUpload(BaseModel):
    filename: str = "uploaded-pfsense.xml"
    content: str


class IptablesUpload(BaseModel):
    filename: str = "uploaded-iptables-save"
    iptables_save: str
    ip_route: str | None = None
    ip_rule: str | None = None
    ip_addr: str | None = None


class CredentialedSourceRequest(BaseModel):
    host: str
    username: str
    password: str | None = None
    api_token: str | None = None


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version=__version__)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__, "environment": settings.environment}

    @app.get("/api/v1/summary")
    async def summary() -> dict[str, object]:
        config = _load_config_from_settings()
        if config is not None:
            return {
                "config_source": config.source.name,
                "interfaces": len(config.interfaces),
                "firewall_rules": len(config.firewall_rules),
                "nat_rules": len(config.nat_rules),
                "flows": len(config.flows),
                "findings": len(config.findings),
                "message": "Loaded pfSense XML from configured local path.",
            }

        return {
            "config_source": None,
            "interfaces": 0,
            "firewall_rules": 0,
            "nat_rules": 0,
            "flows": 0,
            "findings": 0,
            "message": "Set NETWORK_VIZ_PFSENSE_XML_PATH to load a local pfSense XML export.",
        }

    @app.get("/api/v1/policy")
    async def policy() -> dict[str, object]:
        config = _load_config_from_settings()
        if config is None:
            return {
                "source": None,
                "interfaces": [],
                "aliases": [],
                "firewall_rules": [],
                "nat_rules": [],
                "flows": [],
                "findings": [],
                "message": "Set NETWORK_VIZ_PFSENSE_XML_PATH to load a local pfSense XML export.",
            }
        return config.model_dump(mode="json")

    @app.post("/api/v1/policy/pfsense/xml")
    async def upload_pfsense_xml(payload: PfsenseXmlUpload) -> dict[str, object]:
        try:
            config = analyze_flows(
                analyze_risks(parse_pfsense_xml_text(payload.content, payload.filename))
            )
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Unable to parse pfSense XML: {exc}",
            ) from exc
        return config.model_dump(mode="json")

    @app.post("/api/v1/policy/iptables/local")
    async def upload_iptables_local(payload: IptablesUpload) -> dict[str, object]:
        try:
            config = parse_iptables_bundle_text(
                payload.iptables_save,
                name=payload.filename,
                route_content=payload.ip_route,
                rule_content=payload.ip_rule,
                interface_content=payload.ip_addr,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Unable to parse iptables input: {exc}",
            ) from exc
        return config.model_dump(mode="json")

    @app.post("/api/v1/policy/pfsense/api")
    async def pfsense_api_source(_payload: CredentialedSourceRequest) -> dict[str, object]:
        raise HTTPException(
            status_code=501,
            detail=(
                "pfSense API collection is a planned credentialed collector. "
                "Use pfSense XML upload until the read-only API client is implemented."
            ),
        )

    @app.post("/api/v1/policy/iptables/ssh")
    async def iptables_ssh_source(_payload: CredentialedSourceRequest) -> dict[str, object]:
        raise HTTPException(
            status_code=501,
            detail=(
                "Remote SSH collection is a planned credentialed collector. "
                "Upload local command outputs from a VPS until SSH collection is implemented."
            ),
        )

    static_dir = Path(__file__).resolve().parents[3] / "frontend" / "dist"
    if static_dir.exists():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="frontend")

    return app


app = create_app()


def _load_config_from_settings() -> NormalizedConfig | None:
    settings = get_settings()
    path = settings.pfsense_xml_path
    if path is None:
        return None
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"pfSense XML file not found: {path}")
    return analyze_flows(analyze_risks(parse_pfsense_xml(path)))
