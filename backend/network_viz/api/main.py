from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from network_viz import __version__
from network_viz.analysis.flow_engine import analyze_flows
from network_viz.analysis.risk_rules import analyze_risks
from network_viz.collectors.pfsense_xml import parse_pfsense_xml
from network_viz.config import get_settings
from network_viz.normalizer.model import NormalizedConfig


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
