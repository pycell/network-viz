import argparse
import json
from pathlib import Path

from network_viz import __version__
from network_viz.analysis.flow_engine import analyze_flows
from network_viz.analysis.risk_rules import analyze_risks
from network_viz.collectors.pfsense_xml import parse_pfsense_xml


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="network-viz")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    parser.add_argument(
        "command",
        nargs="?",
        choices=["summary", "parse-pfsense", "analyze-pfsense"],
        default="summary",
        help="Command to run",
    )
    parser.add_argument("input_path", nargs="?", type=Path, help="Input configuration file")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(__version__)
        return

    if args.command == "parse-pfsense":
        if args.input_path is None:
            parser.error("parse-pfsense requires an input XML file")
        config = parse_pfsense_xml(args.input_path)
        print(json.dumps(config.model_dump(mode="json"), indent=2))
        return

    if args.command == "analyze-pfsense":
        if args.input_path is None:
            parser.error("analyze-pfsense requires an input XML file")
        config = analyze_flows(analyze_risks(parse_pfsense_xml(args.input_path)))
        print(json.dumps(config.model_dump(mode="json"), indent=2))
        return

    print(
        json.dumps(
            {
                "status": "ok",
                "command": args.command,
                "message": "Sprint 0 CLI foundation is ready. Parsers start in Sprint 1.",
            },
            indent=2,
        )
    )
