import argparse
import json

from network_viz import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="network-viz")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    parser.add_argument(
        "command",
        nargs="?",
        choices=["summary"],
        default="summary",
        help="Command to run",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(__version__)
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
