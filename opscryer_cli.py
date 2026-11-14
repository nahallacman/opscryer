# SPDX-License-Identifier: Apache-2.0
"""Unified command-line reports for the OpsCryer suite."""

import argparse
import json
import sys

import environment_adapters
import live_metrics_poller
import opscryer
import platform_compat
import route_registry
import ticket_chat_portal
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


INVALID_REQUEST = "Invalid opscryer CLI request"


class _Parser(argparse.ArgumentParser):
    """Keep argument errors independent of user-supplied values."""

    def error(self, message):
        self.exit(2, INVALID_REQUEST + "\n")


def _nonempty(value):
    if not value.strip():
        raise argparse.ArgumentTypeError(INVALID_REQUEST)
    return value


def _build_parser():
    parser = _Parser(prog="opscryer_cli.py", description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    descriptions = {
        "doctor": "Report runtime capabilities and package organization",
        "metrics": "Report cluster metrics (live collection requires --live)",
        "routes": "List registered HTML portals and API endpoints",
        "adapters": "Report environment adapter compatibility",
        "ask": "Ask the ticket concierge",
    }
    for command, description in descriptions.items():
        child = commands.add_parser(command, help=description,
                                    description=description, allow_abbrev=False)
        child.add_argument("--json", action="store_true", help="print JSON")
        if command == "metrics":
            child.add_argument("--live", action="store_true", help="allow kubectl collection")
        elif command == "adapters":
            child.add_argument("--adapter", choices=tuple(environment_adapters.ADAPTER_PROFILES))
        elif command == "ask":
            child.add_argument("--question", required=True, type=_nonempty)
            child.add_argument("--persona", default="household_user",
                               choices=tuple(ticket_chat_portal.PERSONAS))
    return parser


def _report(args):
    if args.command == "doctor":
        return {
            "runtime_capabilities": platform_compat.detect_runtime_capabilities(),
            "package_architecture": opscryer.get_package_architecture_map(),
            "route_registry": route_registry.build_route_registry_summary(),
        }
    if args.command == "metrics":
        return live_metrics_poller.poll_live_cluster_metrics(allow_kubectl=args.live)
    if args.command == "routes":
        # The summary contains counts; route metadata lives in the same registry.
        return {
            **route_registry.build_route_registry_summary(),
            "html_portals": [dict(route) for route in route_registry.HTML_PORTAL_ROUTES],
            "api_endpoints": [
                {"path": path, **metadata,
                 "allowed_params": sorted(metadata["allowed_params"])}
                for path, metadata in route_registry.API_V1_ROUTES.items()
            ],
        }
    if args.command == "adapters":
        return environment_adapters.build_adapter_compatibility_catalog(args.adapter)
    return ticket_chat_portal.ask_concierge_chat(args.question, persona=args.persona)


def _text_lines(value, indent=0):
    """Render nested reports consistently without discarding subsystem details."""
    prefix = " " * indent
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list, tuple)):
                yield f"{prefix}{key}:"
                yield from _text_lines(item, indent + 2)
            else:
                yield f"{prefix}{key}: {item}"
    elif isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, (dict, list, tuple)):
                yield prefix + "-"
                yield from _text_lines(item, indent + 2)
            else:
                yield f"{prefix}- {item}"
    else:
        yield prefix + str(value)


def main(argv=None) -> int:
    """Print a report; argparse exits with a fixed message for invalid requests."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report = sanitize(_report(args))
    except ValueError:
        parser.error(INVALID_REQUEST)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"OpsCryer {args.command}")
        print("\n".join(_text_lines(report)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
