# SPDX-License-Identifier: Apache-2.0
"""Enrich RTS currencies from a catalog snapshot without network calls."""

import argparse
from copy import deepcopy
import json
import math
from pathlib import Path
import re

from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")
_CURRENCIES = (
    ("nodes", "Nodes", "supply_cap"),
    ("cpu_load", "CPU Load", "currency_rate"),
    ("ram_load", "RAM Load", "currency_rate"),
    ("network_load", "Network Routes", "currency_rate"),
    ("build_supply", "Build Supply", "food_supply"),
    ("renovate_failures", "Renovate", "upkeep_alert"),
    ("open_mrs", "Open MRs", "production_queue"),
)


def _kind(node):
    return node.get("resource_kind", node.get("resource", {}).get("kind"))


def _runner(node):
    if _kind(node) not in {"Pod", "Deployment"}:
        return False
    meta = node.get("resource", {}).get("metadata", {})
    # Match names and label values, not unrelated annotations or pod logs.
    values = [node.get("label", ""), meta.get("name", "")]
    values.extend(meta.get("labels", {}).values())
    return any(re.search(r"gitlab[-_ .]*runner", str(value), re.IGNORECASE)
               for value in values)


def _count(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and value >= 0)


def build_enriched_live_currencies(catalog=None, extra_signals=None):
    """Return seven fresh currency dicts from a graph dict or JSON file path.

    Node/CPU/RAM currencies are retained, with dangling dropdown links removed.
    Build supply counts discovered GitLab runner Pods and Deployments, not CI
    slots. Network load counts Ingress and Service resources, not bandwidth.
    Derived entries inherit catalog source/example provenance.

    Optional extra_signals maps network_load, renovate_failures and open_mrs to
    a nonnegative finite number, or a dict with count (or display_value), optional
    available, source, example, and dropdown_items. Counts of zero are available;
    missing signals are unavailable. Unknown targets are discarded. All supplied
    text is sanitized and inputs are never mutated.
    """
    if catalog is None:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
    if not isinstance(catalog, dict) or not isinstance(catalog.get("nodes"), list):
        raise ValueError("catalog must contain a nodes array")
    catalog = sanitize(catalog)
    nodes = catalog["nodes"]
    if any(not isinstance(n, dict) or not isinstance(n.get("id"), str)
           or not n["id"] for n in nodes):
        raise ValueError("catalog nodes require nonempty string ids")
    ids = {n["id"] for n in nodes}
    if len(ids) != len(nodes):
        raise ValueError("catalog node ids must be unique after sanitization")
    if extra_signals is not None and not isinstance(extra_signals, dict):
        raise ValueError("extra_signals must be an object")
    signals = sanitize(extra_signals or {})
    original = {c["currency_id"]: c for c in catalog.get("rts_currencies", [])}

    def valid_items(items):
        return [deepcopy(item) for item in items if isinstance(item, dict)
                and isinstance(item.get("target_id"), str) and item["target_id"] in ids]

    result = []
    for key, label, supply in _CURRENCIES:
        currency = {"currency_id": key, "label": label, "icon": "*",
                    "display_value": "Unavailable", "supply_kind": supply,
                    "hex_color": "#94A3B8", "available": False,
                    "dropdown_items": [], "source": catalog.get("source", "provided_catalog"),
                    "example": catalog.get("example", False)}
        if key in {"nodes", "cpu_load", "ram_load"}:
            if key in original:
                currency = deepcopy(original[key])
                currency["dropdown_items"] = valid_items(currency.get("dropdown_items", []))
            result.append(currency)
            continue

        contributors = []
        if key == "build_supply":
            contributors = [n for n in nodes if _runner(n)]
            if contributors:
                pods = sum(_kind(n) == "Pod" for n in contributors)
                currency["display_value"] = (
                    f"{pods} runner pods / {len(contributors) - pods} deployments")
        elif key == "network_load":
            contributors = [n for n in nodes if _kind(n) in {"Ingress", "Service"}]
            if contributors:
                currency["display_value"] = f"{len(contributors)} routes (Ingress/Service)"
        if contributors:
            currency["available"] = True
            currency["dropdown_items"] = [
                {"label": n.get("label", n["id"]), "value": _kind(n), "target_id": n["id"]}
                for n in contributors]

        if key in signals and key != "build_supply":
            signal = signals[key]
            if _count(signal):
                signal = {"count": signal}
            if not isinstance(signal, dict):
                raise ValueError("signal must be a count or object")
            count = signal.get("count")
            display = signal.get("display_value")
            if "count" in signal and not _count(count):
                raise ValueError("signal count must be finite and nonnegative")
            if "available" in signal and not isinstance(signal["available"], bool):
                raise ValueError("signal available must be boolean")
            available = signal.get("available", True)
            if available and count is None and not (isinstance(display, str) and display.strip()):
                raise ValueError("available signal requires count or display_value")
            currency.update(available=available,
                            display_value=(str(count) if count is not None else display)
                            if available else "Unavailable",
                            dropdown_items=valid_items(signal.get("dropdown_items", [])),
                            source=signal.get("source", "extra_signals"),
                            example=signal.get("example", catalog.get("example", False)))
        currency["hex_color"] = "#22C55E" if currency["available"] else "#94A3B8"
        result.append(currency)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--json", action="store_true", help="Print the seven currencies as JSON")
    args = parser.parse_args(argv)
    try:
        result = build_enriched_live_currencies(args.catalog)
        encoded = json.dumps(result, indent=2, allow_nan=False)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        parser.error("unable to enrich a valid cluster catalog")
    if args.json:
        print(encoded)
    else:
        for currency in result:
            print(f"{currency['label']}: {currency['display_value']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
