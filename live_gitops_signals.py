# SPDX-License-Identifier: Apache-2.0
"""Derive GitOps and CI evidence from a sanitized catalog, without network calls."""

import argparse
import json
import math
from pathlib import Path
import re

import live_currencies
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")
_NAMESPACES = {"gitlab", "argocd", "devops-tools", "monitoring"}


def _load(catalog):
    if catalog is None:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
    # Reuse the currency builder's catalog validation and reference checks.
    live_currencies.build_enriched_live_currencies(catalog)
    return sanitize(catalog)


def _kind(node):
    return node.get("resource_kind", node.get("resource", {}).get("kind"))


def _matches(node, pattern):
    meta = node.get("resource", {}).get("metadata", {})
    values = [node.get("label", ""), meta.get("name", "")]
    values.extend(meta.get("labels", {}).values())
    return any(re.search(pattern, str(value), re.IGNORECASE) for value in values)


def _derive(catalog):
    nodes = catalog["nodes"]
    hardware = [n for n in nodes if _kind(n) == "Node"]
    scoped = [n for n in nodes if n.get("namespace", n.get("resource", {}).get(
        "metadata", {}).get("namespace")) in _NAMESPACES]
    workloads = [n for n in scoped if _kind(n) in {
        "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}]
    signals = {}

    def signal(key, contributors, display, evidence, available=True, count=None):
        value = {"display_value": display if available else "Unavailable",
                 "available": available,
                 "source": catalog.get("source", "provided_catalog"),
                 "example": catalog.get("example", False),
                 "evidence": evidence,
                 "dropdown_items": [
                     {"label": n.get("label", n["id"]), "value": evidence,
                      "target_id": n["id"]} for n in contributors]}
        if count is not None:
            value["count"] = count
        signals[key] = value

    ready = sum(any(c.get("type") == "Ready" and c.get("status") == "True"
                    for c in n.get("resource", {}).get("status", {}).get("conditions", []))
                for n in hardware)
    signal("nodes", hardware, f"{ready}/{len(hardware)} Ready",
           "Kubernetes Node status.conditions Ready", bool(hardware))
    for key, field in (("cpu_load", "cpu_percent"), ("ram_load", "ram_percent")):
        measured = []
        for node in hardware:
            value = node.get("metrics", {}).get(field)
            if (isinstance(value, (int, float)) and not isinstance(value, bool)
                    and math.isfinite(value) and 0 <= value <= 100):
                measured.append(node)
        average = sum(n["metrics"][field] for n in measured) / len(measured) if measured else 0
        signal(key, measured, f"{average:.1f}% Avg ({len(measured)}/{len(hardware)} nodes)",
               f"Catalog Node metrics.{field}; missing nodes excluded", bool(measured))
        for item, node in zip(signals[key]["dropdown_items"], measured):
            item["value"] = f"{node['metrics'][field]}%"

    routes = [n for n in scoped if _kind(n) in {"Service", "Ingress"}]
    signal("network_load", routes, f"{len(routes)} routes (Ingress/Service)",
           "GitOps/CI/monitoring Service and Ingress inventory; not bandwidth",
           bool(routes))
    runners = [n for n in workloads if _kind(n) in {"Pod", "Deployment"}
               and _matches(n, r"gitlab[-_ .]*runner")]
    pods = sum(_kind(n) == "Pod" for n in runners)
    signal("build_supply", runners,
           f"{pods} runner pods / {len(runners) - pods} deployments",
           "GitLab runner inventory; not CI slots or job throughput", bool(runners))

    # An exporter is evidence of monitoring infrastructure, not a run result.
    renovate = [n for n in workloads if _matches(n, r"\brenovate\b")]
    runs = [n for n in renovate if _kind(n) in {"Pod", "Job"}
            and not _matches(n, r"renovate[-_ .]*exporter")]
    observed = [n for n in runs if (
        _kind(n) == "Pod" and n.get("resource", {}).get("status", {}).get("phase")
        in {"Failed", "Succeeded"}) or (
        _kind(n) == "Job" and any(c.get("type") in {"Failed", "Complete"}
                                 and c.get("status") == "True" for c in
                                 n.get("resource", {}).get("status", {}).get("conditions", [])))]
    # Count terminal Pods when present; use Jobs only without an observed child
    # Pod so a Job and its Pod cannot count the same run twice.
    owners = {owner.get("uid") for n in observed if _kind(n) == "Pod"
              for owner in n.get("resource", {}).get("metadata", {}).get("ownerReferences", [])
              if owner.get("uid")}
    observed = [n for n in observed if _kind(n) != "Job" or
                n.get("resource", {}).get("metadata", {}).get("uid") not in owners]
    failed = [n for n in observed if n.get("resource", {}).get("status", {}).get("phase")
              == "Failed" or any(c.get("type") == "Failed" and c.get("status") == "True"
                                for c in n.get("resource", {}).get("status", {}).get("conditions", []))]
    signal("renovate_failures", observed or renovate,
           f"{len(failed)} failed / {len(observed)} terminal Renovate workloads",
           "Terminal Renovate Pod/Job status; snapshot only" if observed else
           "Renovate run results not collected; exporter presence is not a failure count",
           bool(observed))
    gitlab = [n for n in workloads if n.get("namespace", n.get("resource", {}).get(
        "metadata", {}).get("namespace")) == "gitlab"]
    signal("open_mrs", gitlab, "Unavailable",
           "GitLab workload inventory only; merge request totals not collected", False)
    return signals


def derive_live_gitops_and_ci_signals(catalog=None):
    """Return seven provenance-tagged signal dicts keyed by RTS currency ID.

    Accept a catalog dict or JSON path. Node readiness and CPU/RAM use Node
    observations. Scoped network and runner counts are inventory proxies.
    Renovate counts cover terminal workloads in this snapshot, not historical
    failures. MR totals remain unavailable without GitLab API observations.
    Every evidence link targets a sanitized catalog node. Inputs are untouched.
    """
    return _derive(_load(catalog))


def enrich_all_seven_live_currencies(catalog=None):
    """Feed snapshot signals into the existing builder and enrich all seven."""
    snapshot = _load(catalog)
    signals = _derive(snapshot)
    result = live_currencies.build_enriched_live_currencies(snapshot, extra_signals=signals)
    # The existing builder preserves Node currencies and owns runner derivation.
    # Apply these grounded observations to those entries too, without changing
    # its public preservation behavior for other callers.
    for currency in result:
        currency.update(signals[currency["currency_id"]])
        currency["hex_color"] = "#22C55E" if currency["available"] else "#94A3B8"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--json", action="store_true", help="Print all seven currencies as JSON")
    args = parser.parse_args(argv)
    try:
        result = enrich_all_seven_live_currencies(args.catalog)
        encoded = json.dumps(result, indent=2, allow_nan=False)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        parser.error("unable to derive signals from a valid cluster catalog")
    if args.json:
        print(encoded)
    else:
        for currency in result:
            print(f"{currency['label']}: {currency['display_value']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
