# SPDX-License-Identifier: Apache-2.0
"""Bounded continuous cluster watch with a sanitized JSON telemetry feed."""

import argparse
import json
import math
from pathlib import Path
import time

from cluster_diff_engine import compute_catalog_diff, summarize_live_cluster_health
from live_advisor import answer_operational_question
from live_currencies import build_enriched_live_currencies
from live_poller import ContinuousClusterPoller, _export
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


SCHEMA_VERSION = "1.0-continuous-watch"
DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")


def build_live_watch_status_card(catalog=None) -> dict:
    """Summarize a supplied snapshot without polling or mutating its contents.

    None reads the bundled snapshot; strings and Paths load JSON catalogs.
    Missing nodes, unready nodes, failed/pending/unknown pods, degraded
    deployments or node hotspots produce DEGRADED. Completed pods and scaled
    zero deployments are healthy. Source/example describe provenance only.
    Invalid input raises a fixed ValueError without raw telemetry or paths.
    """
    try:
        if catalog is None:
            catalog = DEFAULT_CATALOG_PATH
        if isinstance(catalog, (str, Path)):
            catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
        health = summarize_live_cluster_health(catalog)
        nodes = health["node_counts"]
        pods = health["pod_counts"]
        deployments = health["deployment_counts"]
        hotspots = len(health["node_hotspots"])
        degraded = (not nodes["total"] or nodes["not_ready"]
                    or pods["failed"] or pods["pending"] or pods["other"]
                    or deployments["degraded"] or hotspots)
        result = sanitize({
            "source": health["source"], "example": health["example"],
            "status_badge": "DEGRADED" if degraded else "HEALTHY",
            "node_counts": nodes, "pod_counts": pods,
            "deployment_counts": deployments, "hotspots_count": hotspots,
            "notice": "Status reflects the supplied snapshot without background polling.",
        })
        json.dumps(result, allow_nan=False)
        return result
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ValueError("Unable to load valid cluster catalog") from None


def run_continuous_watch_cycle(iterations=1, interval_seconds=5,
                               harvest_live=False, output_path=None,
                               questions=None):
    """Return the latest completed cycle, optionally exporting after each poll.

    Iterations must be a positive integer; intervals follow the poller's minimum
    of five finite seconds. Sleep only between polls. No live collection occurs
    unless explicitly enabled. Questions is a list/tuple of strings (default:
    none); answers retain their order and the advisor's airlock decisions.
    The first cycle has no preceding snapshot, so latest_diff is None.
    Errors propagate to callers; each export atomically replaces the last feed.
    """
    if type(iterations) is not int or iterations < 1:
        raise ValueError("iterations must be a positive integer")
    if (type(interval_seconds) not in (int, float)
            or not math.isfinite(interval_seconds) or interval_seconds < 5):
        raise ValueError("interval_seconds must be finite and at least 5")
    if questions is None:
        questions = ()
    if (not isinstance(questions, (list, tuple))
            or any(not isinstance(question, str) for question in questions)):
        raise ValueError("questions must be a list or tuple of strings")
    questions = tuple(questions)
    poller = ContinuousClusterPoller(interval_seconds=interval_seconds,
                                     harvest_live=harvest_live)
    previous = None
    for index in range(iterations):
        catalog = sanitize(poller.poll_once())
        result = sanitize({
            "schema_version": SCHEMA_VERSION,
            "iterations_completed": index + 1,
            "latest_health": summarize_live_cluster_health(catalog),
            "latest_diff": (compute_catalog_diff(previous, catalog)
                            if previous is not None else None),
            "latest_currencies": build_enriched_live_currencies(catalog),
            "grounded_answers": [answer_operational_question(question, catalog=catalog)
                                 for question in questions],
            "opsec_clean": True,
        })
        # Check serialization before publishing a completed cycle.
        json.dumps(result, allow_nan=False)
        if output_path is not None:
            _export(result, output_path)
        previous = catalog
        if index + 1 < iterations:
            time.sleep(interval_seconds)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harvest-live", action="store_true")
    parser.add_argument("--iterations", type=int, default=1, metavar="N")
    parser.add_argument("--interval", type=float, default=5, metavar="SECONDS")
    parser.add_argument("--output", type=Path, metavar="FILE")
    parser.add_argument("--json", action="store_true",
                        help="Print the latest completed cycle as sanitized JSON")
    args = parser.parse_args(argv)
    if args.iterations < 1:
        parser.error("iterations must be at least 1")
    if not math.isfinite(args.interval) or args.interval < 5:
        parser.error("interval must be finite and at least 5 seconds")
    try:
        result = run_continuous_watch_cycle(
            iterations=args.iterations, interval_seconds=args.interval,
            harvest_live=args.harvest_live, output_path=args.output)
        if args.json:
            print(json.dumps(result, indent=2, allow_nan=False))
        else:
            print(f"Watch cycles completed: {result['iterations_completed']}; "
                  f"source: {result['latest_health']['source']}; "
                  f"opsec_clean={result['opsec_clean']}")
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        # Paths, catalog content and exception messages may contain telemetry.
        print("continuous_watch_unavailable")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
