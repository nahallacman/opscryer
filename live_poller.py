# SPDX-License-Identifier: Apache-2.0
"""Continuous, explicitly opt-in live collection with a sanitized snapshot cache."""

import argparse
from copy import deepcopy
import json
import math
import os
from pathlib import Path
import tempfile
import time

from cluster_harvester import (
    build_live_cluster_spatial_catalog,
    harvest_live_k8s_cluster,
)
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")
_FAILURE_CODES = ("kubectl_unavailable", "inventory_unavailable")


def _export(catalog, path):
    """Replace an export only after its complete sanitized JSON is written."""
    encoded = json.dumps(sanitize(catalog), indent=2, allow_nan=False) + "\n"
    target = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n", dir=target.parent,
                prefix=".live-poller-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(encoded)
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class ContinuousClusterPoller:
    """Poll on demand; construction never collects data or starts a thread.

    ``poll_once`` returns a fresh catalog with ``stale``, ``consecutive_failures``
    and ``last_error`` metadata. ``status`` returns independent polling metadata.
    A fallback is stale only when replacing a previously observed live catalog.
    Successful polls clear failure metadata. The CLI supplies the timed loop.
    """

    def __init__(self, interval_seconds=30, harvest_live=False, timeout=15,
                 export_path=None):
        if (type(interval_seconds) not in (int, float)
                or not math.isfinite(interval_seconds) or interval_seconds < 5):
            raise ValueError("interval_seconds must be finite and at least 5")
        if (type(timeout) not in (int, float)
                or not math.isfinite(timeout) or timeout <= 0):
            raise ValueError("timeout must be positive finite seconds")
        self.interval_seconds = interval_seconds
        self.harvest_live = harvest_live
        self.timeout = timeout
        self.export_path = export_path
        self._catalog = None
        self._last_live = None
        self._poll_count = 0
        self._stale = False
        self._consecutive_failures = 0
        self._last_error = None

    def poll_once(self):
        """Read one snapshot; kubectl runs only when harvest_live is enabled."""
        if self.harvest_live:
            snapshot = harvest_live_k8s_cluster(timeout=self.timeout)
            catalog = build_live_cluster_spatial_catalog(snapshot)
        elif DEFAULT_CATALOG_PATH.is_file():
            catalog = json.loads(DEFAULT_CATALOG_PATH.read_text(encoding="utf-8"))
        else:
            catalog = build_live_cluster_spatial_catalog()
        catalog = sanitize(catalog)
        self._stale = False
        self._last_error = None
        if self.harvest_live and catalog.get("source") == "offline_fallback":
            self._consecutive_failures += 1
            errors = catalog.get("errors", [])
            self._last_error = next((code for code in _FAILURE_CODES if code in errors),
                                    "inventory_unavailable")
            if self._last_live is not None:
                catalog = deepcopy(self._last_live)
                self._stale = True
        else:
            self._consecutive_failures = 0
        if catalog.get("source") == "live_kubectl" and not self._stale:
            self._last_live = deepcopy(catalog)
        catalog.update(stale=self._stale,
                       consecutive_failures=self._consecutive_failures,
                       last_error=self._last_error)
        self._catalog = catalog
        self._poll_count += 1
        if self.export_path is not None:
            _export(catalog, self.export_path)
        return deepcopy(catalog)

    def status(self):
        """Return current metadata without polling or exposing cached containers."""
        return {"interval_seconds": self.interval_seconds,
                "harvest_live": self.harvest_live, "timeout": self.timeout,
                "poll_count": self._poll_count,
                "source": self._catalog.get("source") if self._catalog else None,
                "example": self._catalog.get("example") if self._catalog else None,
                "stale": self._stale,
                "consecutive_failures": self._consecutive_failures,
                "last_error": self._last_error}


def poll_live_cluster_once(export_path=None, harvest_live=False, timeout=15):
    """Return/export one sanitized catalog using a new poller."""
    return ContinuousClusterPoller(harvest_live=harvest_live, timeout=timeout,
                                   export_path=export_path).poll_once()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harvest-live", action="store_true")
    parser.add_argument("--interval", type=float, default=30, metavar="SECONDS")
    parser.add_argument("--max-polls", type=int, metavar="N",
                        help="Stop after N polls; default: run until interrupted")
    parser.add_argument("--export", type=Path, metavar="FILE")
    parser.add_argument("--json", action="store_true",
                        help="Print one sanitized JSON catalog per line")
    args = parser.parse_args(argv)
    if args.max_polls is not None and args.max_polls < 1:
        parser.error("max-polls must be at least 1")
    try:
        poller = ContinuousClusterPoller(args.interval, args.harvest_live,
                                         export_path=args.export)
    except ValueError:
        parser.error("interval must be finite and at least 5 seconds")
    try:
        while True:
            catalog = poller.poll_once()
            if args.json:
                print(json.dumps(catalog, allow_nan=False), flush=True)
            else:
                print(f"Cluster catalog: {catalog['source']}; "
                      f"stale={catalog['stale']}; "
                      f"consecutive_failures={catalog['consecutive_failures']}",
                      flush=True)
            if (args.max_polls is not None
                    and poller.status()["poll_count"] >= args.max_polls):
                break
            time.sleep(poller.interval_seconds)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, TypeError):
        # File paths, JSON parsing errors and exception messages may be sensitive.
        print("cluster_poll_unavailable")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
