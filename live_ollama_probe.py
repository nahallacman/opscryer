# SPDX-License-Identifier: Apache-2.0
"""Offline-first Ollama inventory and advisory GPU/cluster correlation.

Tags establish installed models, not loaded models, free VRAM or inference
health. Cluster readiness comes from a snapshot; placement remains unverified.
"""

import argparse
import json
import math
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from gpu_and_household_triage import allocate_gpu_workload_profile
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")
_MAX_BODY = 1_048_576
_WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}


def _models(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
        raise ValueError("Invalid model inventory")
    models = []
    for item in payload["models"]:
        if not isinstance(item, dict):
            raise ValueError("Invalid model entry")
        name = item.get("name", item.get("model"))
        size = item.get("size")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Invalid model name")
        if size is not None and (type(size) is not int or size < 0):
            raise ValueError("Invalid model size")
        # Allowlist fields; arbitrary provider metadata never leaves this boundary.
        models.append({"name": sanitize(name), "size": size})
    return sorted(models, key=lambda model: (model["name"], model["size"] or 0))


def _offline(status="offline", reason=None):
    return {"schema_version": 1, "source": "offline_fixture", "status": status,
            "live_http": False, "available": False, "example": True,
            "reason": reason, "models": _models({"models": [
                {"name": "qwen2.5-coder:7b", "size": 4_700_000_000},
                {"name": "llama3.1:8b", "size": 4_900_000_000},
                {"name": "qwen2.5:14b", "size": 9_000_000_000}]})}


def probe_local_ollama_models(ollama_url="http://localhost:11434", timeout=3,
                             live_http=False):
    """Return fresh deterministic fixtures offline or sanitized GET /api/tags.

    Live failures return explicitly marked fixtures, with fixed reason codes.
    No endpoint, raw exception, digest or arbitrary metadata is returned.
    """
    if not live_http:
        return _offline()
    try:
        parts = urlsplit(ollama_url)
        if (parts.scheme not in {"http", "https"} or not parts.hostname
                or parts.username is not None or parts.password is not None
                or parts.query or parts.fragment
                or type(timeout) not in (int, float)
                or not math.isfinite(timeout) or timeout <= 0):
            return {**_offline("fallback", "invalid_configuration"), "live_http": True}
        request = Request(ollama_url.rstrip("/") + "/api/tags", method="GET",
                          headers={"Accept": "application/json"})
        with urlopen(request, timeout=timeout) as response:
            body = response.read(_MAX_BODY + 1)
        if len(body) > _MAX_BODY:
            raise ValueError("Inventory too large")
        models = _models(json.loads(body))
        return {"schema_version": 1, "source": "ollama_api_tags", "status": "ok",
                "live_http": True, "available": True, "example": False,
                "reason": None, "models": models}
    except Exception:
        # Transport and malformed provider output share a non-disclosing boundary.
        return {**_offline("fallback", "probe_unavailable"), "live_http": True}


def _load_catalog(catalog):
    try:
        if catalog is None:
            catalog = DEFAULT_CATALOG_PATH
        if isinstance(catalog, (str, Path)):
            catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
        if not isinstance(catalog, dict) or not isinstance(catalog.get("nodes"), list):
            raise ValueError
        if any(not isinstance(node, dict) for node in catalog["nodes"]):
            raise ValueError
        return catalog
    except Exception:
        raise ValueError("Unable to load cluster catalog") from None


def _ready(kind, resource):
    status = resource.get("status", {})
    conditions = status.get("conditions", [])
    if kind == "Pod":
        return any(c.get("type") == "Ready" and c.get("status") == "True"
                   for c in conditions)
    if kind in {"Deployment", "StatefulSet"}:
        desired = resource.get("spec", {}).get("replicas", 1)
        ready = status.get("readyReplicas", 0)
        return (type(desired) is int and type(ready) is int
                and desired > 0 and ready >= desired)
    if kind == "DaemonSet":
        desired, ready = status.get("desiredNumberScheduled", 0), status.get("numberReady", 0)
        return (type(desired) is int and type(ready) is int
                and desired > 0 and ready >= desired)
    return None


def correlate_gpu_models_with_cluster(catalog=None, ollama_probe=None):
    """Map installed model size estimates to planned GPUs and AI workloads.

    Model files are a lower bound on memory, with unknown runtime overhead.
    Workloads are namespace candidates, not evidence of model/device bindings.
    Accept a catalog dict or path; default to the bundled sanitized snapshot.
    """
    catalog = _load_catalog(catalog)
    probe = probe_local_ollama_models() if ollama_probe is None else ollama_probe
    models = _models(probe)
    profile = allocate_gpu_workload_profile()
    workloads = []
    try:
        for node in catalog["nodes"]:
            resource = node.get("resource", {})
            meta = resource.get("metadata", {})
            namespace = node.get("namespace", meta.get("namespace"))
            kind = node.get("resource_kind", resource.get("kind"))
            if namespace not in {"ai-infra", "ai-sandbox"} or kind not in _WORKLOADS:
                continue
            workloads.append({"id": node.get("id"), "name": meta.get("name", node.get("label")),
                              "namespace": namespace, "kind": kind,
                              "snapshot_ready": _ready(kind, resource)})
    except (AttributeError, TypeError):
        raise ValueError("Invalid cluster workload metadata") from None
    workloads.sort(key=lambda workload: str(workload["id"]))
    mappings = []
    for model in models:
        estimates = []
        for gpu in profile["gpus"]:
            estimates.append({"gpu_id": gpu["id"],
                              "ai_assigned": gpu["workload"] == "ai_swarm",
                              "file_size_within_nominal_vram": (
                                  model["size"] <= gpu["vram_gb"] * 1024 ** 3
                                  if model["size"] is not None else None)})
        mappings.append({"model": model["name"], "gpu_estimates": estimates,
                         "candidate_workload_ids": [w["id"] for w in workloads],
                         "placement_verified": False})
    return sanitize({"schema_version": 1, "gpu_profile": profile,
                     "inventory_source": ("ollama_api_tags" if probe.get("source") ==
                                          "ollama_api_tags" else "offline_fixture"),
                     "models": models, "workloads": workloads, "model_mappings": mappings,
                     "inference_ready": None,
                     "limitations": ["File sizes exclude runtime memory overhead.",
                                     "GPU capacity is a simulated plan, not free VRAM.",
                                     "Cluster readiness is snapshot evidence; model placement is unverified."]})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-http", action="store_true")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        probe = probe_local_ollama_models(args.ollama_url, live_http=args.live_http)
        report = {"ollama_probe": probe,
                  "correlation": correlate_gpu_models_with_cluster(ollama_probe=probe)}
    except ValueError:
        print(json.dumps({"error": "Unable to build Ollama readiness report"}))
        return 1
    if args.json:
        print(json.dumps(report, indent=2, allow_nan=False))
    else:
        print(f"Ollama inventory: {probe['status']} ({probe['source']}); "
              f"{len(probe['models'])} models")
        print(f"GPU plan: 3 devices; {len(report['correlation']['workloads'])} AI workloads")
        print("Inference readiness and model placement remain unverified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
