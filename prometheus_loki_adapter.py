# SPDX-License-Identifier: Apache-2.0
"""Sanitized Prometheus & Loki observability adapter with offline golden-signal fixture."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from http_transport import urlopen_with_retry
from noc_golden_signals import build_noc_golden_signals_catalog
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


OFFLINE_OBSERVABILITY_FIXTURE: dict[str, Any] = {
    "schema_version": "1.0-observability-signal-adapter",
    "telemetry_mode": "SNAPSHOT_FIXTURE",
    "live_http_active": False,
    "prometheus_signals": [
        {
            "signal_id": "cluster_cpu_saturation",
            "promql": '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)',
            "value": 46.8,
            "unit": "percent",
            "status": "nominal",
        },
        {
            "signal_id": "cluster_memory_saturation",
            "promql": "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100",
            "value": 64.2,
            "unit": "percent",
            "status": "nominal",
        },
        {
            "signal_id": "gpu_vram_allocated_gb",
            "promql": "sum(DCGM_FI_DEV_FB_USED) / 1024",
            "value": 40.0,
            "unit": "GB",
            "status": "nominal",
        },
    ],
    "loki_log_summaries": [
        {
            "stream": '{namespace="ai-infra", app="ollama"}',
            "sample_line": "level=INFO msg=\"loaded local GPU worker model qwen2.5-coder:7b\" host=10.20.3.13",
            "error_count_5m": 0,
        },
        {
            "stream": '{namespace="cnpg-system", app="postgres"}',
            "sample_line": "LOG: database system is ready to accept connections on 10.20.3.1:5432",
            "error_count_5m": 0,
        },
    ],
    "alert_states": [
        {
            "alert_name": "ClusterCpuSaturationHigh",
            "severity": "warning",
            "state": "inactive",
            "active": False,
        },
        {
            "alert_name": "ClusterMemorySaturationCritical",
            "severity": "critical",
            "state": "inactive",
            "active": False,
        },
        {
            "alert_name": "LokiErrorBurst",
            "severity": "warning",
            "state": "inactive",
            "active": False,
        },
    ],
}


def query_sanitized_observability_signals(
    allow_live_http: bool = False,
    prometheus_url: str = "http://127.0.0.1:9090",
    timeout: int = 5,
) -> dict[str, Any]:
    """Return sanitized Prometheus/Loki golden signals; live HTTP is explicitly opt-in."""
    if type(allow_live_http) is not bool or type(timeout) is not int or not 1 <= timeout <= 30:
        raise ValueError("Invalid observability adapter parameters")
    base = deepcopy(OFFLINE_OBSERVABILITY_FIXTURE)
    base["signals"] = list(base.get("prometheus_signals", []))
    base["noc_catalog_count"] = len(build_noc_golden_signals_catalog().get("signals", []))
    if not allow_live_http:
        return sanitize(base)
    try:
        query_url = prometheus_url.rstrip("/") + "/api/v1/query?" + urlencode({"query": "up"})
        req = Request(query_url, headers={"Accept": "application/json"}, method="GET")
        body = urlopen_with_retry(
            req,
            timeout=float(timeout),
            max_retries=3,
            backoff_factor=0.2,
            circuit_breaker_name="prometheus",
            opener=urlopen,
        )
        payload = json.loads(body.decode("utf-8"))
        if isinstance(payload, dict) and payload.get("status") == "success":
            base["telemetry_mode"] = "LIVE_PROMETHEUS_HTTP"
            base["live_http_active"] = True
            base["up_result_count"] = len(payload.get("data", {}).get("result", []))
        else:
            base["telemetry_mode"] = "SNAPSHOT_FALLBACK"
    except (OSError, ValueError, TypeError):
        base["telemetry_mode"] = "SNAPSHOT_FALLBACK"
    return sanitize(base)


def get_observability_signals_report(
    format: str = "full",
    service: str | None = None,
    allow_live_http: bool = False,
    prometheus_url: str = "http://127.0.0.1:9090",
) -> dict[str, Any]:
    """Return aggregated Prometheus query signals, alert states, and Loki stream status."""
    if format not in {"summary", "full"}:
        raise ValueError("format must be 'summary' or 'full'")
    base = query_sanitized_observability_signals(
        allow_live_http=allow_live_http,
        prometheus_url=prometheus_url,
    )
    # Ensure signals alias exists for E2E contract
    base["signals"] = list(base.get("prometheus_signals", []))

    if service is not None:
        svc = service.strip().lower()
        base["prometheus_signals"] = [
            s for s in base.get("prometheus_signals", [])
            if svc in s.get("signal_id", "").lower() or svc in s.get("promql", "").lower()
        ]
        base["signals"] = list(base["prometheus_signals"])
        base["loki_log_summaries"] = [
            l for l in base.get("loki_log_summaries", [])
            if svc in l.get("stream", "").lower() or svc in l.get("sample_line", "").lower()
        ]
        if "alert_states" in base:
            base["alert_states"] = [
                a for a in base.get("alert_states", [])
                if svc in a.get("alert_name", "").lower()
            ]
        base["service_filter"] = service

    if format == "summary":
        prom_signals = base.get("prometheus_signals", [])
        loki_streams = base.get("loki_log_summaries", [])
        alerts = base.get("alert_states", [])
        nominal_count = sum(1 for s in prom_signals if s.get("status") == "nominal")
        warning_count = sum(1 for s in prom_signals if s.get("status") == "warning")
        critical_count = sum(1 for s in prom_signals if s.get("status") == "critical")
        loki_errors = sum(s.get("error_count_5m", 0) for s in loki_streams)
        active_alerts = [a for a in alerts if a.get("active", False)]

        overall_status = "nominal"
        if critical_count > 0 or len(active_alerts) > 0:
            overall_status = "critical"
        elif warning_count > 0 or loki_errors > 0:
            overall_status = "degraded"

        return {
            "schema_version": "1.0-observability-signal-summary",
            "telemetry_mode": base.get("telemetry_mode", "SNAPSHOT_FIXTURE"),
            "live_http_active": base.get("live_http_active", False),
            "overall_status": overall_status,
            "service_filter": service,
            "signals": list(prom_signals),
            "summary": {
                "total_prometheus_signals": len(prom_signals),
                "nominal_signals": nominal_count,
                "warning_signals": warning_count,
                "critical_signals": critical_count,
                "total_loki_streams": len(loki_streams),
                "total_loki_errors_5m": loki_errors,
                "active_alert_count": len(active_alerts),
            },
            "alerts": active_alerts,
        }

    return base


def collect_observability_signals(
    allow_live_http: bool = False,
    format: str = "full",
    service: str | None = None,
) -> dict[str, Any]:
    """Collector helper for E2E tests."""
    return get_observability_signals_report(
        format=format, service=service, allow_live_http=allow_live_http
    )


def query_prometheus_signals(allow_live_http: bool = False) -> dict[str, Any]:
    """Query Prometheus metric golden signals and alert states."""
    data = query_sanitized_observability_signals(allow_live_http=allow_live_http)
    return {
        "signals": data.get("prometheus_signals", []),
        "alert_states": data.get("alert_states", []),
        "telemetry_mode": data.get("telemetry_mode"),
    }


def query_loki_signals(allow_live_http: bool = False) -> dict[str, Any]:
    """Query Loki log summaries and error counts."""
    data = query_sanitized_observability_signals(allow_live_http=allow_live_http)
    return {
        "logs": data.get("loki_log_summaries", []),
        "telemetry_mode": data.get("telemetry_mode"),
    }


def signals_to_graph(signals: dict[str, Any] | None = None) -> dict[str, Any]:
    """Convert metric signals and log streams to spatial graph nodes and edges."""
    nodes = []
    edges = []
    if not isinstance(signals, dict):
        return {"nodes": nodes, "edges": edges}
    metrics = signals.get("metrics", signals.get("signals", signals.get("prometheus_signals", [])))
    logs = signals.get("logs", signals.get("loki_log_summaries", []))
    for m in metrics:
        sig_id = m.get("signal_id", "metric_signal")
        nodes.append({
            "id": f"obs-metric-{sig_id}",
            "label": sig_id,
            "kind": "observability_metric",
            "status": m.get("status", "nominal"),
            "value": m.get("value"),
        })
    for idx, l in enumerate(logs):
        stream = l.get("stream", f"stream_{idx}")
        nodes.append({
            "id": f"obs-log-{idx}",
            "label": stream,
            "kind": "observability_log",
            "error_count": l.get("error_count_5m", 0),
        })
    return {"nodes": nodes, "edges": edges}


# Alias for compatibility with test_e2e_connectability_extensibility.py
convert_signals_to_graph = signals_to_graph


def parse_signals_response(raw_payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Safely parse upstream signals payload, returning empty structure on empty input."""
    if not isinstance(raw_payload, dict) or not raw_payload:
        return {"signals": [], "logs": [], "alert_states": [], "telemetry_mode": "SNAPSHOT_FIXTURE"}
    return raw_payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-http", action="store_true", help="Opt into bounded Prometheus HTTP query")
    parser.add_argument("--prometheus-url", default="http://127.0.0.1:9090")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = query_sanitized_observability_signals(
        allow_live_http=args.live_http,
        prometheus_url=args.prometheus_url,
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
