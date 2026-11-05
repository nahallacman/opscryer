# SPDX-License-Identifier: Apache-2.0
"""Outbound alerting webhook sink with resilient transport and OPSEC sanitization.

Features:
- Pure Python 3.11+ standard library (zero external runtime dependencies).
- Conforms to '1.0-webhook-notification' payload schema.
- Four-tier URL resolution: explicit argument > OPSCRYER_WEBHOOK_URL > opscryer_config > None.
- Resilient transport with exponential backoff, jitter, and named circuit breaker.
- Full OPSEC sanitization via telemetry_sanitizer and recursive credential scrubbing.
- Convenience helpers for cluster degradation, node hotspots, and Jev escalation.
- Fail-closed error handling: network failures never crash callers.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
import re
import time
from typing import Any, Callable
import urllib.error
from urllib.request import Request, urlopen
import uuid

from http_transport import urlopen_with_retry
import opscryer_config
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo

SCHEMA_VERSION: str = "1.0-webhook-notification"
DEFAULT_TIMEOUT: float = 5.0
DEFAULT_MAX_RETRIES: int = 2
CIRCUIT_BREAKER_NAME: str = "webhook_notifier"
DEFAULT_USER_AGENT: str = "OpsCryer-WebhookNotifier/1.0"
VALID_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "warning", "info", "low"})

logger = logging.getLogger("opscryer.webhook_notifier")

_SENSITIVE_KEY_PATTERN = re.compile(
    r".*(?:password|passwd|secret|token|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization|private[_-]?key|"
    r"cert[_-]?key|tls[_-]?key|ssl[_-]?key|ssh[_-]?key|priv[_-]?key|"
    r"id[_-]?(?:rsa|ed25519|ecdsa|dsa)|privkey|key[_-]?pem|cert[_-]?pem|"
    r"key[_-]?file|cert[_-]?file|(?:^|[_-])key(?:$|[_-])|auth|cred).*",
    re.IGNORECASE,
)

_PEM_BLOCK_PATTERN = re.compile(
    r"-----\s*BEGIN[ A-Za-z0-9_-]+-----[\s\S]*?-----\s*END[ A-Za-z0-9_-]+-----|"
    r"-----\s*BEGIN[ A-Za-z0-9_-]+-----|"
    r"-----\s*END[ A-Za-z0-9_-]+-----"
)


def _scrub_sensitive_entries(obj: Any) -> Any:
    """Recursively scrub sensitive keys, PEM blocks, and tokens from nested structures."""
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            str_key = str(k)
            if _SENSITIVE_KEY_PATTERN.match(str_key):
                cleaned[str_key] = "[REDACTED]"
            else:
                cleaned[str_key] = _scrub_sensitive_entries(v)
        return cleaned
    if isinstance(obj, (list, tuple)):
        items = [_scrub_sensitive_entries(item) for item in obj]
        return tuple(items) if isinstance(obj, tuple) else items
    if isinstance(obj, str):
        return _PEM_BLOCK_PATTERN.sub("[REDACTED]", obj)
    return obj


def resolve_webhook_url(explicit_url: str | None = None) -> str | None:
    """Resolve destination webhook URL following strict four-tier precedence:

    1. Explicit function argument (if non-empty string).
    2. Environment variable os.environ.get("OPSCRYER_WEBHOOK_URL").
    3. Configuration file via opscryer_config.get_config_value("webhook_url", None).
    4. Default None (disabled sink / safe no-op).
    """
    # Tier 1: Explicit function argument (highest precedence)
    if explicit_url is not None and isinstance(explicit_url, str) and explicit_url.strip():
        return explicit_url.strip()

    # Tier 2: Environment variable override
    env_url = os.environ.get("OPSCRYER_WEBHOOK_URL")
    if env_url is not None and isinstance(env_url, str) and env_url.strip():
        return env_url.strip()

    # Tier 3: Unified configuration provider / configuration file
    config_url = opscryer_config.get_config_value("webhook_url", None)
    if config_url is not None and isinstance(config_url, str) and config_url.strip():
        return config_url.strip()

    # Tier 4: Default None (disabled sink / safe no-op)
    return None


def get_default_cluster_metadata() -> dict[str, Any]:
    """Retrieve standard ambient cluster metadata."""
    return {
        "cluster_id": str(opscryer_config.get_config_value("cluster_id", "home-k8s-cluster")),
        "environment": str(opscryer_config.get_config_value("environment", "homelab-production")),
        "engine": "opscryer",
    }


def build_webhook_payload(
    event_type: str,
    severity: str,
    summary: str,
    details: dict[str, Any] | None = None,
    cluster_metadata: dict[str, Any] | None = None,
    event_id: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Construct and sanitize a 1.0-webhook-notification payload."""
    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("event_type must be a non-empty string")
    if not isinstance(severity, str) or not severity.strip():
        raise ValueError("severity must be a non-empty string")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("summary must be a non-empty string")

    clean_severity = severity.strip().lower()
    if clean_severity not in VALID_SEVERITIES:
        raise ValueError(
            f"severity must be one of {sorted(VALID_SEVERITIES)}, got '{clean_severity}'"
        )
    raw_details = details if isinstance(details, dict) else {}

    # Pre-scrub sensitive keys before passing to telemetry sanitizer
    pre_scrubbed_details = _scrub_sensitive_entries(raw_details)

    merged_metadata = get_default_cluster_metadata()
    if isinstance(cluster_metadata, dict):
        merged_metadata.update(cluster_metadata)

    raw_payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id if event_id is not None else uuid.uuid4().hex,
        "timestamp": timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat(),
        "event_type": event_type.strip(),
        "severity": clean_severity,
        "summary": summary.strip(),
        "details": pre_scrubbed_details,
        "cluster_metadata": merged_metadata,
    }

    # Pass entire payload through authoritative OPSEC telemetry sanitizer
    return sanitize_live_home_telemetry_for_demo(raw_payload)


def dispatch_webhook_event(
    event_type: str,
    severity: str,
    summary: str,
    details: dict[str, Any] | None = None,
    webhook_url: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_retries: int = DEFAULT_MAX_RETRIES,
    *,
    cluster_metadata: dict[str, Any] | None = None,
    opener: Callable[..., Any] = urlopen,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> bool:
    """Dispatch an alert event to the configured webhook sink with resilient transport.

    Returns:
    - True if the webhook was successfully dispatched and received 2xx.
    - False if webhook URL is unconfigured (safe no-op) or if delivery failed.
    """
    url = resolve_webhook_url(webhook_url)
    if not url:
        logger.debug("Webhook notification suppressed: no webhook_url configured.")
        return False

    try:
        payload = build_webhook_payload(
            event_type=event_type,
            severity=severity,
            summary=summary,
            details=details,
            cluster_metadata=cluster_metadata,
        )
        payload_bytes = json.dumps(payload, allow_nan=False).encode("utf-8")
    except Exception as err:
        logger.warning("Failed to serialize webhook payload for '%s': %s", event_type, err)
        return False

    req = Request(
        url=url,
        data=payload_bytes,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": DEFAULT_USER_AGENT,
        },
        method="POST",
    )

    try:
        urlopen_with_retry(
            request=req,
            timeout=float(timeout),
            max_retries=int(max_retries),
            backoff_factor=0.2,
            circuit_breaker_name=CIRCUIT_BREAKER_NAME,
            opener=opener,
            sleep_fn=sleep_fn,
        )
        logger.info(
            "Successfully dispatched webhook event '%s' (id=%s) to %s",
            event_type,
            payload.get("event_id"),
            url,
        )
        return True
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as err:
        logger.warning(
            "Failed to dispatch webhook event '%s' (id=%s) to %s: %s",
            event_type,
            payload.get("event_id"),
            url,
            err,
        )
        return False
    except Exception as err:
        logger.warning(
            "Unexpected error during webhook dispatch for '%s': %s",
            event_type,
            err,
        )
        return False


def notify_cluster_degraded(
    score: float,
    reason: str,
    details: dict[str, Any] | None = None,
    **kwargs: Any,
) -> bool:
    """Convenience trigger for cluster health degradation (severity: critical)."""
    merged_details = dict(details or {})
    merged_details.update({
        "health_score": round(float(score), 2),
        "reason": str(reason),
    })
    summary = f"Cluster degraded: {reason} (health score: {score:.2f})"
    return dispatch_webhook_event(
        event_type="cluster_degraded",
        severity="critical",
        summary=summary,
        details=merged_details,
        **kwargs,
    )


def notify_hotspot_detected(
    node_id: str,
    metric: str,
    value: Any,
    details: dict[str, Any] | None = None,
    **kwargs: Any,
) -> bool:
    """Convenience trigger for node resource hotspot detection (severity: warning)."""
    merged_details = dict(details or {})
    merged_details.update({
        "node_id": str(node_id),
        "metric": str(metric),
        "value": value,
    })
    summary = f"Hotspot detected on node {node_id}: {metric}={value}"
    return dispatch_webhook_event(
        event_type="hotspot_detected",
        severity="warning",
        summary=summary,
        details=merged_details,
        **kwargs,
    )


def notify_jev_escalation(
    ticket_id: str,
    reason: str,
    details: dict[str, Any] | None = None,
    **kwargs: Any,
) -> bool:
    """Convenience trigger for Jev System One ticket human escalation (severity: high)."""
    merged_details = dict(details or {})
    merged_details.update({
        "ticket_id": str(ticket_id),
        "escalation_reason": str(reason),
    })
    summary = f"Jev System One ticket {ticket_id} escalated to human review: {reason}"
    return dispatch_webhook_event(
        event_type="jev_escalation",
        severity="high",
        summary=summary,
        details=merged_details,
        **kwargs,
    )


__all__ = [
    "SCHEMA_VERSION",
    "DEFAULT_TIMEOUT",
    "DEFAULT_MAX_RETRIES",
    "CIRCUIT_BREAKER_NAME",
    "DEFAULT_USER_AGENT",
    "VALID_SEVERITIES",
    "resolve_webhook_url",
    "get_default_cluster_metadata",
    "build_webhook_payload",
    "dispatch_webhook_event",
    "notify_cluster_degraded",
    "notify_hotspot_detected",
    "notify_jev_escalation",
]
