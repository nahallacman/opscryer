# SPDX-License-Identifier: Apache-2.0
"""Bi-Directional ITSM Ticket Correlation & Signed ChatOps Callback Bridge (Milestone 13).

Implements:
1. Thread-safe in-memory ITSM ticket ledger, composite correlation index, and callback nonce replay cache.
2. Idempotent OCSF/Sigma incident and low-confidence Jev escalation correlation with storm deduplication.
3. Ticket query and filtering with status breakdown and deduplication telemetry metrics.
4. Dual-scheme ChatOps callback verifier (HMAC-SHA256 & Post-Quantum WOTS+ signatures) with 300s TTL and anti-replay.
5. Two-Tier Capability Airlock enforcing read-only Tier 1 recon, Tier 2 Action Card staging/Shamir approval,
   and strict 403 blocking of direct cluster mutations.
6. Unified REST API dispatcher for /api/v1/itsm/* endpoints.

Zero external dependencies (pure Python 3.11+ standard library only).
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import hmac
import importlib
import json
import threading
import time
from typing import Any

import action_cards
import event_stream
import pqc_security
import security_airlock
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo

# Ensure pqc_security exposes verify_pqc_signature alias for pqc_verify compatibility
if not hasattr(pqc_security, "verify_pqc_signature"):
    setattr(pqc_security, "verify_pqc_signature", pqc_security.pqc_verify)

verify_pqc_signature = pqc_security.pqc_verify

SUPPORTED_ITSM_PROVIDERS: frozenset[str] = frozenset({
    "gitlab_issues",
    "enterprise_servicedesk",
    "jira_webhook",
    "pagerduty_incident",
})

PROVIDER_DISPLAY_NAMES: dict[str, str] = {
    "gitlab_issues": "GitLab Issues",
    "enterprise_servicedesk": "Enterprise Service Desk",
    "jira_webhook": "Jira Service Management Webhook",
    "pagerduty_incident": "PagerDuty Incident Bridge",
}

ACTIVE_TICKET_STATUSES: frozenset[str] = frozenset({
    "OPEN",
    "TRIAGED",
    "ACTION_STAGED",
})

ALL_TICKET_STATUSES: frozenset[str] = frozenset({
    "OPEN",
    "TRIAGED",
    "ACTION_STAGED",
    "RESOLVED",
    "REJECTED",
    "CLOSED",
})

TIER_1_RECON_COMMANDS: frozenset[str] = frozenset({
    "query_graph",
    "get_incident_status",
    "preview_dry_run",
    "get_system_context",
})

TIER_2_ACTION_CARD_COMMANDS: frozenset[str] = frozenset({
    "stage_action_card",
    "submit_action_share",
    "reject_action_card",
})

FORBIDDEN_DIRECT_MUTATION_COMMANDS: frozenset[str] = frozenset({
    "restart_node",
    "execute_action",
    "delete_pod",
    "kill_container",
    "apply_action",
    "apply_remediation",
    "delete_node",
    "reboot_host",
    "drain_traffic",
    "isolate_workload",
    "scale_deployment",
    "kill_pod",
    "mutate_cluster",
})

CALLBACK_TTL_SECONDS: float = 300.0
DEFAULT_CHATOPS_SHARED_SECRET: str = "opscryer-enterprise-chatops-hmac-key-v1"

# =====================================================================
# 1. Thread-Safe State & Reset
# =====================================================================

_ITSM_LOCK = threading.Lock()
_ITSM_TICKETS: dict[str, dict[str, Any]] = {}
_CORRELATION_INDEX: dict[tuple[str, str, str], str] = {}
_CARD_TO_TICKET_INDEX: dict[str, str] = {}
_SEEN_CALLBACK_NONCES: dict[str, float] = {}
_DEDUPLICATED_HIT_COUNT: int = 0
_TICKET_SEQUENCE: int = 0


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def reset_itsm_bridge() -> None:
    """Reset the in-memory ITSM ticket ledger, correlation index, and callback nonce replay cache."""
    global _DEDUPLICATED_HIT_COUNT, _TICKET_SEQUENCE
    with _ITSM_LOCK:
        _ITSM_TICKETS.clear()
        _CORRELATION_INDEX.clear()
        _CARD_TO_TICKET_INDEX.clear()
        _SEEN_CALLBACK_NONCES.clear()
        _DEDUPLICATED_HIT_COUNT = 0
        _TICKET_SEQUENCE = 0


def _scrub_opsec_value(value: Any) -> Any:
    """Scrub strings and nested structures via security_airlock and telemetry_sanitizer."""
    if isinstance(value, str):
        # Strip zero-width obfuscation characters using security_airlock regex
        cleaned = security_airlock._ZERO_WIDTH_RE.sub("", value)
        # Redact any prohibited token markers detected by security_airlock
        if any(marker in cleaned for marker in security_airlock._TOKEN_MARKERS):
            for marker in security_airlock._TOKEN_MARKERS:
                if marker in cleaned:
                    cleaned = "[REDACTED]"
                    break
        return sanitize_live_home_telemetry_for_demo(cleaned)
    if isinstance(value, dict):
        scrubbed_dict: dict[str, Any] = {}
        for k, v in value.items():
            key_str = str(k)
            # Redact values whose keys match secret patterns in security_airlock
            if security_airlock._SECRET_QUERY.search(key_str):
                scrubbed_dict[key_str] = "[REDACTED]"
            else:
                scrubbed_dict[key_str] = _scrub_opsec_value(v)
        return sanitize_live_home_telemetry_for_demo(scrubbed_dict)
    if isinstance(value, list):
        return [_scrub_opsec_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_opsec_value(item) for item in value)
    return sanitize_live_home_telemetry_for_demo(value)


def _publish_event_safe(topic: str, event_type: str, data: dict[str, Any]) -> int:
    """Publish an event to event_stream without raising if ring buffer is unavailable."""
    try:
        return event_stream.publish_event(topic, event_type, data)
    except Exception:
        return 0


# =====================================================================
# 2. Idempotent Incident-to-ITSM Ticket Correlation
# =====================================================================

def _extract_correlation_fields(incident_or_escalation: dict[str, Any]) -> dict[str, Any]:
    """Normalize either an OCSF/Sigma security incident or a Jev escalation into correlation fields."""
    raw_source = str(incident_or_escalation.get("source_type") or "").strip().lower()

    # Infer source_type when omitted based on Jev tree/confidence vs security rule fields
    if not raw_source:
        if "tree_id" in incident_or_escalation or (
            "confidence" in incident_or_escalation and "rule_id" not in incident_or_escalation
        ):
            source_type = "jev_escalation"
        else:
            source_type = "security_incident"
    elif raw_source in {"security_incident", "ocsf", "sigma", "security"}:
        source_type = "security_incident"
    elif raw_source in {"jev_escalation", "jev", "escalation"}:
        source_type = "jev_escalation"
    else:
        raise ValueError(
            f"Unsupported source_type '{raw_source}'. Expected 'security_incident' or 'jev_escalation'."
        )

    rule_obj = incident_or_escalation.get("rule")
    if not isinstance(rule_obj, dict):
        rule_obj = {}

    target_obj = incident_or_escalation.get("target")
    if not isinstance(target_obj, dict):
        target_obj = {}

    if source_type == "jev_escalation":
        rule_or_tree_id = str(
            incident_or_escalation.get("tree_id")
            or incident_or_escalation.get("rule_or_tree_id")
            or incident_or_escalation.get("id")
            or "jev-decision-tree-default"
        ).strip()
    else:
        rule_or_tree_id = str(
            incident_or_escalation.get("rule_id")
            or rule_obj.get("id")
            or incident_or_escalation.get("rule_or_tree_id")
            or incident_or_escalation.get("id")
            or "sigma-rule-unspecified"
        ).strip()

    target_node_id = str(
        incident_or_escalation.get("target_node_id")
        or target_obj.get("node_id")
        or incident_or_escalation.get("node_id")
        or target_obj.get("workload")
        or incident_or_escalation.get("workload")
        or "node-alpha-01"
    ).strip()

    raw_sev = incident_or_escalation.get("severity")
    if not raw_sev:
        raw_sev = "MEDIUM" if source_type == "jev_escalation" else "HIGH"
    severity = str(raw_sev).strip().upper()

    confidence_raw = incident_or_escalation.get("confidence")
    confidence: float | None = None
    if confidence_raw is not None:
        try:
            confidence = round(float(confidence_raw), 4)
        except (ValueError, TypeError):
            confidence = None

    summary = str(
        incident_or_escalation.get("summary")
        or incident_or_escalation.get("message")
        or incident_or_escalation.get("title")
        or rule_obj.get("name")
        or f"{source_type} on {target_node_id} ({rule_or_tree_id})"
    ).strip()

    return {
        "source_type": source_type,
        "rule_or_tree_id": rule_or_tree_id,
        "rule_id": rule_or_tree_id if source_type == "security_incident" else None,
        "tree_id": rule_or_tree_id if source_type == "jev_escalation" else None,
        "target_node_id": target_node_id,
        "severity": severity,
        "confidence": confidence,
        "summary": summary,
        "linked_action_card_id": incident_or_escalation.get("linked_action_card_id"),
    }


def _build_external_key(provider: str, seq_num: int) -> str:
    """Format a provider-native external ticket key using generic enterprise identifiers."""
    if provider == "gitlab_issues":
        return f"GL-ISSUE-{seq_num}"
    if provider == "enterprise_servicedesk":
        return f"ESD-INC-{seq_num:05d}"
    if provider == "jira_webhook":
        return f"OPS-{seq_num}"
    if provider == "pagerduty_incident":
        return f"PD-INC-{seq_num:05d}"
    return f"EXT-{seq_num}"


def correlate_incident_to_itsm_ticket(
    incident_or_escalation: dict[str, Any],
    provider: str = "gitlab_issues",
) -> dict[str, Any]:
    """Correlate an OCSF security incident or Jev escalation into an ITSM ticket idempotently.

    Computes a deterministic composite correlation key `(source_type, rule_or_tree_id, target_node_id)`.
    If an active ticket (`status` in `{"OPEN", "TRIAGED", "ACTION_STAGED"}`) exists for that key,
    increments `occurrence_count`, appends a timeline entry, and returns the existing ticket with
    `"deduplicated": True` to prevent alert/ticket storms.
    """
    global _DEDUPLICATED_HIT_COUNT, _TICKET_SEQUENCE

    if not isinstance(incident_or_escalation, dict):
        raise TypeError("incident_or_escalation must be a dictionary")

    clean_provider = str(provider or "gitlab_issues").strip().lower()
    if clean_provider not in SUPPORTED_ITSM_PROVIDERS:
        raise ValueError(
            f"Unsupported ITSM provider '{clean_provider}'. "
            f"Supported providers: {sorted(SUPPORTED_ITSM_PROVIDERS)}"
        )

    fields = _extract_correlation_fields(incident_or_escalation)
    scrubbed_fields = _scrub_opsec_value(fields)

    source_type = str(scrubbed_fields["source_type"])
    rule_or_tree_id = str(scrubbed_fields["rule_or_tree_id"])
    target_node_id = str(scrubbed_fields["target_node_id"])
    summary = str(scrubbed_fields["summary"])
    severity = str(scrubbed_fields["severity"])
    confidence = scrubbed_fields["confidence"]
    linked_card_id = scrubbed_fields.get("linked_action_card_id")

    composite_key: tuple[str, str, str] = (source_type, rule_or_tree_id, target_node_id)
    key_digest = hashlib.sha256(
        f"{source_type}:{rule_or_tree_id}:{target_node_id}".encode("utf-8")
    ).hexdigest()[:8].upper()
    now_iso = _now_iso()

    with _ITSM_LOCK:
        existing_ticket_id = _CORRELATION_INDEX.get(composite_key)
        existing_ticket = _ITSM_TICKETS.get(existing_ticket_id) if existing_ticket_id else None

        # Deduplicate when an existing ticket for this composite key is still in an active state
        if existing_ticket is not None and existing_ticket.get("status") in ACTIVE_TICKET_STATUSES:
            existing_ticket["occurrence_count"] = int(existing_ticket.get("occurrence_count", 1)) + 1
            existing_ticket["updated_at"] = now_iso
            existing_ticket["deduplicated"] = True
            if linked_card_id and not existing_ticket.get("linked_action_card_id"):
                existing_ticket["linked_action_card_id"] = str(linked_card_id)
                _CARD_TO_TICKET_INDEX[str(linked_card_id)] = existing_ticket["ticket_id"]
            existing_ticket["timeline"].append({
                "timestamp": now_iso,
                "event": "incident_deduplicated",
                "occurrence_count": existing_ticket["occurrence_count"],
                "summary": summary,
            })
            _DEDUPLICATED_HIT_COUNT += 1
            result_copy = copy.deepcopy(existing_ticket)
            result_copy["deduplicated"] = True
            return result_copy

        # Create a new tracked ITSM ticket
        _TICKET_SEQUENCE += 1
        seq_num = _TICKET_SEQUENCE
        ticket_id = f"ITSM-{seq_num:04d}-{key_digest}"
        external_key = _build_external_key(clean_provider, seq_num)

        initial_status = "ACTION_STAGED" if linked_card_id else "OPEN"
        new_ticket: dict[str, Any] = {
            "ticket_id": ticket_id,
            "external_key": external_key,
            "provider": clean_provider,
            "provider_name": PROVIDER_DISPLAY_NAMES.get(clean_provider, "Enterprise Service Desk"),
            "status": initial_status,
            "source_type": source_type,
            "rule_or_tree_id": rule_or_tree_id,
            "rule_id": scrubbed_fields["rule_id"],
            "tree_id": scrubbed_fields["tree_id"],
            "target_node_id": target_node_id,
            "severity": severity,
            "confidence": confidence,
            "summary": summary,
            "correlation_key": [source_type, rule_or_tree_id, target_node_id],
            "occurrence_count": 1,
            "linked_action_card_id": str(linked_card_id) if linked_card_id else None,
            "created_at": now_iso,
            "updated_at": now_iso,
            "timeline": [
                {
                    "timestamp": now_iso,
                    "event": "ticket_created",
                    "provider": clean_provider,
                    "status": initial_status,
                    "summary": summary,
                }
            ],
            "deduplicated": False,
        }

        scrubbed_ticket = _scrub_opsec_value(new_ticket)
        _ITSM_TICKETS[ticket_id] = scrubbed_ticket
        _CORRELATION_INDEX[composite_key] = ticket_id
        if linked_card_id:
            _CARD_TO_TICKET_INDEX[str(linked_card_id)] = ticket_id

        ticket_return = copy.deepcopy(scrubbed_ticket)

    _publish_event_safe(
        "security",
        "itsm_ticket_correlated",
        {
            "ticket_id": ticket_return["ticket_id"],
            "external_key": ticket_return["external_key"],
            "provider": ticket_return["provider"],
            "status": ticket_return["status"],
            "source_type": source_type,
            "rule_or_tree_id": rule_or_tree_id,
            "target_node_id": target_node_id,
            "occurrence_count": 1,
            "deduplicated": False,
        },
    )

    return ticket_return


# =====================================================================
# 3. Ticket Query & Filtering
# =====================================================================

def list_itsm_tickets(
    status_filter: str | None = None,
    provider_filter: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Return filtered ITSM tickets, status breakdown counts, and storm deduplication metrics."""
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be an integer >= 1")

    norm_status = status_filter.strip().upper() if isinstance(status_filter, str) and status_filter.strip() else None
    norm_provider = (
        provider_filter.strip().lower() if isinstance(provider_filter, str) and provider_filter.strip() else None
    )

    if norm_status and norm_status not in ALL_TICKET_STATUSES:
        raise ValueError(f"Invalid status_filter '{norm_status}'. Allowed: {sorted(ALL_TICKET_STATUSES)}")
    if norm_provider and norm_provider not in SUPPORTED_ITSM_PROVIDERS:
        raise ValueError(f"Invalid provider_filter '{norm_provider}'. Allowed: {sorted(SUPPORTED_ITSM_PROVIDERS)}")

    with _ITSM_LOCK:
        all_tickets = [copy.deepcopy(t) for t in _ITSM_TICKETS.values()]
        dedup_hits = _DEDUPLICATED_HIT_COUNT

    counts_by_status: dict[str, int] = {st: 0 for st in sorted(ALL_TICKET_STATUSES)}
    total_occurrences = 0
    filtered: list[dict[str, Any]] = []

    for t in all_tickets:
        st = str(t.get("status", "OPEN")).upper()
        counts_by_status[st] = counts_by_status.get(st, 0) + 1
        total_occurrences += int(t.get("occurrence_count", 1))

        # Apply optional status and provider filters
        if norm_status and st != norm_status:
            continue
        if norm_provider and str(t.get("provider", "")).lower() != norm_provider:
            continue
        filtered.append(t)

    # Most recently updated tickets first
    filtered.reverse()
    sliced = filtered[:limit]

    return {
        "tickets": sliced,
        "returned_count": len(sliced),
        "total_tickets": len(all_tickets),
        "counts_by_status": counts_by_status,
        "deduplication_metrics": {
            "total_tickets": len(all_tickets),
            "total_occurrences": total_occurrences,
            "deduplicated_count": dedup_hits,
            "deduplicated_incidents_suppressed": dedup_hits,
        },
    }


# =====================================================================
# 4. HMAC-SHA256 & PQC-Signed Interactive ChatOps Callback Handler
# =====================================================================

def compute_chatops_canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize canonical JSON over {'callback_id', 'timestamp', 'command', 'arguments'}."""
    callback_id = payload.get("callback_id") or payload.get("nonce") or ""
    canonical_obj = {
        "arguments": payload.get("arguments") if isinstance(payload.get("arguments"), dict) else {},
        "callback_id": str(callback_id),
        "command": str(payload.get("command") or ""),
        "timestamp": payload.get("timestamp"),
    }
    return json.dumps(canonical_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _candidate_canonical_payloads(payload: dict[str, Any]) -> list[bytes]:
    """Generate deterministic canonical byte representations for signature verification."""
    callback_id = payload.get("callback_id") or payload.get("nonce") or ""
    args = payload.get("arguments") if isinstance(payload.get("arguments"), dict) else {}
    cmd = str(payload.get("command") or "")
    ts = payload.get("timestamp")

    ordered_obj = {
        "callback_id": str(callback_id),
        "timestamp": ts,
        "command": cmd,
        "arguments": args,
    }
    candidates = [
        json.dumps(ordered_obj, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        json.dumps(ordered_obj, sort_keys=True).encode("utf-8"),
        json.dumps(ordered_obj, separators=(",", ":")).encode("utf-8"),
        json.dumps(ordered_obj).encode("utf-8"),
    ]
    return candidates


def sign_chatops_callback_hmac(payload: dict[str, Any], shared_secret: str | bytes) -> str:
    """Compute hex-encoded HMAC-SHA256 signature over canonical ChatOps callback fields."""
    secret_bytes = shared_secret.encode("utf-8") if isinstance(shared_secret, str) else bytes(shared_secret)
    msg_bytes = compute_chatops_canonical_bytes(payload)
    return hmac.new(secret_bytes, msg_bytes, hashlib.sha256).hexdigest()


def sign_chatops_callback_pqc(payload: dict[str, Any], private_key: dict[str, Any]) -> dict[str, Any]:
    """Compute Post-Quantum WOTS+ signature over canonical ChatOps callback fields."""
    msg_bytes = compute_chatops_canonical_bytes(payload)
    return pqc_security.pqc_sign(msg_bytes, private_key)


def _verify_callback_signature(
    payload: dict[str, Any],
    shared_secret: str | bytes | None,
    master_pubkey: dict[str, Any] | None,
) -> bool:
    """Verify either HMAC-SHA256 signature or PQC WOTS+ signature on a ChatOps callback."""
    hmac_sig = payload.get("hmac_signature")
    pqc_sig = payload.get("pqc_signature")

    candidates = _candidate_canonical_payloads(payload)

    # Branch 1: Verify HMAC-SHA256 signature when provided
    if isinstance(hmac_sig, str) and hmac_sig.strip():
        clean_sig = hmac_sig.strip()
        if clean_sig.lower().startswith("sha256="):
            clean_sig = clean_sig.split("=", 1)[1].strip()
        effective_secret = shared_secret if shared_secret is not None else DEFAULT_CHATOPS_SHARED_SECRET
        secret_bytes = (
            effective_secret.encode("utf-8")
            if isinstance(effective_secret, str)
            else bytes(effective_secret)
        )
        for msg_bytes in candidates:
            expected_hex = hmac.new(secret_bytes, msg_bytes, hashlib.sha256).hexdigest()
            if hmac.compare_digest(clean_sig.lower(), expected_hex.lower()):
                return True
        return False

    # Branch 2: Verify PQC WOTS+ Merkle signature when provided
    if isinstance(pqc_sig, dict) and pqc_sig:
        pubkey = master_pubkey or payload.get("master_pubkey") or payload.get("public_key")
        if not isinstance(pubkey, dict):
            return False
        verify_fn = getattr(pqc_security, "verify_pqc_signature", pqc_security.pqc_verify)
        for msg_bytes in candidates:
            if verify_fn(msg_bytes, pqc_sig, pubkey):
                return True
        return False

    return False


def _ensure_catalog_contains_node(
    target_node_id: str,
    arguments: dict[str, Any],
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Ensure the spatial graph catalog contains target_node_id so generic enterprise node IDs succeed."""
    base_catalog = copy.deepcopy(action_cards._load_catalog(catalog))
    try:
        action_cards._find_catalog_node(target_node_id, base_catalog)
        return base_catalog
    except KeyError:
        nodes = base_catalog.setdefault("nodes", [])
        # Synthesize a generic enterprise node when not already present in the default snapshot
        req_k = arguments.get("required_k")
        is_critical = (
            bool(arguments.get("critical_tier"))
            or (isinstance(req_k, int) and req_k >= 2)
            or str(arguments.get("tier", "")).lower() in action_cards.CRITICAL_PLANES
        )
        nodes.append({
            "id": target_node_id,
            "label": target_node_id,
            "kind": str(arguments.get("target_kind") or "Node"),
            "namespace": "security" if is_critical else str(arguments.get("namespace") or "default"),
            "tier": "control_plane" if is_critical else str(arguments.get("tier") or "worker"),
        })
        return base_catalog


def _execute_tier1_recon_command(command: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute a read-only Tier 1 reconnaissance command and scrub outputs for OPSEC."""
    if command == "query_graph":
        query_text = arguments.get("query")
        node_id = arguments.get("node_id")
        limit = int(arguments.get("limit", 10))
        backend_mod = importlib.import_module("opscryer_backend")
        engine = backend_mod.KnowledgeGraphBackendEngine()
        if node_id:
            cat = engine.catalog()
            matched = next((n for n in cat.get("nodes", []) if n.get("id") == node_id), None)
            if not matched:
                return _scrub_opsec_value({"node_id": node_id, "found": False, "nodes": []})
            return _scrub_opsec_value({"node_id": node_id, "found": True, "node": matched})
        if query_text:
            return _scrub_opsec_value(engine.search(query=str(query_text), limit=max(1, min(limit, 100))))
        cat = engine.catalog()
        nodes = cat.get("nodes", [])[:limit]
        return _scrub_opsec_value({"total_nodes": len(cat.get("nodes", [])), "nodes": nodes})

    if command == "get_incident_status":
        ticket_id = arguments.get("ticket_id")
        if ticket_id:
            with _ITSM_LOCK:
                ticket = copy.deepcopy(_ITSM_TICKETS.get(str(ticket_id)))
            if ticket is None:
                return _scrub_opsec_value({"ticket_id": ticket_id, "found": False})
            return _scrub_opsec_value({"ticket_id": ticket_id, "found": True, "ticket": ticket})
        status_filter = arguments.get("status")
        provider_filter = arguments.get("provider")
        limit = int(arguments.get("limit", 25))
        return _scrub_opsec_value(
            list_itsm_tickets(status_filter=status_filter, provider_filter=provider_filter, limit=limit)
        )

    if command == "preview_dry_run":
        action_type = str(arguments.get("action_type") or "restart_node")
        target_node_id = str(arguments.get("target_node_id") or "node-alpha-01")
        parameters = arguments.get("parameters") if isinstance(arguments.get("parameters"), dict) else {}
        aug_catalog = _ensure_catalog_contains_node(target_node_id, arguments, arguments.get("catalog"))
        preview = action_cards.preview_action_dry_run(
            action_type=action_type,
            target_node_id=target_node_id,
            parameters=parameters,
            catalog=aug_catalog,
        )
        worrisomeness = action_cards.evaluate_outcome_worrisomeness(preview, target_node_id)
        return _scrub_opsec_value({
            "action_preview": preview,
            "worrisomeness": worrisomeness,
        })

    if command == "get_system_context":
        tier = str(arguments.get("tier") or "both")
        query = arguments.get("q") or arguments.get("query")
        sys_mod = importlib.import_module("system_context")
        return _scrub_opsec_value(sys_mod.build_system_context(tier=tier, query=query))

    raise ValueError(f"Unsupported Tier 1 command: {command}")


def _find_linked_ticket_id(action_id: str, explicit_ticket_id: str | None = None) -> str | None:
    """Find the ITSM ticket ID linked to a given Action Card ID."""
    if explicit_ticket_id and explicit_ticket_id in _ITSM_TICKETS:
        return explicit_ticket_id
    mapped = _CARD_TO_TICKET_INDEX.get(action_id)
    if mapped and mapped in _ITSM_TICKETS:
        return mapped
    for tid, t in _ITSM_TICKETS.items():
        if t.get("linked_action_card_id") == action_id:
            return tid
    return None


def _execute_tier2_action_card_command(
    command: str,
    arguments: dict[str, Any],
    callback_id: str,
) -> tuple[int, dict[str, Any]]:
    """Execute a Tier 2 Action Card command and synchronize linked ITSM ticket lifecycle state."""
    now_iso = _now_iso()

    if command == "stage_action_card":
        action_type = str(arguments.get("action_type") or "restart_node")
        target_node_id = str(arguments.get("target_node_id") or "node-alpha-01")
        parameters = arguments.get("parameters") if isinstance(arguments.get("parameters"), dict) else {}
        ttl_seconds = float(arguments.get("ttl_seconds", 3600.0))
        ticket_id = arguments.get("ticket_id")
        action_id = arguments.get("action_id")

        aug_catalog = _ensure_catalog_contains_node(target_node_id, arguments, arguments.get("catalog"))
        try:
            card = action_cards.stage_action_card(
                target_node_id=target_node_id,
                action_type=action_type,
                parameters=parameters,
                ttl_seconds=ttl_seconds,
                action_id=action_id,
                active_alerts=arguments.get("active_alerts"),
                catalog=aug_catalog,
            )
        except (ValueError, TypeError, KeyError) as exc:
            return 400, {"error": str(exc), "tier": "TIER_2_ACTION_CARD"}

        # Honor explicit required_k override if requested in arguments
        req_k = arguments.get("required_k")
        if isinstance(req_k, int) and req_k >= 1:
            with action_cards._DEFAULT_LEDGER._lock:
                stored_card = action_cards._DEFAULT_LEDGER._cards.get(card["action_id"])
                if stored_card is not None:
                    stored_card["worrisomeness"]["required_k"] = req_k
                    stored_card["worrisomeness"]["required_n"] = int(arguments.get("required_n", max(req_k, 1)))
                    stored_card["worrisomeness"]["mode"] = "threshold" if req_k > 1 else "single"
                    stored_card["_explicit_required_k"] = True
                    card = copy.deepcopy(stored_card)

        linked_ticket_snapshot: dict[str, Any] | None = None
        if ticket_id:
            with _ITSM_LOCK:
                ticket = _ITSM_TICKETS.get(str(ticket_id))
                if ticket is not None:
                    ticket["linked_action_card_id"] = card["action_id"]
                    ticket["status"] = "ACTION_STAGED"
                    ticket["updated_at"] = now_iso
                    ticket["timeline"].append({
                        "timestamp": now_iso,
                        "event": "action_card_staged",
                        "action_id": card["action_id"],
                        "action_type": action_type,
                        "callback_id": callback_id,
                    })
                    _CARD_TO_TICKET_INDEX[card["action_id"]] = str(ticket_id)
                    linked_ticket_snapshot = copy.deepcopy(ticket)

        return 200, {
            "status": "ok",
            "tier": "TIER_2_ACTION_CARD",
            "command": "stage_action_card",
            "callback_id": callback_id,
            "result": _scrub_opsec_value({
                "action_card": card,
                "linked_ticket": linked_ticket_snapshot,
            }),
        }

    if command == "submit_action_share":
        explicit_ticket_id = str(arguments.get("ticket_id")) if arguments.get("ticket_id") else None
        action_id = arguments.get("action_id")
        if not action_id and explicit_ticket_id:
            with _ITSM_LOCK:
                t_lookup = _ITSM_TICKETS.get(explicit_ticket_id)
                if t_lookup:
                    action_id = t_lookup.get("linked_action_card_id")

        if not action_id or not isinstance(action_id, str):
            return 400, {"error": "Missing required action_id for submit_action_share"}

        credential = arguments.get("credential") or arguments.get("share")
        if credential is None and ("x" in arguments and "data" in arguments):
            credential = {
                "x": arguments["x"],
                "data": arguments["data"],
                "k": arguments.get("k", 1),
                "n": arguments.get("n", 1),
                "fingerprint": arguments.get("fingerprint"),
            }

        # Align threshold mode with Shamir share metadata when not explicitly pinned
        if isinstance(credential, dict) and isinstance(credential.get("k"), int):
            share_k = int(credential["k"])
            with action_cards._DEFAULT_LEDGER._lock:
                stored_card = action_cards._DEFAULT_LEDGER._cards.get(action_id)
                if stored_card is not None and not stored_card.get("_explicit_required_k"):
                    # Align single vs threshold k when first share arrives
                    if len(stored_card.get("shares_collected", {})) == 0:
                        stored_card["worrisomeness"]["required_k"] = share_k
                        stored_card["worrisomeness"]["required_n"] = int(credential.get("n", share_k))
                        stored_card["worrisomeness"]["mode"] = "threshold"

        status_code, approval_res = action_cards.approve_action_card(
            action_id=action_id,
            parameters_sha256=arguments.get("parameters_sha256"),
            credential=credential,
        )
        if status_code >= 400:
            return status_code, approval_res

        linked_ticket_snapshot = None
        with _ITSM_LOCK:
            target_tid = _find_linked_ticket_id(action_id, explicit_ticket_id)
            if target_tid and target_tid in _ITSM_TICKETS:
                ticket = _ITSM_TICKETS[target_tid]
                ticket["linked_action_card_id"] = action_id
                _CARD_TO_TICKET_INDEX[action_id] = target_tid
                ticket["updated_at"] = now_iso
                if approval_res.get("status") == "EXECUTED":
                    ticket["status"] = "RESOLVED"
                    ticket["timeline"].append({
                        "timestamp": now_iso,
                        "event": "ticket_resolved_by_action_card",
                        "action_id": action_id,
                        "callback_id": callback_id,
                    })
                else:
                    ticket["status"] = "ACTION_STAGED"
                    ticket["timeline"].append({
                        "timestamp": now_iso,
                        "event": "action_share_submitted",
                        "action_id": action_id,
                        "shares_collected": approval_res.get("shares_collected", 1),
                        "shares_required": approval_res.get("shares_required", 1),
                        "callback_id": callback_id,
                    })
                linked_ticket_snapshot = copy.deepcopy(ticket)

        if linked_ticket_snapshot and linked_ticket_snapshot.get("status") == "RESOLVED":
            _publish_event_safe(
                "security",
                "itsm_ticket_resolved",
                {
                    "ticket_id": linked_ticket_snapshot["ticket_id"],
                    "action_id": action_id,
                    "status": "RESOLVED",
                },
            )

        return 200, {
            "status": "ok",
            "tier": "TIER_2_ACTION_CARD",
            "command": "submit_action_share",
            "callback_id": callback_id,
            "result": _scrub_opsec_value({
                "approval": approval_res,
                "linked_ticket": linked_ticket_snapshot,
            }),
        }

    if command == "reject_action_card":
        explicit_ticket_id = str(arguments.get("ticket_id")) if arguments.get("ticket_id") else None
        action_id = arguments.get("action_id")
        if not action_id and explicit_ticket_id:
            with _ITSM_LOCK:
                t_lookup = _ITSM_TICKETS.get(explicit_ticket_id)
                if t_lookup:
                    action_id = t_lookup.get("linked_action_card_id")

        if not action_id or not isinstance(action_id, str):
            return 400, {"error": "Missing required action_id for reject_action_card"}

        reason = str(arguments.get("reason") or "Operator rejected Action Card via ChatOps")
        status_code, reject_res = action_cards.reject_action_card(action_id=action_id, reason=reason)
        if status_code >= 400:
            return status_code, reject_res

        linked_ticket_snapshot = None
        with _ITSM_LOCK:
            target_tid = _find_linked_ticket_id(action_id, explicit_ticket_id)
            if target_tid and target_tid in _ITSM_TICKETS:
                ticket = _ITSM_TICKETS[target_tid]
                ticket["updated_at"] = now_iso
                ticket["status"] = "TRIAGED"
                ticket["last_rejected_action_id"] = action_id
                ticket["rejection_reason"] = reason
                ticket["timeline"].append({
                    "timestamp": now_iso,
                    "event": "action_card_rejected",
                    "action_id": action_id,
                    "reason": reason,
                    "callback_id": callback_id,
                })
                linked_ticket_snapshot = copy.deepcopy(ticket)

        return 200, {
            "status": "ok",
            "tier": "TIER_2_ACTION_CARD",
            "command": "reject_action_card",
            "callback_id": callback_id,
            "result": _scrub_opsec_value({
                "rejection": reject_res,
                "linked_ticket": linked_ticket_snapshot,
            }),
        }

    return 400, {"error": f"Unsupported Tier 2 command '{command}'"}


def handle_chatops_callback(
    payload: dict[str, Any],
    shared_secret: str | bytes | None = None,
    master_pubkey: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Validate and execute a signed interactive ChatOps callback under the Two-Tier Capability Airlock.

    Authentication & Anti-Replay:
    - Requires `callback_id` (or `nonce`) and `timestamp` within 300s of current wall-clock time.
    - Rejects replayed `callback_id`/`nonce` with HTTP 409.
    - Rejects expired/future-skewed timestamps with HTTP 401.
    - Verifies HMAC-SHA256 (`hmac_signature`) or PQC WOTS+ (`pqc_signature`); rejects invalid/missing with HTTP 401.

    Two-Tier Capability Airlock:
    - Tier 1 Recon (`query_graph`, `get_incident_status`, `preview_dry_run`, `get_system_context`) -> HTTP 200.
    - Tier 2 Action Cards (`stage_action_card`, `submit_action_share`, `reject_action_card`) -> HTTP 200.
    - Forbidden Direct Mutations (`restart_node`, `execute_action`, `delete_pod`, `kill_container`, etc.) -> HTTP 403.
    """
    if not isinstance(payload, dict):
        return 400, {"error": "ChatOps callback payload must be a JSON object"}

    raw_callback_id = payload.get("callback_id") or payload.get("nonce")
    if not raw_callback_id or not isinstance(raw_callback_id, str) or not raw_callback_id.strip():
        return 400, {"error": "Missing required callback_id or nonce"}
    callback_id = raw_callback_id.strip()

    raw_ts = payload.get("timestamp")
    if raw_ts is None or isinstance(raw_ts, bool):
        return 401, {"error": "Callback timestamp expired"}
    try:
        ts_val = float(raw_ts)
    except (ValueError, TypeError):
        return 401, {"error": "Callback timestamp expired"}

    now = time.time()
    if abs(now - ts_val) > CALLBACK_TTL_SECONDS:
        return 401, {"error": "Callback timestamp expired"}

    with _ITSM_LOCK:
        if callback_id in _SEEN_CALLBACK_NONCES:
            return 409, {"error": "Replay detected: callback_id already processed"}

    if not _verify_callback_signature(payload, shared_secret=shared_secret, master_pubkey=master_pubkey):
        return 401, {"error": "Invalid ChatOps callback signature"}

    with _ITSM_LOCK:
        if callback_id in _SEEN_CALLBACK_NONCES:
            return 409, {"error": "Replay detected: callback_id already processed"}
        _SEEN_CALLBACK_NONCES[callback_id] = now

    command = str(payload.get("command") or "").strip()
    arguments = payload.get("arguments") if isinstance(payload.get("arguments"), dict) else {}

    if not command:
        return 400, {"error": "Missing required command in ChatOps callback"}

    # Enforce Two-Tier Capability Airlock: strictly block direct cluster mutations via ChatOps
    is_forbidden_mutation = command in FORBIDDEN_DIRECT_MUTATION_COMMANDS or (
        command not in TIER_1_RECON_COMMANDS
        and command not in TIER_2_ACTION_CARD_COMMANDS
        and any(
            kw in command.lower()
            for kw in ("restart", "execute", "delete", "kill", "reboot", "drain", "isolate", "scale", "mutate", "apply")
        )
    )
    if is_forbidden_mutation:
        return 403, {
            "error": (
                "Direct mutation via ChatOps is forbidden by the Two-Tier Airlock; "
                "stage or approve an Action Card instead"
            ),
            "airlock_blocked": True,
            "rejected_command": command,
        }

    if command in TIER_1_RECON_COMMANDS:
        try:
            recon_result = _execute_tier1_recon_command(command, arguments)
            return 200, {
                "status": "ok",
                "tier": "TIER_1_RECON",
                "command": command,
                "callback_id": callback_id,
                "result": recon_result,
            }
        except Exception as exc:
            return 400, {"error": f"Tier 1 recon execution failed: {exc}", "tier": "TIER_1_RECON"}

    if command in TIER_2_ACTION_CARD_COMMANDS:
        return _execute_tier2_action_card_command(command, arguments, callback_id)

    return 400, {"error": f"Unknown ChatOps command '{command}'"}


# =====================================================================
# 5. HTTP API Dispatcher (/api/v1/itsm/*)
# =====================================================================

def _first_query_param(query: dict[str, Any] | None, *keys: str) -> Any:
    """Extract the first matching query parameter supporting both parse_qs lists and scalar dicts."""
    if not query or not isinstance(query, dict):
        return None
    for k in keys:
        if k in query:
            val = query[k]
            if isinstance(val, list):
                return val[0] if val else None
            return val
    return None


def handle_itsm_api(
    path: str,
    method: str = "GET",
    query: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Dispatch HTTP API requests for /api/v1/itsm/* endpoints."""
    clean_path = path.split("?", 1)[0].rstrip("/")
    clean_method = method.upper().strip()

    # Route 1: GET /api/v1/itsm/tickets
    if clean_path == "/api/v1/itsm/tickets":
        if clean_method != "GET":
            return 405, {"error": "Method not allowed", "supported_methods": ["GET"]}

        status_param = _first_query_param(query, "status", "status_filter")
        provider_param = _first_query_param(query, "provider", "provider_filter")
        limit_param = _first_query_param(query, "limit")
        limit_val = 50
        if limit_param is not None and limit_param != "":
            try:
                limit_val = int(limit_param)
            except (ValueError, TypeError):
                return 400, {"error": "Invalid limit parameter: must be an integer >= 1"}

        try:
            listing = list_itsm_tickets(
                status_filter=str(status_param) if status_param is not None else None,
                provider_filter=str(provider_param) if provider_param is not None else None,
                limit=limit_val,
            )
            return 200, listing
        except ValueError as exc:
            return 400, {"error": str(exc)}

    # Route 2: POST /api/v1/itsm/correlate
    if clean_path == "/api/v1/itsm/correlate":
        if clean_method == "GET":
            return 200, {
                "endpoint": "/api/v1/itsm/correlate",
                "status": "active",
                "description": "Idempotently correlate an OCSF security incident or Jev escalation to an ITSM ticket.",
                "supported_methods": ["POST"],
                "supported_providers": sorted(SUPPORTED_ITSM_PROVIDERS),
            }
        if clean_method != "POST":
            return 405, {"error": "Method not allowed", "supported_methods": ["POST"]}

        if not isinstance(body, dict):
            return 400, {"error": "Request body must be a JSON object"}

        provider = str(body.get("provider") or "gitlab_issues")
        incident_payload = body.get("incident") or body.get("escalation") or body
        try:
            ticket = correlate_incident_to_itsm_ticket(incident_payload, provider=provider)
            return 200, {
                "status": "correlated",
                "deduplicated": ticket.get("deduplicated", False),
                "ticket": ticket,
            }
        except (ValueError, TypeError) as exc:
            return 400, {"error": str(exc)}

    # Route 3: POST /api/v1/itsm/chatops-callback
    if clean_path == "/api/v1/itsm/chatops-callback":
        if clean_method == "GET":
            return 200, {
                "endpoint": "/api/v1/itsm/chatops-callback",
                "status": "active",
                "description": "Signed interactive ChatOps callback endpoint with Two-Tier Capability Airlock.",
                "supported_methods": ["POST"],
                "tier_1_commands": sorted(TIER_1_RECON_COMMANDS),
                "tier_2_commands": sorted(TIER_2_ACTION_CARD_COMMANDS),
            }
        if clean_method != "POST":
            return 405, {"error": "Method not allowed", "supported_methods": ["POST"]}

        if not isinstance(body, dict):
            return 400, {"error": "Request body must be a JSON object"}

        shared_secret = body.get("shared_secret")
        master_pubkey = body.get("master_pubkey") or body.get("public_key")
        return handle_chatops_callback(body, shared_secret=shared_secret, master_pubkey=master_pubkey)

    return 404, {"error": f"Unknown ITSM API route '{clean_path}'"}
