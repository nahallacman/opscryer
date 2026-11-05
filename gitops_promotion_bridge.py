# SPDX-License-Identifier: Apache-2.0
"""2-Stage GitOps Dev-to-Prod Promotion Bridge (Wave 3 Milestone 11).

Governs promotion between the fast-test dev deployment (``opscryer-suite-dev``
in ``dev-envs``) and the ArgoCD-reconciled production deployment
(``opscryer-prod`` in ``security``):

1. Thread-safe in-memory state tracking ``dev_environment_state``,
   ``prod_environment_state``, and staged promotion records.
2. Deterministic SHA-256 bundle drift detection (``IN_SYNC``, ``DEV_AHEAD``,
   ``PROD_DRIFT``) across module manifests.
3. 2-Stage Promotion Readiness Evaluator:
   - Stage 1A: Full-suite merge gate attestation (tests_passed, zero failures,
     zero errors, zero OPSEC violations, >= 196 tests run).
   - Stage 1B: Live ``dev-envs`` synthetic probe verification (healthz, readyz,
     metrics, mcp all HTTP 200).
4. Stage 2 Cryptographic Action Card stager targeting ``opscryer-prod-security``
   in the critical ``security`` tier with 4-Signal Outcome Predictor threshold
   escalation (k-of-n Shamir lock) and ``direct_prod_apply_allowed=False``.
5. Pure-stdlib HTTP API dispatcher for ``/api/v1/gitops-promotion/*``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
import threading
import time
from typing import Any

import action_cards
import event_stream
import security_airlock
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo

SCHEMA_VERSION = "1.0-gitops-promotion-bridge"
MIN_REQUIRED_TESTS_RUN = 196
REQUIRED_DEV_PROBES = ("healthz", "readyz", "metrics", "mcp")
ARGO_PROD_APP_PATH = "gitops/apps/opscryer-prod.yaml"
PROD_HELM_TEMPLATE_PATH = "infrastructure/opscryer-prod/templates/opscryer-prod.yaml"
PROD_ACTION_TARGET_NODE_ID = "opscryer-prod-security"
COMPARE_BASE_URL = "https://gitlab.example.org/prod/home-k8s/-/compare"

_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")
_OPERATOR_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
_PROD_DRIFT_HASH_MARKERS = (
    "drift",
    "hotfix",
    "dirty",
    "tamper",
    "unreconciled",
    "out_of_band",
    "out-of-band",
    "manual",
    "prod_only",
    "prod-only",
)

# Register promote_to_prod in action_cards permitted action types and ensure
# the critical security-tier target node resolves cleanly during dry-run preview.
action_cards.PERMITTED_ACTION_TYPES = frozenset(
    set(action_cards.PERMITTED_ACTION_TYPES) | {"promote_to_prod"}
)

_ORIGINAL_FIND_CATALOG_NODE = action_cards._find_catalog_node


def _promotion_aware_find_catalog_node(
    target_node_id: str, catalog: dict[str, Any]
) -> dict[str, Any]:
    """Resolve opscryer-prod-security in critical security tier if absent from snapshot."""
    try:
        return _ORIGINAL_FIND_CATALOG_NODE(target_node_id, catalog)
    except KeyError:
        if target_node_id == PROD_ACTION_TARGET_NODE_ID:
            return {
                "id": PROD_ACTION_TARGET_NODE_ID,
                "label": "opscryer-prod",
                "kind": "Deployment",
                "namespace": "security",
                "tier": "security",
            }
        raise


action_cards._find_catalog_node = _promotion_aware_find_catalog_node


def _default_prod_modules() -> dict[str, str]:
    """Return baseline production module SHA-256 manifest."""
    baseline = (
        "action_cards.py",
        "cybersecurity_bridge.py",
        "event_stream.py",
        "mcp_bridge.py",
        "node_federation.py",
        "openapi_spec.py",
        "opscryer_backend.py",
        "opscryer_browser.py",
        "pqc_security.py",
        "route_registry.py",
        "security_airlock.py",
        "telemetry_sanitizer.py",
    )
    return {
        name: hashlib.sha256(f"prod-v2:{name}".encode("utf-8")).hexdigest()
        for name in baseline
    }


def _default_dev_modules() -> dict[str, str]:
    """Return default dev-envs module SHA-256 manifest ahead of prod with Wave 3 modules."""
    modules = _default_prod_modules()
    wave3_additions = (
        "gitops_promotion_bridge.py",
        "live_cluster_collector.py",
        "otlp_trace_exporter.py",
        "resilient_state_store.py",
    )
    for name in wave3_additions:
        modules[name] = hashlib.sha256(f"dev-v3:{name}".encode("utf-8")).hexdigest()
    # Mark core integration descriptors as updated for Wave 3
    for updated in ("opscryer_browser.py", "route_registry.py", "openapi_spec.py"):
        modules[updated] = hashlib.sha256(f"dev-v3:{updated}".encode("utf-8")).hexdigest()
    return modules


def _default_dev_state() -> dict[str, Any]:
    return {
        "deployment": "opscryer-suite-dev",
        "namespace": "dev-envs",
        "tier": "dev",
        "delivery_mode": "ephemeral_fast_test",
        "node": "node-beta",
        "modules": _default_dev_modules(),
        "probes": {
            "healthz": 200,
            "readyz": 200,
            "metrics": 200,
            "mcp": 200,
        },
        "test_attestation": {
            "tests_passed": True,
            "failures": 0,
            "errors": 0,
            "opsec_violations": 0,
            "tests_run": 256,
        },
    }


def _default_prod_state() -> dict[str, Any]:
    container_spec = {
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 10001,
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
        }
    }
    return {
        "deployment": "opscryer-prod",
        "namespace": "security",
        "tier": "security",
        "delivery_mode": "argocd_gitops_reconciled",
        "node": "node-alpha",
        "argo_app": ARGO_PROD_APP_PATH,
        "prod_chart": PROD_HELM_TEMPLATE_PATH,
        "direct_prod_apply_allowed": False,
        "modules": _default_prod_modules(),
        "security_context_audit": security_airlock.audit_container_security_context(container_spec),
    }


_STATE_LOCK = threading.Lock()
_DEV_ENVIRONMENT_STATE: dict[str, Any] = _default_dev_state()
_PROD_ENVIRONMENT_STATE: dict[str, Any] = _default_prod_state()
_STAGED_PROMOTIONS: list[dict[str, Any]] = []


def reset_promotion_bridge() -> dict[str, Any]:
    """Reset in-memory dev/prod environment state and staged promotion records."""
    global _DEV_ENVIRONMENT_STATE, _PROD_ENVIRONMENT_STATE
    with _STATE_LOCK:
        _DEV_ENVIRONMENT_STATE = _default_dev_state()
        _PROD_ENVIRONMENT_STATE = _default_prod_state()
        _STAGED_PROMOTIONS.clear()
        return {
            "status": "reset",
            "dev_environment_state": copy.deepcopy(_DEV_ENVIRONMENT_STATE),
            "prod_environment_state": copy.deepcopy(_PROD_ENVIRONMENT_STATE),
            "staged_promotions": [],
        }


def get_promotion_bridge_state() -> dict[str, Any]:
    """Return a thread-safe deep copy of the current bridge state."""
    with _STATE_LOCK:
        return {
            "dev_environment_state": copy.deepcopy(_DEV_ENVIRONMENT_STATE),
            "prod_environment_state": copy.deepcopy(_PROD_ENVIRONMENT_STATE),
            "staged_promotions": copy.deepcopy(_STAGED_PROMOTIONS),
        }


def _scrub_airlock_output(payload: dict[str, Any]) -> dict[str, Any]:
    """Sanitize promotion payload through security_airlock normalization and telemetry_sanitizer."""
    sanitized = sanitize_live_home_telemetry_for_demo(payload)
    serialized = json.dumps(sanitized, sort_keys=True)
    normalized = security_airlock.normalize_airlock_query(serialized)
    for token_marker in security_airlock._TOKEN_MARKERS:
        if token_marker in normalized:
            raise ValueError("OPSEC airlock blocked token marker in promotion output")
    return sanitized


def _extract_modules_and_meta(
    manifest: dict[str, Any] | None, fallback_modules: dict[str, str]
) -> tuple[dict[str, str], dict[str, Any]]:
    """Extract normalized module->hash mapping and optional metadata flags."""
    if manifest is None:
        return dict(fallback_modules), {}
    if not isinstance(manifest, dict):
        raise TypeError(f"Manifest must be a dict or None, got {type(manifest).__name__}")

    if "modules" in manifest and isinstance(manifest["modules"], dict):
        raw_mods = manifest["modules"]
        meta = {k: v for k, v in manifest.items() if k != "modules"}
    else:
        meta_keys = {
            "out_of_band_drift",
            "prod_drift",
            "manual_hotfix",
            "unreconciled",
            "drift_status",
            "deployment",
            "namespace",
            "generation",
        }
        has_meta = any(k in manifest for k in meta_keys)
        if has_meta:
            raw_mods = {
                k: v for k, v in manifest.items()
                if k not in meta_keys and isinstance(v, str)
            }
            meta = {k: v for k, v in manifest.items() if k in meta_keys}
        else:
            raw_mods = manifest
            meta = {}

    normalized_mods: dict[str, str] = {}
    for k, v in raw_mods.items():
        if not isinstance(k, str) or not k.strip():
            raise ValueError("Module name in manifest must be a non-empty string")
        if not isinstance(v, str) or not v.strip():
            raise ValueError(f"Module hash for '{k}' must be a non-empty string")
        normalized_mods[k.strip()] = v.strip()

    return normalized_mods, meta


def _compute_bundle_sha256(modules: dict[str, str]) -> str:
    """Compute canonical SHA-256 checksum over sorted module hashes."""
    canonical = json.dumps(modules, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def compute_environment_bundle_drift(
    dev_manifest: dict[str, Any] | None = None,
    prod_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare dev (opscryer-suite-dev, dev-envs) vs prod (opscryer-prod, security) bundles.

    Returns schema_version, drift_status (IN_SYNC, DEV_AHEAD, or PROD_DRIFT),
    dev_bundle_sha256, prod_bundle_sha256, changed_modules, added_modules,
    removed_modules, and promotion_required.
    """
    with _STATE_LOCK:
        default_dev_mods = dict(_DEV_ENVIRONMENT_STATE["modules"])
        default_prod_mods = dict(_PROD_ENVIRONMENT_STATE["modules"])

    dev_mods, dev_meta = _extract_modules_and_meta(dev_manifest, default_dev_mods)
    prod_mods, prod_meta = _extract_modules_and_meta(prod_manifest, default_prod_mods)

    dev_bundle_sha256 = _compute_bundle_sha256(dev_mods)
    prod_bundle_sha256 = _compute_bundle_sha256(prod_mods)

    added_modules = sorted(m for m in dev_mods if m not in prod_mods)
    removed_modules = sorted(m for m in prod_mods if m not in dev_mods)
    changed_modules = sorted(
        m for m in dev_mods if m in prod_mods and dev_mods[m] != prod_mods[m]
    )

    explicit_prod_drift = bool(
        prod_meta.get("out_of_band_drift")
        or prod_meta.get("prod_drift")
        or prod_meta.get("manual_hotfix")
        or prod_meta.get("unreconciled")
        or prod_meta.get("drift_status") == "PROD_DRIFT"
    )
    prod_gen = prod_meta.get("generation")
    dev_gen = dev_meta.get("generation")
    if isinstance(prod_gen, int) and isinstance(dev_gen, int) and prod_gen > dev_gen:
        explicit_prod_drift = True

    prod_marker_drift = False
    for m in changed_modules + removed_modules:
        prod_val = prod_mods.get(m, "").lower()
        if any(marker in prod_val for marker in _PROD_DRIFT_HASH_MARKERS):
            prod_marker_drift = True
            break

    if dev_bundle_sha256 == prod_bundle_sha256 and not explicit_prod_drift:
        drift_status = "IN_SYNC"
    elif (
        explicit_prod_drift
        or prod_marker_drift
        or (bool(removed_modules) and not added_modules and not changed_modules)
    ):
        drift_status = "PROD_DRIFT"
    else:
        drift_status = "DEV_AHEAD"

    promotion_required = drift_status != "IN_SYNC"

    return {
        "schema_version": SCHEMA_VERSION,
        "drift_status": drift_status,
        "dev_bundle_sha256": dev_bundle_sha256,
        "prod_bundle_sha256": prod_bundle_sha256,
        "changed_modules": changed_modules,
        "added_modules": added_modules,
        "removed_modules": removed_modules,
        "promotion_required": promotion_required,
        "dev_environment": {
            "deployment": "opscryer-suite-dev",
            "namespace": "dev-envs",
            "module_count": len(dev_mods),
        },
        "prod_environment": {
            "deployment": "opscryer-prod",
            "namespace": "security",
            "module_count": len(prod_mods),
        },
    }


def evaluate_promotion_readiness(
    test_attestation: dict[str, Any] | None = None,
    dev_probes: dict[str, Any] | None = None,
    dev_manifest: dict[str, Any] | None = None,
    prod_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate 2-Stage GitOps promotion readiness across Stage 1A and Stage 1B gates.

    Stage 1A (Full-Suite Merge Gate Attestation):
      - tests_passed is True
      - failures == 0
      - errors == 0
      - opsec_violations == 0
      - tests_run >= 196

    Stage 1B (Live Dev Synthetic Probes in dev-envs):
      - healthz == 200
      - readyz == 200
      - metrics == 200
      - mcp == 200
    """
    with _STATE_LOCK:
        default_att = copy.deepcopy(_DEV_ENVIRONMENT_STATE["test_attestation"])
        default_probes = copy.deepcopy(_DEV_ENVIRONMENT_STATE["probes"])

    if test_attestation is None:
        att = default_att
    elif isinstance(test_attestation, dict):
        if len(test_attestation) == 0:
            att = {}
        else:
            att = {**default_att, **test_attestation}
    else:
        raise TypeError("test_attestation must be a dict or None")

    if dev_probes is None:
        probes = default_probes
    elif isinstance(dev_probes, dict):
        if len(dev_probes) == 0:
            probes = {}
        else:
            probes = {**default_probes, **dev_probes}
    else:
        raise TypeError("dev_probes must be a dict or None")

    blocking_reasons: list[str] = []

    # Stage 1A checks
    raw_passed = att.get("tests_passed", att.get("passed"))
    tests_passed_ok = raw_passed is True
    failures_val = att.get("failures")
    failures_ok = type(failures_val) is int and failures_val == 0
    errors_val = att.get("errors")
    errors_ok = type(errors_val) is int and errors_val == 0
    opsec_val = att.get("opsec_violations")
    opsec_ok = type(opsec_val) is int and opsec_val == 0
    tests_run_val = att.get("tests_run")
    tests_run_ok = type(tests_run_val) is int and tests_run_val >= MIN_REQUIRED_TESTS_RUN

    if not tests_passed_ok:
        blocking_reasons.append("Stage 1A failed: tests_passed must be True")
    if not failures_ok:
        blocking_reasons.append(f"Stage 1A failed: test failures must be 0 (got {failures_val})")
    if not errors_ok:
        blocking_reasons.append(f"Stage 1A failed: test errors must be 0 (got {errors_val})")
    if not opsec_ok:
        blocking_reasons.append(
            f"Stage 1A failed: opsec_violations must be 0 (got {opsec_val})"
        )
    if not tests_run_ok:
        blocking_reasons.append(
            f"Stage 1A failed: tests_run must be >= {MIN_REQUIRED_TESTS_RUN} (got {tests_run_val})"
        )

    stage1a_passed = (
        tests_passed_ok and failures_ok and errors_ok and opsec_ok and tests_run_ok
    )

    # Stage 1B checks
    probe_results: dict[str, bool] = {}
    for probe_name in REQUIRED_DEV_PROBES:
        status_val = probes.get(probe_name)
        ok = type(status_val) is int and status_val == 200
        probe_results[probe_name] = ok
        if not ok:
            blocking_reasons.append(
                f"Stage 1B failed: dev-envs probe '{probe_name}' returned {status_val} (expected 200)"
            )

    stage1b_passed = all(probe_results.values())
    stage1_passed = stage1a_passed and stage1b_passed

    drift = compute_environment_bundle_drift(
        dev_manifest=dev_manifest, prod_manifest=prod_manifest
    )

    stage1_checks = {
        "stage1a_merge_gate_attestation": {
            "passed": stage1a_passed,
            "tests_passed": tests_passed_ok,
            "failures_zero": failures_ok,
            "errors_zero": errors_ok,
            "opsec_violations_zero": opsec_ok,
            "tests_run_sufficient": tests_run_ok,
            "min_required_tests_run": MIN_REQUIRED_TESTS_RUN,
            "observed": {
                "tests_passed": raw_passed,
                "failures": failures_val,
                "errors": errors_val,
                "opsec_violations": opsec_val,
                "tests_run": tests_run_val,
            },
        },
        "stage1b_dev_synthetic_probes": {
            "passed": stage1b_passed,
            "namespace": "dev-envs",
            "deployment": "opscryer-suite-dev",
            "probes_ok": probe_results,
            "observed_status_codes": {k: probes.get(k) for k in REQUIRED_DEV_PROBES},
        },
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "stage1_passed": stage1_passed,
        "ready_for_stage2_action_card": stage1_passed,
        "blocking_reasons": blocking_reasons,
        "drift": drift,
        "stage1_checks": stage1_checks,
    }


def _validate_branch_and_operator(
    operator_id: Any, source_branch: Any, target_branch: Any
) -> tuple[str, str, str]:
    if not isinstance(operator_id, str) or not _OPERATOR_RE.fullmatch(operator_id.strip()):
        raise ValueError("Invalid operator_id: must be a non-empty alphanumeric/hyphen identifier")
    if not isinstance(source_branch, str) or not _BRANCH_RE.fullmatch(source_branch.strip()):
        raise ValueError("Invalid source_branch: must be a safe git branch ref")
    if not isinstance(target_branch, str) or not _BRANCH_RE.fullmatch(target_branch.strip()):
        raise ValueError("Invalid target_branch: must be a safe git branch ref")
    clean_source = source_branch.strip()
    clean_target = target_branch.strip()
    if ".." in clean_source or ".." in clean_target:
        raise ValueError("Branch names must not contain '..' path traversal sequences")
    if clean_source == clean_target:
        raise ValueError("source_branch and target_branch must be distinct")
    return operator_id.strip(), clean_source, clean_target


def stage_gitops_prod_promotion(
    operator_id: str = "operator-lead",
    source_branch: str = "feat/opscryer-wave3-release",
    target_branch: str = "main",
    test_attestation: dict[str, Any] | None = None,
    dev_probes: dict[str, Any] | None = None,
    dev_manifest: dict[str, Any] | None = None,
    prod_manifest: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Evaluate Stage 1 gates and stage a cryptographically signed Stage 2 Action Card."""
    try:
        safe_operator, safe_source, safe_target = _validate_branch_and_operator(
            operator_id, source_branch, target_branch
        )
    except ValueError as exc:
        return 400, {"error": str(exc), "code": "INVALID_PROMOTION_PARAMETERS"}

    try:
        readiness = evaluate_promotion_readiness(
            test_attestation=test_attestation,
            dev_probes=dev_probes,
            dev_manifest=dev_manifest,
            prod_manifest=prod_manifest,
        )
    except (TypeError, ValueError) as exc:
        return 400, {"error": str(exc), "code": "INVALID_READINESS_PAYLOAD"}

    if not readiness["stage1_passed"]:
        return 409, {
            "error": "Stage 1 promotion gates not satisfied",
            "readiness": _scrub_airlock_output(readiness),
        }

    drift = readiness["drift"]
    compare_url = f"{COMPARE_BASE_URL}/{safe_target}...{safe_source}"
    promotion_id = f"promo-{secrets.token_hex(8)}"
    staged_at = time.time()

    card_parameters = {
        "promotion_id": promotion_id,
        "operator_id": safe_operator,
        "source_branch": safe_source,
        "target_branch": safe_target,
        "source_environment": "dev-envs/opscryer-suite-dev",
        "target_environment": "security/opscryer-prod",
        "dev_bundle_sha256": drift["dev_bundle_sha256"],
        "prod_bundle_sha256": drift["prod_bundle_sha256"],
        "drift_status": drift["drift_status"],
        "changed_modules": drift["changed_modules"],
        "added_modules": drift["added_modules"],
        "removed_modules": drift["removed_modules"],
        "argo_app": ARGO_PROD_APP_PATH,
        "prod_chart": PROD_HELM_TEMPLATE_PATH,
        "direct_prod_apply_allowed": False,
        "compare_url": compare_url,
    }

    card = action_cards.stage_action_card(
        target_node_id=PROD_ACTION_TARGET_NODE_ID,
        action_type="promote_to_prod",
        parameters=card_parameters,
    )

    promotion_plan = {
        "promotion_id": promotion_id,
        "action_id": card["action_id"],
        "operator_id": safe_operator,
        "source_branch": safe_source,
        "target_branch": safe_target,
        "argo_app": ARGO_PROD_APP_PATH,
        "prod_chart": PROD_HELM_TEMPLATE_PATH,
        "direct_prod_apply_allowed": False,
        "compare_url": compare_url,
        "source_environment": {
            "deployment": "opscryer-suite-dev",
            "namespace": "dev-envs",
            "bundle_sha256": drift["dev_bundle_sha256"],
        },
        "target_environment": {
            "deployment": "opscryer-prod",
            "namespace": "security",
            "bundle_sha256": drift["prod_bundle_sha256"],
        },
        "changed_modules": drift["changed_modules"],
        "added_modules": drift["added_modules"],
        "removed_modules": drift["removed_modules"],
    }

    worrisomeness = card.get("worrisomeness", {})
    threshold_lock = {
        "mode": worrisomeness.get("mode", "threshold"),
        "escalate_to_threshold": worrisomeness.get("escalate_to_threshold", True),
        "required_k": worrisomeness.get("required_k", 2),
        "required_n": worrisomeness.get("required_n", 3),
        "risk_level": worrisomeness.get("risk_level", "HIGH"),
        "signals_triggered": worrisomeness.get("signals_triggered", []),
    }

    record = {
        "schema_version": SCHEMA_VERSION,
        "status": "STAGED_FOR_APPROVAL",
        "promotion_id": promotion_id,
        "action_id": card["action_id"],
        "operator_id": safe_operator,
        "source_branch": safe_source,
        "target_branch": safe_target,
        "argo_app": ARGO_PROD_APP_PATH,
        "prod_chart": PROD_HELM_TEMPLATE_PATH,
        "direct_prod_apply_allowed": False,
        "compare_url": compare_url,
        "promotion_plan": promotion_plan,
        "action_card": card,
        "worrisomeness": worrisomeness,
        "threshold_lock": threshold_lock,
        "readiness": readiness,
        "drift": drift,
        "staged_at": staged_at,
    }

    clean_record = _scrub_airlock_output(record)

    with _STATE_LOCK:
        _STAGED_PROMOTIONS.append(copy.deepcopy(clean_record))

    try:
        event_stream.publish_event(
            "system",
            "gitops_promotion_staged",
            {
                "promotion_id": promotion_id,
                "action_id": card["action_id"],
                "operator_id": safe_operator,
                "source_branch": safe_source,
                "target_branch": safe_target,
                "compare_url": compare_url,
                "dev_bundle_sha256": drift["dev_bundle_sha256"],
                "prod_bundle_sha256": drift["prod_bundle_sha256"],
                "required_k": threshold_lock["required_k"],
                "required_n": threshold_lock["required_n"],
            },
        )
    except Exception:
        pass

    return 200, clean_record


def handle_gitops_promotion_api(
    path: str,
    method: str = "GET",
    query: dict[str, Any] | None = None,
    body: dict[str, Any] | str | bytes | None = None,
) -> tuple[int, dict[str, Any]]:
    """Dispatch HTTP requests for /api/v1/gitops-promotion/* routes."""
    clean_path = (path or "").split("?", 1)[0].strip()
    if len(clean_path) > 1:
        clean_path = clean_path.rstrip("/")
    clean_method = (method or "GET").upper().strip()
    _ = query or {}

    if clean_path == "/api/v1/gitops-promotion/status":
        if clean_method != "GET":
            return 405, {
                "error": f"Method '{clean_method}' not allowed for {clean_path}",
                "supported_methods": ["GET"],
            }
        with _STATE_LOCK:
            dev_state = copy.deepcopy(_DEV_ENVIRONMENT_STATE)
            prod_state = copy.deepcopy(_PROD_ENVIRONMENT_STATE)
            staged_list = copy.deepcopy(_STAGED_PROMOTIONS)

        drift = compute_environment_bundle_drift(
            dev_manifest=dev_state["modules"],
            prod_manifest=prod_state["modules"],
        )
        readiness = evaluate_promotion_readiness(
            test_attestation=dev_state["test_attestation"],
            dev_probes=dev_state["probes"],
            dev_manifest=dev_state["modules"],
            prod_manifest=prod_state["modules"],
        )

        dev_posture = {
            "deployment": dev_state["deployment"],
            "namespace": dev_state["namespace"],
            "tier": dev_state["tier"],
            "delivery_mode": dev_state["delivery_mode"],
            "node": dev_state["node"],
            "bundle_sha256": drift["dev_bundle_sha256"],
            "module_count": len(dev_state["modules"]),
            "probes": dev_state["probes"],
            "test_attestation": dev_state["test_attestation"],
        }
        prod_posture = {
            "deployment": prod_state["deployment"],
            "namespace": prod_state["namespace"],
            "tier": prod_state["tier"],
            "delivery_mode": prod_state["delivery_mode"],
            "node": prod_state["node"],
            "argo_app": prod_state["argo_app"],
            "prod_chart": prod_state["prod_chart"],
            "direct_prod_apply_allowed": False,
            "bundle_sha256": drift["prod_bundle_sha256"],
            "module_count": len(prod_state["modules"]),
            "security_context_audit": prod_state["security_context_audit"],
        }

        status_payload = {
            "schema_version": SCHEMA_VERSION,
            "endpoint": "/api/v1/gitops-promotion/status",
            "status": "healthy",
            "drift": drift,
            "readiness": readiness,
            "staged_promotions": staged_list,
            "staged_count": len(staged_list),
            "environments": {
                "dev-envs": dev_posture,
                "security": prod_posture,
                "dev": dev_posture,
                "prod": prod_posture,
            },
            "dual_environment_posture": {
                "dev-envs": dev_posture,
                "security": prod_posture,
            },
        }
        return 200, _scrub_airlock_output(status_payload)

    if clean_path == "/api/v1/gitops-promotion/stage":
        if clean_method != "POST":
            return 405, {
                "error": f"Method '{clean_method}' not allowed for {clean_path}",
                "supported_methods": ["POST"],
            }

        body_dict: dict[str, Any] = {}
        if body is not None:
            if isinstance(body, dict):
                body_dict = body
            elif isinstance(body, (str, bytes)):
                if isinstance(body, (str, bytes)) and len(body.strip()) > 0:
                    try:
                        parsed = json.loads(body)
                    except Exception:
                        return 400, {"error": "Invalid JSON request body", "code": "INVALID_JSON"}
                    if not isinstance(parsed, dict):
                        return 400, {
                            "error": "JSON request body must be an object",
                            "code": "INVALID_BODY_TYPE",
                        }
                    body_dict = parsed
            else:
                return 400, {
                    "error": "Request body must be a JSON object",
                    "code": "INVALID_BODY_TYPE",
                }

        operator_id = body_dict.get("operator_id", "operator-lead")
        source_branch = body_dict.get("source_branch", "feat/opscryer-wave3-release")
        target_branch = body_dict.get("target_branch", "main")
        test_attestation = body_dict.get("test_attestation")
        dev_probes = body_dict.get("dev_probes")
        dev_manifest = body_dict.get("dev_manifest")
        prod_manifest = body_dict.get("prod_manifest")

        return stage_gitops_prod_promotion(
            operator_id=operator_id,
            source_branch=source_branch,
            target_branch=target_branch,
            test_attestation=test_attestation,
            dev_probes=dev_probes,
            dev_manifest=dev_manifest,
            prod_manifest=prod_manifest,
        )

    return 404, {"error": f"Unknown gitops-promotion route '{clean_path}'"}
