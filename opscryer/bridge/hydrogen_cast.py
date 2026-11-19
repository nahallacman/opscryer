# SPDX-License-Identifier: Apache-2.0
"""OpsCryer bridge for zero-Brain pre-dumped Hydrogen task casts.

Allows OpsCryer UI portals and ``/api/v1/cast/hydrogen`` callers to dispatch
target-only automated casts (e.g., ``{"target": "deploy/agy-ai-orchestrator"}``)
backed by Meshworks' standalone bundle reader and OpsCryer's security airlock +
telemetry sanitizer with zero import-time side effects and zero Brain runtime calls.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9._:/@-]{1,128}$")
_PUBLIC_ALLOWED_CAST_PROVIDERS: Tuple[str, ...] = (
    "ollama",
    "openai_compatible",
    "gemini",
    "deterministic_cutoff",
)
_PUBLIC_ALLOWED_PROVIDER_SET = frozenset(_PUBLIC_ALLOWED_CAST_PROVIDERS)
_BLOCKED_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata", "instance-data"})


def _resolve_within_bundle(root: Path, candidate: Path, *, allow_root: bool = False) -> Path:
    """Resolve candidate strictly within root, rejecting symlinks or traversal escapes."""
    root_resolved = root.resolve()
    cur = candidate
    while cur != root and cur != root_resolved and cur.parent != cur:
        if cur.is_symlink():
            raise ValueError(f"Unsafe symlink component in bundle path: '{cur}'")
        cur = cur.parent
    cand_resolved = candidate.resolve()
    if cand_resolved != root_resolved and not cand_resolved.is_relative_to(root_resolved):
        raise ValueError(f"Unsafe path escape outside bundle root: '{candidate}'")
    if not allow_root and cand_resolved == root_resolved:
        raise ValueError(f"Bundle artifact path cannot point to root directory: '{candidate}'")
    return cand_resolved


def _permitted_cast_host_suffixes() -> tuple[str, ...]:
    """Return local/cluster suffixes plus any configured OPSCRYER_ALLOWED_HOST_SUFFIXES."""
    suffixes = [".cluster.local", ".internal", ".local"]
    raw_extra = os.environ.get("OPSCRYER_ALLOWED_HOST_SUFFIXES", "").strip()
    if raw_extra:
        for item in raw_extra.split(","):
            cleaned = item.strip().lower()
            if cleaned:
                suffixes.append(cleaned if cleaned.startswith(".") else f".{cleaned}")
    return tuple(dict.fromkeys(suffixes))


def _validate_public_cast_endpoint_url(url: str) -> str:
    """Restrict public cast provider endpoint overrides to safe local/private enclave URLs."""
    cleaned = str(url or "").strip()
    if (
        not cleaned
        or not cleaned.startswith(("http://", "https://", "local://"))
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in cleaned)
    ):
        raise ValueError("Invalid cast provider endpoint URL")
    parsed = urlparse(cleaned)
    if parsed.scheme.lower() == "local":
        return cleaned
    if parsed.username or parsed.password:
        raise ValueError("Embedded credentials are forbidden in cast endpoint URL")
    host = (parsed.hostname or "").strip().lower().strip("[]")
    if not host or host in _BLOCKED_METADATA_HOSTS or host in {"0.0.0.0", "::"}:
        raise ValueError("Blocked or missing cast endpoint hostname")
    # Permit loopback hosts, private cluster/local suffixes, or OPSCRYER_ALLOWED_HOST_SUFFIXES overrides.
    if host in {"localhost", "127.0.0.1", "::1"} or any(
        host == suffix.lstrip(".") or host.endswith(suffix)
        for suffix in _permitted_cast_host_suffixes()
    ):
        return cleaned
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(
            "Public cast endpoint_url must target loopback, RFC1918 private, local://, .cluster.local, .internal, or .local"
        ) from exc
    # Allow only loopback or RFC1918 private IPs; explicitly reject link-local IMDS (169.254/16, fe80::/10), multicast, and unspecified.
    if (
        not (addr.is_loopback or addr.is_private)
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    ):
        raise ValueError("Cast endpoint IP is outside permitted local/private enclave ranges")
    return cleaned


def _scrub_public_cast_models_listing(listing: Dict[str, Any]) -> Dict[str, Any]:
    """Filter cast model profiles to public-release-safe providers only."""
    cleaned = dict(listing) if isinstance(listing, dict) else {}
    raw_providers = cleaned.get("supported_providers") or list(_PUBLIC_ALLOWED_CAST_PROVIDERS)
    filtered_providers = [str(p) for p in raw_providers if str(p) in _PUBLIC_ALLOWED_PROVIDER_SET]
    if not filtered_providers:
        filtered_providers = list(_PUBLIC_ALLOWED_CAST_PROVIDERS)
    cleaned["supported_providers"] = filtered_providers

    raw_tiers = cleaned.get("tiers") or []
    filtered_tiers = [
        tier
        for tier in raw_tiers
        if isinstance(tier, dict) and str(tier.get("provider") or "") in _PUBLIC_ALLOWED_PROVIDER_SET
    ]
    surviving_ids = {str(tier.get("tier_id") or "") for tier in filtered_tiers if tier.get("tier_id")}
    cleaned["tiers"] = filtered_tiers
    cleaned["fallback_chain"] = [
        str(tid) for tid in (cleaned.get("fallback_chain") or []) if str(tid) in surviving_ids
    ]
    if str(cleaned.get("default_tier") or "") not in surviving_ids:
        cleaned["default_tier"] = "hydrogen" if "hydrogen" in surviving_ids else (next(iter(surviving_ids), "hydrogen"))
    return cleaned
_SECRET_QUERY_RE = re.compile(
    r"\b(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret)\b"
    r"|(?:gl" + r"pat-|gh" + r"p_|gh" + r"o_|s" + r"k-)",
    re.IGNORECASE,
)


def _meshworks_repo_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "meshworks"


def _default_predump_dir() -> Path:
    env_dir = os.environ.get("MESHWORKS_PREDUMP_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    return Path(__file__).resolve().parents[3] / "brain" / "data" / "predumped_bundle"


def _ensure_sibling_meshworks_on_path() -> bool:
    repo = _meshworks_repo_dir()
    if repo.is_dir():
        repo_str = str(repo)
        if repo_str not in sys.path:
            sys.path.append(repo_str)
        return True
    return False


def _ensure_opscryer_root_on_path() -> None:
    root = str(Path(__file__).resolve().parents[2])
    if root not in sys.path:
        sys.path.insert(0, root)


def _is_contract_catalog(catalog: Optional[Dict[str, Any]]) -> bool:
    # KnowledgeGraphBackendEngine requires schema_version plus a non-empty list of nodes.
    return (
        isinstance(catalog, dict)
        and bool(catalog.get("schema_version"))
        and isinstance(catalog.get("nodes"), list)
    )


def _iter_catalog_nodes(catalog: Optional[Dict[str, Any]]) -> List[Tuple[str, Dict[str, Any]]]:
    if not isinstance(catalog, dict):
        return []
    raw_nodes = catalog.get("nodes")
    if isinstance(raw_nodes, dict):
        return [(str(nid), attrs) for nid, attrs in raw_nodes.items() if isinstance(attrs, dict)]
    if isinstance(raw_nodes, list):
        items: List[Tuple[str, Dict[str, Any]]] = []
        for attrs in raw_nodes:
            if isinstance(attrs, dict):
                nid = str(attrs.get("id") or attrs.get("node_id") or "")
                if nid:
                    items.append((nid, attrs))
        return items
    return []


def resolve_target_context_from_catalog(
    target: str,
    catalog: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Read matching node attributes from an OpsCryer catalog without mutating it."""
    target_norm = str(target or "").strip()
    target_low = target_norm.lower()
    target_leaf = target_low.rsplit("/", 1)[-1]
    for nid, attrs in _iter_catalog_nodes(catalog):
        nid_low = nid.lower()
        label_low = str(attrs.get("label") or "").lower()
        # Match exact node ID, suffix leaf name, or display label cleanly.
        if nid_low == target_low or nid_low.endswith(f":{target_leaf}") or label_low == target_low:
            return {
                "matched": True,
                "node_id": nid,
                "label": str(attrs.get("label") or nid),
                "kind": str(attrs.get("kind") or ""),
                "domain": str(attrs.get("domain") or ""),
                "health": str(attrs.get("health") or "unknown"),
            }
    return {"matched": False, "target": target_norm}


def _stdlib_list_predumped_fallback(bundle_dir: Optional[Path] = None) -> Dict[str, Any]:
    root = Path(bundle_dir) if bundle_dir is not None else _default_predump_dir()
    manifest_path = root / "bundle-manifest.json"
    if not manifest_path.is_file():
        return {
            "available": False,
            "skills_mode": "predumped_standalone",
            "brain_checks_performed": 0,
            "bundle_dir": str(root),
            "skill_count": 0,
            "skills": [],
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    skills = manifest.get("skills") if isinstance(manifest.get("skills"), list) else []
    return {
        "available": True,
        "schema_version": str(manifest.get("schema_version") or "brain-predumped-bundle/v1"),
        "skills_mode": "predumped_standalone",
        "brain_checks_performed": 0,
        "bundle_dir": str(root),
        "skill_count": len(skills),
        "skills": skills,
    }


def _parse_optional_str_list(raw: Any) -> Optional[List[str]]:
    if raw is None:
        return None
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    if isinstance(raw, str):
        return [item.strip() for item in raw.split(",") if item.strip()]
    raise ValueError("Expected list or comma-delimited string")


def _stdlib_list_cast_models_fallback(bundle_dir: Optional[Path] = None) -> Dict[str, Any]:
    root = Path(bundle_dir) if bundle_dir is not None else _default_predump_dir()
    cfg_path = root / "cast-models.json"
    default_tiers = {
        "hydrogen": {
            "rank": 30,
            "provider": os.environ.get("MESHWORKS_HYDROGEN_PROVIDER") or "ollama",
            "model_name": os.environ.get("MESHWORKS_HYDROGEN_MODEL") or "nemotron-mini:4b",
            "base_url": os.environ.get("MESHWORKS_HYDROGEN_ENDPOINT") or "http://localhost:11434",
            "cost_per_1k_usd": 0.0,
            "max_prompt_tokens": 400,
            "num_predict": 192,
            "requires_credential": False,
            "llm_inference_required": True,
        },
        "zero_token_cutoff": {
            "rank": 0,
            "provider": "deterministic_cutoff",
            "model_name": "predumped-template-only",
            "base_url": "local://deterministic-cutoff",
            "cost_per_1k_usd": 0.0,
            "max_prompt_tokens": 140,
            "num_predict": 0,
            "requires_credential": False,
            "llm_inference_required": False,
        },
    }
    default_tier = "hydrogen"
    fallback_chain = ["hydrogen", "zero_token_cutoff"]
    if cfg_path.is_file():
        overlay = json.loads(cfg_path.read_text(encoding="utf-8"))
        if isinstance(overlay, dict) and isinstance(overlay.get("tiers"), dict):
            for tid, spec in overlay["tiers"].items():
                if isinstance(spec, dict):
                    merged = dict(default_tiers.get(tid, {}))
                    merged.update(spec)
                    default_tiers[tid] = merged
        if isinstance(overlay, dict) and overlay.get("default_tier"):
            default_tier = str(overlay["default_tier"])
        if isinstance(overlay, dict) and isinstance(overlay.get("fallback_chain"), list):
            fallback_chain = [str(item) for item in overlay["fallback_chain"]]
    tiers_out = [
        {"tier_id": tid, **spec}
        for tid, spec in sorted(default_tiers.items(), key=lambda item: (-int(item[1].get("rank", 15)), item[0]))
    ]
    return _scrub_public_cast_models_listing({
        "schema_version": "brain-cast-models/v1",
        "skills_mode": "predumped_standalone",
        "brain_checks_performed": 0,
        "default_tier": default_tier,
        "supported_providers": list(_PUBLIC_ALLOWED_CAST_PROVIDERS),
        "fallback_chain": fallback_chain,
        "tiers": tiers_out,
    })


def _stdlib_cast_fallback(
    target: str,
    skill_id: Optional[str] = None,
    query: Optional[str] = None,
    bundle_dir: Optional[Path] = None,
    model_name: Optional[str] = None,
    max_prompt_tokens: Optional[int] = None,
    model_tier: Optional[str] = None,
    provider: Optional[str] = None,
    service_cutoff: bool = False,
    quota_exhausted: bool = False,
    unavailable_providers: Optional[List[str]] = None,
    unavailable_tiers: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Pure-stdlib fallback cast builder when sibling ``meshworks`` repo is absent."""
    root = Path(bundle_dir) if bundle_dir is not None else _default_predump_dir()
    requested_tier = model_tier or "hydrogen"
    candidate_prov = (
        provider
        or (os.environ.get("MESHWORKS_HYDROGEN_PROVIDER") if requested_tier == "hydrogen" else None)
        or "ollama"
    )
    if candidate_prov not in _PUBLIC_ALLOWED_PROVIDER_SET:
        raise ValueError(f"Unsupported public cast provider: '{candidate_prov}'")
    # Downgrade standalone casts to zero_token_cutoff on service cutoff, quota exhaustion, or blocked tier/provider.
    force_cutoff = bool(
        service_cutoff
        or quota_exhausted
        or (unavailable_tiers and requested_tier in unavailable_tiers)
        or (unavailable_providers and candidate_prov in unavailable_providers)
    )
    effective_tier = "zero_token_cutoff" if force_cutoff else requested_tier
    effective_prov = "deterministic_cutoff" if effective_tier == "zero_token_cutoff" else candidate_prov
    effective_model = (
        "predumped-template-only"
        if effective_tier == "zero_token_cutoff"
        else str(model_name or os.environ.get("MESHWORKS_HYDROGEN_MODEL") or "nemotron-mini:4b")
    )
    failover_occurred = bool(force_cutoff or effective_tier != requested_tier)
    effective_budget = max(80, int(max_prompt_tokens if max_prompt_tokens is not None else (140 if effective_tier == "zero_token_cutoff" else 400)))
    manifest_path = root / "bundle-manifest.json"
    if manifest_path.is_symlink() or manifest_path.exists():
        manifest_path = _resolve_within_bundle(root, manifest_path)
    anchor: Dict[str, Any] = {
        "skill_id": skill_id or "deploy-k8s",
        "source_tier": "builtin",
        "version": "1.0.0",
        "default_playbook": "k8s-deploy-rollout",
        "command_templates": [f"kubectl rollout status {target} --timeout=60s"],
        "verification_checks": ["Verify target pods report Ready=True cleanly."],
        "stop_conditions": ["Never query Central Brain at runtime in predumped standalone mode."],
        "subgraph_slice": {"nodes": {}, "edges": []},
        "jev_anchors": [],
    }
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        skills = [s for s in (manifest.get("skills") or []) if isinstance(s, dict)]
        chosen = next((s for s in skills if s.get("id") == skill_id), None) if skill_id else None
        if chosen is None and skills:
            chosen = next((s for s in skills if s.get("id") == "deploy-k8s"), skills[0])
        if chosen is not None:
            rel_anchor = str(chosen.get("context_anchor_path") or "").strip()
            if (
                not rel_anchor
                or rel_anchor.startswith(("/", "\\"))
                or "\\" in rel_anchor
                or ".." in Path(rel_anchor).parts
            ):
                raise ValueError(f"Unsafe context_anchor_path '{rel_anchor}' in bundle manifest")
            anchor_file = _resolve_within_bundle(root, root / rel_anchor)
            if anchor_file.is_file():
                anchor = json.loads(anchor_file.read_text(encoding="utf-8"))

    bound_cmds = [str(c).replace("{target}", target) for c in anchor.get("command_templates", [])]
    if not bound_cmds:
        bound_cmds = [f"kubectl rollout status {target} --timeout=60s"]
    sys_prompt = (
        f"Hydrogen runner for skill {anchor.get('skill_id', 'deploy-k8s')}. "
        f"Zero Brain checks at runtime. Use only preloaded commands for {target}."
    )
    usr_prompt = f"Target -> {target}\nPlaybook -> {anchor.get('default_playbook', 'k8s-deploy-rollout')}\nCommands -> {'; '.join(bound_cmds[:3])}"
    est_tokens = max(1, (len(f"{sys_prompt}\n{usr_prompt}".encode("utf-8")) + 3) // 4)
    digest = hashlib.sha256(f"{target}:{anchor.get('skill_id')}:{';'.join(bound_cmds)}".encode("utf-8")).hexdigest()
    return {
        "schema_version": "hydrogen-cast-envelope/v1",
        "skills_mode": "predumped_standalone",
        "brain_checks_performed": 0,
        "model_tier": effective_tier,
        "provider": effective_prov,
        "model_name": effective_model,
        "llm_inference_required": effective_prov != "deterministic_cutoff",
        "cost_per_1k_usd": 0.0,
        "model_resolution": {
            "requested_tier": requested_tier,
            "resolved_tier": effective_tier,
            "provider": effective_prov,
            "model_name": effective_model,
            "failover_occurred": failover_occurred,
            "service_cutoff": bool(service_cutoff),
            "quota_exhausted": bool(quota_exhausted),
        },
        "target": target,
        "skill_id": str(anchor.get("skill_id") or "deploy-k8s"),
        "source_tier": str(anchor.get("source_tier") or "builtin"),
        "skill_version": str(anchor.get("version") or "1.0.0"),
        "playbook": str(anchor.get("default_playbook") or "k8s-deploy-rollout"),
        "system_prompt": sys_prompt,
        "user_prompt": usr_prompt,
        "estimated_prompt_tokens": est_tokens,
        "token_budget": effective_budget,
        "within_token_budget": est_tokens <= effective_budget,
        "bound_commands": bound_cmds,
        "verification_checks": list(anchor.get("verification_checks") or []),
        "stop_conditions": list(anchor.get("stop_conditions") or []),
        "kg_slice": anchor.get("subgraph_slice") or {"nodes": {}, "edges": []},
        "jev_anchors": list(anchor.get("jev_anchors") or []),
        "ollama_generate_payload": {
            "model": model_name,
            "system": sys_prompt,
            "prompt": usr_prompt,
            "stream": False,
            "options": {"temperature": 0.0, "num_predict": 192},
        },
        "golf_score": {"score": 0, "tier": "PAR_GROUNDED", "violations": []},
        "summary": f"Cast {anchor.get('skill_id', 'deploy-k8s')} -> target {target} via predumped standalone anchor.",
        "cast_sha256": digest,
    }


def handle_hydrogen_cast_request(
    body: Optional[Dict[str, Any]],
    catalog: Optional[Dict[str, Any]] = None,
    predumped_bundle_dir: Optional[Path] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Validate, cast, optionally stage an action card, and sanitize a Hydrogen standalone cast."""
    _ensure_opscryer_root_on_path()
    import action_cards
    import security_airlock
    import telemetry_sanitizer

    payload = body if isinstance(body, dict) else {}
    action = str(payload.get("action") or "").strip()
    if action == "list_cast_models":
        if _ensure_sibling_meshworks_on_path():
            from meshworks.cast_models import list_cast_model_profiles

            listed = list_cast_model_profiles(bundle_dir=predumped_bundle_dir)
        else:
            listed = _stdlib_list_cast_models_fallback(bundle_dir=predumped_bundle_dir)
        scrubbed = _scrub_public_cast_models_listing(listed)
        return 200, telemetry_sanitizer.sanitize_live_home_telemetry_for_demo(scrubbed)
    if action == "list_predumped_harnesses":
        if _ensure_sibling_meshworks_on_path():
            from meshworks.cast_harness import list_predumped_harnesses

            listed = list_predumped_harnesses(bundle_dir=predumped_bundle_dir)
        else:
            listed = _stdlib_list_predumped_fallback(bundle_dir=predumped_bundle_dir)
        return 200, telemetry_sanitizer.sanitize_live_home_telemetry_for_demo(listed)

    raw_text_for_airlock = " ".join(
        str(payload.get(field) or "")
        for field in ("target", "query", "skill", "skill_id")
    ).strip()
    if _SECRET_QUERY_RE.search(raw_text_for_airlock):
        return 403, {"error": "secret_hunting_blocked", "airlock_blocked": True}

    contract_catalog = catalog if _is_contract_catalog(catalog) else None
    airlock_check = security_airlock.evaluate_code_search_airlock(
        f"manifest {raw_text_for_airlock}".strip(),
        catalog=contract_catalog,
    )
    if airlock_check.get("reason") == "secret_hunting_blocked":
        return 403, {"error": "secret_hunting_blocked", "airlock_blocked": True}

    target = str(payload.get("target") or "").strip()
    if not target:
        return 400, {
            "error": "missing_target",
            "detail": "Field 'target' is required for predumped Hydrogen cast.",
        }
    if not _SAFE_TARGET_RE.fullmatch(target):
        return 400, {
            "error": "invalid_target",
            "detail": "Target must match [A-Za-z0-9._:/@-]{1,128}.",
        }

    target_ctx = resolve_target_context_from_catalog(target, catalog=catalog)
    skill_id = str(payload.get("skill_id") or payload.get("skill") or "").strip() or None
    query = str(payload.get("query") or "").strip() or None
    model_name = str(payload.get("model") or payload.get("model_name") or "").strip() or None
    model_tier = str(payload.get("model_tier") or payload.get("tier") or "").strip() or None
    provider = str(payload.get("provider") or "").strip() or None
    endpoint_url = str(payload.get("endpoint_url") or payload.get("endpoint") or "").strip() or None
    service_cutoff = bool(payload.get("service_cutoff", False))
    quota_exhausted = bool(payload.get("quota_exhausted", False))

    try:
        raw_budget = payload.get("max_prompt_tokens")
        max_prompt_tokens = int(raw_budget) if raw_budget is not None else None
        raw_cost = (
            payload.get("max_cost_per_1k_usd")
            if "max_cost_per_1k_usd" in payload
            else payload.get("max_cost_usd")
        )
        max_cost_per_1k_usd = float(raw_cost) if raw_cost is not None else None
        unavailable_providers = _parse_optional_str_list(payload.get("unavailable_providers"))
        unavailable_tiers = _parse_optional_str_list(payload.get("unavailable_tiers"))

        if provider is not None and provider not in _PUBLIC_ALLOWED_PROVIDER_SET:
            raise ValueError(f"Unsupported public cast provider: {provider}")
        if endpoint_url is not None:
            endpoint_url = _validate_public_cast_endpoint_url(endpoint_url)

        if _ensure_sibling_meshworks_on_path():
            from meshworks.cast_harness import cast_hydrogen_task

            envelope = cast_hydrogen_task(
                target=target,
                skill_id=skill_id,
                query=query,
                bundle_dir=predumped_bundle_dir,
                target_context=target_ctx if target_ctx.get("matched") else None,
                model_name=model_name,
                max_prompt_tokens=max_prompt_tokens,
                model_tier=model_tier,
                provider=provider,
                endpoint_url=endpoint_url,
                service_cutoff=service_cutoff,
                quota_exhausted=quota_exhausted,
                unavailable_providers=unavailable_providers,
                unavailable_tiers=unavailable_tiers,
                max_cost_per_1k_usd=max_cost_per_1k_usd,
                allowed_providers=list(_PUBLIC_ALLOWED_CAST_PROVIDERS),
                allow_builtin_fallback=True,
            )
        else:
            envelope = _stdlib_cast_fallback(
                target=target,
                skill_id=skill_id,
                query=query,
                bundle_dir=predumped_bundle_dir,
                model_name=model_name,
                max_prompt_tokens=max_prompt_tokens,
                model_tier=model_tier,
                provider=provider,
                service_cutoff=service_cutoff,
                quota_exhausted=quota_exhausted,
                unavailable_providers=unavailable_providers,
                unavailable_tiers=unavailable_tiers,
            )
    except (ValueError, TypeError, PermissionError) as exc:
        return 400, {
            "error": "invalid_cast_model_config",
            "detail": str(exc) if isinstance(exc, ValueError) else "Disallowed or invalid cast model configuration",
        }

    dispatch_mode = str(payload.get("dispatch_mode") or "preview").strip()
    envelope["dispatch_mode"] = dispatch_mode
    envelope["catalog_context"] = target_ctx

    if dispatch_mode == "stage_action_card":
        action_type = str(payload.get("action_type") or "restart_node").strip()
        if action_type not in action_cards.PERMITTED_ACTION_TYPES:
            return 400, {
                "error": "invalid_action_type",
                "permitted_action_types": sorted(action_cards.PERMITTED_ACTION_TYPES),
            }
        candidate_node_id = str(target_ctx.get("node_id") or target)
        try:
            card = action_cards.stage_action_card(
                target_node_id=candidate_node_id,
                action_type=action_type,
                parameters={
                    "skills_mode": "predumped_standalone",
                    "skill_id": envelope["skill_id"],
                    "cast_sha256": envelope["cast_sha256"],
                    "model_tier": envelope.get("model_tier", "hydrogen"),
                    "provider": envelope.get("provider", "ollama"),
                    "failover_occurred": bool(
                        (envelope.get("model_resolution") or {}).get("failover_occurred", False)
                    ),
                },
                catalog=contract_catalog,
            )
            envelope["staged_action_card"] = {"staged": True, "card": card}
        except (KeyError, ValueError):
            envelope["staged_action_card"] = {
                "staged": False,
                "reason": "target_not_in_spatial_catalog",
            }

    sanitized = telemetry_sanitizer.sanitize_live_home_telemetry_for_demo(envelope)
    return 200, sanitized
