# SPDX-License-Identifier: Apache-2.0
"""Read-only identity and secret-service observations from snapshot resources."""

import re

from oidc_rbac_verifier import audit_cluster_ingress_oidc_posture
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


def resource_records(catalog):
    """Yield deterministic identity/resource pairs from a validated snapshot."""
    for node in sorted(catalog["nodes"], key=lambda item: item["id"]):
        if "resource" not in node:
            continue
        resource = node["resource"]
        metadata = resource.get("metadata", {})
        yield {
            "node_id": node["id"],
            "kind": node.get("resource_kind", resource.get("kind")),
            "namespace": metadata.get("namespace", node.get("namespace", "default")),
            "name": metadata.get("name", node.get("label", node["id"])),
        }, resource


def pod_posture(resource):
    """Keep phase, Ready and crash evidence separate; absence is unknown."""
    status = resource.get("status", {})
    conditions = [c["status"] for c in status.get("conditions", [])
                  if c.get("type") == "Ready" and "status" in c]
    ready = (False if "False" in conditions else
             True if conditions and all(c == "True" for c in conditions) else None)
    crashing = any(c.get("state", {}).get("waiting", {}).get("reason")
                   == "CrashLoopBackOff"
                   for field in ("containerStatuses", "initContainerStatuses")
                   for c in status.get(field, []))
    phase = status.get("phase")
    return {"phase": phase, "ready": ready, "crash_loop": crashing,
            "status": ("degraded" if crashing or ready is False or
                       phase in {"Failed", "Pending", "Unknown"} else
                       "ready_observed" if phase == "Running" and ready is True
                       else "unknown")}


def inspect_openbao_and_externalsecrets(catalog):
    """Observe explicit seal and sync fields; readiness cannot prove unsealed."""
    openbao, external = [], []
    for row, resource in resource_records(catalog):
        if row["kind"] == "Pod" and re.fullmatch(r"openbao-\d+", row["name"]):
            status = resource.get("status", {})
            sealed = status.get("sealed")
            openbao.append({**row, **pod_posture(resource),
                            "sealed": sealed,
                            "seal_status": ("sealed" if sealed is True else
                                            "unsealed_observed" if sealed is False
                                            else "unknown")})
        elif row["kind"] == "ExternalSecret":
            conditions = [c.get("status") for c in
                          resource.get("status", {}).get("conditions", [])
                          if c.get("type") == "Ready"]
            external.append({**row, "sync_status": (
                "not_synced" if "False" in conditions else
                "synced_observed" if conditions and all(c == "True" for c in conditions)
                else "unknown")})
    return sanitize({"openbao": openbao, "external_secrets": external,
                     "live_enforcement_verified": False})


def inspect_oidc_and_ingress_auth(catalog):
    """Combine Authentik pod observations with the existing ingress audit."""
    authentik = [{**row, **pod_posture(resource)}
                 for row, resource in resource_records(catalog)
                 if row["kind"] == "Pod" and "authentik" in row["name"].casefold()]
    ingress = audit_cluster_ingress_oidc_posture(catalog)
    if ingress["status"] == "invalid_catalog":
        raise ValueError("Invalid secops cockpit catalog")
    return sanitize({"authentik": authentik, "ingress_auth": ingress,
                     "oidc_runtime_verified": False})
