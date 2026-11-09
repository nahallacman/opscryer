# SPDX-License-Identifier: Apache-2.0
"""Offline metadata provenance and OpenBao availability posture.

Digests cover canonical workload identity only, never credential material.
Catalog observations cannot attest live Raft membership, seal/KMS health, or
fields omitted by the harvester. No network calls or secret retrieval occur.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re

from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as _sanitize


DEFAULT_CATALOG = Path(__file__).resolve().with_name("live-cluster-sanitized.json")
HARDWARE_NODES = ("nodealpha01", "nodebeta02", "nodegamma03")
_WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
              "Job", "CronJob"}
_SENSITIVE = re.compile(
    r"password|passwd|secret|token|credential|api[_-]?key|private[_-]?key|"
    r"authorization|unseal[_-]?key", re.I)
_REFERENCE = {"secretKeyRef", "secretRef", "secretName", "secret",
              "imagePullSecrets", "secretProviderClass", "secretKeySelector"}
_PLACEHOLDERS = {"[REDACTED]", "<redacted>", "***"}


def _load(catalog):
    try:
        if catalog is None or isinstance(catalog, (str, Path)):
            with Path(DEFAULT_CATALOG if catalog is None else catalog).open(
                    encoding="utf-8") as stream:
                catalog = json.load(stream)
        if not isinstance(catalog, dict) or not isinstance(catalog.get("nodes"), list):
            raise ValueError
        resources = []
        for node in catalog["nodes"]:
            if not isinstance(node, dict):
                raise ValueError
            resource = node.get("resource")
            if resource is None:
                continue  # Spatial graph roots are not Kubernetes resources.
            if (not isinstance(resource, dict) or
                    not isinstance(resource.get("kind"), str) or
                    not isinstance(resource.get("metadata"), dict) or
                    not isinstance(resource["metadata"].get("name"), str)):
                raise ValueError
            resources.append(resource)
        # Reject malformed nested input without echoing any catalog content.
        json.dumps(catalog, allow_nan=False)
        def validate(value):
            if isinstance(value, dict):
                if any(not isinstance(key, str) for key in value):
                    raise ValueError
                for child in value.values():
                    validate(child)
            elif isinstance(value, list):
                for child in value:
                    validate(child)
        validate(catalog)
        for resource in resources:
            if not isinstance(resource.get("spec", {}), dict):
                raise ValueError
            identity = _identity(resource)
            if any(value is not None and not isinstance(value, str)
                   for value in identity.values()):
                raise ValueError
        return resources
    except (OSError, ValueError, TypeError, RecursionError):
        raise ValueError("Unable to load a valid cluster catalog") from None


def _object(value):
    return value if isinstance(value, dict) else {}


def _pod_spec(resource):
    spec = _object(resource.get("spec"))
    if resource["kind"] == "CronJob":
        spec = _object(_object(spec.get("jobTemplate")).get("spec"))
    if resource["kind"] != "Pod":
        spec = _object(_object(spec.get("template")).get("spec"))
    return spec


def _identity(resource):
    metadata = resource["metadata"]
    spec = _pod_spec(resource)
    # Labels, annotations and arbitrary owner metadata can contain credentials.
    # Only explicitly selected identity fields enter this hash domain.
    return {"kind": resource["kind"], "name": metadata["name"],
            "namespace": metadata.get("namespace", "default"),
            "uid": metadata.get("uid"),
            "service_account": spec.get("serviceAccountName", "default")}


def _present(value):
    return value is not None and value != "" and value != {} and value != []


def _leaks(value):
    """Yield fixed codes only; never return keys, paths, or credential values."""
    if isinstance(value, dict):
        name = value.get("name")
        literal = value.get("value")
        if (isinstance(name, str) and _SENSITIVE.search(name) and _present(literal)
                and (not isinstance(literal, str) or literal not in _PLACEHOLDERS)):
            yield "literal_sensitive_environment"
        for key, child in value.items():
            if key in _REFERENCE and isinstance(child, (dict, list)):
                yield from _leaks(child)
                continue
            if key in {"secretName", "secretProviderClass"} and isinstance(child, str):
                continue  # Kubernetes reference identifiers, not secret payloads.
            if _SENSITIVE.search(key) and _present(child):
                if not isinstance(child, str) or child not in _PLACEHOLDERS:
                    yield "literal_sensitive_field"
            else:
                yield from _leaks(child)
    elif isinstance(value, list):
        for child in value:
            yield from _leaks(child)
    elif isinstance(value, str):
        # Sanitizer also recognizes embedded assignments, bearer credentials,
        # token prefixes and JWTs. Do not mistake ordinary IP/MAC redaction
        # for a secret finding.
        if "[REDACTED]" in _sanitize(value) and "[REDACTED]" not in value:
            yield "embedded_sensitive_literal"


def audit_openbao_secret_provenance(catalog=None):
    """Audit supplied graph dict/path, defaulting to the bundled live catalog.

SHA-256 uses UTF-8 canonical JSON (sorted keys, compact separators) of the
sanitized identity. Findings identify resource ordinals and fixed reason codes.
Zero findings means no recognized literals in observed fields, not proof that
omitted specs or unrecognized arbitrary strings are free of secrets.
"""
    resources = _load(catalog)
    workloads, findings = [], []
    observed_specs = 0
    for index, resource in enumerate(resources):
        if isinstance(resource.get("spec"), dict):
            observed_specs += 1
            for code in _leaks(resource["spec"]):
                findings.append({"resource_index": index, "code": code})
        if resource["kind"] == "Secret":
            for field in ("data", "stringData"):
                value = resource.get(field)
                if _present(value) and value not in ("[REDACTED]", "<redacted>", "***"):
                    findings.append({"resource_index": index,
                                     "code": "embedded_secret_payload"})
        if resource["kind"] in _WORKLOADS:
            identity = _sanitize(_identity(resource))
            canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False, allow_nan=False)
            workloads.append({"identity": identity,
                              "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest()})
    workloads.sort(key=lambda item: (item["sha256"], json.dumps(item["identity"], sort_keys=True)))
    return _sanitize({"algorithm": "SHA-256", "digest_scope": "sanitized_workload_identity_v1",
                      "workloads": workloads, "findings": findings,
                      "resource_count": len(resources), "observed_specs": observed_specs,
                      "zero_plaintext_leakage": bool(observed_specs) and not findings,
                      "status": "failed" if findings else (
                          "passed_observed_fields" if observed_specs else "unknown"),
                      "coverage": "Observed fields only; omitted specs and arbitrary literals cannot be verified."})


def _ready(resource):
    conditions = _object(resource.get("status")).get("conditions", [])
    if not isinstance(conditions, list):
        return False
    ready = [c.get("status") for c in conditions
             if isinstance(c, dict) and c.get("type") == "Ready"]
    return ready == ["True"]


def _server(resource):
    if resource["kind"] != "Pod":
        return False
    meta = resource["metadata"]
    labels = _object(meta.get("labels"))
    owners = meta.get("ownerReferences", [])
    owned = isinstance(owners, list) and any(
        isinstance(o, dict) and o.get("kind") == "StatefulSet" and
        o.get("name") == "openbao" for o in owners)
    return owned or (labels.get("app.kubernetes.io/name") == "openbao" and
                     labels.get("component") == "server")


def verify_raft_kms_quorum(catalog=None):
    """Evaluate three-server placement and Ready observations, with majority 2.

Pod readiness is an availability proxy; it never attests actual Raft votes or
KMS/seal functionality. Missing, duplicate, or ambiguous evidence fails closed.
"""
    resources = _load(catalog)
    nodes = {name: [r for r in resources if r["kind"] == "Node" and
                    r["metadata"]["name"] == name] for name in HARDWARE_NODES}
    servers = [r for r in resources if _server(r)]
    placements = {name: [] for name in HARDWARE_NODES}
    identities = [(r["metadata"].get("namespace", "default"), r["metadata"]["name"])
                  for r in servers]
    unique = len(set(identities)) == len(identities)
    members = []
    for resource in servers:
        host = _object(resource.get("spec")).get("nodeName")
        hardware_ready = host in nodes and len(nodes[host]) == 1 and _ready(nodes[host][0])
        available = (unique and hardware_ready and _ready(resource) and
                     _object(resource.get("status")).get("phase") == "Running" and
                     not resource["metadata"].get("deletionTimestamp"))
        if host in placements:
            placements[host].append(available)
        # Use ordinal identifiers so unexpected pod names never reach output.
        members.append({"member_index": len(members),
                        "hardware_node": host if host in nodes else "unrecognized",
                        "available": bool(available)})
    distributed = len(servers) == 3 and unique and all(len(v) == 1 for v in placements.values())
    available = sum(m["available"] for m in members)
    majority = len(servers) == 3 and unique and available >= 2
    posture = "healthy" if majority and distributed and available == 3 else (
        "degraded" if majority else "quorum_at_risk")
    return _sanitize({"status": posture, "expected_members": 3, "required_majority": 2,
                      "observed_members": len(servers), "available_members": available,
                      "availability_majority": majority, "distributed_across_hardware": distributed,
                      "hardware_nodes": [{"name": name,
                                          "ready": len(nodes[name]) == 1 and _ready(nodes[name][0]),
                                          "placed_members": len(placements[name])}
                                         for name in HARDWARE_NODES],
                      "members": members, "raft_quorum_verified": False,
                      "kms_verified": False,
                      "coverage": "Catalog readiness and placement only; live Raft membership and KMS/seal evidence unavailable."})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", metavar="FILE", type=Path)
    parser.add_argument("--json", action="store_true", help="Emit structured JSON")
    args = parser.parse_args(argv)
    try:
        # Load once so both reports assess the same snapshot.
        resources = _load(args.catalog)
        catalog = {"nodes": [{"resource": r} for r in resources]}
        report = _sanitize({"provenance": audit_openbao_secret_provenance(catalog),
                            "quorum": verify_raft_kms_quorum(catalog)})
    except ValueError:
        print(json.dumps(_sanitize({"error": "Unable to load a valid cluster catalog"})))
        return 2
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print("Provenance: " + report["provenance"]["status"])
        print("Raft KMS posture: " + report["quorum"]["status"])
        print(report["quorum"]["coverage"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
