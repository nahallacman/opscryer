# SPDX-License-Identifier: Apache-2.0
"""Offline Authentik authorization policy and observed ingress posture.

This module does not verify JWT signatures or install HTTP enforcement. Callers
must supply claims from trusted OIDC middleware, setting signature_verified=True
only after cryptographic verification against pinned issuer keys. Never copy that
flag from a request or decoded JWT. Issuer/audience are deployment policy constants,
not values learned from claims or the catalog. Reports contain fixed codes and
resource ordinals only, so arbitrary catalog/claim values cannot escape.
"""

import argparse
import json
import math
from pathlib import Path
import re
import time
from urllib.parse import urlsplit


DEFAULT_CATALOG = Path(__file__).resolve().with_name("live-cluster-sanitized.json")
TRUSTED_ISSUER = "https://auth.cluster.example.org/application/o/opscryer/"
TRUSTED_AUDIENCE = "opscryer"
GROUPS = ("platform-admins", "sre-operators", "readonly-viewers", "household-gamers")
_ADMIN = frozenset(GROUPS[:1])
_OPS = frozenset(GROUPS[:2])
_READ = frozenset(GROUPS[:3])
_HOUSEHOLD = frozenset((GROUPS[0], GROUPS[3]))
# Exact paths: unlisted routes, including descendants, are denied for everyone.
ROUTE_POLICY = {
    "/": frozenset(GROUPS), "/chat": frozenset(GROUPS),
    "/api/v1/chat-concierge": frozenset(GROUPS),
    "/api/v1/two-act-status": _READ, "/api/v1/dogfood-zoom": _READ,
    "/api/v1/oscal-summary": _READ, "/api/v1/live-cluster-health": _READ,
    "/api/v1/live-cluster-currencies": _READ,
    "/api/v1/live-cluster-ask": _OPS,
    "/api/v1/live-cluster-oidc": _OPS,
    "/admin": _ADMIN, "/api/v1/admin": _ADMIN,
}
_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+cluster\.example\.org\Z")


def _load(catalog):
    try:
        if catalog is None or isinstance(catalog, (str, Path)):
            catalog = json.loads(Path(DEFAULT_CATALOG if catalog is None else catalog)
                                 .read_text(encoding="utf-8"))
        if not isinstance(catalog, dict) or not isinstance(catalog.get("nodes"), list):
            raise ValueError
        json.dumps(catalog, allow_nan=False)
        resources = []
        for node in catalog["nodes"]:
            if not isinstance(node, dict):
                raise ValueError
            resource = node.get("resource")
            if resource is None:
                continue
            if not isinstance(resource, dict) or not isinstance(resource.get("kind"), str):
                raise ValueError
            if resource["kind"] == "Ingress":
                if (not isinstance(resource.get("metadata"), dict) or
                        not isinstance(resource.get("spec"), dict)):
                    raise ValueError
                resources.append(resource)
        return resources
    except (OSError, ValueError, TypeError, RecursionError):
        raise ValueError("Invalid cluster catalog") from None


def _rules(resource):
    rules = resource["spec"].get("rules", [])
    if not isinstance(rules, list) or any(not isinstance(r, dict) for r in rules):
        raise ValueError("Invalid ingress rules")
    return rules


def _host(value):
    return isinstance(value, str) and len(value) <= 253 and bool(_HOST.fullmatch(value))


def _ingress_groups(resource, host=None):
    if host == "opscryer.cluster.example.org":
        # Individual OpsCryer paths still receive the exact route matrix below.
        return frozenset(GROUPS)
    namespace = resource["metadata"].get("namespace")
    if namespace in ("gaming", "game-servers", "media"):
        return _HOUSEHOLD
    if namespace == "monitoring":
        return _READ
    if namespace in ("iam", "security", "kube-system", "kubernetes-dashboard"):
        return _ADMIN
    # Unclassified namespaces get the most restrictive policy.
    if namespace in ("ai-infra", "ai-sandbox", "ansible-semaphore", "argocd",
                     "default", "dev-envs", "devops-tools", "gitlab", "harbor",
                     "notifications", "runbookgate", "packet-aggregator-demo"):
        return _OPS
    return _ADMIN


def _timestamp(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _claims_valid(claims):
    if not isinstance(claims, dict) or claims.get("signature_verified") is not True:
        return False
    if claims.get("iss") != TRUSTED_ISSUER:
        return False
    audience = claims.get("aud")
    if isinstance(audience, str):
        audience = [audience]
    if (not isinstance(audience, list) or not audience or
            any(not isinstance(a, str) or not a for a in audience) or
            TRUSTED_AUDIENCE not in audience):
        return False
    if (len(audience) > 1 or "azp" in claims) and claims.get("azp") != TRUSTED_AUDIENCE:
        return False
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        return False
    now = time.time()
    expiry = claims.get("exp")
    if not _timestamp(expiry) or expiry <= now:
        return False
    for field in ("nbf", "iat"):
        if field in claims and (not _timestamp(claims[field]) or
                                claims[field] > now or claims[field] >= expiry):
            return False
    groups = claims.get("groups")
    return (isinstance(groups, list) and bool(groups) and
            all(isinstance(g, str) and bool(g.strip()) for g in groups))


def _target_groups(target, resources):
    if (not isinstance(target, str) or not target or
            any(ord(c) < 33 or ord(c) == 127 for c in target) or
            any(c in target for c in ("%", "\\", "?", "#"))):
        return frozenset()
    if target.startswith("/"):
        return ROUTE_POLICY.get(target, frozenset())
    # Bare hostnames or HTTPS URLs only; no userinfo, ports or ambiguous paths.
    url = urlsplit(target if "://" in target else "https://" + target)
    if url.scheme != "https" or not _host(url.netloc):
        return frozenset()
    path = url.path or "/"
    if "//" in path or any(p in (".", "..") for p in path.split("/")):
        return frozenset()
    matches = [r for r in resources if any(rule.get("host") == url.netloc
                                          for rule in _rules(r))]
    if not matches:
        return frozenset()
    # Conflicting/duplicate ingress observations cannot broaden privileges.
    groups = frozenset.intersection(*(_ingress_groups(r, url.netloc) for r in matches))
    if url.netloc == "opscryer.cluster.example.org":
        return groups & ROUTE_POLICY.get(path, frozenset())
    return groups


def evaluate_oidc_rbac_access(claims, target_route, catalog=None):
    """Return allowed/status_code/reason, without reflecting supplied values.

    Accept a graph dict or JSON path; default to the bundled sanitized snapshot.
    The signature_verified marker is a trusted middleware contract, not evidence
    that an arbitrary dictionary or a raw JWT is authentic. This API must remain
    behind that trust boundary. Unknown targets and bad catalogs deny all roles.
    """
    denied = {"allowed": False, "status_code": 403, "reason": "invalid_claims"}
    try:
        if not _claims_valid(claims):
            return denied
        resources = _load(catalog)
        permitted = _target_groups(target_route, resources)
        if permitted.intersection(claims["groups"]):
            return {"allowed": True, "status_code": 200, "reason": "group_authorized"}
        return {**denied, "reason": "policy_denied"}
    except (ValueError, TypeError, RecursionError, OverflowError):
        return {**denied, "reason": "invalid_policy_input"}


def _authentik_endpoint(value, path):
    if not isinstance(value, str):
        return False
    return value == "https://auth.cluster.example.org" + path


def audit_cluster_ingress_oidc_posture(catalog=None):
    """Audit observed nginx forward-auth configuration, never assert enforcement.

    Missing annotations are unknown evidence, not proof of anonymous access.
    Findings use ingress ordinals; hostnames, annotations and tokens are omitted.
    """
    try:
        resources = _load(catalog)
        records = []
        for index, resource in enumerate(resources):
            rules = _rules(resource)
            annotations = resource["metadata"].get("annotations", {})
            if not isinstance(annotations, dict):
                raise ValueError
            findings = []
            hosts = [r.get("host") for r in rules]
            if not hosts or not all(_host(h) for h in hosts):
                findings.append("missing_or_unsupported_host")
            prefix = "nginx.ingress.kubernetes.io/"
            if not _authentik_endpoint(annotations.get(prefix + "auth-url"),
                                      "/outpost.goauthentik.io/auth/nginx"):
                findings.append("authentik_forward_auth_unverified")
            if not _authentik_endpoint(annotations.get(prefix + "auth-signin"),
                                      "/outpost.goauthentik.io/start?rd=$escaped_request_uri"):
                findings.append("authentik_signin_unverified")
            tls = resource["spec"].get("tls", [])
            covered = set()
            if isinstance(tls, list):
                for entry in tls:
                    if isinstance(entry, dict) and isinstance(entry.get("hosts"), list):
                        covered.update(h for h in entry["hosts"] if _host(h))
            if not hosts or not all(_host(h) and h in covered for h in hosts):
                findings.append("tls_hosts_unverified")
            records.append({"ingress_index": index,
                            "allowed_groups": sorted(_ingress_groups(resource)),
                            "status": "unknown" if findings else "configured_observed_fields",
                            "findings": findings})
        configured = sum(not r["findings"] for r in records)
        return {"status": ("configured_observed_fields" if records and
                           configured == len(records) else "unknown"),
                "ingress_count": len(records), "configured_count": configured,
                "ingresses": records, "enforcement_verified": False,
                "coverage": "Snapshot metadata only; live authentication and group enforcement require runtime verification."}
    except (ValueError, TypeError, RecursionError):
        return {"status": "invalid_catalog", "ingress_count": 0,
                "configured_count": 0, "ingresses": [], "enforcement_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, help="Sanitized cluster JSON catalog")
    parser.add_argument("--json", action="store_true", help="Emit JSON posture report")
    args = parser.parse_args(argv)
    report = audit_cluster_ingress_oidc_posture(args.catalog)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("OIDC posture: " + report["status"])
        print(f"Configured ingress observations: {report['configured_count']}/{report['ingress_count']}")
        print("Live enforcement is unverified.")
    return 0 if report["status"] == "configured_observed_fields" else 1


if __name__ == "__main__":
    raise SystemExit(main())
