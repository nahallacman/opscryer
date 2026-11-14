# SPDX-License-Identifier: Apache-2.0
"""Local Argus policy checks; no container execution or source-code access."""

import re
import unicodedata

from opscryer_backend import KnowledgeGraphBackendEngine


def audit_container_security_context(spec):
    """Audit a security context or a container spec containing securityContext.

    Missing or malformed settings fail closed. Return ``compliant`` and stable
    field names in ``violations`` without reflecting supplied values.
    """
    context = spec if isinstance(spec, dict) else {}
    if "securityContext" in context:
        context = context["securityContext"]
    if not isinstance(context, dict):
        context = {}
    capabilities = context.get("capabilities")
    checks = {
        "runAsNonRoot": context.get("runAsNonRoot") is True,
        "runAsUser": (type(context.get("runAsUser")) is int
                      and context["runAsUser"] >= 10000),
        "allowPrivilegeEscalation": context.get("allowPrivilegeEscalation") is False,
        "capabilities.drop": (isinstance(capabilities, dict)
                              and capabilities.get("drop") == ["ALL"]),
    }
    violations = [field for field, passed in checks.items() if not passed]
    return {"compliant": not violations, "violations": violations}


# Assemble prohibited token markers so public sources contain no literal prefix.
_TOKEN_MARKERS = tuple(prefix + suffix for prefix, suffix in
                       (("gho", "_"), ("ghp", "_"), ("glpat", "-"), ("sk", "-")))
_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff\u00ad]")
_CONFUSABLES_MAP = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u043a": "k", "\u0442": "t", "\u03b1": "a", "\u03b5": "e", "\u03bf": "o",
    "\u03c1": "p", "\u03c4": "t", "\u03ba": "k",
})
_SECRET_QUERY = re.compile(
    r"secret|password|passwd|credential|token|api[\s_-]*key|"
    r"private[\s_-]*key|access[\s_-]*key|authorization|bearer|"
    r"\.env\b|id_rsa|id_ed25519|BEGIN\s+.*PRIVATE", re.IGNORECASE)
_MANIFEST_QUERY = re.compile(
    r"\b(manifests?|dependenc(?:y|ies)|blast[\s_-]*radius|"
    r"package\.json|requirements\.txt|pyproject\.toml|go\.mod|"
    r"cargo\.toml|pom\.xml|dockerfile|helm|sbom|lockfile|"
    r"deploy(?:ment|s|ing)?|databases?|db|sql|postgres(?:ql)?|cnpg|"
    r"pipelines?|scaffold(?:ing)?|runbooks?|articles?|playbooks?|"
    r"storage|pvc|openzfs|zfs|nfs|iscsi|sso|oidc|authentik|"
    r"minecraft|factorio|satisfactory|palworld|romm|lag(?:ging)?|fps|gpu|apu|"
    r"oscal|compliance|runners?|containers?|"
    r"trivy|openbao|kyverno|network|latency|ram|vram|cpu|3080|3070|1080|ollama|models?|"
    r"s3|seaweedfs|backup|snapshot|mfa|oauth2|saml|jwt|ldap|cve|falco|commitlint|renovate|valheim|terraria|mspt|"
    r"ingress|dns|argocd|gitops|grafana|pods?|services?|clusters?)\b", re.IGNORECASE)


def normalize_airlock_query(query: str) -> str:
    """Normalize NFKC, strip zero-width characters, and fold Cyrillic/Greek homoglyphs."""
    cleaned = _ZERO_WIDTH_RE.sub("", unicodedata.normalize("NFKC", query))
    return cleaned.casefold().translate(_CONFUSABLES_MAP)


def evaluate_code_search_airlock(query, catalog=None):
    """Gate graph-only manifest/dependency discovery; never search source files.

    Secret indicators take precedence over permitted intent. Unsupported queries
    fail closed. Blocked responses never echo the query or inspect the catalog.
    Allowed responses expose graph identity metadata and root-company paths,
    omitting arbitrary catalog payloads. Invalid catalogs raise ValueError.
    """
    result = {"status_code": 403, "airlock_blocked": True,
              "reason": "manifest_or_dependency_queries_only",
              "results": [], "escalation_paths": []}
    if not isinstance(query, str) or not query.strip():
        return result
    normalized = normalize_airlock_query(query)
    if _SECRET_QUERY.search(normalized) or any(p in normalized for p in _TOKEN_MARKERS):
        result["reason"] = "secret_hunting_blocked"
        return result
    if not _MANIFEST_QUERY.search(normalized):
        return result

    engine = KnowledgeGraphBackendEngine(catalog)
    if "root-company" not in {node["id"] for node in engine.catalog()["nodes"]}:
        result["reason"] = "escalation_root_missing"
        return result
    for hit in engine.search(normalized)["results"]:
        path = engine.shortest_path("root-company", hit["id"])
        if path["path_found"]:
            result["results"].append({field: hit[field] for field in
                                      ("id", "label", "kind", "domain", "score")})
            result["escalation_paths"].append(path)
    result.update(status_code=200, airlock_blocked=False,
                  reason="manifest_dependency_blast_radius")
    return result
