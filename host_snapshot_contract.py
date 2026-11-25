# SPDX-License-Identifier: Apache-2.0
"""Provider-agnostic OPSCRYER_HOST_SNAPSHOT v1 contract validator and sanitizer.

Enforces fail-closed origin allowlists, bounded payload size/depth/cardinality,
recursive credential/secret key and Bearer-token value rejection, legacy top-level
GitOps field normalization into ``data.providers.gitlab``, and extensible provider
namespaces (``gitlab``, ``kubernetes``, ``aws``, and custom providers).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
import re
from typing import Any
from urllib.parse import urlsplit

HOST_SNAPSHOT_MESSAGE_TYPE = "OPSCRYER_HOST_SNAPSHOT"
HOST_READY_MESSAGE_TYPE = "OPSCRYER_READY"
HOST_SNAPSHOT_CONTRACT_VERSION = 1

MAX_HOST_SNAPSHOT_BYTES = 524_288
MAX_HOST_SNAPSHOT_DEPTH = 16
MAX_COLLECTION_ITEMS = 1_000
MAX_SOURCE_LENGTH = 128
MAX_TIMESTAMP_LENGTH = 64
MAX_PROVIDER_KEY_LENGTH = 64

_PROVIDER_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_CAMEL_BOUNDARY_1 = re.compile(r"([a-z0-9])([A-Z])")
_CAMEL_BOUNDARY_2 = re.compile(r"([A-Z]+)([A-Z][a-z])")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_BEARER_VALUE_RE = re.compile(r"^\s*bearer\s+\S+", re.IGNORECASE)

_PROTOTYPE_POLLUTION_KEYS = frozenset({"__proto__", "constructor", "prototype"})

FORBIDDEN_SECRET_EXACT_KEYS = frozenset(
    {
        "token",
        "tokens",
        "access_token",
        "refresh_token",
        "id_token",
        "private_token",
        "oauth_token",
        "auth_token",
        "session_token",
        "csrf_token",
        "bearer_token",
        "service_account_token",
        "aws_session_token",
        "authorization",
        "proxy_authorization",
        "www_authenticate",
        "cookie",
        "cookies",
        "set_cookie",
        "secret",
        "secrets",
        "client_secret",
        "session_secret",
        "webhook_secret",
        "signing_secret",
        "jwt_secret",
        "secret_key",
        "secret_access_key",
        "aws_secret_access_key",
        "password",
        "passwords",
        "passwd",
        "passphrase",
        "pwd",
        "api_key",
        "apikey",
        "x_api_key",
        "api_keys",
        "apikeys",
        "private_key",
        "privatekey",
        "private_keys",
        "privatekeys",
        "ssh_key",
        "signing_key",
        "encryption_key",
        "master_key",
        "credential",
        "credentials",
        "kubeconfig",
        "bearer",
    }
)

_FORBIDDEN_SECRET_WORDS = frozenset(
    {
        "token",
        "tokens",
        "secret",
        "secrets",
        "password",
        "passwords",
        "passwd",
        "passphrase",
        "cookie",
        "cookies",
        "authorization",
        "kubeconfig",
        "apikey",
        "apikeys",
        "privatekey",
        "privatekeys",
        "credential",
        "credentials",
    }
)

_FORBIDDEN_SECRET_WORD_PAIRS = frozenset(
    {
        ("api", "key"),
        ("api", "keys"),
        ("private", "key"),
        ("private", "keys"),
        ("secret", "key"),
        ("secret", "keys"),
        ("session", "key"),
        ("signing", "key"),
        ("client", "secret"),
        ("access", "key"),
    }
)


class HostSnapshotValidationError(ValueError):
    """Raised when an OPSCRYER_HOST_SNAPSHOT payload violates contract or security rules."""

    def __init__(self, message: str, *, code: str = "invalid_snapshot") -> None:
        super().__init__(message)
        self.code = code


def _has_control_chars(text: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)


def normalize_origin(raw_origin: str) -> str | None:
    """Normalize an HTTP(S) browser origin to ``scheme://host[:port]`` or return ``None``.

    Fails closed on empty strings, ``"null"``, wildcards (``"*"``), non-HTTP(S)
    schemes, embedded credentials, paths, query strings, fragments, or control characters.
    """
    if not isinstance(raw_origin, str):
        return None
    candidate = raw_origin.strip()
    if (
        not candidate
        or candidate.lower() == "null"
        or "*" in candidate
        or "@" in candidate
        or any(ch.isspace() for ch in candidate)
        or _has_control_chars(candidate)
    ):
        return None
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    if (
        not parsed.hostname
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None

    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default_port = 80 if scheme == "http" else 443
    if port is None or port == default_port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def parse_allowed_host_origins(
    origins: str | Iterable[str] | None,
    *,
    same_origin: str | None = None,
) -> frozenset[str]:
    """Parse and normalize a collection or comma/space-delimited string of allowed origins."""
    resolved: set[str] = set()
    if same_origin is not None:
        norm_same = normalize_origin(same_origin)
        if norm_same:
            resolved.add(norm_same)

    if origins is None:
        return frozenset(resolved)

    raw_items: list[str] = []
    if isinstance(origins, str):
        raw_items.extend(part for part in origins.replace(",", " ").split() if part)
    elif isinstance(origins, Iterable):
        for entry in origins:
            if isinstance(entry, str):
                raw_items.extend(part for part in entry.replace(",", " ").split() if part)

    for item in raw_items:
        normalized = normalize_origin(item)
        if normalized:
            resolved.add(normalized)
    return frozenset(resolved)


def is_trusted_host_origin(
    event_origin: str,
    allowed_origins: str | Iterable[str] | None,
    *,
    same_origin: str | None = None,
) -> bool:
    """Return True iff ``event_origin`` is a valid HTTP(S) origin in the allowlist (fail closed)."""
    normalized_event = normalize_origin(event_origin)
    if not normalized_event:
        return False
    allowlist = parse_allowed_host_origins(allowed_origins, same_origin=same_origin)
    if not allowlist:
        return False
    return normalized_event in allowlist


def _normalize_key_tokens(key: str) -> tuple[str, tuple[str, ...]]:
    step1 = _CAMEL_BOUNDARY_2.sub(r"\1_\2", key)
    step2 = _CAMEL_BOUNDARY_1.sub(r"\1_\2", step1)
    norm = _NON_ALNUM_RE.sub("_", step2.lower()).strip("_")
    words = tuple(part for part in norm.split("_") if part)
    return norm, words


def is_forbidden_secret_key(key: str) -> bool:
    """Return True if ``key`` matches a forbidden credential/secret/token or proto-pollution key."""
    if not isinstance(key, str):
        return True
    stripped = key.strip()
    if not stripped:
        return False
    if stripped in _PROTOTYPE_POLLUTION_KEYS or stripped.lower() in _PROTOTYPE_POLLUTION_KEYS:
        return True
    norm, words = _normalize_key_tokens(stripped)
    if norm in FORBIDDEN_SECRET_EXACT_KEYS:
        return True
    if any(word in _FORBIDDEN_SECRET_WORDS for word in words):
        return True
    for idx in range(len(words) - 1):
        if (words[idx], words[idx + 1]) in _FORBIDDEN_SECRET_WORD_PAIRS:
            return True
    return False


def find_forbidden_secret_paths(
    payload: Any,
    *,
    max_depth: int = MAX_HOST_SNAPSHOT_DEPTH,
) -> list[str]:
    """Recursively scan ``payload`` for forbidden credential keys or Bearer credential values."""
    hits: list[str] = []

    def _walk(node: Any, path: str, depth: int) -> None:
        if depth > max_depth:
            raise HostSnapshotValidationError(
                f"Host snapshot nesting exceeds maximum depth of {max_depth}",
                code="max_depth_exceeded",
            )
        if isinstance(node, Mapping):
            for raw_key, value in node.items():
                if not isinstance(raw_key, str):
                    raise HostSnapshotValidationError(
                        "Host snapshot object keys must be strings",
                        code="invalid_field_type",
                    )
                child_path = f"{path}.{raw_key}" if path else raw_key
                if raw_key in _PROTOTYPE_POLLUTION_KEYS or raw_key.lower() in _PROTOTYPE_POLLUTION_KEYS:
                    raise HostSnapshotValidationError(
                        f"Forbidden prototype key at {child_path}",
                        code="forbidden_prototype_key",
                    )
                if is_forbidden_secret_key(raw_key):
                    hits.append(child_path)
                _walk(value, child_path, depth + 1)
        elif isinstance(node, (list, tuple)):
            if len(node) > MAX_COLLECTION_ITEMS:
                raise HostSnapshotValidationError(
                    f"Collection at {path or '$'} exceeds maximum of {MAX_COLLECTION_ITEMS} items",
                    code="collection_too_large",
                )
            for idx, item in enumerate(node):
                _walk(item, f"{path}[{idx}]", depth + 1)
        elif isinstance(node, str):
            if _BEARER_VALUE_RE.match(node):
                hits.append(path or "$")

    _walk(payload, "", 0)
    return hits


def _sanitize_json_value(value: Any, *, path: str, depth: int = 0) -> Any:
    if depth > MAX_HOST_SNAPSHOT_DEPTH:
        raise HostSnapshotValidationError(
            f"Host snapshot nesting exceeds maximum depth of {MAX_HOST_SNAPSHOT_DEPTH}",
            code="max_depth_exceeded",
        )
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise HostSnapshotValidationError(
                f"Non-finite number at {path}",
                code="invalid_field_type",
            )
        return value
    if isinstance(value, str):
        if "\x00" in value:
            raise HostSnapshotValidationError(
                f"Null byte rejected in string at {path}",
                code="invalid_field_type",
            )
        return value
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise HostSnapshotValidationError(
                f"Collection at {path} exceeds maximum of {MAX_COLLECTION_ITEMS} items",
                code="collection_too_large",
            )
        return [
            _sanitize_json_value(item, path=f"{path}[{idx}]", depth=depth + 1)
            for idx, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        clean_obj: dict[str, Any] = {}
        for raw_key, raw_val in value.items():
            if not isinstance(raw_key, str):
                raise HostSnapshotValidationError(
                    f"Non-string key rejected at {path}",
                    code="invalid_field_type",
                )
            clean_obj[raw_key] = _sanitize_json_value(
                raw_val,
                path=f"{path}.{raw_key}",
                depth=depth + 1,
            )
        return clean_obj
    raise HostSnapshotValidationError(
        f"Unsupported value type at {path}",
        code="invalid_field_type",
    )


def _require_list(value: Any, *, field_name: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise HostSnapshotValidationError(
            f"Field '{field_name}' must be a list",
            code="invalid_field_type",
        )
    if len(value) > MAX_COLLECTION_ITEMS:
        raise HostSnapshotValidationError(
            f"Field '{field_name}' exceeds maximum of {MAX_COLLECTION_ITEMS} items",
            code="collection_too_large",
        )
    return _sanitize_json_value(value, path=field_name)


def validate_and_sanitize_host_snapshot(
    payload: Mapping[str, Any] | str | bytes,
    *,
    event_origin: str | None = None,
    allowed_origins: str | Iterable[str] | None = None,
    same_origin: str | None = None,
    max_bytes: int = MAX_HOST_SNAPSHOT_BYTES,
) -> dict[str, Any]:
    """Validate and normalize an ``OPSCRYER_HOST_SNAPSHOT`` v1 message (fail closed).

    - Validates ``event_origin`` against ``allowed_origins`` / ``same_origin`` when supplied.
    - Enforces ``max_bytes`` serialized payload limit and ``MAX_HOST_SNAPSHOT_DEPTH``.
    - Rejects any forbidden secret/token key or Bearer credential string recursively.
    - Normalizes legacy top-level ``mergeRequests``, ``starredRepos``, and ``pipelines``
      into ``data.providers.gitlab`` while keeping top-level mirrors synchronized.
    - Preserves ``kubernetes``, ``aws``, and arbitrary extensible provider objects under
      ``data.providers``.
    """
    if event_origin is not None or allowed_origins is not None or same_origin is not None:
        if not is_trusted_host_origin(
            event_origin or "",
            allowed_origins,
            same_origin=same_origin,
        ):
            raise HostSnapshotValidationError(
                "Rejected OPSCRYER_HOST_SNAPSHOT from untrusted origin",
                code="untrusted_origin",
            )

    if isinstance(payload, (bytes, bytearray)):
        if len(payload) > max_bytes:
            raise HostSnapshotValidationError(
                f"Host snapshot exceeds maximum size of {max_bytes} bytes",
                code="payload_too_large",
            )
        try:
            decoded = payload.decode("utf-8")
            parsed_obj = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HostSnapshotValidationError(
                "Malformed JSON in host snapshot payload",
                code="invalid_envelope",
            ) from exc
    elif isinstance(payload, str):
        if len(payload.encode("utf-8")) > max_bytes:
            raise HostSnapshotValidationError(
                f"Host snapshot exceeds maximum size of {max_bytes} bytes",
                code="payload_too_large",
            )
        try:
            parsed_obj = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise HostSnapshotValidationError(
                "Malformed JSON in host snapshot payload",
                code="invalid_envelope",
            ) from exc
    elif isinstance(payload, Mapping):
        parsed_obj = payload
    else:
        raise HostSnapshotValidationError(
            "Host snapshot payload must be a JSON object",
            code="invalid_envelope",
        )

    if not isinstance(parsed_obj, Mapping):
        raise HostSnapshotValidationError(
            "Host snapshot root must be a JSON object",
            code="invalid_envelope",
        )

    secret_paths = find_forbidden_secret_paths(parsed_obj, max_depth=MAX_HOST_SNAPSHOT_DEPTH)
    if secret_paths:
        raise HostSnapshotValidationError(
            f"Forbidden credential or secret field rejected at {secret_paths[0]}",
            code="forbidden_secret_key",
        )

    try:
        serialized = json.dumps(parsed_obj, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HostSnapshotValidationError(
            "Host snapshot payload is not valid JSON",
            code="invalid_envelope",
        ) from exc
    if len(serialized) > max_bytes:
        raise HostSnapshotValidationError(
            f"Host snapshot exceeds maximum size of {max_bytes} bytes",
            code="payload_too_large",
        )

    msg_type = parsed_obj.get("type")
    if msg_type != HOST_SNAPSHOT_MESSAGE_TYPE:
        raise HostSnapshotValidationError(
            f"Expected message type '{HOST_SNAPSHOT_MESSAGE_TYPE}'",
            code="invalid_type",
        )

    raw_version = parsed_obj.get("version")
    if raw_version is None:
        version = HOST_SNAPSHOT_CONTRACT_VERSION
    elif not isinstance(raw_version, bool) and isinstance(raw_version, int) and raw_version == HOST_SNAPSHOT_CONTRACT_VERSION:
        version = raw_version
    else:
        raise HostSnapshotValidationError(
            f"Unsupported host snapshot contract version; expected {HOST_SNAPSHOT_CONTRACT_VERSION}",
            code="unsupported_version",
        )

    raw_source = parsed_obj.get("source")
    if not isinstance(raw_source, str) or not raw_source.strip() or len(raw_source) > MAX_SOURCE_LENGTH or _has_control_chars(raw_source):
        raise HostSnapshotValidationError(
            "Field 'source' must be a non-empty printable string",
            code="invalid_field_type",
        )
    source = raw_source.strip()

    raw_revision = parsed_obj.get("revision", 0)
    if isinstance(raw_revision, bool) or not isinstance(raw_revision, int) or raw_revision < 0:
        raise HostSnapshotValidationError(
            "Field 'revision' must be a non-negative integer",
            code="invalid_field_type",
        )

    raw_updated_at = parsed_obj.get("updatedAt", "")
    if (
        not isinstance(raw_updated_at, str)
        or len(raw_updated_at) > MAX_TIMESTAMP_LENGTH
        or _has_control_chars(raw_updated_at)
    ):
        raise HostSnapshotValidationError(
            "Field 'updatedAt' must be an ISO-8601 timestamp string",
            code="invalid_field_type",
        )

    raw_connected = parsed_obj.get("connected", False)
    if not isinstance(raw_connected, bool):
        raise HostSnapshotValidationError(
            "Field 'connected' must be a boolean",
            code="invalid_field_type",
        )

    raw_data = parsed_obj.get("data")
    if not isinstance(raw_data, Mapping):
        raise HostSnapshotValidationError(
            "Field 'data' must be an object",
            code="invalid_field_type",
        )

    catalog_entities = _require_list(
        raw_data.get("catalogEntities"),
        field_name="data.catalogEntities",
    )
    for idx, entity in enumerate(catalog_entities):
        if not isinstance(entity, dict):
            raise HostSnapshotValidationError(
                f"Catalog entity at data.catalogEntities[{idx}] must be an object",
                code="invalid_field_type",
            )

    has_top_mrs = "mergeRequests" in raw_data and raw_data.get("mergeRequests") is not None
    has_top_starred = "starredRepos" in raw_data and raw_data.get("starredRepos") is not None
    has_top_pipelines = "pipelines" in raw_data and raw_data.get("pipelines") is not None

    top_mrs = _require_list(raw_data.get("mergeRequests"), field_name="data.mergeRequests")
    top_starred = _require_list(raw_data.get("starredRepos"), field_name="data.starredRepos")
    top_pipelines = _require_list(raw_data.get("pipelines"), field_name="data.pipelines")

    raw_providers = raw_data.get("providers")
    if raw_providers is None:
        raw_providers = {}
    elif not isinstance(raw_providers, Mapping):
        raise HostSnapshotValidationError(
            "Field 'data.providers' must be an object",
            code="invalid_field_type",
        )

    normalized_providers: dict[str, dict[str, Any]] = {}
    for provider_key, provider_val in raw_providers.items():
        if (
            not isinstance(provider_key, str)
            or len(provider_key) > MAX_PROVIDER_KEY_LENGTH
            or not _PROVIDER_KEY_RE.match(provider_key)
        ):
            raise HostSnapshotValidationError(
                "Invalid provider identifier in data.providers",
                code="invalid_field_type",
            )
        if not isinstance(provider_val, Mapping):
            raise HostSnapshotValidationError(
                f"Provider 'data.providers.{provider_key}' must be an object",
                code="invalid_field_type",
            )
        sanitized_provider = _sanitize_json_value(
            provider_val,
            path=f"data.providers.{provider_key}",
            depth=2,
        )
        normalized_providers[provider_key] = sanitized_provider

    raw_gitlab = normalized_providers.get("gitlab", {})
    gitlab_mrs = (
        _require_list(raw_gitlab.get("mergeRequests"), field_name="data.providers.gitlab.mergeRequests")
        if "mergeRequests" in raw_gitlab and raw_gitlab.get("mergeRequests") is not None
        else [ item for item in top_mrs ]
    )
    gitlab_starred = (
        _require_list(raw_gitlab.get("starredRepos"), field_name="data.providers.gitlab.starredRepos")
        if "starredRepos" in raw_gitlab and raw_gitlab.get("starredRepos") is not None
        else [ item for item in top_starred ]
    )
    gitlab_pipelines = (
        _require_list(raw_gitlab.get("pipelines"), field_name="data.providers.gitlab.pipelines")
        if "pipelines" in raw_gitlab and raw_gitlab.get("pipelines") is not None
        else [ item for item in top_pipelines ]
    )

    normalized_providers["gitlab"] = {
        **raw_gitlab,
        "mergeRequests": gitlab_mrs,
        "starredRepos": gitlab_starred,
        "pipelines": gitlab_pipelines,
    }

    if "kubernetes" in normalized_providers:
        raw_k8s = normalized_providers["kubernetes"]
        normalized_providers["kubernetes"] = {
            **raw_k8s,
            "clusters": _require_list(
                raw_k8s.get("clusters"),
                field_name="data.providers.kubernetes.clusters",
            ),
            "workloads": _require_list(
                raw_k8s.get("workloads"),
                field_name="data.providers.kubernetes.workloads",
            ),
        }

    if "aws" in normalized_providers:
        raw_aws = normalized_providers["aws"]
        normalized_providers["aws"] = {
            **raw_aws,
            "accounts": _require_list(
                raw_aws.get("accounts"),
                field_name="data.providers.aws.accounts",
            ),
            "resources": _require_list(
                raw_aws.get("resources"),
                field_name="data.providers.aws.resources",
            ),
        }

    out_top_mrs = top_mrs if (has_top_mrs and top_mrs) else [item for item in gitlab_mrs]
    out_top_starred = top_starred if (has_top_starred and top_starred) else [item for item in gitlab_starred]
    out_top_pipelines = top_pipelines if (has_top_pipelines and top_pipelines) else [item for item in gitlab_pipelines]

    return {
        "type": HOST_SNAPSHOT_MESSAGE_TYPE,
        "version": version,
        "source": source,
        "revision": raw_revision,
        "updatedAt": raw_updated_at,
        "connected": raw_connected,
        "data": {
            "catalogEntities": catalog_entities,
            "providers": normalized_providers,
            "mergeRequests": out_top_mrs,
            "starredRepos": out_top_starred,
            "pipelines": out_top_pipelines,
        },
    }


def inspect_host_snapshot(
    payload: Mapping[str, Any] | str | bytes,
    *,
    event_origin: str | None = None,
    allowed_origins: str | Iterable[str] | None = None,
    same_origin: str | None = None,
    max_bytes: int = MAX_HOST_SNAPSHOT_BYTES,
) -> dict[str, Any]:
    """Non-throwing wrapper around ``validate_and_sanitize_host_snapshot``."""
    try:
        snapshot = validate_and_sanitize_host_snapshot(
            payload,
            event_origin=event_origin,
            allowed_origins=allowed_origins,
            same_origin=same_origin,
            max_bytes=max_bytes,
        )
        return {
            "valid": True,
            "snapshot": snapshot,
            "error": None,
            "error_code": None,
        }
    except HostSnapshotValidationError as exc:
        return {
            "valid": False,
            "snapshot": None,
            "error": str(exc),
            "error_code": exc.code,
        }


__all__ = [
    "FORBIDDEN_SECRET_EXACT_KEYS",
    "HOST_READY_MESSAGE_TYPE",
    "HOST_SNAPSHOT_CONTRACT_VERSION",
    "HOST_SNAPSHOT_MESSAGE_TYPE",
    "MAX_COLLECTION_ITEMS",
    "MAX_HOST_SNAPSHOT_BYTES",
    "MAX_HOST_SNAPSHOT_DEPTH",
    "HostSnapshotValidationError",
    "find_forbidden_secret_paths",
    "inspect_host_snapshot",
    "is_forbidden_secret_key",
    "is_trusted_host_origin",
    "normalize_origin",
    "parse_allowed_host_origins",
    "validate_and_sanitize_host_snapshot",
]
