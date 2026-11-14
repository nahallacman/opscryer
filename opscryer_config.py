# SPDX-License-Identifier: Apache-2.0
"""Unified hierarchical configuration subsystem for OpsCryer.

Supports four-tier precedence loading:
1. Explicit CLI arguments / function overrides (highest)
2. Environment variables prefixed with OPSCRYER_*
3. Configuration file (.yaml or .json)
4. Built-in defaults (lowest)

Pure standard library implementation with zero external dependencies (no PyYAML).
Provides safe secret masking for configuration dumps and diagnostics.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Mapping

# ---------------------------------------------------------------------------
# Default Configuration Specification
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: dict[str, Any] = {
    # Nested sections for modular and E2E subsystem compatibility
    "server": {
        "port": 8088,
        "host": "127.0.0.1",
        "api_base_url": "",
        "read_only": True,
    },
    "logging": {
        "level": "INFO",
    },
    "network": {
        "timeout_seconds": 5.0,
        "max_retries": 3,
        "backoff_factor": 0.2,
        "ingress_host": "ops.cluster.example.org",
        "tls_enabled": True,
    },
    # Piece A - Browser & UI (Flat keys)
    "organization_name": "Acme Cloud Engineering",
    "domain_suffix": "example.org",
    "default_mode": "STANDALONE_MOCK",
    "api_base_url": "",
    "port": 8088,
    "dataset_path": "",
    "read_only_public_mode": True,
    # ITSM & Jev System One
    "itsm_provider_name": "Enterprise Service Desk",
    "ollama_url": "http://localhost:11434",
    "jev_provider": "ollama",
    "jev_model": "qwen2.5-coder:7b",
    "jev_min_confidence": 0.80,
    "codex_command": "codex",
    "openai_base_url": "",
    # Observability & Logging
    "log_level": "INFO",
    "prometheus_url": "http://127.0.0.1:9090",
    "loki_url": "http://127.0.0.1:3100",
    "timeout": 5.0,
    # Webhooks & Adapters
    "webhook_url": "",
    "adapter_profile": "proxmox_k8s",
}

SENSITIVE_KEY_SUBSTRINGS: tuple[str, ...] = (
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "auth",
    "credential",
)

REDACTED_PLACEHOLDER = "[REDACTED]"

# Singleton runtime configuration cache
_CURRENT_CONFIG: dict[str, Any] | None = None

# Cached explicit CLI / runtime overrides for 4-tier precedence
_CURRENT_CLI_OVERRIDES: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Pure Standard Library YAML & JSON Parser
# ---------------------------------------------------------------------------

def _strip_inline_comment(line: str) -> str:
    """Strip comments starting with # outside of quoted strings."""
    in_quote: str | None = None
    for i, ch in enumerate(line):
        if ch in ('"', "'"):
            if in_quote is None:
                in_quote = ch
            elif in_quote == ch:
                in_quote = None
        elif ch == '#' and in_quote is None:
            return line[:i].rstrip()
    return line.rstrip()


def _parse_scalar(val_str: str) -> Any:
    """Coerce scalar string to typed Python value."""
    val_str = val_str.strip()
    if not val_str:
        return ""
    if (val_str.startswith('"') and val_str.endswith('"')) or (val_str.startswith("'") and val_str.endswith("'")):
        return val_str[1:-1]
    lower = val_str.lower()
    if lower in ("true", "yes", "on"):
        return True
    if lower in ("false", "no", "off"):
        return False
    if lower in ("null", "~", "none"):
        return None
    if val_str.isdigit() or (val_str.startswith("-") and val_str[1:].isdigit()):
        try:
            return int(val_str)
        except ValueError:
            pass
    try:
        return float(val_str)
    except ValueError:
        pass
    return val_str


def parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse flat or nested YAML text into a dict using pure Python standard library."""
    stripped = text.strip()
    if not stripped:
        return {}
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    lines = text.splitlines()
    cleaned_lines: list[tuple[int, str]] = []
    for line in lines:
        clean = _strip_inline_comment(line)
        if not clean.strip():
            continue
        indent = len(clean) - len(clean.lstrip(" "))
        cleaned_lines.append((indent, clean.strip()))

    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]

    for i, (indent, content) in enumerate(cleaned_lines):
        while stack and stack[-1][0] >= indent:
            stack.pop()
        container = stack[-1][1] if stack else root

        if ":" in content:
            k, _, v = content.partition(":")
            key = k.strip()
            val_str = v.strip()
            if val_str:
                container[key] = _parse_scalar(val_str)
            else:
                has_nested = (i + 1 < len(cleaned_lines) and cleaned_lines[i + 1][0] > indent)
                if has_nested:
                    new_dict: dict[str, Any] = {}
                    container[key] = new_dict
                    stack.append((indent, new_dict))
                else:
                    container[key] = ""

    return root


def parse_simple_yaml_file(path: str | Path) -> dict[str, Any]:
    """Read and parse a YAML or JSON file path."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {}
    raw = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json" or raw.strip().startswith("{"):
        if raw.strip():
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
            return {}
        return {}
    return parse_simple_yaml(raw)


# ---------------------------------------------------------------------------
# Hierarchical Merging & Environment Variable Handling
# ---------------------------------------------------------------------------

def _deep_merge(target: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge source into target in-place."""
    for k, v in source.items():
        if isinstance(v, dict) and isinstance(target.get(k), dict):
            _deep_merge(target[k], v)
        else:
            target[k] = copy.deepcopy(v)
    return target


def _coerce_env_value(key: str, val_str: str) -> Any:
    """Coerce environment variable string using DEFAULT_CONFIG hints when available."""
    hint = DEFAULT_CONFIG.get(key)
    if hint is None:
        for section in ("server", "logging", "network"):
            sec_dict = DEFAULT_CONFIG.get(section)
            if isinstance(sec_dict, dict) and key in sec_dict:
                hint = sec_dict[key]
                break
    if hint is not None:
        if isinstance(hint, bool):
            return val_str.strip().lower() in ("true", "1", "yes", "on")
        if isinstance(hint, int):
            try:
                return int(val_str.strip())
            except ValueError:
                return val_str
        if isinstance(hint, float):
            try:
                return float(val_str.strip())
            except ValueError:
                return val_str
    return _parse_scalar(val_str)


def _load_env_config(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Extract and coerce OPSCRYER_* environment variables."""
    if environ is None:
        environ = os.environ
    env_cfg: dict[str, Any] = {}
    for k, v in environ.items():
        if k.startswith("OPSCRYER_"):
            suffix = k[len("OPSCRYER_"):].lower()
            if "__" in suffix:
                parts = suffix.split("__")
                curr = env_cfg
                for part in parts[:-1]:
                    curr = curr.setdefault(part, {})
                curr[parts[-1]] = _coerce_env_value(parts[-1], v)
            else:
                val = _coerce_env_value(suffix, v)
                env_cfg[suffix] = val
                # Synchronize common top-level aliases with section dictionaries
                if suffix == "port":
                    env_cfg.setdefault("server", {})["port"] = val
                elif suffix == "log_level":
                    env_cfg.setdefault("logging", {})["level"] = val
                elif suffix == "timeout_seconds":
                    env_cfg.setdefault("network", {})["timeout_seconds"] = val
                elif suffix == "max_retries":
                    env_cfg.setdefault("network", {})["max_retries"] = val
                elif suffix == "timeout":
                    env_cfg.setdefault("network", {})["timeout_seconds"] = val
        elif k == "OPENAI_API_KEY" and "openai_api_key" not in env_cfg:
            env_cfg["openai_api_key"] = v
        elif k == "OPENAI_API_BASE" and "openai_base_url" not in env_cfg:
            env_cfg["openai_base_url"] = v
        elif k == "OPENAI_MODEL" and "jev_model" not in env_cfg:
            env_cfg["jev_model"] = v
    return env_cfg


# ---------------------------------------------------------------------------
# Public API Contract
# ---------------------------------------------------------------------------

def _lookup_in_dict(source: Mapping[str, Any], key: str) -> tuple[bool, Any]:
    """Look up a key or dot-separated path in source dictionary with alias resolution.

    Returns (True, value) if found, or (False, None) if not present.
    """
    if key in source:
        return True, source[key]

    if "." in key:
        parts = key.split(".")
        curr: Any = source
        found = True
        for part in parts:
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                found = False
                break
        if found:
            return True, curr

    # Fallback lookups across common alias pairs
    if key == "server.port" and "port" in source:
        return True, source["port"]
    if key == "port" and isinstance(source.get("server"), dict) and "port" in source["server"]:
        return True, source["server"]["port"]
    if key == "logging.level" and "log_level" in source:
        return True, source["log_level"]
    if key == "log_level" and isinstance(source.get("logging"), dict) and "level" in source["logging"]:
        return True, source["logging"]["level"]
    if key == "network.timeout_seconds":
        if "timeout_seconds" in source:
            return True, source["timeout_seconds"]
        if "timeout" in source:
            return True, source["timeout"]
    if key == "network.timeout_seconds" and "timeout" in source:
        return True, source["timeout"]
    if key == "timeout" and isinstance(source.get("network"), dict) and "timeout_seconds" in source["network"]:
        return True, source["network"]["timeout_seconds"]
    if key == "timeout_seconds" and isinstance(source.get("network"), dict) and "timeout_seconds" in source["network"]:
        return True, source["network"]["timeout_seconds"]
    if key == "network.max_retries" and "max_retries" in source:
        return True, source["max_retries"]
    if key == "max_retries" and isinstance(source.get("network"), dict) and "max_retries" in source["network"]:
        return True, source["network"]["max_retries"]

    return False, None


def load_unified_config(
    config_path: str | Path | None = None,
    cli_overrides: dict[str, Any] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Load configuration with precedence: CLI overrides > OPSCRYER_* env > config file > defaults."""
    global _CURRENT_CONFIG, _CURRENT_CLI_OVERRIDES

    # 1. Base Defaults
    merged = copy.deepcopy(DEFAULT_CONFIG)

    # 2. Config File Layer
    resolved_path: Path | None = None
    if config_path is not None:
        resolved_path = Path(config_path)
    elif os.environ.get("OPSCRYER_CONFIG"):
        resolved_path = Path(os.environ["OPSCRYER_CONFIG"])
    else:
        for candidate in ("config.yaml", "config.yml", "config.json"):
            cp = Path(candidate)
            if cp.exists() and cp.is_file():
                resolved_path = cp
                break

    if resolved_path and resolved_path.exists() and resolved_path.is_file():
        file_cfg = parse_simple_yaml_file(resolved_path)
        _deep_merge(merged, file_cfg)
        # Synchronize port if file specifies server.port or port
        if "server" in file_cfg and isinstance(file_cfg["server"], dict) and "port" in file_cfg["server"]:
            merged["port"] = file_cfg["server"]["port"]
        elif "port" in file_cfg:
            merged.setdefault("server", {})["port"] = file_cfg["port"]

    # 3. Environment Variable Layer
    env_cfg = _load_env_config()
    _deep_merge(merged, env_cfg)

    # 4. CLI Overrides & Keyword Arguments (Tier 1 Precedence)
    active_overrides: dict[str, Any] = {}
    if cli_overrides:
        clean_overrides = {k: copy.deepcopy(v) for k, v in cli_overrides.items() if v is not None}
        _deep_merge(active_overrides, clean_overrides)
        if "port" in clean_overrides:
            active_overrides.setdefault("server", {})["port"] = clean_overrides["port"]
        if "server" in clean_overrides and isinstance(clean_overrides["server"], dict) and "port" in clean_overrides["server"]:
            active_overrides["port"] = clean_overrides["server"]["port"]
        if "log_level" in clean_overrides:
            active_overrides.setdefault("logging", {})["level"] = clean_overrides["log_level"]
        if "logging" in clean_overrides and isinstance(clean_overrides["logging"], dict) and "level" in clean_overrides["logging"]:
            active_overrides["log_level"] = clean_overrides["logging"]["level"]

    if kwargs:
        clean_kwargs = {k: copy.deepcopy(v) for k, v in kwargs.items() if v is not None}
        _deep_merge(active_overrides, clean_kwargs)
        if "port" in clean_kwargs:
            active_overrides.setdefault("server", {})["port"] = clean_kwargs["port"]
        if "server" in clean_kwargs and isinstance(clean_kwargs["server"], dict) and "port" in clean_kwargs["server"]:
            active_overrides["port"] = clean_kwargs["server"]["port"]
        if "log_level" in clean_kwargs:
            active_overrides.setdefault("logging", {})["level"] = clean_kwargs["log_level"]
        if "logging" in clean_kwargs and isinstance(clean_kwargs["logging"], dict) and "level" in clean_kwargs["logging"]:
            active_overrides["log_level"] = clean_kwargs["logging"]["level"]

    if active_overrides:
        _deep_merge(merged, active_overrides)
        if "port" in active_overrides:
            merged.setdefault("server", {})["port"] = active_overrides["port"]
        if "server" in active_overrides and isinstance(active_overrides["server"], dict) and "port" in active_overrides["server"]:
            merged["port"] = active_overrides["server"]["port"]

    _CURRENT_CLI_OVERRIDES = active_overrides
    _CURRENT_CONFIG = merged
    return copy.deepcopy(_CURRENT_CONFIG)


def get_config_value(key: str, default: Any = None) -> Any:
    """Retrieve configuration value by key or dot-separated path.

    Precedence order:
    1. Explicit CLI overrides (_CURRENT_CLI_OVERRIDES)
    2. Dynamic environment variables (OPSCRYER_*)
    3. Configuration file & defaults (_CURRENT_CONFIG)
    4. Function fallback default
    """
    global _CURRENT_CONFIG, _CURRENT_CLI_OVERRIDES
    if not key:
        return default

    # Tier 1: Check cached explicit CLI / runtime overrides
    if _CURRENT_CLI_OVERRIDES:
        found, val = _lookup_in_dict(_CURRENT_CLI_OVERRIDES, key)
        if found:
            return val

    # Tier 2: Check dynamic environment variable overrides
    env_cfg = _load_env_config()
    found, val = _lookup_in_dict(env_cfg, key)
    if found:
        return val

    # Tier 3 & 4: Fall back to loaded configuration (File > Defaults)
    if _CURRENT_CONFIG is None:
        load_unified_config()
    assert _CURRENT_CONFIG is not None

    found, val = _lookup_in_dict(_CURRENT_CONFIG, key)
    if found:
        return val

    return default


def _is_sensitive_key(key: str) -> bool:
    k_lower = key.lower()
    return any(sub in k_lower for sub in SENSITIVE_KEY_SUBSTRINGS)


def _sanitize_dict(data: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for k, v in data.items():
        if _is_sensitive_key(k):
            if isinstance(v, dict):
                sanitized[k] = _sanitize_dict(v)
            elif isinstance(v, list):
                sanitized[k] = [
                    _sanitize_dict(item) if isinstance(item, dict)
                    else [_sanitize_value(sub) for sub in item] if isinstance(item, list)
                    else REDACTED_PLACEHOLDER
                    for item in v
                ]
            else:
                sanitized[k] = REDACTED_PLACEHOLDER
        elif isinstance(v, dict):
            sanitized[k] = _sanitize_dict(v)
        elif isinstance(v, list):
            sanitized[k] = [_sanitize_value(item) for item in v]
        else:
            sanitized[k] = copy.deepcopy(v)
    return sanitized


def _sanitize_value(val: Any) -> Any:
    if isinstance(val, dict):
        return _sanitize_dict(val)
    if isinstance(val, list):
        return [_sanitize_value(item) for item in val]
    return val


def dump_sanitized_config() -> dict[str, Any]:
    """Return a deep copy of configuration with sensitive keys masked."""
    global _CURRENT_CONFIG
    if _CURRENT_CONFIG is None:
        load_unified_config()
    assert _CURRENT_CONFIG is not None
    return _sanitize_dict(_CURRENT_CONFIG)


def reset_config() -> None:
    """Reset singleton cache for clean test isolation."""
    global _CURRENT_CONFIG, _CURRENT_CLI_OVERRIDES
    _CURRENT_CONFIG = None
    _CURRENT_CLI_OVERRIDES = {}


def configure_logging(level: str | int | None = None) -> Any:
    """Configure opscryer logger level based on parameter, env var, or config value."""
    import logging

    logger = logging.getLogger("opscryer")
    if level is None:
        lvl_str = os.environ.get("OPSCRYER_LOG_LEVEL")
        if not lvl_str:
            lvl_str = str(get_config_value("log_level", "INFO"))
    else:
        lvl_str = str(level)
    lvl_str = lvl_str.upper().strip()
    valid_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "WARN": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    effective = valid_levels.get(lvl_str, logging.INFO)
    logger.setLevel(effective)
    return logger

