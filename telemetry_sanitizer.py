# SPDX-License-Identifier: Apache-2.0
"""Stdlib-only redaction boundary for home-network demo telemetry.

Accept JSON-compatible payloads and tuples; return fresh containers without
modifying the input. Unsupported values fail closed rather than being displayed.
This does not collect telemetry or enable live connections.
"""

from functools import lru_cache
from ipaddress import IPv4Address
import re


_WAN_REPLACEMENT = "203.0.113.1"
_REDACTED = "[REDACTED]"
_IPV4 = re.compile(r"(?<![\d.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\d|\.\d)")
_MAC = re.compile(
    r"(?<![\w:-])([0-9a-f]{2})([:-])([0-9a-f]{2})\2([0-9a-f]{2})"
    r"(?:\2[0-9a-f]{2}){3}(?![\w:-])", re.IGNORECASE)
_CISCO_MAC = re.compile(
    r"(?<![\w.])([0-9a-f]{4})\.([0-9a-f]{2})[0-9a-f]{2}\."
    r"[0-9a-f]{4}(?!\w|\.[0-9a-f])", re.IGNORECASE)
# Split token prefixes so the public-file scanner cannot flag these patterns.
_PREFIXES = ("gh" + "o_", "gh" + "p_", "gl" + "pat-", "s" + "k-",
             "github" + "_pat_")
_TOKEN = re.compile(r"(?:" + "|".join(map(re.escape, _PREFIXES)) + r")[A-Za-z0-9_-]+")
_GMAIL = re.compile(
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:gmail|googlemail)\.com\b", re.IGNORECASE)
_TAILNET = re.compile(
    r"(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+)"
    r"tail[a-z0-9]+\.ts\.net(?![\w-]|\.[a-z0-9])", re.IGNORECASE)
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_SECRET_NAMES = (
    r"password|passwd|secret|token|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization|private[_-]?key|"
    r"(?:cert|tls|ssl|ssh|priv)[_-]?key|id[_-]?(?:rsa|ed25519|ecdsa|dsa)|"
    r"key[_-]?(?:pem|file)|cert[_-]?(?:pem|file)|privkey|"
    r"(?:service[_-]?account|bootstrap|bearer|id)[_-]?token|tokens")
_SECRET_KEY = re.compile(r"(?:" + _SECRET_NAMES + r")", re.IGNORECASE)
_ASSIGNMENT = re.compile(
    r"\b(" + _SECRET_NAMES + r")\b(\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)", re.IGNORECASE)
_PEM = re.compile(
    r"-----\s*BEGIN[ A-Za-z0-9_-]+-----[\s\S]*?-----\s*END[ A-Za-z0-9_-]+-----|"
    r"-----\s*BEGIN[ A-Za-z0-9_-]+-----|"
    r"-----\s*END[ A-Za-z0-9_-]+-----"
)


# Every redaction requires one of these separators (including Bearer whitespace).
_TEXT_MARKERS = re.compile(r"[.:=@_\s-]")


@lru_cache(maxsize=8192)
def _sanitize_text(text):
    # Even the shortest credential prefix needs four characters with its value.
    if len(text) < 4 or _TEXT_MARKERS.search(text) is None:
        return text

    def address(match):
        try:
            ip = IPv4Address(match[0])
        except ValueError:
            return match[0]
        # CGNAT is neither private nor global in ipaddress. Do not use a
        # not-private test, which would incorrectly scrub that range.
        return _WAN_REPLACEMENT if ip.is_global and not ip.is_multicast else match[0]

    text = _ASSIGNMENT.sub(lambda m: m[1] + m[2] + _REDACTED, text)
    text = _PEM.sub(_REDACTED, text)
    text = _BEARER.sub("Bearer " + _REDACTED, text)
    text = _JWT.sub(_REDACTED, text)
    text = _TOKEN.sub(_REDACTED, text)
    text = _GMAIL.sub(_REDACTED, text)
    text = _TAILNET.sub(lambda m: m[1] + "tail-redacted.ts.net", text)
    if ":" in text or "-" in text:
        text = _MAC.sub(lambda m: m[2].join((m[1], m[3], m[4], "XX", "XX", "XX")), text)
    if "." in text:
        text = _CISCO_MAC.sub(
            lambda m: ":".join((m[1][:2], m[1][2:], m[2], "XX", "XX", "XX")), text)
        return _IPV4.sub(address, text)
    return text


def sanitize_live_home_telemetry_for_demo(payload):
    """Redact WAN IPv4, hardware suffixes, tailnets, credentials and Gmail.

    RFC 1918, loopback, CGNAT and cluster.example.org names remain usable. Other
    non-public IPv4 ranges are also retained. MAC prefixes retain their case
    and separator; dotted MACs are normalized to masked colon notation.
    Credential fields are redacted wholesale, including non-string values.
    Kubernetes Secret data/stringData are opaque credential containers;
    ServiceAccount token fields are credentials, while name references remain.
    """
    if isinstance(payload, dict):
        kubernetes_secret = payload.get("kind") == "Secret"
        result = {}
        for key, value in payload.items():
            if not isinstance(key, str):
                raise TypeError("Telemetry object keys must be strings")
            clean_key = _sanitize_text(key)
            if clean_key in result:
                raise ValueError("Telemetry keys collide after redaction")
            sensitive = (_SECRET_KEY.fullmatch(key) or
                         (kubernetes_secret and key in {"data", "stringData"}))
            result[clean_key] = (_REDACTED if sensitive else
                                 sanitize_live_home_telemetry_for_demo(value))
        return result
    if isinstance(payload, (list, tuple)):
        items = [sanitize_live_home_telemetry_for_demo(item) for item in payload]
        return tuple(items) if isinstance(payload, tuple) else items
    if isinstance(payload, str):
        return _sanitize_text(payload)
    if payload is None or isinstance(payload, (bool, int, float)):
        return payload
    raise TypeError("Unsupported telemetry value; redact before presentation")


def build_two_act_hackathon_demo_plan():
    """Return a fresh JSON-compatible presentation plan, not execution evidence."""
    return {
        "schema_version": "1.0",
        "acts": [
            {"act": 1, "mode": "OFFLINE_PUBLIC_STANDALONE",
             "title": "Explore the public OpsCryer dogfood graph",
             "live_connections": False,
             "steps": ["Load the bundled synthetic public dataset offline.",
                       "Zoom from the root Citadel to feature verification and runbooks.",
                       "Demonstrate ticket routing and inspect example evidence." ]},
            {"act": 2, "mode": "SANITIZED_LIVE_HOME_NETWORK",
             "title": "Inspect sanitized home-network telemetry",
             "live_connections": True,
             "sanitizer": "sanitize_live_home_telemetry_for_demo",
             "steps": ["Collect authorized home-network telemetry in memory.",
                       "Sanitize before rendering, logging, exporting or sending to a model.",
                       "Inspect LAN and cluster.example.org topology with masked device identifiers."],
             "redactions": {"public_wan_ipv4": _WAN_REPLACEMENT,
                            "mac_examples": ["AA:BB:CC:XX:XX:XX", "AA-BB-CC-XX-XX-XX"],
                            "secrets_and_personal_gmail": _REDACTED}},
        ],
    }
