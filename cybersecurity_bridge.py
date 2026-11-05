# SPDX-License-Identifier: Apache-2.0
"""Multi-standard cybersecurity telemetry normalization, pure-stdlib Sigma evaluation,
sliding-window alert deduplication, 1-hop blast-radius subgraph enrichment, and unified REST API.
"""

from __future__ import annotations

import copy
import datetime
import fnmatch
import ipaddress
import json
import logging
import re
import threading
import time
import uuid
from typing import Any, Generator, Sequence

from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo

logger = logging.getLogger("opscryer.cybersecurity_bridge")

# Canonical 5-tier Severity Definition
SEVERITY_NAMES: tuple[str, ...] = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_MAP: dict[str, int] = {
    "INFORMATIONAL": 0,
    "INFO": 0,
    "LOW": 1,
    "NOTICE": 1,
    "MEDIUM": 2,
    "WARN": 2,
    "WARNING": 2,
    "HIGH": 3,
    "ERROR": 3,
    "CRITICAL": 4,
    "FATAL": 4,
    "ALERT": 4,
    "EMERGENCY": 4,
}

CRITICAL_TIERS: frozenset[str] = frozenset({
    "control_plane",
    "security",
    "iam",
    "storage",
    "kube-system",
})


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _canonical_severity(val: Any) -> tuple[str, int]:
    """Map any severity indicator to (canonical_name, canonical_id)."""
    if isinstance(val, int):
        if val <= 0:
            return "INFORMATIONAL", 0
        if val == 1:
            return "LOW", 1
        if val == 2:
            return "MEDIUM", 2
        if val == 3:
            return "HIGH", 3
        return "CRITICAL", 4
    if isinstance(val, str):
        cleaned = val.strip().upper()
        if cleaned in SEVERITY_MAP:
            s_id = SEVERITY_MAP[cleaned]
            return SEVERITY_NAMES[s_id], s_id
        # Check numeric in string
        try:
            num = int(cleaned)
            return _canonical_severity(num)
        except ValueError:
            pass
    return "INFORMATIONAL", 0


# =====================================================================
# 1. Multi-Standard Schema Normalization
# =====================================================================

def _split_cef_header(raw_line: str) -> list[str]:
    """Split a CEF line into its 8 components handling escaped pipes."""
    if not isinstance(raw_line, str) or not raw_line.startswith("CEF:"):
        raise ValueError("CEF line must start with 'CEF:'")
    parts: list[str] = []
    current: list[str] = []
    i = 0
    escaped = False
    while i < len(raw_line) and len(parts) < 7:
        c = raw_line[i]
        if escaped:
            current.append(c)
            escaped = False
        elif c == "\\":
            escaped = True
        elif c == "|":
            parts.append("".join(current))
            current = []
        else:
            current.append(c)
        i += 1
    if len(parts) < 7:
        parts.append("".join(current))
    else:
        parts.append(raw_line[i:] if i <= len(raw_line) else "")
    if len(parts) < 8:
        parts += [""] * (8 - len(parts))
    return parts


def _parse_cef_extension(ext: str) -> dict[str, str]:
    """Parse CEF extension key=value pairs handling escaped characters and unquoted spaces."""
    ext = ext.strip()
    if not ext:
        return {}
    pattern = re.compile(r'(?:^|\s+)([a-zA-Z0-9_]+)=')
    matches = list(pattern.finditer(ext))
    result: dict[str, str] = {}
    for i, m in enumerate(matches):
        key = m.group(1)
        val_start = m.end()
        val_end = matches[i + 1].start() if i + 1 < len(matches) else len(ext)
        raw_val = ext[val_start:val_end].strip()
        unescaped = raw_val.replace(r"\=", "=").replace(r"\|", "|").replace(r"\\", "\\")
        result[key] = unescaped
    return result


def _unpack_otlp_val(v_dict: Any) -> Any:
    if not isinstance(v_dict, dict):
        return v_dict
    if "stringValue" in v_dict:
        return v_dict["stringValue"]
    if "intValue" in v_dict:
        try:
            return int(v_dict["intValue"])
        except Exception:
            return v_dict["intValue"]
    if "boolValue" in v_dict:
        return bool(v_dict["boolValue"])
    if "doubleValue" in v_dict:
        try:
            return float(v_dict["doubleValue"])
        except Exception:
            return v_dict["doubleValue"]
    if "arrayValue" in v_dict:
        arr_val = v_dict.get("arrayValue")
        if isinstance(arr_val, dict):
            raw_vals = arr_val.get("values") or []
            if isinstance(raw_vals, list):
                return [_unpack_otlp_val(x) for x in raw_vals]
            return []
        elif isinstance(arr_val, list):
            return [_unpack_otlp_val(x) for x in arr_val]
        return []
    if "kvlistValue" in v_dict:
        kv_val = v_dict.get("kvlistValue")
        if isinstance(kv_val, dict):
            raw_vals = kv_val.get("values") or []
            if isinstance(raw_vals, list):
                return _unpack_otlp_attributes(raw_vals)
            return {}
        elif isinstance(kv_val, list):
            return _unpack_otlp_attributes(kv_val)
        return {}
    return v_dict


def _unpack_otlp_attributes(attrs: list[dict[str, Any]] | None) -> dict[str, Any]:
    if not attrs or not isinstance(attrs, list):
        return {}
    res: dict[str, Any] = {}
    for item in attrs:
        if not isinstance(item, dict):
            continue
        k = item.get("key")
        v_dict = item.get("value")
        if not k:
            continue
        res[k] = _unpack_otlp_val(v_dict)
    return res


def _detect_format(raw_event: Any) -> str:
    if isinstance(raw_event, str):
        s = raw_event.strip()
        if s.startswith("CEF:"):
            return "cef"
        try:
            parsed = json.loads(s)
            return _detect_format(parsed)
        except Exception:
            return "cef" if "CEF:" in raw_event else "generic"

    if isinstance(raw_event, dict):
        if "resourceLogs" in raw_event:
            return "otlp"
        if "class_uid" in raw_event or "category_uid" in raw_event:
            return "ocsf"
        if "metadata" in raw_event and isinstance(raw_event["metadata"], dict) and "profiles" in raw_event["metadata"]:
            return "ocsf"
        if "rule" in raw_event and isinstance(raw_event["rule"], dict) and ("level" in raw_event["rule"] or "agent" in raw_event):
            return "wazuh"
        if "priority" in raw_event and ("output_fields" in raw_event or "output" in raw_event):
            return "falco"
        if "alert" in raw_event and isinstance(raw_event["alert"], dict) and ("signature" in raw_event["alert"] or "signature_id" in raw_event["alert"]):
            return "suricata"
        if "title" in raw_event and ("cve" in raw_event or "cvssv3_score" in raw_event or "component_name" in raw_event):
            return "defectdojo"
        if "kibana.alert.rule.rule_id" in raw_event or "kibana" in raw_event:
            return "elastic"
        if "streams" in raw_event:
            return "loki"
        if "@timestamp" in raw_event or ("event" in raw_event and "host" in raw_event):
            return "ecs"
    return "generic"


def normalize_security_event(raw_event: dict | str, format_hint: str = "auto") -> dict[str, Any]:
    """Normalize raw security event telemetry from 4 standards or 6 connectors into canonical OCSF v1.1.

    Deeply sanitizes all fields with telemetry_sanitizer.sanitize_live_home_telemetry_for_demo.
    """
    if isinstance(raw_event, str):
        stripped = raw_event.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                raw_event = json.loads(stripped)
            except Exception:
                pass

    detected_format = _detect_format(raw_event) if format_hint == "auto" else format_hint.lower()

    # Defaults
    event_id = f"sec-{uuid.uuid4().hex[:8]}"
    ts_iso = _now_iso()
    ts_ms = _now_ms()
    sev_name = "INFORMATIONAL"
    sev_id = 0
    category = "Findings"
    activity = "Create"
    rule_id = "rule-unspecified"
    rule_name = "Security Telemetry Finding"
    rule_desc = ""
    rule_tags: list[str] = []
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []

    target_node_id = "unknown_node"
    target_workload = "unknown_workload"
    target_namespace = "default"
    target_cluster = "homelab-cluster"
    target_ip = "127.0.0.1"
    target_port: int | None = None

    source_ip = "127.0.0.1"
    source_port: int | None = None
    source_user = "system"
    source_host = "local"
    proc_pid: int | None = None
    proc_name = ""
    proc_cmdline = ""
    proc_parent_pid: int | None = None

    vulns: list[dict[str, Any]] = []
    trace_id = ""
    span_id = ""
    message = ""
    raw_unmapped: dict[str, Any] = {}

    if detected_format == "cef" and isinstance(raw_event, str):
        try:
            parts = _split_cef_header(raw_event)
            # parts: [CEF:ver, vendor, product, version, class_id, name, severity, ext]
            if len(parts) < 8:
                parts += [""] * (8 - len(parts))
            rule_id = parts[4] or rule_id
            rule_name = parts[5] or rule_name
            raw_sev = parts[6]
            try:
                cef_sev_num = int(raw_sev)
                if cef_sev_num <= 2:
                    sev_name, sev_id = "INFORMATIONAL", 0
                elif cef_sev_num <= 4:
                    sev_name, sev_id = "LOW", 1
                elif cef_sev_num <= 6:
                    sev_name, sev_id = "MEDIUM", 2
                elif cef_sev_num <= 8:
                    sev_name, sev_id = "HIGH", 3
                else:
                    sev_name, sev_id = "CRITICAL", 4
            except ValueError:
                sev_name, sev_id = _canonical_severity(raw_sev)

            ext = _parse_cef_extension(parts[7])
            source_ip = ext.get("src", source_ip)
            if "spt" in ext:
                try:
                    source_port = int(ext["spt"])
                except ValueError:
                    pass
            source_user = ext.get("suser", source_user)
            source_host = ext.get("shost", source_host)

            target_ip = ext.get("dst", target_ip)
            if "dpt" in ext:
                try:
                    target_port = int(ext["dpt"])
                except ValueError:
                    pass
            target_node_id = ext.get("dhost", target_node_id)
            target_workload = ext.get("cs1", target_workload)
            target_namespace = ext.get("cs2", target_namespace)
            trace_id = ext.get("cs3", trace_id)
            event_id = ext.get("externalId", event_id)
            message = ext.get("msg", rule_name)
            raw_unmapped = {k: v for k, v in ext.items() if k not in {
                "src", "spt", "suser", "shost", "dst", "dpt", "dhost", "cs1", "cs2", "cs3", "externalId", "msg"
            }}
            raw_unmapped["device_vendor"] = parts[1]
            raw_unmapped["device_product"] = parts[2]
            raw_unmapped["device_version"] = parts[3]
        except Exception:
            # Fall back gracefully to generic normalization on malformed CEF lines
            message = raw_event or rule_name
            raw_unmapped["raw_payload"] = raw_event

    elif detected_format == "ocsf" and isinstance(raw_event, dict):
        event_id = str(raw_event.get("finding_info", {}).get("uid") or raw_event.get("id") or event_id)
        if "time" in raw_event:
            try:
                ts_ms = int(raw_event["time"])
                ts_iso = datetime.datetime.fromtimestamp(ts_ms / 1000, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                pass
        raw_sev = raw_event.get("severity_id") or raw_event.get("severity")
        if isinstance(raw_sev, int):
            ocsf_map = {1: ("INFORMATIONAL", 0), 2: ("LOW", 1), 3: ("MEDIUM", 2), 4: ("HIGH", 3), 5: ("CRITICAL", 4), 6: ("CRITICAL", 4)}
            sev_name, sev_id = ocsf_map.get(raw_sev, ("INFORMATIONAL", 0))
        else:
            sev_name, sev_id = _canonical_severity(raw_sev)

        f_info = raw_event.get("finding_info", {})
        rule_name = f_info.get("title", rule_name)
        rule_desc = f_info.get("desc", rule_desc)
        rule_tags = f_info.get("types", rule_tags)
        message = raw_event.get("message") or rule_desc or rule_name

        device = raw_event.get("device") or raw_event.get("endpoint") or {}
        target_node_id = device.get("hostname") or device.get("name") or target_node_id
        target_ip = device.get("ip", target_ip)
        target_namespace = device.get("namespace", target_namespace)
        target_workload = raw_event.get("workload") or raw_event.get("service", {}).get("name") or target_workload

        actor = raw_event.get("actor") or raw_event.get("src_endpoint") or {}
        source_user = actor.get("user", {}).get("name", source_user)
        source_ip = actor.get("ip", source_ip)
        proc = actor.get("process", {})
        proc_name = proc.get("name", "")
        proc_cmdline = proc.get("cmdline", "")
        proc_pid = proc.get("pid")

        if "vulnerabilities" in raw_event and isinstance(raw_event["vulnerabilities"], list):
            vulns = raw_event["vulnerabilities"]

    elif detected_format == "ecs" and isinstance(raw_event, dict):
        if "@timestamp" in raw_event:
            ts_iso = str(raw_event["@timestamp"])
        event_id = str(raw_event.get("event", {}).get("id") or raw_event.get("id") or event_id)
        raw_sev = raw_event.get("event", {}).get("severity") or raw_event.get("log", {}).get("level")
        sev_name, sev_id = _canonical_severity(raw_sev)

        rule_block = raw_event.get("rule", {})
        rule_id = str(rule_block.get("id") or rule_id)
        rule_name = str(rule_block.get("name") or rule_name)
        rule_desc = str(rule_block.get("description") or rule_desc)
        message = str(raw_event.get("message") or rule_desc or rule_name)

        host = raw_event.get("host", {})
        target_node_id = host.get("name") or host.get("id") or target_node_id
        target_ip = host.get("ip") if isinstance(host.get("ip"), str) else (host.get("ip", [target_ip])[0] if isinstance(host.get("ip"), list) else target_ip)

        container = raw_event.get("container", {})
        service = raw_event.get("service", {})
        target_workload = container.get("name") or service.get("name") or target_workload
        target_namespace = raw_event.get("orchestrator", {}).get("namespace", target_namespace)

        source = raw_event.get("source", {})
        source_ip = source.get("ip", source_ip)
        source_port = source.get("port", source_port)
        source_user = source.get("user", {}).get("name", source_user)

        process = raw_event.get("process", {})
        proc_pid = process.get("pid", proc_pid)
        proc_name = process.get("name", proc_name)
        proc_cmdline = process.get("command_line", proc_cmdline)

        trace = raw_event.get("trace", {})
        trace_id = trace.get("id", trace_id)
        span_id = raw_event.get("span", {}).get("id", span_id)

    elif detected_format == "otlp" and isinstance(raw_event, dict):
        r_logs = raw_event.get("resourceLogs") or []
        if isinstance(r_logs, list):
            first_res = next((item for item in r_logs if isinstance(item, dict)), None)
            if first_res is not None:
                res_obj = first_res.get("resource")
                res_dict = res_obj if isinstance(res_obj, dict) else {}
                r_attrs = _unpack_otlp_attributes(res_dict.get("attributes"))
                target_workload = r_attrs.get("service.name") or r_attrs.get("k8s.container.name") or target_workload
                target_node_id = r_attrs.get("k8s.node.name") or r_attrs.get("host.name") or target_node_id
                target_namespace = r_attrs.get("k8s.namespace.name") or target_namespace
                target_cluster = r_attrs.get("k8s.cluster.name") or target_cluster

                scope_logs = first_res.get("scopeLogs") or []
                if isinstance(scope_logs, list):
                    first_scope = next((item for item in scope_logs if isinstance(item, dict)), None)
                    if first_scope is not None:
                        log_records = first_scope.get("logRecords") or []
                        if isinstance(log_records, list):
                            rec = next((item for item in log_records if isinstance(item, dict)), None)
                            if rec is not None:
                                t_nano = rec.get("timeUnixNano")
                                if t_nano:
                                    try:
                                        ts_ms = int(t_nano) // 1_000_000
                                        ts_iso = datetime.datetime.fromtimestamp(ts_ms / 1000, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                                    except Exception:
                                        pass
                                sev_num = rec.get("severityNumber")
                                if isinstance(sev_num, int):
                                    if sev_num <= 12:
                                        sev_name, sev_id = "INFORMATIONAL", 0
                                    elif sev_num <= 16:
                                        sev_name, sev_id = "MEDIUM", 2
                                    elif sev_num <= 20:
                                        sev_name, sev_id = "HIGH", 3
                                    else:
                                        sev_name, sev_id = "CRITICAL", 4
                                else:
                                    sev_name, sev_id = _canonical_severity(rec.get("severityText"))

                                body_val = rec.get("body")
                                if isinstance(body_val, dict):
                                    message = body_val.get("stringValue") or str(body_val)
                                elif body_val is not None:
                                    message = str(body_val)
                                trace_id = rec.get("traceId", trace_id)
                                span_id = rec.get("spanId", span_id)
                                rec_attrs = _unpack_otlp_attributes(rec.get("attributes"))
                                rule_id = rec_attrs.get("security.rule.id") or rule_id
                                source_ip = rec_attrs.get("source.ip", source_ip)
                                source_user = rec_attrs.get("source.user", source_user)

    elif detected_format == "wazuh" and isinstance(raw_event, dict):
        rule = raw_event.get("rule", {})
        rule_id = str(rule.get("id") or rule_id)
        rule_name = str(rule.get("description") or rule_name)
        message = str(raw_event.get("full_log") or rule_name)
        level = rule.get("level")
        if isinstance(level, int):
            if level <= 3:
                sev_name, sev_id = "INFORMATIONAL", 0
            elif level <= 6:
                sev_name, sev_id = "LOW", 1
            elif level <= 9:
                sev_name, sev_id = "MEDIUM", 2
            elif level <= 12:
                sev_name, sev_id = "HIGH", 3
            else:
                sev_name, sev_id = "CRITICAL", 4
        else:
            sev_name, sev_id = _canonical_severity(level)

        mitre = rule.get("mitre", {})
        mitre_tactics = mitre.get("tactic", mitre_tactics)
        mitre_techniques = mitre.get("id", mitre_techniques)

        agent = raw_event.get("agent", {})
        target_node_id = agent.get("name") or agent.get("id") or target_node_id
        target_ip = agent.get("ip", target_ip)

        data = raw_event.get("data", {})
        source_ip = data.get("srcip", source_ip)
        source_user = data.get("srcuser", source_user)
        target_workload = data.get("workload", target_workload)
        target_namespace = data.get("namespace", target_namespace)

    elif detected_format == "falco" and isinstance(raw_event, dict):
        rule_name = str(raw_event.get("rule") or rule_name)
        rule_id = f"falco-{rule_name.lower().replace(' ', '-')}"
        priority = raw_event.get("priority", "Notice")
        falco_map = {
            "DEBUG": ("INFORMATIONAL", 0),
            "INFORMATIONAL": ("INFORMATIONAL", 0),
            "INFO": ("INFORMATIONAL", 0),
            "NOTICE": ("LOW", 1),
            "WARNING": ("MEDIUM", 2),
            "ERROR": ("HIGH", 3),
            "CRITICAL": ("CRITICAL", 4),
            "ALERT": ("CRITICAL", 4),
            "EMERGENCY": ("CRITICAL", 4),
        }
        sev_name, sev_id = falco_map.get(str(priority).upper(), ("LOW", 1))
        message = str(raw_event.get("output") or rule_name)
        rule_tags = raw_event.get("tags", rule_tags)

        out_fields = raw_event.get("output_fields", {})
        target_workload = out_fields.get("k8s.pod.name") or out_fields.get("container.name") or target_workload
        target_namespace = out_fields.get("k8s.ns.name") or target_namespace
        target_node_id = out_fields.get("container.id") or out_fields.get("k8s.pod.name") or target_node_id
        proc_name = out_fields.get("proc.name", proc_name)
        proc_cmdline = out_fields.get("proc.cmdline", proc_cmdline)
        source_user = out_fields.get("user.name", source_user)

    elif detected_format == "suricata" and isinstance(raw_event, dict):
        alert = raw_event.get("alert", {})
        rule_name = str(alert.get("signature") or rule_name)
        rule_id = str(alert.get("signature_id") or rule_id)
        category = str(alert.get("category") or "Network Activity")
        suricata_sev = alert.get("severity")
        if suricata_sev == 1:
            if "exploit" in rule_name.lower() or "rce" in rule_name.lower():
                sev_name, sev_id = "CRITICAL", 4
            else:
                sev_name, sev_id = "HIGH", 3
        elif suricata_sev == 2:
            sev_name, sev_id = "MEDIUM", 2
        elif suricata_sev == 3:
            sev_name, sev_id = "LOW", 1
        elif suricata_sev == 4:
            sev_name, sev_id = "INFORMATIONAL", 0
        else:
            sev_name, sev_id = _canonical_severity(suricata_sev)

        source_ip = raw_event.get("src_ip", source_ip)
        source_port = raw_event.get("src_port", source_port)
        target_ip = raw_event.get("dest_ip", target_ip)
        target_port = raw_event.get("dest_port", target_port)
        http_info = raw_event.get("http", {})
        if "hostname" in http_info:
            target_workload = http_info["hostname"]
        message = rule_name

    elif detected_format == "defectdojo" and isinstance(raw_event, dict):
        rule_name = str(raw_event.get("title") or rule_name)
        rule_desc = str(raw_event.get("description") or rule_desc)
        message = rule_desc or rule_name
        sev_name, sev_id = _canonical_severity(raw_event.get("severity"))
        target_workload = str(raw_event.get("component_name") or target_workload)
        if "cve" in raw_event:
            vulns.append({
                "cve": raw_event.get("cve"),
                "cvss": float(raw_event.get("cvssv3_score", 0.0)) if raw_event.get("cvssv3_score") else None,
                "severity": sev_name,
                "package_name": target_workload,
                "package_version": raw_event.get("component_version", ""),
                "fixed_version": raw_event.get("mitigation", ""),
            })

    elif detected_format == "elastic" and isinstance(raw_event, dict):
        kibana_rule = raw_event.get("kibana.alert.rule", raw_event.get("rule", {}))
        if not isinstance(kibana_rule, dict):
            kibana_rule = {}
        rule_id = str(raw_event.get("kibana.alert.rule.rule_id") or kibana_rule.get("rule_id") or rule_id)
        rule_name = str(raw_event.get("kibana.alert.rule.name") or kibana_rule.get("name") or rule_name)
        raw_sev = (
            raw_event.get("kibana.alert.rule.severity")
            or kibana_rule.get("severity")
            or raw_event.get("severity")
        )
        sev_name, sev_id = _canonical_severity(raw_sev)
        host = raw_event.get("host", {})
        if isinstance(host, dict):
            target_node_id = host.get("name", target_node_id)
        proc_obj = raw_event.get("process", {})
        if isinstance(proc_obj, dict):
            proc_name = proc_obj.get("name", proc_name)
            proc_cmdline = proc_obj.get("command_line") or proc_obj.get("cmdline") or proc_cmdline
        message = raw_event.get("message") or rule_name

    elif detected_format == "loki" and isinstance(raw_event, dict):
        streams = raw_event.get("streams", [])
        if streams and isinstance(streams, list):
            stream_labels = streams[0].get("stream", {})
            rule_id = stream_labels.get("rule_id", rule_id)
            sev_name, sev_id = _canonical_severity(stream_labels.get("severity") or stream_labels.get("level"))
            target_workload = stream_labels.get("workload", target_workload)
            target_node_id = stream_labels.get("node", target_node_id)
            values = streams[0].get("values", [])
            if values and isinstance(values, list) and len(values[0]) > 1:
                val_text = values[0][1]
                try:
                    nested_json = json.loads(val_text)
                    message = nested_json.get("message", val_text)
                    trace_id = nested_json.get("trace_id", trace_id)
                    span_id = nested_json.get("span_id", span_id)
                except Exception:
                    message = val_text

    else:
        # Generic dictionary fallback
        if isinstance(raw_event, dict):
            rule_id = str(raw_event.get("rule_id") or raw_event.get("id") or rule_id)
            rule_name = str(raw_event.get("title") or raw_event.get("rule_name") or rule_name)
            sev_name, sev_id = _canonical_severity(raw_event.get("severity") or raw_event.get("level"))
            target_node_id = str(raw_event.get("target_node_id") or raw_event.get("node_id") or raw_event.get("node") or target_node_id)
            target_workload = str(raw_event.get("target_workload") or raw_event.get("workload") or raw_event.get("service") or target_workload)
            target_namespace = str(raw_event.get("namespace", target_namespace))
            message = str(raw_event.get("message") or raw_event.get("description") or rule_name)

            proc_obj = raw_event.get("process")
            if isinstance(proc_obj, dict):
                proc_name = proc_obj.get("name") or proc_name
                proc_cmdline = proc_obj.get("command_line") or proc_obj.get("cmdline") or proc_cmdline
                proc_pid = proc_obj.get("pid", proc_pid)

            user_obj = raw_event.get("user")
            if isinstance(user_obj, dict):
                source_user = user_obj.get("name") or source_user
            elif isinstance(user_obj, str):
                source_user = user_obj

            source_ip = str(raw_event.get("source_ip") or raw_event.get("src_ip") or source_ip)
            target_ip = str(raw_event.get("destination_ip") or raw_event.get("target_ip") or raw_event.get("dest_ip") or target_ip)

            tgt_dict = raw_event.get("target")
            if isinstance(tgt_dict, dict):
                target_ip = str(tgt_dict.get("ip") or target_ip)
                target_node_id = str(tgt_dict.get("node_id") or target_node_id)
                target_workload = str(tgt_dict.get("workload") or target_workload)
                target_namespace = str(tgt_dict.get("namespace") or target_namespace)

            src_dict = raw_event.get("source")
            if isinstance(src_dict, dict):
                source_ip = str(src_dict.get("ip") or source_ip)
                source_user = str(src_dict.get("user") or source_user)
                if isinstance(src_dict.get("process"), dict):
                    proc_name = src_dict["process"].get("name") or proc_name
                    proc_cmdline = src_dict["process"].get("cmdline") or src_dict["process"].get("command_line") or proc_cmdline

            known_keys = {
                "rule_id", "id", "title", "rule_name", "severity", "level", "target_node_id", "node_id", "node",
                "target_workload", "workload", "service", "namespace", "message", "description",
                "process", "user", "source_ip", "src_ip", "destination_ip", "target_ip", "dest_ip", "target", "source"
            }
            raw_unmapped = {k: v for k, v in raw_event.items() if k not in known_keys}

    canonical: dict[str, Any] = {
        "schema_version": "1.1.0",
        "standard_source": detected_format,
        "event_id": event_id,
        "timestamp": ts_iso,
        "timestamp_ms": ts_ms,
        "severity": sev_name,
        "severity_id": sev_id,
        "category": category,
        "activity": activity,
        "rule": {
            "id": rule_id,
            "name": rule_name,
            "description": rule_desc,
            "tags": rule_tags,
            "mitre": {
                "tactics": mitre_tactics,
                "techniques": mitre_techniques,
            },
        },
        "target": {
            "node_id": target_node_id,
            "workload": target_workload,
            "namespace": target_namespace,
            "cluster": target_cluster,
            "ip": target_ip,
            "port": target_port,
        },
        "source": {
            "ip": source_ip,
            "port": source_port,
            "user": source_user,
            "host": source_host,
            "process": {
                "pid": proc_pid,
                "name": proc_name,
                "cmdline": proc_cmdline,
                "parent_pid": proc_parent_pid,
            },
        },
        "vulnerabilities": vulns,
        "trace_context": {
            "trace_id": trace_id,
            "span_id": span_id,
        },
        "message": message,
        "raw_unmapped": raw_unmapped,
        "deduplication": None,
        "blast_radius": None,
        "enriched_subgraph": None,
        # Top-level convenience accessors for downstream consumers
        "target_node_id": target_node_id,
        "target_workload": target_workload,
        "rule_id": rule_id,
    }

    # Pass through OPSEC sanitization to ensure no WAN IPs or secrets leak
    sanitized: dict[str, Any] = sanitize_live_home_telemetry_for_demo(canonical)
    return sanitized


# =====================================================================
# 2. Pure-Stdlib Safe Sigma Rule Evaluator (Recursive Descent Grammar)
# =====================================================================

def _resolve_field(event: dict[str, Any], path: str) -> Any:
    """Resolve dotted or nested field path from normalized or vendor event."""
    if path in event:
        return event[path]
    parts = path.split(".")
    curr: Any = event
    found = True
    for p in parts:
        if isinstance(curr, dict) and p in curr:
            curr = curr[p]
        elif isinstance(curr, list):
            sub_items: list[Any] = []
            for item in curr:
                if isinstance(item, dict) and p in item:
                    sub_items.append(item[p])
            if sub_items:
                curr = sub_items
            else:
                found = False
                break
        else:
            found = False
            break
    if found and curr is not None and curr != "":
        return curr

    alias_map: dict[str, tuple[str, ...]] = {
        "process.name": ("source", "process", "name"),
        "process.command_line": ("source", "process", "cmdline"),
        "process.cmdline": ("source", "process", "cmdline"),
        "process.pid": ("source", "process", "pid"),
        "destination.ip": ("target", "ip"),
        "destination.port": ("target", "port"),
        "target.ip": ("target", "ip"),
        "target.port": ("target", "port"),
        "target.node_id": ("target", "node_id"),
        "target.node": ("target", "node_id"),
        "host.name": ("target", "node_id"),
        "source.ip": ("source", "ip"),
        "source.port": ("source", "port"),
        "source.user": ("source", "user"),
        "user.name": ("source", "user"),
        "service.name": ("target", "workload"),
        "k8s.pod.name": ("target", "workload"),
        "target.workload": ("target", "workload"),
        "target.namespace": ("target", "namespace"),
    }
    if path in alias_map:
        curr = event
        for p in alias_map[path]:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                curr = None
                break
        if curr is not None and curr != "":
            return curr

    if "raw_unmapped" in event and isinstance(event["raw_unmapped"], dict):
        if path in event["raw_unmapped"] and event["raw_unmapped"][path] is not None and event["raw_unmapped"][path] != "":
            return event["raw_unmapped"][path]
        curr = event["raw_unmapped"]
        found = True
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                found = False
                break
        if found and curr is not None and curr != "":
            return curr
    return None


def _match_single_value(val: Any, pattern: Any, modifiers: list[str]) -> bool:
    if val is None:
        return pattern is None
    str_val = str(val)

    if "cidr" in modifiers:
        try:
            val_ip_str = str(val).strip()
            if ":" in val_ip_str and not val_ip_str.startswith("[") and val_ip_str.count(":") == 1:
                val_ip_str = val_ip_str.split(":")[0]
            ip_obj = ipaddress.ip_address(val_ip_str)
            pat_str = str(pattern).strip()
            if "/" not in pat_str:
                net_obj = ipaddress.ip_network(f"{pat_str}/32" if ip_obj.version == 4 else f"{pat_str}/128", strict=False)
            else:
                net_obj = ipaddress.ip_network(pat_str, strict=False)
            return ip_obj in net_obj
        except Exception:
            return False

    if "re" in modifiers:
        try:
            return bool(re.search(str(pattern), str_val, re.IGNORECASE))
        except Exception:
            return False

    if "contains" in modifiers:
        return str(pattern).lower() in str_val.lower()

    if "startswith" in modifiers:
        return str_val.lower().startswith(str(pattern).lower())

    if "endswith" in modifiers:
        return str_val.lower().endswith(str(pattern).lower())

    if isinstance(pattern, (int, float, bool)) and isinstance(val, (int, float, bool)):
        return val == pattern
    return str_val.lower() == str(pattern).lower()


def _check_field_match(val: Any, pattern: Any, modifiers: list[str]) -> bool:
    val_items = val if isinstance(val, list) else [val]
    pat_items = pattern if isinstance(pattern, list) else [pattern]
    for v in val_items:
        for p in pat_items:
            if _match_single_value(v, p, modifiers):
                return True
    return False


def _evaluate_selection_dict(event: dict[str, Any], sel_dict: dict[str, Any]) -> bool:
    for key, pattern in sel_dict.items():
        parts = key.split("|")
        field_path = parts[0].strip()
        modifiers = [m.strip().lower() for m in parts[1:]]
        val = _resolve_field(event, field_path)
        if val is None and pattern is not None:
            return False
        if not _check_field_match(val, pattern, modifiers):
            return False
    return True


def _evaluate_selection_block(event: dict[str, Any], block: Any) -> bool:
    if isinstance(block, dict):
        return _evaluate_selection_dict(event, block)
    if isinstance(block, list):
        for item in block:
            if isinstance(item, dict) and _evaluate_selection_dict(event, item):
                return True
        return False
    return False


class _SigmaConditionParser:
    """Safe pure-stdlib recursive descent condition evaluator without eval() or exec()."""

    def __init__(self, condition_str: str, selection_results: dict[str, bool]) -> None:
        self.raw_cond = condition_str.strip()
        self.results = selection_results
        self.tokens = self._tokenize(self.raw_cond)
        self.pos = 0

    def _tokenize(self, text: str) -> list[tuple[str, str]]:
        tokens: list[tuple[str, str]] = []
        i = 0
        n = len(text)
        while i < n:
            c = text[i]
            if c.isspace():
                i += 1
                continue
            if c == "(":
                tokens.append(("LPAREN", "("))
                i += 1
                continue
            if c == ")":
                tokens.append(("RPAREN", ")"))
                i += 1
                continue

            rest = text[i:]
            # Multi-word quantifiers: '1 of <pattern>' or 'all of <pattern>'
            m_1of = re.match(r"^1\s+of\s+([a-zA-Z0-9_*]+)", rest, re.IGNORECASE)
            if m_1of:
                tokens.append(("QUANT_1_OF", m_1of.group(1)))
                i += len(m_1of.group(0))
                continue

            m_allof = re.match(r"^all\s+of\s+([a-zA-Z0-9_*]+)", rest, re.IGNORECASE)
            if m_allof:
                tokens.append(("QUANT_ALL_OF", m_allof.group(1)))
                i += len(m_allof.group(0))
                continue

            m_word = re.match(r"^[a-zA-Z0-9_*]+", rest)
            if m_word:
                word = m_word.group(0)
                w_lower = word.lower()
                if w_lower == "and":
                    tokens.append(("AND", "and"))
                elif w_lower == "or":
                    tokens.append(("OR", "or"))
                elif w_lower == "not":
                    tokens.append(("NOT", "not"))
                else:
                    tokens.append(("IDENTIFIER", word))
                i += len(word)
                continue

            # Skip unrecognized character
            i += 1
        return tokens

    def parse(self) -> bool:
        if not self.tokens:
            return False
        try:
            val = self._expr()
            if self.pos < len(self.tokens):
                raise ValueError(
                    f"Unparsed trailing tokens at pos {self.pos}: {self.tokens[self.pos:]}"
                )
            return bool(val)
        except Exception as e:
            logger.debug("Condition parse error for '%s': %s", self.raw_cond, e)
            return False

    def _expr(self) -> bool:
        return self._or_term()

    def _or_term(self) -> bool:
        left = self._and_term()
        while self.pos < len(self.tokens) and self.tokens[self.pos][0] == "OR":
            self.pos += 1
            right = self._and_term()
            left = left or right
        return left

    def _and_term(self) -> bool:
        left = self._not_term()
        while self.pos < len(self.tokens) and self.tokens[self.pos][0] == "AND":
            self.pos += 1
            right = self._not_term()
            left = left and right
        return left

    def _not_term(self) -> bool:
        if self.pos < len(self.tokens) and self.tokens[self.pos][0] == "NOT":
            self.pos += 1
            return not self._not_term()
        return self._factor()

    def _factor(self) -> bool:
        if self.pos >= len(self.tokens):
            return False
        token_type, token_val = self.tokens[self.pos]
        if token_type == "LPAREN":
            self.pos += 1
            res = self._expr()
            if self.pos < len(self.tokens) and self.tokens[self.pos][0] == "RPAREN":
                self.pos += 1
            else:
                raise ValueError("Expected RPAREN ')' after expression")
            return res
        if token_type == "QUANT_1_OF":
            self.pos += 1
            return self._eval_quantifier(token_val, mode="1_of")
        if token_type == "QUANT_ALL_OF":
            self.pos += 1
            return self._eval_quantifier(token_val, mode="all_of")
        if token_type == "IDENTIFIER":
            self.pos += 1
            return self._eval_identifier(token_val)
        self.pos += 1
        return False

    def _eval_identifier(self, name: str) -> bool:
        if "*" in name:
            matched = [k for k in self.results if fnmatch.fnmatch(k, name)]
            return any(self.results[k] for k in matched)
        return self.results.get(name, False)

    def _eval_quantifier(self, pattern: str, mode: str) -> bool:
        if pattern.lower() == "them":
            target_keys = list(self.results.keys())
        else:
            target_keys = [k for k in self.results if fnmatch.fnmatch(k, pattern)]

        if not target_keys:
            return False
        if mode == "1_of":
            return any(self.results[k] for k in target_keys)
        if mode == "all_of":
            return all(self.results[k] for k in target_keys)
        return False


def evaluate_sigma_rules(
    normalized_event: dict[str, Any],
    rules: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Evaluate pure-stdlib Sigma detection rules against normalized event.

    Never uses eval() or exec().
    """
    if rules is None:
        rules = _GLOBAL_INCIDENT_STORE.list_rules()

    matches: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        detection = rule.get("detection")
        if not isinstance(detection, dict):
            continue

        selection_results: dict[str, bool] = {}
        for block_name, block_content in detection.items():
            if block_name == "condition":
                continue
            selection_results[block_name] = _evaluate_selection_block(normalized_event, block_content)

        condition_str = detection.get("condition")
        if not condition_str or not isinstance(condition_str, str):
            if "selection" in selection_results and "filter" in selection_results:
                condition_str = "selection and not filter"
            elif "selection" in selection_results:
                condition_str = "selection"
            else:
                condition_str = "1 of them"

        parser = _SigmaConditionParser(condition_str, selection_results)
        matched = parser.parse()

        if matched:
            rule_id = str(rule.get("id") or "sigma-unnamed")
            rule_title = str(rule.get("title") or rule.get("name") or rule_id)
            level = str(rule.get("level", "medium")).upper()
            target_node = (
                (normalized_event.get("target") or {}).get("node_id")
                or normalized_event.get("target_node_id")
                or "unknown_node"
            )
            target_workload = (
                (normalized_event.get("target") or {}).get("workload")
                or normalized_event.get("target_workload")
                or "unknown_workload"
            )
            matches.append({
                "matched": True,
                "rule_id": rule_id,
                "rule_title": rule_title,
                "severity": level,
                "description": rule.get("description", ""),
                "matched_selections": [k for k, v in selection_results.items() if v],
                "timestamp": time.time(),
                "event": normalized_event,
                "target_node_id": target_node,
                "target_workload": target_workload,
            })
    return matches


# =====================================================================
# 3. Alert Storm Deduplicator (Sliding Time Window)
# =====================================================================

class AlertDeduplicator:
    """Thread-safe sliding-window alert deduplicator keyed by (rule_id, target_node, workload)."""

    def __init__(self, default_window_seconds: int = 300) -> None:
        self.default_window_seconds = default_window_seconds
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}

    def deduplicate(self, incident: dict[str, Any], window_seconds: int | None = None) -> dict[str, Any]:
        win = window_seconds if window_seconds is not None else self.default_window_seconds
        rule_id = str(
            (incident.get("rule") or {}).get("id")
            or incident.get("rule_id")
            or incident.get("id")
            or "unknown_rule"
        ).strip()
        target_node = str(
            (incident.get("target") or {}).get("node_id")
            or incident.get("target_node_id")
            or incident.get("node_id")
            or "unknown_node"
        ).strip()
        workload = str(
            (incident.get("target") or {}).get("workload")
            or incident.get("target_workload")
            or incident.get("workload")
            or "unknown_workload"
        ).strip()

        dedup_key = f"{rule_id}::{target_node}::{workload}"
        now = time.time()

        with self._lock:
            if dedup_key in self._entries:
                entry = self._entries[dedup_key]
                if now - entry["window_start"] >= win:
                    # Window expired; reset
                    entry["window_start"] = now
                    entry["first_seen"] = now
                    entry["last_seen"] = now
                    entry["occurrence_count"] = 1
                    entry["is_suppressed"] = False
                else:
                    # Within window
                    entry["occurrence_count"] += 1
                    entry["last_seen"] = now
                    entry["is_suppressed"] = True
            else:
                entry = {
                    "first_seen": now,
                    "last_seen": now,
                    "window_start": now,
                    "occurrence_count": 1,
                    "is_suppressed": False,
                }
                self._entries[dedup_key] = entry

            # Periodic memory pruning of stale keys
            stale_threshold = max(3600.0, float(win * 2))
            stale_keys = [k for k, v in self._entries.items() if now - v["last_seen"] > stale_threshold]
            for k in stale_keys:
                del self._entries[k]

            occurrence_count = entry["occurrence_count"]
            is_suppressed = entry["is_suppressed"]
            first_seen = entry["first_seen"]
            last_seen = entry["last_seen"]

        incident["dedup_key"] = dedup_key
        incident["occurrence_count"] = occurrence_count
        incident["is_suppressed"] = is_suppressed
        incident["first_seen"] = first_seen
        incident["last_seen"] = last_seen
        incident["deduplication"] = {
            "dedup_key": dedup_key,
            "occurrence_count": occurrence_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "is_suppressed": is_suppressed,
            "window_seconds": win,
        }
        return incident

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


_GLOBAL_DEDUPLICATOR = AlertDeduplicator()


def deduplicate_security_incident(incident: dict[str, Any], window_seconds: int = 300) -> dict[str, Any]:
    return _GLOBAL_DEDUPLICATOR.deduplicate(incident, window_seconds=window_seconds)


def reset_alert_deduplicator() -> None:
    _GLOBAL_DEDUPLICATOR.clear()


# =====================================================================
# 4. 1-Hop Blast-Radius Subgraph Enrichment
# =====================================================================

def enrich_with_1hop_neighborhood(
    incident: dict[str, Any],
    catalog: dict[str, Any] | Any | None = None,
) -> dict[str, Any]:
    """Enrich incident with 1-hop upstream, downstream, and colocated spatial graph neighborhood.

    Integrates with KnowledgeGraphBackendEngine and publishes to event_stream topic 'security'.
    """
    target_node_id = str(
        (incident.get("target") or {}).get("node_id")
        or incident.get("target_node_id")
        or incident.get("node_id")
        or incident.get("target_workload")
        or "unknown_node"
    ).strip()

    cat: dict[str, Any] = {}
    if catalog is None:
        try:
            from opscryer_backend import KnowledgeGraphBackendEngine
            cat = KnowledgeGraphBackendEngine().catalog()
        except Exception as e:
            logger.debug("Catalog load fallback: %s", e)
            cat = {"nodes": [], "edges": []}
    elif hasattr(catalog, "catalog") and callable(catalog.catalog):
        cat = catalog.catalog()
    elif isinstance(catalog, dict):
        cat = catalog

    raw_nodes = cat.get("nodes") or []
    nodes = [n for n in raw_nodes if isinstance(n, dict)] if isinstance(raw_nodes, list) else []

    raw_edges = cat.get("edges") or []
    edges = [e for e in raw_edges if isinstance(e, dict)] if isinstance(raw_edges, list) else []

    matched_node: dict[str, Any] | None = None
    for n in nodes:
        if n.get("id") == target_node_id or n.get("label") == target_node_id:
            matched_node = n
            break

    if matched_node is None:
        matched_node = {
            "id": target_node_id,
            "label": target_node_id,
            "kind": "unresolved_in_catalog",
            "domain": "unknown",
            "summary": "Node not found in spatial graph catalog",
            "primary_url": "",
        }

    target_id = matched_node.get("id", target_node_id)

    # 1-hop upstream
    upstream_nodes: list[dict[str, Any]] = []
    seen_upstream = set()
    for e in edges:
        if e.get("target") == target_id:
            src_id = e.get("source")
            if src_id and src_id not in seen_upstream and src_id != target_id:
                seen_upstream.add(src_id)
                src_node = next((n for n in nodes if n.get("id") == src_id), None)
                upstream_nodes.append({
                    "id": src_id,
                    "label": src_node.get("label", src_id) if src_node else src_id,
                    "kind": src_node.get("kind", "service") if src_node else "service",
                    "domain": src_node.get("domain", "default") if src_node else "default",
                    "relation": e.get("relation", "depends_on"),
                })

    for n in nodes:
        children = n.get("drilldown_children") or []
        if isinstance(children, list) and target_id in children:
            n_id = n.get("id")
            if n_id and n_id not in seen_upstream:
                seen_upstream.add(n_id)
                upstream_nodes.append({
                    "id": n_id,
                    "label": n.get("label", n_id),
                    "kind": n.get("kind", "container"),
                    "domain": n.get("domain", "default"),
                    "relation": "parent_container",
                })

    # 1-hop downstream
    downstream_nodes: list[dict[str, Any]] = []
    seen_downstream = set()
    for e in edges:
        if e.get("source") == target_id:
            tgt_id = e.get("target")
            if tgt_id and tgt_id not in seen_downstream and tgt_id != target_id:
                seen_downstream.add(tgt_id)
                tgt_node = next((n for n in nodes if n.get("id") == tgt_id), None)
                downstream_nodes.append({
                    "id": tgt_id,
                    "label": tgt_node.get("label", tgt_id) if tgt_node else tgt_id,
                    "kind": tgt_node.get("kind", "service") if tgt_node else "service",
                    "domain": tgt_node.get("domain", "default") if tgt_node else "default",
                    "relation": e.get("relation", "routes_to"),
                })

    matched_children = matched_node.get("drilldown_children") or []
    if isinstance(matched_children, list):
        for child_id in matched_children:
            if child_id and child_id not in seen_downstream:
                seen_downstream.add(child_id)
                c_node = next((n for n in nodes if n.get("id") == child_id), None)
                downstream_nodes.append({
                    "id": child_id,
                    "label": c_node.get("label", child_id) if c_node else child_id,
                    "kind": c_node.get("kind", "workload") if c_node else "workload",
                    "domain": c_node.get("domain", "default") if c_node else "default",
                    "relation": "child_workload",
                })

    # Colocated workloads
    colocated_workloads: list[str] = list(matched_node.get("workloads") or [])
    tgt_workload = (incident.get("target") or {}).get("workload")
    if not colocated_workloads and tgt_workload:
        colocated_workloads.append(tgt_workload)

    # Critical tier identification
    critical_tiers_matched: set[str] = set()
    for item in [matched_node] + upstream_nodes + downstream_nodes:
        domain = str(item.get("domain", "")).lower()
        kind = str(item.get("kind", "")).lower()
        label = str(item.get("label", "")).lower()
        for c_tier in CRITICAL_TIERS:
            if c_tier in domain or c_tier in kind or c_tier in label:
                critical_tiers_matched.add(c_tier)

    critical_tier_impacted = len(critical_tiers_matched) > 0

    subgraph = {
        "target_node": {
            "id": matched_node.get("id"),
            "label": matched_node.get("label"),
            "kind": matched_node.get("kind"),
            "domain": matched_node.get("domain"),
            "summary": matched_node.get("summary", ""),
            "primary_url": matched_node.get("primary_url", ""),
        },
        "upstream": upstream_nodes,
        "downstream": downstream_nodes,
        "workloads": sorted(list(set(colocated_workloads))),
        "hop_count": 1,
        "total_impacted_nodes": 1 + len(upstream_nodes) + len(downstream_nodes),
        "critical_tier_impacted": critical_tier_impacted,
        "critical_tiers": sorted(list(critical_tiers_matched)),
    }

    sanitized_subgraph = sanitize_live_home_telemetry_for_demo(subgraph)
    incident["blast_radius"] = sanitized_subgraph
    incident["enriched_subgraph"] = sanitized_subgraph

    # Publish to event_stream topic "security"
    try:
        from event_stream import publish_event
        publish_event("security", "security_incident", incident)
    except Exception as exc:
        logger.debug("Event stream publish bypassed/skipped: %s", exc)

    return incident


# =====================================================================
# 5. Pluggable Third-Party Sink Formatters
# =====================================================================

def format_for_sink(incident: dict[str, Any], sink_type: str) -> dict[str, Any] | str:
    """Format canonical incident for Wazuh, Falco, Suricata, DefectDojo, Elastic, Loki, Tempo, CEF, OCSF, ECS, OTLP."""
    sink = sink_type.strip().lower()
    rule = incident.get("rule") if isinstance(incident.get("rule"), dict) else {}
    target = incident.get("target") if isinstance(incident.get("target"), dict) else {}
    source = incident.get("source") if isinstance(incident.get("source"), dict) else {}
    trace_context = incident.get("trace_context") if isinstance(incident.get("trace_context"), dict) else {}
    proc = source.get("process") if isinstance(source.get("process"), dict) else {}
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}

    if sink == "wazuh":
        wazuh_level = min(16, max(0, incident.get("severity_id", 0) * 4))
        payload: dict[str, Any] = {
            "timestamp": incident.get("timestamp"),
            "rule": {
                "id": rule.get("id", "001"),
                "level": wazuh_level,
                "description": rule.get("description") or rule.get("name", "Alert"),
                "mitre": {
                    "id": mitre.get("techniques", []),
                    "tactic": mitre.get("tactics", []),
                },
            },
            "agent": {
                "id": "001",
                "name": target.get("node_id", "unknown_node"),
                "ip": target.get("ip", "127.0.0.1"),
            },
            "data": {
                "srcip": source.get("ip", "127.0.0.1"),
                "srcuser": source.get("user", "system"),
                "workload": target.get("workload", "unknown_workload"),
                "namespace": target.get("namespace", "default"),
            },
            "full_log": incident.get("message", ""),
        }
        return sanitize_live_home_telemetry_for_demo(payload)

    if sink == "falco":
        falco_prio_map = {0: "Informational", 1: "Notice", 2: "Warning", 3: "Error", 4: "Critical"}
        prio = falco_prio_map.get(incident.get("severity_id", 1), "Notice")
        payload = {
            "time": incident.get("timestamp"),
            "rule": rule.get("name", "Falco Rule"),
            "priority": prio,
            "output": incident.get("message", ""),
            "output_fields": {
                "container.id": target.get("node_id", "unknown_node"),
                "k8s.pod.name": target.get("workload", "unknown_workload"),
                "k8s.ns.name": target.get("namespace", "default"),
                "proc.name": proc.get("name", ""),
                "proc.cmdline": proc.get("cmdline", ""),
                "user.name": source.get("user", "root"),
            },
            "tags": rule.get("tags", []),
        }
        return sanitize_live_home_telemetry_for_demo(payload)

    if sink == "suricata":
        suricata_sev_map = {0: 4, 1: 3, 2: 2, 3: 1, 4: 1}
        payload = {
            "timestamp": incident.get("timestamp"),
            "event_type": "alert",
            "src_ip": source.get("ip", "127.0.0.1"),
            "src_port": source.get("port"),
            "dest_ip": target.get("ip", "127.0.0.1"),
            "dest_port": target.get("port"),
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2000001,
                "rev": 1,
                "signature": rule.get("name", "Suricata Alert"),
                "category": incident.get("category", "Network Activity"),
                "severity": suricata_sev_map.get(incident.get("severity_id", 1), 3),
            },
        }
        return sanitize_live_home_telemetry_for_demo(payload)

    if sink == "defectdojo":
        cve_id = None
        vulns = incident.get("vulnerabilities")
        if vulns and isinstance(vulns, list) and len(vulns) > 0 and isinstance(vulns[0], dict):
            cve_id = vulns[0].get("cve")
        payload = {
            "title": f"[OpsCryer Detection] {rule.get('name', 'Security Finding')}",
            "description": f"Rule {rule.get('id')} triggered on {target.get('workload')}: {incident.get('message')}",
            "severity": incident.get("severity", "Medium").capitalize(),
            "cve": cve_id,
            "component_name": target.get("workload") or target.get("node_id"),
            "active": True,
            "verified": True,
            "tags": ["opscryer", "sigma", "automated-escalation"] + rule.get("tags", []),
        }
        return sanitize_live_home_telemetry_for_demo(payload)

    if sink in {"elastic", "elastic_security"}:
        payload = {
            "@timestamp": incident.get("timestamp"),
            "event": {
                "id": incident.get("event_id"),
                "kind": "alert",
                "category": [incident.get("category", "Findings").lower()],
                "severity": incident.get("severity_id", 1),
            },
            "kibana.alert.rule.rule_id": rule.get("id"),
            "kibana.alert.rule.name": rule.get("name"),
            "kibana.alert.rule.severity": incident.get("severity", "low").lower(),
            "host": {
                "name": target.get("node_id"),
                "ip": target.get("ip"),
            },
            "service": {
                "name": target.get("workload"),
            },
            "source": {
                "ip": source.get("ip"),
                "user": {"name": source.get("user")},
            },
            "process": proc,
            "message": incident.get("message"),
        }
        return sanitize_live_home_telemetry_for_demo(payload)

    if sink == "loki":
        ts_ns = f"{incident.get('timestamp_ms', _now_ms())}000000"
        log_line = json.dumps({
            "event_id": incident.get("event_id"),
            "message": incident.get("message"),
            "trace_id": trace_context.get("trace_id", ""),
            "span_id": trace_context.get("span_id", ""),
        })
        payload = {
            "streams": [
                {
                    "stream": {
                        "job": "security",
                        "service": "cybersecurity_bridge",
                        "rule_id": rule.get("id", "sigma"),
                        "severity": incident.get("severity", "informational").lower(),
                        "workload": target.get("workload", "unknown"),
                        "node": target.get("node_id", "unknown"),
                    },
                    "values": [
                        [ts_ns, log_line]
                    ],
                }
            ]
        }
        return sanitize_live_home_telemetry_for_demo(payload)

    if sink == "tempo":
        payload = {
            "trace_id": trace_context.get("trace_id", ""),
            "span_id": trace_context.get("span_id", ""),
            "incident_id": incident.get("event_id"),
            "rule_id": rule.get("id"),
            "timestamp": incident.get("timestamp"),
            "deep_link": f"/tempo/trace/{trace_context.get('trace_id')}?spanId={trace_context.get('span_id')}",
        }
        return sanitize_live_home_telemetry_for_demo(payload)

    if sink == "cef":
        sev_id_val = incident.get("severity_id")
        cef_sev = min(10, (sev_id_val if isinstance(sev_id_val, int) else 0) * 2 + 1)
        r_id = str(rule.get("id", "0")).replace("|", "\\|")
        r_name = str(rule.get("name", "Alert")).replace("|", "\\|")
        msg = str(incident.get("message", "")).replace("=", "\\=").replace("|", "\\|")
        src = source.get("ip", "127.0.0.1")
        dst = target.get("ip", "127.0.0.1")
        dhost = target.get("node_id", "unknown")
        cs1 = target.get("workload", "unknown")
        cef_str = f"CEF:0|OpsCryer|CybersecurityBridge|1.0|{r_id}|{r_name}|{cef_sev}|src={src} dst={dst} dhost={dhost} cs1={cs1} cs1Label=Workload msg={msg}"
        return sanitize_live_home_telemetry_for_demo(cef_str)

    if sink == "ecs":
        return format_for_sink(incident, "elastic")

    # Default: return canonical OCSF v1.1
    return sanitize_live_home_telemetry_for_demo(incident)


# =====================================================================
# 6. Thread-Safe Incident Store & Seed Rules
# =====================================================================

DEFAULT_SEED_RULES: list[dict[str, Any]] = [
    {
        "id": "sigma-k8s-priv-exec",
        "title": "Privileged Shell Execution in Container",
        "status": "stable",
        "description": "Detects interactive shell execution within a container",
        "level": "high",
        "tags": ["attack.execution", "attack.t1059"],
        "logsource": {"category": "process_creation", "product": "kubernetes"},
        "detection": {
            "selection_proc": {
                "process.name": ["bash", "sh", "zsh"],
                "process.command_line|contains": ["/bin/sh", "/bin/bash", "-i"],
            },
            "filter_flannel": {
                "user.name": "system:serviceaccount:kube-system:flannel",
            },
            "condition": "selection_proc and not filter_flannel",
        },
    },
    {
        "id": "sigma-c2-network-beacon",
        "title": "C2 Network Beaconing Activity",
        "status": "stable",
        "description": "Detects outbound network connection to suspicious IP ranges",
        "level": "critical",
        "tags": ["attack.command_and_control", "attack.t1071"],
        "logsource": {"category": "network_activity", "product": "suricata"},
        "detection": {
            "selection_ip": {
                "destination.ip|cidr": ["10.0.0.0/8", "172.20.0.0/16"],
            },
            "condition": "selection_ip",
        },
    },
    {
        "id": "sigma-auth-failed-burst",
        "title": "Authentication Failure Burst",
        "status": "stable",
        "description": "Detects authentication failure events from untrusted sources",
        "level": "medium",
        "tags": ["attack.credential_access", "attack.t1110"],
        "logsource": {"category": "authentication", "product": "wazuh"},
        "detection": {
            "selection_auth": {
                "category": ["Findings", "Authentication"],
            },
            "condition": "selection_auth",
        },
    },
]


class SecurityIncidentStore:
    """Thread-safe bounded in-memory store for cybersecurity incidents and Sigma rules."""

    def __init__(self, capacity: int = 1000) -> None:
        self.capacity = capacity
        self._lock = threading.Lock()
        self._incidents: list[dict[str, Any]] = []
        self._rules: dict[str, dict[str, Any]] = {}
        self.reset_rules()

    def reset_rules(self) -> None:
        with self._lock:
            self._rules.clear()
            for r in DEFAULT_SEED_RULES:
                self._rules[r["id"]] = copy.deepcopy(r)

    def ingest(self, incident: dict[str, Any]) -> None:
        with self._lock:
            self._incidents.append(copy.deepcopy(incident))
            if len(self._incidents) > self.capacity:
                self._incidents = self._incidents[-self.capacity:]

    def get_incidents(
        self,
        severity: str | None = None,
        standard: str | None = None,
        since_time: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        with self._lock:
            matches = list(self._incidents)

        if severity:
            sev_target = severity.strip().upper()
            matches = [i for i in matches if i.get("severity", "").upper() == sev_target]

        if standard:
            std_target = standard.strip().lower()
            matches = [i for i in matches if i.get("standard_source", "").lower() == std_target]

        if since_time:
            matches = [i for i in matches if i.get("timestamp", "") >= since_time]

        matches.reverse()
        return [copy.deepcopy(i) for i in matches[:limit]]

    def register_rule(self, rule: dict[str, Any]) -> str:
        rule_id = str(rule.get("id") or f"sigma-{uuid.uuid4().hex[:6]}")
        rule_copy = copy.deepcopy(rule)
        rule_copy["id"] = rule_id
        with self._lock:
            self._rules[rule_id] = rule_copy
        return rule_id

    def list_rules(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return [copy.deepcopy(r) for r in list(self._rules.values())[:limit]]

    def clear(self) -> None:
        with self._lock:
            self._incidents.clear()
        self.reset_rules()

    def __len__(self) -> int:
        with self._lock:
            return len(self._incidents)


_GLOBAL_INCIDENT_STORE = SecurityIncidentStore()


def register_sigma_rule(rule: dict[str, Any]) -> str:
    return _GLOBAL_INCIDENT_STORE.register_rule(rule)


def list_sigma_rules(limit: int = 100) -> list[dict[str, Any]]:
    return _GLOBAL_INCIDENT_STORE.list_rules(limit=limit)


def reset_security_bridge() -> None:
    """Reset incidents, deduplicator, and restore default seed rules."""
    _GLOBAL_INCIDENT_STORE.clear()
    reset_alert_deduplicator()


# =====================================================================
# 7. Unified REST API Gateway Handler
# =====================================================================

def handle_security_api(
    path: str,
    method: str,
    query: dict[str, list[str]],
    body: dict[str, Any] | None = None,
    catalog: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Unified HTTP API handler for /api/v1/security/* endpoints."""
    clean_path = path.split("?", 1)[0].rstrip("/")
    clean_method = method.upper()

    # Route 1: /api/v1/security/ingest
    if clean_path == "/api/v1/security/ingest":
        if clean_method == "GET":
            return 200, {
                "endpoint": "/api/v1/security/ingest",
                "status": "active",
                "description": "Ingest multi-standard security telemetry with Sigma evaluation and 1-hop graph enrichment.",
                "supported_methods": ["POST"],
                "supported_standards": [
                    "ocsf", "ecs", "cef", "otlp", "wazuh", "falco", "suricata", "defectdojo", "elastic", "loki"
                ],
            }
        if clean_method == "POST":
            if not isinstance(body, dict):
                return 400, {"error": "Request body must be a JSON object"}
            standard = body.get("standard", "auto")
            raw_payload = body.get("payload")
            if raw_payload is None:
                # If 'payload' is omitted, treat the whole body as payload
                raw_payload = body

            try:
                normalized = normalize_security_event(raw_payload, format_hint=standard)
                matched_rules = evaluate_sigma_rules(normalized)
                deduplicated = deduplicate_security_incident(normalized)
                enriched = enrich_with_1hop_neighborhood(deduplicated, catalog=catalog)
                _GLOBAL_INCIDENT_STORE.ingest(enriched)

                # Attempt event stream publish
                event_seq = 0
                try:
                    from event_stream import publish_event
                    event_seq = publish_event("security", "ingest_completed", {
                        "event_id": enriched.get("event_id"),
                        "rule_id": (enriched.get("rule") or {}).get("id"),
                        "severity": enriched.get("severity"),
                    })
                except Exception:
                    pass

                return 200, {
                    "status": "ingested",
                    "incident": enriched,
                    "deduplicated": enriched.get("is_suppressed", False),
                    "matched_rules": matched_rules,
                    "event_seq": event_seq,
                }
            except Exception as e:
                logger.error("Ingest failure: %s", e)
                return 400, {"error": f"Failed to ingest security telemetry: {e}"}
        return 405, {"error": "method not allowed", "allowed_method": "POST"}

    # Route 2: /api/v1/security/incidents
    if clean_path == "/api/v1/security/incidents":
        if clean_method != "GET":
            return 405, {"error": "method not allowed", "allowed_method": "GET"}
        sev = query.get("severity", [None])[0]
        std = query.get("standard", [None])[0]
        since_time = query.get("since_time", [None])[0]
        limit_str = query.get("limit", ["100"])[0]
        try:
            limit = int(limit_str)
            if limit < 1 or limit > 100:
                return 400, {"error": "limit must be an integer between 1 and 100"}
        except ValueError:
            return 400, {"error": "limit must be an integer between 1 and 100"}

        incidents = _GLOBAL_INCIDENT_STORE.get_incidents(
            severity=sev, standard=std, since_time=since_time, limit=limit
        )
        return 200, {
            "endpoint": "/api/v1/security/incidents",
            "total_count": len(_GLOBAL_INCIDENT_STORE),
            "returned_count": len(incidents),
            "incidents": incidents,
        }

    # Route 3: /api/v1/security/rules
    if clean_path == "/api/v1/security/rules":
        if clean_method == "GET":
            limit_str = query.get("limit", ["100"])[0]
            try:
                limit = int(limit_str)
                if limit < 1 or limit > 100:
                    return 400, {"error": "limit must be an integer between 1 and 100"}
            except ValueError:
                return 400, {"error": "limit must be an integer between 1 and 100"}

            rules = _GLOBAL_INCIDENT_STORE.list_rules(limit=limit)
            return 200, {
                "endpoint": "/api/v1/security/rules",
                "total_rules": len(rules),
                "rules": rules,
            }
        if clean_method == "POST":
            if not isinstance(body, dict):
                return 400, {"error": "Request body must be a JSON object"}
            rule_obj = body.get("rule", body)
            if not isinstance(rule_obj, dict) or "id" not in rule_obj or "detection" not in rule_obj:
                return 400, {"error": "Rule must contain 'id' and 'detection'"}
            try:
                rule_id = _GLOBAL_INCIDENT_STORE.register_rule(rule_obj)
                return 201, {
                    "status": "registered",
                    "rule_id": rule_id,
                    "rule": rule_obj,
                }
            except Exception as e:
                return 400, {"error": f"Failed to register rule: {e}"}
        return 405, {"error": "method not allowed", "allowed_method": "GET, POST"}

    # Route 4: /api/v1/security/sigma-eval (Optional standalone evaluator)
    if clean_path == "/api/v1/security/sigma-eval":
        if clean_method != "POST":
            return 405, {"error": "method not allowed", "allowed_method": "POST"}
        if not isinstance(body, dict):
            return 400, {"error": "Request body must be a JSON object"}
        event_data = body.get("event")
        if not event_data:
            return 400, {"error": "Missing 'event' in request body"}
        rules_data = body.get("rules") or ([body.get("rule")] if body.get("rule") else None)
        try:
            matches = evaluate_sigma_rules(event_data, rules=rules_data)
            return 200, {
                "matches": matches,
                "matched_count": len(matches),
            }
        except Exception as e:
            return 400, {"error": f"Sigma evaluation failed: {e}"}

    return 404, {"error": "Unknown security API route"}
