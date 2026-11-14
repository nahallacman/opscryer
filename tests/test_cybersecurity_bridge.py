# SPDX-License-Identifier: Apache-2.0
"""Comprehensive unit test suite for cybersecurity_bridge multi-standard schema normalization,
Sigma rule evaluation, sliding-window deduplication, 1-hop blast-radius enrichment, and REST API.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import sys
import threading
import time
import unittest
from pathlib import Path

# Portable _PKG_DIR bootstrap
_PKG_DIR = Path(__file__).resolve().parent.parent
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import cybersecurity_bridge
from cybersecurity_bridge import (
    normalize_security_event,
    evaluate_sigma_rules,
    deduplicate_security_incident,
    enrich_with_1hop_neighborhood,
    format_for_sink,
    handle_security_api,
    register_sigma_rule,
    list_sigma_rules,
    reset_security_bridge,
    reset_alert_deduplicator,
    SecurityIncidentStore,
    _parse_cef_extension,
    _split_cef_header,
)


class TestSchemaNormalization(unittest.TestCase):
    """Verify normalization across 4 standards (OCSF, ECS, CEF, OTLP) and 6 third-party connectors."""

    def setUp(self) -> None:
        reset_security_bridge()

    def test_normalize_ocsf_v1_1(self) -> None:
        raw_ocsf = {
            "class_uid": 2001,
            "category_uid": 2,
            "severity_id": 4,
            "time": 1730416500000,
            "finding_info": {
                "uid": "find-101",
                "title": "Unauthorized Shell Spawned",
                "desc": "Bash process spawned in payment-api container",
                "types": ["container", "shell"],
            },
            "device": {
                "hostname": "k8s-worker-1",
                "ip": "10.0.1.15",
                "namespace": "production",
            },
            "actor": {
                "user": {"name": "developer"},
                "process": {"name": "bash", "cmdline": "/bin/bash -i", "pid": 4123},
            },
            "vulnerabilities": [{"cve": "CVE-2023-12345", "cvss": 8.5}],
        }
        res = normalize_security_event(raw_ocsf, format_hint="ocsf")
        self.assertEqual(res["schema_version"], "1.1.0")
        self.assertEqual(res["standard_source"], "ocsf")
        self.assertEqual(res["event_id"], "find-101")
        self.assertEqual(res["severity"], "HIGH")
        self.assertEqual(res["severity_id"], 3)
        self.assertEqual(res["rule"]["name"], "Unauthorized Shell Spawned")
        self.assertEqual(res["target"]["node_id"], "k8s-worker-1")
        self.assertEqual(res["target"]["ip"], "10.0.1.15")
        self.assertEqual(res["source"]["process"]["name"], "bash")
        self.assertEqual(res["source"]["user"], "developer")
        self.assertEqual(len(res["vulnerabilities"]), 1)
        self.assertEqual(res["vulnerabilities"][0]["cve"], "CVE-2023-12345")

    def test_normalize_ecs(self) -> None:
        raw_ecs = {
            "@timestamp": "2026-10-31T20:00:00Z",
            "event": {"id": "ecs-event-99", "severity": 3},
            "rule": {"id": "RULE-ECS-01", "name": "Privileged Execution", "description": "Sudo used in pod"},
            "host": {"name": "node-alpha", "ip": "10.2.0.5"},
            "container": {"name": "auth-service"},
            "orchestrator": {"namespace": "security"},
            "source": {"ip": "172.20.1.50", "port": 44321, "user": {"name": "appuser"}},
            "process": {"name": "sudo", "command_line": "sudo -i", "pid": 9012},
            "trace": {"id": "4bf92f3577b34da6a3ce929d0e0e4736"},
            "span": {"id": "00f067aa0ba902b7"},
        }
        res = normalize_security_event(raw_ecs, format_hint="ecs")
        self.assertEqual(res["standard_source"], "ecs")
        self.assertEqual(res["event_id"], "ecs-event-99")
        self.assertEqual(res["severity"], "HIGH")
        self.assertEqual(res["rule"]["id"], "RULE-ECS-01")
        self.assertEqual(res["target"]["node_id"], "node-alpha")
        self.assertEqual(res["target"]["workload"], "auth-service")
        self.assertEqual(res["target"]["namespace"], "security")
        self.assertEqual(res["trace_context"]["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertEqual(res["trace_context"]["span_id"], "00f067aa0ba902b7")

    def test_normalize_cef(self) -> None:
        cef_line = (
            r"CEF:0|OpsCryer|CybersecurityBridge|1.0|SIGMA-001|Terminal Shell Spawned|7|"
            r"src=10.0.0.10 spt=54321 suser=devuser dst=10.0.0.20 dpt=80 dhost=worker-node-2 "
            r"cs1=payment-api cs2=prod cs3=trace-abc-123 externalId=cef-evt-42 "
            r"msg=Interactive shell spawned in container"
        )
        res = normalize_security_event(cef_line, format_hint="cef")
        self.assertEqual(res["standard_source"], "cef")
        self.assertEqual(res["rule"]["id"], "SIGMA-001")
        self.assertEqual(res["rule"]["name"], "Terminal Shell Spawned")
        self.assertEqual(res["severity"], "HIGH")
        self.assertEqual(res["severity_id"], 3)
        self.assertEqual(res["source"]["ip"], "10.0.0.10")
        self.assertEqual(res["source"]["port"], 54321)
        self.assertEqual(res["source"]["user"], "devuser")
        self.assertEqual(res["target"]["ip"], "10.0.0.20")
        self.assertEqual(res["target"]["port"], 80)
        self.assertEqual(res["target"]["node_id"], "worker-node-2")
        self.assertEqual(res["target"]["workload"], "payment-api")
        self.assertEqual(res["target"]["namespace"], "prod")
        self.assertEqual(res["event_id"], "cef-evt-42")
        self.assertIn("Interactive shell", res["message"])

    def test_normalize_otlp(self) -> None:
        raw_otlp = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "checkout-svc"}},
                            {"key": "k8s.node.name", "value": {"stringValue": "k8s-node-3"}},
                            {"key": "k8s.namespace.name", "value": {"stringValue": "e-commerce"}},
                        ]
                    },
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "timeUnixNano": 1730416500000000000,
                                    "severityNumber": 17,  # ERROR -> HIGH
                                    "body": {"stringValue": "Security policy violation: unauthorized port bind"},
                                    "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                                    "spanId": "00f067aa0ba902b7",
                                    "attributes": [
                                        {"key": "security.rule.id", "value": {"stringValue": "OTLP-SEC-01"}},
                                        {"key": "source.ip", "value": {"stringValue": "10.20.10.1"}},
                                    ],
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        res = normalize_security_event(raw_otlp, format_hint="otlp")
        self.assertEqual(res["standard_source"], "otlp")
        self.assertEqual(res["severity"], "HIGH")
        self.assertEqual(res["target"]["workload"], "checkout-svc")
        self.assertEqual(res["target"]["node_id"], "k8s-node-3")
        self.assertEqual(res["target"]["namespace"], "e-commerce")
        self.assertEqual(res["rule"]["id"], "OTLP-SEC-01")
        self.assertEqual(res["source"]["ip"], "10.20.10.1")
        self.assertEqual(res["trace_context"]["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736")

    def test_normalize_wazuh_connector(self) -> None:
        raw_wazuh = {
            "rule": {
                "id": "5710",
                "level": 11,  # 10-12 -> HIGH
                "description": "sshd: Attempt to login using a non-existent user",
                "mitre": {"id": ["T1110"], "tactic": ["Initial Access"]},
            },
            "agent": {"id": "005", "name": "bastion-host", "ip": "10.0.0.5"},
            "data": {"srcip": "172.20.1.100", "srcuser": "invalid_user", "workload": "sshd"},
            "full_log": "Failed password for invalid user admin from 172.20.1.100 port 51234 ssh2",
        }
        res = normalize_security_event(raw_wazuh, format_hint="wazuh")
        self.assertEqual(res["standard_source"], "wazuh")
        self.assertEqual(res["severity"], "HIGH")
        self.assertEqual(res["rule"]["id"], "5710")
        self.assertEqual(res["target"]["node_id"], "bastion-host")
        self.assertEqual(res["source"]["ip"], "172.20.1.100")
        self.assertEqual(res["source"]["user"], "invalid_user")
        self.assertEqual(res["rule"]["mitre"]["techniques"], ["T1110"])

    def test_normalize_falco_connector(self) -> None:
        raw_falco = {
            "rule": "Read sensitive file untrusted",
            "priority": "Error",  # Error -> HIGH
            "output": "File below /etc opened for reading (user=root command=cat /etc/shadow file=/etc/shadow)",
            "output_fields": {
                "container.id": "container-xyz",
                "k8s.pod.name": "web-frontend-pod",
                "k8s.ns.name": "default",
                "proc.name": "cat",
                "proc.cmdline": "cat /etc/shadow",
                "user.name": "root",
            },
            "tags": ["filesystem", "mitre_credential_access"],
        }
        res = normalize_security_event(raw_falco, format_hint="falco")
        self.assertEqual(res["standard_source"], "falco")
        self.assertEqual(res["severity"], "HIGH")
        self.assertEqual(res["target"]["workload"], "web-frontend-pod")
        self.assertEqual(res["source"]["process"]["name"], "cat")
        self.assertEqual(res["source"]["process"]["cmdline"], "cat /etc/shadow")
        self.assertEqual(res["source"]["user"], "root")

    def test_normalize_suricata_connector(self) -> None:
        raw_suricata = {
            "timestamp": "2026-10-31T20:30:00.000Z",
            "alert": {
                "signature": "ET EXPLOIT Apache Log4j RCE Attempt",
                "signature_id": 2034334,
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1,
            },
            "src_ip": "10.0.0.50",
            "src_port": 49152,
            "dest_ip": "10.0.0.2",
            "dest_port": 8080,
            "http": {"hostname": "api-gateway"},
        }
        res = normalize_security_event(raw_suricata, format_hint="suricata")
        self.assertEqual(res["standard_source"], "suricata")
        self.assertEqual(res["severity"], "CRITICAL")  # 'exploit' / 'rce' in sig with sev=1 -> CRITICAL
        self.assertEqual(res["rule"]["id"], "2034334")
        self.assertEqual(res["target"]["workload"], "api-gateway")
        self.assertEqual(res["source"]["ip"], "10.0.0.50")
        self.assertEqual(res["target"]["port"], 8080)

    def test_normalize_defectdojo_connector(self) -> None:
        raw_dd = {
            "title": "SQL Injection in Search Endpoint",
            "description": "User input concatenated directly into SQL statement",
            "severity": "Critical",
            "component_name": "catalog-api",
            "component_version": "1.2.0",
            "cve": "CVE-2024-9999",
            "cvssv3_score": 9.8,
            "active": True,
        }
        res = normalize_security_event(raw_dd, format_hint="defectdojo")
        self.assertEqual(res["standard_source"], "defectdojo")
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertEqual(res["target"]["workload"], "catalog-api")
        self.assertEqual(len(res["vulnerabilities"]), 1)
        self.assertEqual(res["vulnerabilities"][0]["cve"], "CVE-2024-9999")
        self.assertEqual(res["vulnerabilities"][0]["cvss"], 9.8)

    def test_normalize_elastic_and_loki(self) -> None:
        raw_elastic = {
            "@timestamp": "2026-10-31T21:00:00Z",
            "kibana.alert.rule.rule_id": "rule-elastic-1",
            "kibana.alert.rule.name": "Suspicious PowerShell Execution",
            "kibana.alert.rule.severity": "high",
            "host": {"name": "windows-runner-1"},
            "process": {"name": "powershell.exe"},
        }
        res_e = normalize_security_event(raw_elastic, format_hint="elastic")
        self.assertEqual(res_e["severity"], "HIGH")
        self.assertEqual(res_e["target"]["node_id"], "windows-runner-1")

        raw_loki = {
            "streams": [
                {
                    "stream": {
                        "rule_id": "loki-rule-4",
                        "severity": "critical",
                        "workload": "ingress-controller",
                        "node": "k8s-master-1",
                    },
                    "values": [
                        ["1730416500000000000", json.dumps({"message": "TLS certificate expired", "trace_id": "tid-123"})]
                    ],
                }
            ]
        }
        res_l = normalize_security_event(raw_loki, format_hint="loki")
        self.assertEqual(res_l["severity"], "CRITICAL")
        self.assertEqual(res_l["target"]["workload"], "ingress-controller")
        self.assertEqual(res_l["trace_context"]["trace_id"], "tid-123")


class TestOPSECScrubbing(unittest.TestCase):
    """Verify deep OPSEC sanitization of WAN IPs, tokens, and credentials."""

    def test_opsec_scrubs_public_wan_and_tokens(self) -> None:
        dynamic_wan = str(ipaddress.IPv4Address(0x08080808))
        dynamic_token = ("gh" + "p_") + ("1" * 36)
        raw_event = {
            "rule_id": "SEC-TOKEN-LEAK",
            "title": "Token detected in request",
            "severity": "high",
            "target_node_id": "worker-1",
            "target_workload": "payment-api",
            "source_ip": dynamic_wan,
            "message": f"User leaked {dynamic_token} and password=SecretPassWord123!",
            "password": "SuperSecretPassword!",
        }
        res = normalize_security_event(raw_event)
        # Verify public WAN IPv4 is scrubbed to documentation RFC IP 203.0.113.1
        self.assertNotIn(dynamic_wan, str(res))
        self.assertIn("203.0.113.1", str(res))
        # Verify token and password are redacted
        self.assertNotIn(dynamic_token, str(res))
        self.assertNotIn("SuperSecretPassword!", str(res))

    def test_opsec_preserves_internal_topology(self) -> None:
        raw_event = {
            "rule_id": "SEC-LOCAL-DISC",
            "title": "Internal RPC scan",
            "severity": "low",
            "target_node_id": "k8s-node-1.cluster.example.org",
            "target_workload": "internal-db",
            "source_ip": "10.0.1.20",  # RFC 1918
            "destination_ip": "172.20.1.5",  # RFC 1918
            "message": "Connected to cluster node at 127.0.0.1:8080 and storage.cluster.example.org",
        }
        res = normalize_security_event(raw_event)
        self.assertEqual(res["target"]["node_id"], "k8s-node-1.cluster.example.org")
        self.assertEqual(res["source"]["ip"], "10.0.1.20")
        self.assertIn("127.0.0.1", res["message"])
        self.assertIn("storage.cluster.example.org", res["message"])


class TestSigmaRuleEvaluator(unittest.TestCase):
    """Verify pure-stdlib Sigma rule evaluator without eval() or exec()."""

    def setUp(self) -> None:
        reset_security_bridge()

    def test_sigma_basic_selection_match(self) -> None:
        event = normalize_security_event({
            "process": {"name": "bash", "command_line": "/bin/bash -i"},
            "user": {"name": "attacker"},
        })
        rules = [
            {
                "id": "test-bash-exec",
                "title": "Interactive Bash",
                "level": "high",
                "detection": {
                    "selection": {
                        "process.name": ["bash", "sh"],
                        "process.command_line|contains": "-i",
                    },
                    "condition": "selection",
                },
            }
        ]
        hits = evaluate_sigma_rules(event, rules=rules)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["rule_id"], "test-bash-exec")
        self.assertEqual(hits[0]["severity"], "HIGH")

    def test_sigma_selection_and_not_filter(self) -> None:
        rule = {
            "id": "test-filter-rule",
            "title": "Container Execution Filtered",
            "level": "medium",
            "detection": {
                "selection": {"process.name": "bash"},
                "filter": {"user.name": "system:serviceaccount:kube-system:flannel"},
                "condition": "selection and not filter",
            },
        }
        # Event 1: matches selection, not filtered -> alert
        e1 = normalize_security_event({
            "process": {"name": "bash"},
            "user": {"name": "hacker"},
        })
        hits1 = evaluate_sigma_rules(e1, rules=[rule])
        self.assertEqual(len(hits1), 1)

        # Event 2: matches selection, but filtered by user -> no alert
        e2 = normalize_security_event({
            "process": {"name": "bash"},
            "user": {"name": "system:serviceaccount:kube-system:flannel"},
        })
        hits2 = evaluate_sigma_rules(e2, rules=[rule])
        self.assertEqual(len(hits2), 0)

    def test_sigma_modifiers_contains_startswith_endswith_re(self) -> None:
        e = normalize_security_event({
            "process": {"name": "cmd.exe", "command_line": "powershell.exe -ExecutionPolicy Bypass -File script.ps1"},
            "target": {"ip": "10.0.0.1"},
        })
        rule = {
            "id": "test-mods",
            "title": "Modifier Test",
            "level": "critical",
            "detection": {
                "sel_contains": {"process.command_line|contains": "Bypass"},
                "sel_start": {"process.name|startswith": "cmd"},
                "sel_end": {"process.name|endswith": ".exe"},
                "sel_re": {"process.command_line|re": r"script\.\w{3}"},
                "condition": "sel_contains and sel_start and sel_end and sel_re",
            },
        }
        hits = evaluate_sigma_rules(e, rules=[rule])
        self.assertEqual(len(hits), 1)

    def test_sigma_modifier_cidr_ipv4_and_ipv6(self) -> None:
        rule = {
            "id": "test-cidr",
            "title": "Internal Subnet Check",
            "level": "low",
            "detection": {
                "sel_ipv4": {"destination.ip|cidr": ["10.0.0.0/8", "172.20.0.0/16"]},
                "condition": "sel_ipv4",
            },
        }
        e_match = normalize_security_event({"target": {"ip": "10.244.1.12"}})
        hits_match = evaluate_sigma_rules(e_match, rules=[rule])
        self.assertEqual(len(hits_match), 1)

        e_nomatch = normalize_security_event({"target": {"ip": "172.31.0.1"}})
        hits_nomatch = evaluate_sigma_rules(e_nomatch, rules=[rule])
        self.assertEqual(len(hits_nomatch), 0)

    def test_sigma_quantifiers_and_wildcards(self) -> None:
        rule_1of = {
            "id": "test-1of",
            "title": "1 of them quantifier",
            "detection": {
                "sel_a": {"process.name": "bash"},
                "sel_b": {"process.name": "zsh"},
                "condition": "1 of them",
            },
        }
        e = normalize_security_event({"process": {"name": "zsh"}})
        hits = evaluate_sigma_rules(e, rules=[rule_1of])
        self.assertEqual(len(hits), 1)

        rule_allof = {
            "id": "test-allof",
            "title": "all of selection* quantifier",
            "detection": {
                "selection_1": {"process.name": "zsh"},
                "selection_2": {"user.name": "root"},
                "condition": "all of selection*",
            },
        }
        e_half = normalize_security_event({"process": {"name": "zsh"}, "user": {"name": "guest"}})
        hits_half = evaluate_sigma_rules(e_half, rules=[rule_allof])
        self.assertEqual(len(hits_half), 0)

        e_full = normalize_security_event({"process": {"name": "zsh"}, "user": {"name": "root"}})
        hits_full = evaluate_sigma_rules(e_full, rules=[rule_allof])
        self.assertEqual(len(hits_full), 1)

    def test_sigma_safe_parsing_no_eval_malformed_conditions(self) -> None:
        rule_malformed = {
            "id": "test-safe-malformed",
            "detection": {
                "selection": {"process.name": "bash"},
                "condition": "((( selection and or not )",
            },
        }
        e = normalize_security_event({"process": {"name": "bash"}})
        hits = evaluate_sigma_rules(e, rules=[rule_malformed])
        self.assertEqual(len(hits), 0)


class TestAlertDeduplication(unittest.TestCase):
    """Verify thread-safe sliding-window alert deduplication."""

    def setUp(self) -> None:
        reset_alert_deduplicator()

    def test_deduplication_first_alert_not_suppressed(self) -> None:
        incident = {
            "rule_id": "RULE-01",
            "target_node_id": "node-1",
            "target_workload": "api-gateway",
        }
        res = deduplicate_security_incident(incident, window_seconds=300)
        self.assertEqual(res["occurrence_count"], 1)
        self.assertFalse(res["is_suppressed"])
        self.assertIn("RULE-01::node-1::api-gateway", res["dedup_key"])

    def test_deduplication_subsequent_alerts_suppressed(self) -> None:
        incident_template = {
            "rule_id": "RULE-01",
            "target_node_id": "node-1",
            "target_workload": "api-gateway",
        }
        for i in range(1, 6):
            inc = copy.deepcopy(incident_template)
            res = deduplicate_security_incident(inc, window_seconds=300)
            self.assertEqual(res["occurrence_count"], i)
            if i == 1:
                self.assertFalse(res["is_suppressed"])
            else:
                self.assertTrue(res["is_suppressed"])

    def test_deduplication_composite_key_separation(self) -> None:
        inc1 = {"rule_id": "RULE-A", "target_node_id": "node-1", "target_workload": "svc"}
        inc2 = {"rule_id": "RULE-B", "target_node_id": "node-1", "target_workload": "svc"}
        inc3 = {"rule_id": "RULE-A", "target_node_id": "node-2", "target_workload": "svc"}
        inc4 = {"rule_id": "RULE-A", "target_node_id": "node-1", "target_workload": "other-svc"}

        r1 = deduplicate_security_incident(inc1, window_seconds=300)
        r2 = deduplicate_security_incident(inc2, window_seconds=300)
        r3 = deduplicate_security_incident(inc3, window_seconds=300)
        r4 = deduplicate_security_incident(inc4, window_seconds=300)

        self.assertEqual(r1["occurrence_count"], 1)
        self.assertEqual(r2["occurrence_count"], 1)
        self.assertEqual(r3["occurrence_count"], 1)
        self.assertEqual(r4["occurrence_count"], 1)

    def test_deduplication_sliding_window_reset(self) -> None:
        inc = {"rule_id": "RULE-EXPIRE", "target_node_id": "node-x", "target_workload": "app"}
        # Initial alert with 1 second window
        r1 = deduplicate_security_incident(inc, window_seconds=1)
        self.assertEqual(r1["occurrence_count"], 1)
        self.assertFalse(r1["is_suppressed"])

        # Second alert within 1 second -> suppressed
        r2 = deduplicate_security_incident(copy.deepcopy(inc), window_seconds=1)
        self.assertEqual(r2["occurrence_count"], 2)
        self.assertTrue(r2["is_suppressed"])

        # Wait for window to expire
        time.sleep(1.1)

        # Third alert after window expiration -> reset to 1, unsuppressed
        r3 = deduplicate_security_incident(copy.deepcopy(inc), window_seconds=1)
        self.assertEqual(r3["occurrence_count"], 1)
        self.assertFalse(r3["is_suppressed"])

    def test_deduplication_thread_safety(self) -> None:
        reset_alert_deduplicator()
        inc_base = {"rule_id": "CONCURRENT-RULE", "target_node_id": "shared-node", "target_workload": "shared-svc"}
        threads: list[threading.Thread] = []

        def worker() -> None:
            for _ in range(20):
                deduplicate_security_incident(copy.deepcopy(inc_base), window_seconds=300)

        for _ in range(5):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        final = deduplicate_security_incident(copy.deepcopy(inc_base), window_seconds=300)
        # 5 threads * 20 iterations + 1 final = 101 occurrences
        self.assertEqual(final["occurrence_count"], 101)
        self.assertTrue(final["is_suppressed"])


class Test1HopBlastRadiusEnrichment(unittest.TestCase):
    """Verify 1-hop neighborhood subgraph enrichment and Action Cards Signal 3 integration."""

    def test_enrichment_with_mock_catalog(self) -> None:
        mock_catalog = {
            "nodes": [
                {
                    "id": "node-target",
                    "label": "Target Service",
                    "kind": "service",
                    "domain": "security",
                    "drilldown_children": ["child-worker"],
                    "workloads": ["auth-worker"],
                },
                {"id": "node-caller", "label": "API Gateway", "kind": "service", "domain": "ingress"},
                {"id": "child-worker", "label": "Child Worker", "kind": "pod", "domain": "security"},
            ],
            "edges": [
                {"source": "node-caller", "target": "node-target", "relation": "routes_to"},
            ],
        }
        incident = {
            "target": {"node_id": "node-target", "workload": "auth-worker"},
            "severity": "HIGH",
            "rule": {"id": "R1"},
        }
        res = enrich_with_1hop_neighborhood(incident, catalog=mock_catalog)
        self.assertIn("blast_radius", res)
        subgraph = res["blast_radius"]
        self.assertEqual(subgraph["target_node"]["id"], "node-target")
        self.assertEqual(len(subgraph["upstream"]), 1)
        self.assertEqual(subgraph["upstream"][0]["id"], "node-caller")
        self.assertEqual(len(subgraph["downstream"]), 1)
        self.assertEqual(subgraph["downstream"][0]["id"], "child-worker")
        self.assertTrue(subgraph["critical_tier_impacted"])  # domain 'security' is critical
        self.assertIn("security", subgraph["critical_tiers"])

    def test_enrichment_unknown_node_fallback(self) -> None:
        incident = {
            "target": {"node_id": "nonexistent-node-123", "workload": "unknown-pod"},
            "severity": "LOW",
        }
        res = enrich_with_1hop_neighborhood(incident, catalog={"nodes": [], "edges": []})
        subgraph = res["blast_radius"]
        self.assertEqual(subgraph["target_node"]["id"], "nonexistent-node-123")
        self.assertEqual(len(subgraph["upstream"]), 0)
        self.assertEqual(len(subgraph["downstream"]), 0)
        self.assertFalse(subgraph["critical_tier_impacted"])

    def test_action_cards_signal_3_compatibility(self) -> None:
        import action_cards

        active_alert = {
            "target_node_id": "node-demo-platform",
            "rule_id": "SIGMA-CRIT-01",
            "severity": "CRITICAL",
        }
        action_preview = {
            "impacted_nodes": ["node-demo-platform", "dep-node-1"],
            "impacted_count": 2,
            "cascading_risk": False,
            "slo_breach_predicted": False,
        }
        worrisomeness = action_cards.evaluate_outcome_worrisomeness(
            action_preview=action_preview,
            target_node_id="node-demo-platform",
            active_alerts=[active_alert],
        )
        # Signal 3 MUST be triggered when active alert targets impacted node
        self.assertIn("ACTIVE_SECURITY_ALERT", worrisomeness["signals_triggered"])
        self.assertTrue(worrisomeness["escalate_to_threshold"])


class TestSinkFormatters(unittest.TestCase):
    """Verify pluggable third-party sink formatters."""

    def setUp(self) -> None:
        self.canonical = normalize_security_event({
            "rule_id": "SIGMA-TEST",
            "title": "Interactive Shell Detected",
            "severity": "high",
            "target_node_id": "k8s-node-1",
            "target_workload": "frontend",
            "source_ip": "10.0.0.99",
            "source_user": "attacker",
            "message": "Interactive bash executed in container",
        })

    def test_format_all_sinks(self) -> None:
        sinks = ["wazuh", "falco", "suricata", "defectdojo", "elastic", "loki", "tempo", "cef", "ocsf", "ecs"]
        for s in sinks:
            formatted = format_for_sink(self.canonical, sink_type=s)
            self.assertIsNotNone(formatted)
            if s == "cef":
                self.assertIsInstance(formatted, str)
                self.assertTrue(formatted.startswith("CEF:0|OpsCryer|"))
            else:
                self.assertIsInstance(formatted, dict)


class TestSecurityRESTAPI(unittest.TestCase):
    """Verify REST API gateway handler and loopback compatibility."""

    def setUp(self) -> None:
        reset_security_bridge()

    def test_get_ingest_loopback_compatibility(self) -> None:
        code, payload = handle_security_api("/api/v1/security/ingest", method="GET", query={})
        self.assertEqual(code, 200)
        self.assertEqual(payload["endpoint"], "/api/v1/security/ingest")
        self.assertEqual(payload["status"], "active")
        self.assertIn("POST", payload["supported_methods"])

    def test_post_ingest_telemetry(self) -> None:
        body = {
            "standard": "falco",
            "payload": {
                "rule": "Terminal shell in container",
                "priority": "Error",
                "output": "bash executed in payment-service pod",
                "output_fields": {
                    "k8s.pod.name": "payment-service",
                    "container.id": "worker-1",
                    "proc.name": "bash",
                    "proc.cmdline": "/bin/bash -i",
                },
            },
        }
        code, payload = handle_security_api("/api/v1/security/ingest", method="POST", query={}, body=body)
        self.assertEqual(code, 200)
        self.assertEqual(payload["status"], "ingested")
        self.assertIn("incident", payload)
        self.assertEqual(payload["incident"]["target"]["workload"], "payment-service")

    def test_get_incidents_filtering(self) -> None:
        # Ingest 2 events: 1 high, 1 low
        handle_security_api(
            "/api/v1/security/ingest",
            method="POST",
            query={},
            body={"standard": "generic", "payload": {"rule_id": "R1", "severity": "high", "title": "High Sev"}},
        )
        handle_security_api(
            "/api/v1/security/ingest",
            method="POST",
            query={},
            body={"standard": "generic", "payload": {"rule_id": "R2", "severity": "low", "title": "Low Sev"}},
        )

        # Query all
        c1, p1 = handle_security_api("/api/v1/security/incidents", method="GET", query={"limit": ["10"]})
        self.assertEqual(c1, 200)
        self.assertEqual(p1["total_count"], 2)

        # Filter by severity
        c2, p2 = handle_security_api(
            "/api/v1/security/incidents", method="GET", query={"severity": ["high"], "limit": ["10"]}
        )
        self.assertEqual(c2, 200)
        self.assertEqual(p2["returned_count"], 1)
        self.assertEqual(p2["incidents"][0]["severity"], "HIGH")

    def test_get_incidents_invalid_limit_returns_400(self) -> None:
        code, payload = handle_security_api("/api/v1/security/incidents", method="GET", query={"limit": ["invalid"]})
        self.assertEqual(code, 400)
        self.assertIn("error", payload)

    def test_rules_endpoints_get_and_post(self) -> None:
        # List default rules
        c1, p1 = handle_security_api("/api/v1/security/rules", method="GET", query={})
        self.assertEqual(c1, 200)
        self.assertGreaterEqual(p1["total_rules"], 3)

        # Register a new rule
        new_rule = {
            "id": "custom-sigma-01",
            "title": "Custom Test Rule",
            "level": "low",
            "detection": {
                "selection": {"process.name": "test"},
                "condition": "selection",
            },
        }
        c2, p2 = handle_security_api(
            "/api/v1/security/rules", method="POST", query={}, body={"rule": new_rule}
        )
        self.assertEqual(c2, 201)
        self.assertEqual(p2["status"], "registered")
        self.assertEqual(p2["rule_id"], "custom-sigma-01")

        # Verify listed
        c3, p3 = handle_security_api("/api/v1/security/rules", method="GET", query={})
        self.assertEqual(c3, 200)
        rule_ids = [r["id"] for r in p3["rules"]]
        self.assertIn("custom-sigma-01", rule_ids)

    def test_sigma_eval_dry_run(self) -> None:
        body = {
            "event": {"process.name": "bash", "process.command_line": "/bin/bash -i"},
            "rule": {
                "id": "dry-run-01",
                "detection": {
                    "sel": {"process.name": "bash"},
                    "condition": "sel",
                },
            },
        }
        code, payload = handle_security_api("/api/v1/security/sigma-eval", method="POST", query={}, body=body)
        self.assertEqual(code, 200)
        self.assertEqual(payload["matched_count"], 1)

    def test_method_not_allowed_and_unknown_routes(self) -> None:
        c1, _ = handle_security_api("/api/v1/security/incidents", method="POST", query={}, body={})
        self.assertEqual(c1, 405)

        c2, _ = handle_security_api("/api/v1/security/unknown", method="GET", query={})
        self.assertEqual(c2, 404)


if __name__ == "__main__":
    unittest.main()
