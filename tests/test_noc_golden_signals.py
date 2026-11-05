# SPDX-License-Identifier: Apache-2.0
"""Catalog coverage, safe query contracts and exhaustive kiosk transitions."""

from ipaddress import ip_address, ip_network
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import noc_golden_signals as noc
from cluster_diff_engine import summarize_live_cluster_health

from noc_golden_signals import (
    build_noc_golden_signals_catalog,
    correlate_noc_signals_with_live_catalog,
    simulate_kiosk_view_cycler,
)


class GoldenSignalsTests(unittest.TestCase):
    def setUp(self):
        self.catalog = build_noc_golden_signals_catalog()

    def test_each_internal_node_has_all_five_signals_and_zero_fallbacks(self):
        expected = {"latency", "traffic", "errors", "saturation", "gpu_vram"}
        self.assertEqual({s["id"] for s in self.catalog["signals"]}, expected)
        nodes = self.catalog["nodes"]
        self.assertEqual(len({n["id"] for n in nodes}), len(nodes))
        self.assertEqual(len({n["address"] for n in nodes}), len(nodes))
        for network in ("10.20.3.0/24", "10.20.4.0/24"):
            self.assertTrue(any(ip_address(n["address"]) in ip_network(network)
                                for n in nodes))
        for node in nodes:
            self.assertIn(node["cluster"], ("10.20.3.0/24", "10.20.4.0/24"))
            self.assertIn(ip_address(node["address"]), ip_network(node["cluster"]))
            self.assertEqual(set(node["queries"]), expected)
            for query in node["queries"].values():
                self.assertIn(node["address"], query)
                self.assertTrue(query.endswith(") or on() vector(0)"))
                self.assertNotIn(" by ", query)  # One sample per node panel.
        self.assertEqual(self.catalog["missing_data_value"], 0)
        json.dumps(self.catalog, allow_nan=False)

    def test_metric_semantics_and_denominator_guards(self):
        for node in self.catalog["nodes"]:
            queries = node["queries"]
            for signal in ("latency", "errors", "saturation", "gpu_vram"):
                self.assertIn("/ clamp_min(", queries[signal])
            latency = queries["latency"]
            self.assertIn("http_request_duration_seconds_sum", latency)
            self.assertIn("http_request_duration_seconds_count", latency)
            for signal in ("latency", "traffic", "errors"):
                self.assertIn("rate(", queries[signal])
                self.assertIn("[5m]", queries[signal])
                self.assertIn(node["address"] + ":8000", queries[signal])
            self.assertIn('status=~"5.."', queries["errors"])
            self.assertIn("node_memory_MemTotal_bytes", queries["saturation"])
            self.assertIn("node_memory_MemAvailable_bytes", queries["saturation"])
            self.assertIn(node["address"] + ":9100", queries["saturation"])
            for metric in ("DCGM_FI_DEV_FB_USED", "DCGM_FI_DEV_FB_FREE"):
                self.assertIn(metric, queries["gpu_vram"])
            self.assertIn(node["address"] + ":9400", queries["gpu_vram"])

    def test_nine_views_have_valid_references_and_builds_are_independent(self):
        views = self.catalog["views"]
        self.assertEqual([v["id"] for v in views], list(range(1, 10)))
        nodes = {n["id"] for n in self.catalog["nodes"]}
        signals = {s["id"] for s in self.catalog["signals"]}
        for view in views:
            self.assertTrue(set(view["node_ids"]))
            self.assertTrue(set(view["node_ids"]) <= nodes)
            self.assertTrue(set(view["signal_ids"]))
            self.assertTrue(set(view["signal_ids"]) <= signals)
        views[0]["node_ids"].clear()
        self.assertTrue(views[1]["node_ids"])
        self.catalog["nodes"][0]["queries"].clear()
        fresh = build_noc_golden_signals_catalog()
        self.assertTrue(fresh["nodes"][0]["queries"])
        self.assertTrue(fresh["views"][0]["node_ids"])


class LiveCatalogCorrelationTests(unittest.TestCase):
    def fixture(self):
        def resource(kind, name, status=None, spec=None):
            return {"id": f"{kind}/{name}", "resource_kind": kind,
                    "resource": {"metadata": {"name": name, "namespace": "apps"},
                                 "status": status or {}, "spec": spec or {}}}

        return {"source": "custom_snapshot", "example": True, "nodes": [
            resource("Node", "ready", {"conditions": [{"type": "Ready", "status": "True"}]}),
            resource("Node", "unready"),
            resource("Pod", "failed", {"phase": "Failed"}),
            resource("Pod", "pending", {"phase": "Pending"}),
            resource("Pod", "running", {"phase": "Running"}),
            resource("Service", "web"),
            resource("Ingress", "web", spec={"rules": [
                {"host": "web.cluster.example.org", "http": {"paths": [
                    {"backend": {"service": {"name": "web"}}}]}}]}),
        ]}

    def test_bundled_snapshot_is_grounded_and_offline(self):
        with patch("cluster_harvester.subprocess.run") as collect:
            result = correlate_noc_signals_with_live_catalog()
            collect.assert_not_called()
        health = summarize_live_cluster_health()
        self.assertEqual(result["source"], health["source"])
        self.assertEqual(result["observations"]["node_counts"], health["node_counts"])
        self.assertEqual(result["observations"]["failed_pods_by_namespace"],
                         health["failed_pods_by_namespace"])
        self.assertIn("nodebeta02", result["observations"]["not_ready_nodes"])
        self.assertIn("gitlab", result["observations"]["failed_pods_by_namespace"])
        self.assertEqual(result["signals"]["errors"]["failed_pods"], health["pod_counts"]["failed"])
        self.assertEqual(result["signals"]["errors"]["pending_pods"], health["pod_counts"]["pending"])
        self.assertFalse(result["signals"]["latency"]["available"])
        self.assertIsNone(result["signals"]["latency"]["value"])
        self.assertIn("Offline snapshot", result["signals"]["latency"]["notice"])
        self.assertEqual(result, correlate_noc_signals_with_live_catalog())
        json.dumps(result, allow_nan=False)

    def test_custom_counts_routes_namespaces_and_independent_results(self):
        catalog = self.fixture()
        before = deepcopy(catalog)
        result = correlate_noc_signals_with_live_catalog(catalog)
        signals = result["signals"]
        self.assertEqual(set(signals), {"latency", "traffic", "errors", "saturation"})
        self.assertEqual(signals["saturation"]["unready_node_ratio"], 0.5)
        self.assertEqual(signals["errors"]["affected_pods"], 2)
        self.assertEqual(signals["traffic"]["service_count"], 1)
        self.assertEqual(signals["traffic"]["ingress_count"], 1)
        self.assertEqual(signals["traffic"]["ingress_host_count"], 1)
        self.assertIsNone(signals["traffic"]["request_rate"])
        self.assertEqual(result["observations"]["pending_pods_by_namespace"],
                         {"apps": {"count": 1, "pod_ids": ["Pod/pending"]}})
        self.assertEqual(result["observations"]["ingress_hosts"],
                         {"web.cluster.example.org": [{"namespace": "apps", "service": "web"}]})
        self.assertEqual(catalog, before)
        catalog["nodes"].reverse()
        self.assertEqual(result, correlate_noc_signals_with_live_catalog(catalog))
        result["observations"]["ready_nodes"].clear()
        self.assertEqual(correlate_noc_signals_with_live_catalog(catalog)["observations"]["ready_nodes"],
                         ["ready"])

    def test_path_string_and_default_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(self.fixture()), encoding="utf-8")
            expected = correlate_noc_signals_with_live_catalog(self.fixture())
            self.assertEqual(correlate_noc_signals_with_live_catalog(path), expected)
            self.assertEqual(correlate_noc_signals_with_live_catalog(str(path)), expected)
            with patch.object(noc, "DEFAULT_CATALOG_PATH", path):
                self.assertEqual(correlate_noc_signals_with_live_catalog(), expected)

    def test_empty_snapshot_has_unknown_capacity_and_no_fabricated_counts(self):
        result = correlate_noc_signals_with_live_catalog({"nodes": []})
        self.assertIsNone(result["signals"]["saturation"]["unready_node_ratio"])
        self.assertEqual(result["signals"]["errors"]["affected_pods"], 0)
        self.assertEqual(result["signals"]["traffic"]["service_count"], 0)
        self.assertEqual(result["observations"]["pending_pods_by_namespace"], {})

    def test_sanitizes_all_observations_without_mutating_input(self):
        catalog = self.fixture()
        wan = ".".join(map(str, (8, 8, 4, 4)))
        mac = ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))
        secret = "gh" + "p_examplecredential"
        catalog["source"] = secret
        catalog["nodes"][0]["resource"]["metadata"]["name"] = wan
        catalog["nodes"][3]["resource"]["metadata"]["namespace"] = mac
        catalog["nodes"][5]["resource"]["metadata"]["name"] = secret
        before = deepcopy(catalog)
        encoded = json.dumps(correlate_noc_signals_with_live_catalog(catalog))
        for raw in (wan, mac, secret):
            self.assertNotIn(raw, encoded)
        for clean in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "[REDACTED]", "web.cluster.example.org"):
            self.assertIn(clean, encoded)
        self.assertEqual(catalog, before)

    def test_invalid_catalogs_have_fixed_non_disclosing_errors(self):
        invalid = [False, 42, [], {}, {"nodes": {}}, {"nodes": [None]},
                   {"nodes": [{"id": ""}]}, {"nodes": [{"id": "same"}] * 2},
                   {"nodes": [{"id": "bad", "resource": None}]}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-catalog.json"
            invalid.append(path)  # Missing file.
            for catalog in invalid:
                with self.subTest(catalog_type=type(catalog).__name__):
                    with self.assertRaisesRegex(ValueError, "^Unable to load valid cluster catalog$"):
                        correlate_noc_signals_with_live_catalog(catalog)
            for text in ("private invalid JSON", "[]", '{"nodes": [null]}'):
                path.write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "^Unable to load valid cluster catalog$"):
                    correlate_noc_signals_with_live_catalog(path)


class KioskCyclerTests(unittest.TestCase):
    def test_default_fifty_presses_complete_five_wraps(self):
        result = simulate_kiosk_view_cycler()
        self.assertEqual(result["history"], list(range(1, 10)) * 5 + list(range(1, 7)))
        self.assertEqual(result["current_view"], 6)
        self.assertEqual(result["wrap_count"], 5)

    def test_every_transition_for_varied_view_counts_and_wrap_boundaries(self):
        for count in (1, 2, 3, 9, 17):
            for presses in (0, count - 1, count, count + 1, count * 4, 10000):
                with self.subTest(count=count, presses=presses):
                    result = simulate_kiosk_view_cycler(count, presses)
                    history = result["history"]
                    self.assertEqual(len(history), presses + 1)
                    self.assertEqual(history[0], 1)
                    self.assertEqual(result["current_view"], presses % count + 1)
                    self.assertEqual(result["wrap_count"], presses // count)
                    wraps = 0
                    for before, after in zip(history, history[1:]):
                        self.assertTrue(1 <= after <= count)
                        if before == count:
                            self.assertEqual(after, 1)
                            wraps += 1
                        else:
                            self.assertEqual(after, before + 1)
                    self.assertEqual(wraps, result["wrap_count"])

    def test_invalid_inputs_are_rejected_before_replay(self):
        for count in (0, -1, True, False, 1.0, "9", None):
            with self.subTest(count=count), self.assertRaises(ValueError):
                simulate_kiosk_view_cycler(count, 0)
        for presses in (-1, True, False, 1.0, "50", None):
            with self.subTest(presses=presses), self.assertRaises(ValueError):
                simulate_kiosk_view_cycler(9, presses)


if __name__ == "__main__":
    unittest.main()
