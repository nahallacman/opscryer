# SPDX-License-Identifier: Apache-2.0
"""Tests for Live /nodes Hardware Metrics Parity & Honest UNAVAILABLE_NO_EXPORTER States (Wave 3)."""

from __future__ import annotations

from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch
from urllib.request import urlopen

OPSCRYER_ROOT = Path(__file__).resolve().parent.parent
if str(OPSCRYER_ROOT) not in sys.path:
    sys.path.insert(0, str(OPSCRYER_ROOT))

import live_metrics_poller as poller
import opscryer_browser


class TestLiveNodesHardwareMetricsParity(unittest.TestCase):
    """Proves OpsCryer /nodes & /api/v1/nodes/hardware-metrics surface live CPU/RAM/GPU + honest UNAVAILABLE_NO_EXPORTER."""

    def setUp(self) -> None:
        poller.clear_live_metrics_cache()
        self.addCleanup(poller.clear_live_metrics_cache)

    def test_01_brain_catalog_cpu_ram_gpu_and_unavailable_no_exporter(self) -> None:
        brain_cat = {
            "nodes": [
                {
                    "id": "k8s-node-streamserver",
                    "label": "Node: streamserver",
                    "kind": "physical_hardware",
                    "metrics": {
                        "ready": True,
                        "cpu_pct": 37.5,
                        "mem_pct": 54.0,
                        "gpu_util_pct": 81.0,
                        "gpu_vram_used_mib": 7168.0,
                        "gpu_vram_total_mib": 10240.0,
                        "gpu_vram_pct": 70.0,
                        "gpu_temp_c": 67.0,
                    },
                },
                {
                    "id": "k8s-node-lowpoweredserver",
                    "label": "Node: lowpoweredserver",
                    "kind": "physical_hardware",
                    "metrics": {
                        "ready": True,
                        "cpu_pct": 14.0,
                        "mem_pct": 48.0,
                    },
                },
                {
                    "id": "k8s-node-unmonitored",
                    "label": "Node: unmonitored",
                    "kind": "physical_hardware",
                    "metrics": {"ready": True},
                },
            ]
        }
        res = poller.poll_live_nodes_hardware_metrics(brain_catalog=brain_cat)
        self.assertEqual(res["schema_version"], "1.0-live-nodes-hardware-metrics")
        self.assertTrue(res["honest_zero_fabrication"])
        self.assertEqual(res["exporter_summary"]["total_nodes"], 3)
        self.assertEqual(res["exporter_summary"]["cpu_reporting"], 2)
        self.assertEqual(res["exporter_summary"]["ram_reporting"], 2)
        self.assertEqual(res["exporter_summary"]["gpu_reporting"], 1)
        self.assertEqual(res["exporter_summary"]["unavailable_nodes"], 1)

        by_name = {n["name"]: n for n in res["nodes"]}
        self.assertEqual(by_name["streamserver"]["exporter_status"], "COMPLETE")
        self.assertEqual(by_name["streamserver"]["gpu_percent"], 81.0)
        self.assertEqual(by_name["streamserver"]["gpu_vram_percent"], 70.0)
        self.assertEqual(by_name["streamserver"]["gpu_temp_c"], 67.0)
        self.assertEqual(by_name["streamserver"]["gpu_status"], "OK")

        # CPU-only node must show GPU=UNAVAILABLE_NO_EXPORTER (None, NEVER 0).
        self.assertIsNone(by_name["lowpoweredserver"]["gpu_percent"])
        self.assertEqual(by_name["lowpoweredserver"]["gpu_status"], "UNAVAILABLE_NO_EXPORTER")
        self.assertEqual(by_name["lowpoweredserver"]["exporter_status"], "PARTIAL_EXPORTERS")

        # Unmonitored node must show UNAVAILABLE_NO_EXPORTER across CPU, RAM, and GPU.
        self.assertIsNone(by_name["unmonitored"]["cpu_percent"])
        self.assertIsNone(by_name["unmonitored"]["ram_percent"])
        self.assertIsNone(by_name["unmonitored"]["gpu_percent"])
        self.assertEqual(by_name["unmonitored"]["cpu_status"], "UNAVAILABLE_NO_EXPORTER")
        self.assertEqual(by_name["unmonitored"]["ram_status"], "UNAVAILABLE_NO_EXPORTER")
        self.assertEqual(by_name["unmonitored"]["gpu_status"], "UNAVAILABLE_NO_EXPORTER")
        self.assertEqual(by_name["unmonitored"]["exporter_status"], "UNAVAILABLE_NO_EXPORTER")

    def test_02_prometheus_overlay_and_imds_ssrf_guard(self) -> None:
        with self.assertRaises(ValueError):
            poller.poll_live_nodes_hardware_metrics(prometheus_url="http://169.254.169.254/latest/meta-data")
        with self.assertRaises(ValueError):
            poller.poll_live_nodes_hardware_metrics(prometheus_url="file:///etc/passwd")

        def _fake_prom(_url: str, expr: str):
            if "node_cpu_seconds_total" in expr:
                return [{"metric": {"node": "gpu-box"}, "value": [1700000000, "55.2"]}]
            if "DCGM_FI_DEV_GPU_UTIL" in expr:
                return [{"metric": {"Hostname": "gpu-box"}, "value": [1700000000, "91.0"]}]
            if "DCGM_FI_DEV_FB_USED" in expr:
                return [{"metric": {"Hostname": "gpu-box"}, "value": [1700000000, "8192"]}]
            if "DCGM_FI_DEV_FB_FREE" in expr:
                return [{"metric": {"Hostname": "gpu-box"}, "value": [1700000000, "8192"]}]
            return []

        res = poller.poll_live_nodes_hardware_metrics(
            prometheus_url="http://prom.cluster.example.org:9090",
            catalog={"nodes": []},
            prom_query_fn=_fake_prom,
        )
        self.assertTrue(res["prometheus_configured"])
        node = next(n for n in res["nodes"] if n["name"] == "gpu-box")
        self.assertEqual(node["cpu_percent"], 55.2)
        self.assertEqual(node["cpu_status"], "OK")
        self.assertIsNone(node["ram_percent"])
        self.assertEqual(node["ram_status"], "UNAVAILABLE_NO_EXPORTER")
        self.assertEqual(node["gpu_percent"], 91.0)
        self.assertEqual(node["gpu_vram_percent"], 50.0)
        self.assertEqual(node["gpu_status"], "OK")
        self.assertEqual(node["exporter_status"], "PARTIAL_EXPORTERS")

    def test_03_http_gateway_nodes_html_and_hardware_metrics_api_e2e(self) -> None:
        with patch.dict(os.environ, {"OPSCRYER_BRAIN_API_URL": "", "OPSCRYER_PROMETHEUS_URL": ""}, clear=False):
            handler_cls = opscryer_browser._build_frontend_handler("")
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
            port = server.server_address[1]
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            try:
                with urlopen(f"http://127.0.0.1:{port}/nodes", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    html = resp.read().decode("utf-8")
                self.assertIn("UNAVAILABLE_NO_EXPORTER", html)
                self.assertIn("/api/v1/nodes/hardware-metrics", html)
                self.assertNotIn("innerHTML", html)

                with urlopen(f"http://127.0.0.1:{port}/api/v1/nodes/hardware-metrics", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    payload = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(payload["schema_version"], "1.0-live-nodes-hardware-metrics")
                self.assertTrue(payload["honest_zero_fabrication"])
                self.assertIn("nodes", payload)
                self.assertIn("exporter_summary", payload)
            finally:
                server.shutdown()
                server.server_close()
                t.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
