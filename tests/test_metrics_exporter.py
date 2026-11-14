# SPDX-License-Identifier: Apache-2.0
"""Unit and HTTP integration tests for the Prometheus /metrics exporter."""

from __future__ import annotations

import http.client
import math
import re
import socketserver
import threading
import time
import unittest

from opscryer_browser import _build_frontend_handler
import metrics_exporter


class TestMetricsExporterUnit(unittest.TestCase):
    def setUp(self) -> None:
        metrics_exporter.reset_metrics()

    def tearDown(self) -> None:
        metrics_exporter.reset_metrics()

    def test_escaping_docstring_and_labels(self) -> None:
        self.assertEqual(metrics_exporter._escape_help("Help\\with\nnewlines"), "Help\\\\with\\nnewlines")
        self.assertEqual(metrics_exporter._escape_label_value('val"with\\and\n'), 'val\\"with\\\\and\\n')

    def test_number_formatting(self) -> None:
        self.assertEqual(metrics_exporter._format_value(42), "42")
        self.assertEqual(metrics_exporter._format_value(1.0), "1.0")
        self.assertEqual(metrics_exporter._format_value(0.95), "0.95")
        self.assertEqual(metrics_exporter._format_value(float("nan")), "NaN")
        self.assertEqual(metrics_exporter._format_value(float("inf")), "+Inf")
        self.assertEqual(metrics_exporter._format_value(float("-inf")), "-Inf")

    def test_counter_increments_and_resets(self) -> None:
        counter = metrics_exporter.Counter("test_counter", "Test doc")
        counter.inc(1, method="GET", status="200")
        counter.inc(2, method="GET", status="200")
        counter.inc(1, method="POST", status="400")
        self.assertEqual(counter.get(method="GET", status="200"), 3.0)
        self.assertEqual(counter.get(method="POST", status="400"), 1.0)
        self.assertEqual(counter.get(method="DELETE", status="404"), 0.0)

        family = counter.collect()
        self.assertEqual(family.name, "test_counter")
        self.assertEqual(family.metric_type, "counter")
        self.assertEqual(len(family.samples), 2)

        counter.reset()
        self.assertEqual(len(counter.collect().samples), 0)

    def test_gauge_set_and_resets(self) -> None:
        gauge = metrics_exporter.Gauge("test_gauge", "Test doc")
        gauge.set(42, host="nodegamma03")
        self.assertEqual(gauge.get(host="nodegamma03"), 42)
        family = gauge.collect()
        self.assertEqual(family.name, "test_gauge")
        self.assertEqual(family.metric_type, "gauge")
        self.assertEqual(family.samples[0].value, 42)

    def test_format_prometheus_text_structure(self) -> None:
        mf = metrics_exporter.MetricFamily("opscryer_test_metric", "Test metric help", "gauge")
        mf.add_sample("opscryer_test_metric", {"env": "prod"}, 1)
        output = metrics_exporter.format_prometheus_text([mf])

        self.assertTrue(output.endswith("\n"), "Prometheus text must terminate with newline")
        lines = output.strip().split("\n")
        self.assertEqual(lines[0], "# HELP opscryer_test_metric Test metric help")
        self.assertEqual(lines[1], "# TYPE opscryer_test_metric gauge")
        self.assertEqual(lines[2], 'opscryer_test_metric{env="prod"} 1')

    def test_core_metrics_emission(self) -> None:
        metrics_exporter.record_http_request("GET", "/metrics", 200)
        text = metrics_exporter.generate_latest_metrics()

        # Assert presence of all core operational metrics
        self.assertIn("# HELP opscryer_uptime_seconds", text)
        self.assertIn("# TYPE opscryer_uptime_seconds gauge", text)
        self.assertRegex(text, r"opscryer_uptime_seconds \d+(\.\d+)?")

        self.assertIn("# HELP opscryer_http_requests_total", text)
        self.assertIn("# TYPE opscryer_http_requests_total counter", text)
        self.assertIn('opscryer_http_requests_total{endpoint="/metrics",method="GET",status="200"} 1', text)

        self.assertIn("# HELP opscryer_cluster_health_status", text)
        self.assertIn("# TYPE opscryer_cluster_health_status gauge", text)

        self.assertIn("# HELP opscryer_cluster_health_score", text)
        self.assertIn("# TYPE opscryer_cluster_health_score gauge", text)
        self.assertRegex(text, r"opscryer_cluster_health_score [01](\.\d+)?")

        self.assertIn("# HELP opscryer_active_gpu_count", text)
        self.assertIn("# TYPE opscryer_active_gpu_count gauge", text)
        self.assertIn("opscryer_active_gpu_count 4", text)

        self.assertIn("# HELP opscryer_total_gpu_vram_gb", text)
        self.assertIn("# TYPE opscryer_total_gpu_vram_gb gauge", text)
        self.assertIn("opscryer_total_gpu_vram_gb 40", text)

        self.assertIn("# HELP opscryer_scale_down_workload_count", text)
        self.assertIn("# TYPE opscryer_scale_down_workload_count gauge", text)
        self.assertIn("opscryer_scale_down_workload_count 7", text)

        self.assertIn("# HELP opscryer_live_currency_rate", text)
        self.assertIn("# TYPE opscryer_live_currency_rate gauge", text)
        for pair in ("nodes", "cpu_load", "ram_load", "network_load", "build_supply", "renovate_failures", "open_mrs"):
            self.assertIn(f'opscryer_live_currency_rate{{pair="{pair}"}}', text)

    def test_currency_rate_parser(self) -> None:
        self.assertEqual(metrics_exporter.parse_currency_rate({"available": True, "display_value": "3/3 Ready"}), 3.0)
        self.assertEqual(metrics_exporter.parse_currency_rate({"available": True, "display_value": "24% Avg"}), 24.0)
        self.assertEqual(metrics_exporter.parse_currency_rate({"available": True, "display_value": "48% Avg"}), 48.0)
        self.assertEqual(metrics_exporter.parse_currency_rate({"available": True, "display_value": "15 routes (Ingress/Service)"}), 15.0)
        self.assertEqual(metrics_exporter.parse_currency_rate({"available": True, "display_value": "2 runner pods / 0 deployments"}), 2.0)
        self.assertEqual(metrics_exporter.parse_currency_rate({"available": False, "display_value": "Unavailable"}), 0.0)
        self.assertEqual(metrics_exporter.parse_currency_rate({"available": True, "count": 5}), 5.0)

    def test_cluster_health_score_calculation(self) -> None:
        score = metrics_exporter.calculate_cluster_health_score()
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_concurrent_counter_increments(self) -> None:
        threads: list[threading.Thread] = []
        for _ in range(10):
            def worker():
                for _ in range(50):
                    metrics_exporter.record_http_request("GET", "/api/v1/test", 200)
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        counter_val = metrics_exporter.REGISTRY.http_requests_total.get(
            method="GET", endpoint="/api/v1/test", status="200"
        )
        self.assertEqual(counter_val, 500.0)


class TestMetricsExporterHttpIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        handler_cls = _build_frontend_handler()
        cls.server = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        metrics_exporter.reset_metrics()

    def tearDown(self) -> None:
        metrics_exporter.reset_metrics()

    def test_http_get_metrics_success(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/metrics")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()

        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "text/plain; version=0.0.4; charset=utf-8")
        self.assertIn("# HELP opscryer_uptime_seconds", body)
        self.assertIn("# HELP opscryer_http_requests_total", body)
        self.assertIn("# HELP opscryer_cluster_health_status", body)
        self.assertIn("# HELP opscryer_cluster_health_score", body)
        self.assertIn("opscryer_active_gpu_count 4", body)
        self.assertIn("opscryer_total_gpu_vram_gb 40", body)
        self.assertIn("opscryer_scale_down_workload_count 7", body)

    def test_http_get_metrics_rejects_query_parameters(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/metrics?format=json")
        resp = conn.getresponse()
        resp.read()
        conn.close()

        self.assertEqual(resp.status, 400)

    def test_http_post_metrics_rejects_with_405(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/metrics")
        resp = conn.getresponse()
        resp.read()
        conn.close()

        self.assertEqual(resp.status, 405)

    def test_http_requests_tracked_across_endpoints(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/scale")
        conn.getresponse().read()

        conn.request("GET", "/metrics")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()

        self.assertIn('opscryer_http_requests_total{endpoint="/scale",method="GET",status="200"} 1', body)


if __name__ == "__main__":
    unittest.main()
