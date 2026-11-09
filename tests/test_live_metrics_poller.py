# SPDX-License-Identifier: Apache-2.0
"""Offline metrics, deterministic cache expiry, safe rendering and transport."""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import io
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from unittest.mock import MagicMock, patch

from golden_path_gates import _opsec_count
import live_metrics_poller as poller


def snapshot(source="live_kubectl"):
    """Small Kubernetes inventory processed by the real catalog builder."""
    return {"source": source, "example": source != "live_kubectl", "errors": [],
            "items": [
                {"kind": "Node", "metadata": {"name": "worker.cluster.example.org"},
                 "status": {"conditions": [{"type": "Ready", "status": "True"}]}},
                {"kind": "Pod", "metadata": {"name": "web", "namespace": "apps"},
                 "spec": {"nodeName": "worker.cluster.example.org"},
                 "status": {"phase": "Running"}},
            ]}


def catalog():
    result = poller.cluster_harvester.build_live_cluster_spatial_catalog(snapshot())
    worker = next(n for n in result["nodes"] if n.get("resource_kind") == "Node")
    worker["metrics"] = {"cpu_percent": 82, "ram_percent": 76,
                         "cpu_used": "820m", "ram_used": "3Gi"}
    for identity, namespace, phase in (("failed", "apps", "Failed"),
                                        ("pending", "batch", "Pending")):
        result["nodes"].append({
            "id": identity, "resource_kind": "Pod",
            "resource": {"kind": "Pod", "metadata": {
                "name": identity, "namespace": namespace},
                "spec": {"nodeName": "worker.cluster.example.org"}, "status": {"phase": phase}}})
    return result


class MetricsTestCase(unittest.TestCase):
    def setUp(self):
        poller.clear_live_metrics_cache()
        self.addCleanup(poller.clear_live_metrics_cache)
        # No test may accidentally invoke real cluster collection.
        self.harvest = self.enterContext(patch.object(
            poller.cluster_harvester, "harvest_live_k8s_cluster",
            return_value=snapshot()))

    def assert_clean(self, output):
        self.assertEqual(_opsec_count(output.encode("utf-8")), 0)


class PollingTests(MetricsTestCase):
    def test_default_uses_snapshot_without_harvesting(self):
        result = poller.poll_live_cluster_metrics()
        self.assertEqual(result["schema_version"], "1.0-live-metrics-stream")
        self.assertEqual(result["telemetry_mode"], "SNAPSHOT_CACHE")
        self.assertIs(result["live_kubectl_active"], False)
        self.assertEqual(result["ttl_seconds"], 10)
        self.assertEqual(result["freshness_label"], "CACHED SNAPSHOT (offline-safe)")
        self.assertEqual(len(result["rts_currencies"]), 7)
        self.assert_clean(json.dumps(result))
        self.harvest.assert_not_called()

    def test_missing_snapshot_uses_offline_builder(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
                poller.cluster_diff_engine, "DEFAULT_CATALOG_PATH",
                Path(directory) / "missing.json"):
            result = poller.poll_live_cluster_metrics()
        self.assertEqual(result["telemetry_mode"], "SNAPSHOT_CACHE")
        self.assertIs(result["live_kubectl_active"], False)
        self.harvest.assert_not_called()

    def test_live_fallback_and_recovery_transitions(self):
        self.harvest.side_effect = [snapshot(), snapshot("offline_fallback"), snapshot()]
        results = [poller.poll_live_cluster_metrics()]
        results.extend(poller.poll_live_cluster_metrics(True, 0) for _ in range(3))
        self.assertEqual([r["telemetry_mode"] for r in results],
                         ["SNAPSHOT_CACHE", "LIVE_KUBECTL", "SNAPSHOT_FALLBACK", "LIVE_KUBECTL"])
        self.assertEqual([r["live_kubectl_active"] for r in results], [False, True, False, True])
        self.assertEqual(results[1]["freshness_label"], "LIVE (real-time kubectl poll)")
        self.assertEqual(results[2]["freshness_label"], "CACHED SNAPSHOT (offline-safe)")
        self.assertEqual(self.harvest.call_count, 3)
        self.harvest.assert_called_with(timeout=6)

    def test_collection_exceptions_fall_back_without_exposing_details(self):
        for exception in (OSError, ValueError, TypeError, RuntimeError):
            with self.subTest(exception=exception.__name__):
                self.harvest.side_effect = exception("private collection detail")
                result = poller.poll_live_cluster_metrics(True, 0)
                self.assertEqual(result["telemetry_mode"], "SNAPSHOT_FALLBACK")
                self.assertFalse(result["live_kubectl_active"])
                self.assertNotIn("private collection detail", json.dumps(result))

    def test_aggregation_metrics_and_explicit_catalog_do_not_harvest(self):
        supplied = catalog()
        before = deepcopy(supplied)
        result = poller.poll_live_cluster_metrics(True, catalog=supplied)
        self.assertEqual(result["telemetry_mode"], "SNAPSHOT_CACHE")
        self.assertEqual(result["node_metrics"], [{
            "node_id": next(n["id"] for n in supplied["nodes"] if n.get("resource_kind") == "Node"),
            "name": "worker.cluster.example.org", "ready": True, "cpu_percent": 82,
            "ram_percent": 76, "cpu_used": "820m", "ram_used": "3Gi",
            "running_pod_count": 1, "failed_pod_count": 1}])
        self.assertEqual(result["namespace_pressure"], [
            {"namespace": "apps", "running_pods": 1, "failed_pods": 1, "pending_pods": 0},
            {"namespace": "batch", "running_pods": 0, "failed_pods": 0, "pending_pods": 1}])
        self.assertEqual(result["health"]["node_counts"], {"total": 1, "ready": 1, "not_ready": 0})
        self.assertEqual(supplied, before)
        self.harvest.assert_not_called()

    def test_empty_catalog(self):
        result = poller.poll_live_cluster_metrics(catalog={"nodes": []})
        self.assertEqual(result["node_metrics"], [])
        self.assertEqual(result["namespace_pressure"], [])
        self.assertEqual(len(result["rts_currencies"]), 7)

    def test_parameter_validation(self):
        for arguments in ({"allow_kubectl": 1}, {"allow_kubectl": "true"},
                          *({"ttl_seconds": value} for value in
                            (-1, 3601, True, 1.5, "10", None))):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(
                    ValueError, "^Invalid live metrics parameters$"):
                poller.poll_live_cluster_metrics(**arguments)
        self.harvest.assert_not_called()


class CacheTests(MetricsTestCase):
    def test_reuse_before_ttl_and_refresh_at_expiry(self):
        with patch.object(poller.time, "monotonic", return_value=100) as clock:
            first = poller.poll_live_cluster_metrics(True, 10)
            clock.return_value = 109.99
            second = poller.poll_live_cluster_metrics(True, 10)
            self.assertEqual(first, second)
            self.harvest.assert_called_once_with(timeout=6)
            clock.return_value = 110
            poller.poll_live_cluster_metrics(True, 10)
            self.assertEqual(self.harvest.call_count, 2)

    def test_cached_results_are_independent_deep_copies(self):
        original = poller.poll_live_cluster_metrics(True)
        # Mutate both the initial return and a cache-hit return.
        original["node_metrics"].clear()
        hit = poller.poll_live_cluster_metrics(True)
        self.assertTrue(hit["node_metrics"])
        hit["health"]["node_counts"]["total"] = 999
        self.assertEqual(poller.poll_live_cluster_metrics(True)["health"]["node_counts"]["total"], 1)
        self.harvest.assert_called_once()

    def test_clear_discards_cache_without_collecting(self):
        poller.poll_live_cluster_metrics(True)
        poller.clear_live_metrics_cache()
        self.harvest.assert_called_once()
        poller.poll_live_cluster_metrics(True)
        self.assertEqual(self.harvest.call_count, 2)

    def test_cache_keys_separate_live_offline_and_ttl(self):
        poller.poll_live_cluster_metrics(False, 10)
        self.harvest.assert_not_called()
        poller.poll_live_cluster_metrics(True, 10)
        poller.poll_live_cluster_metrics(True, 20)
        poller.poll_live_cluster_metrics(True, 10)
        self.assertEqual(self.harvest.call_count, 2)
        self.assertEqual(poller.poll_live_cluster_metrics()["telemetry_mode"], "SNAPSHOT_CACHE")

    def test_zero_ttl_disables_reuse_and_catalog_bypasses_cache(self):
        for _ in range(2):
            poller.poll_live_cluster_metrics(True, 0)
        self.assertEqual(self.harvest.call_count, 2)
        for _ in range(2):
            result = poller.poll_live_cluster_metrics(True, catalog={"nodes": []})
            self.assertEqual(result["node_metrics"], [])
        self.assertEqual(self.harvest.call_count, 2)


class RenderingTests(MetricsTestCase):
    def test_markdown_structure_and_literal_cells(self):
        supplied = catalog()
        worker = next(n for n in supplied["nodes"] if n.get("resource_kind") == "Node")
        worker["resource"]["metadata"]["name"] = '<img src=x> | [link](x)\n*bold*'
        worker["metrics"]["ram_used"] = None
        markdown = poller.render_live_metrics_markdown(catalog=supplied)
        self.assertTrue(markdown.startswith("# Live Cluster Metrics & Telemetry Stream\n"))
        self.assertIn("Telemetry mode: **SNAPSHOT_CACHE**", markdown)
        for title in ("Per-node telemetry", "Live RTS currencies", "Namespace workload pressure"):
            self.assertIn("## " + title, markdown)
        separators = [line for line in markdown.splitlines() if line.startswith("| --- |")]
        self.assertEqual(len(separators), 3)
        self.assertIn("| Node | Ready | CPU (%) | RAM (%) |", markdown)
        self.assertIn("| Namespace | Running pods | Failed pods | Pending pods |", markdown)
        self.assertIn(r"&lt;img src=x&gt; \| \[link\]\(x\) \*bold\*", markdown)
        self.assertIn("Unavailable", markdown)
        self.assertNotIn("<img", markdown)
        self.harvest.assert_not_called()

    def test_html_structure_navigation_and_safe_dynamic_content(self):
        html = poller.render_live_metrics_html()
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        for destination in ("/", "/hub", "/chat", "/incidents", "/capacity",
                            "/games", "/kb", "/storage", "/secops", "/metrics-live"):
            self.assertIn('href="' + destination + '"', html)
        self.assertIn('href="/metrics-live" aria-current="page"', html)
        for identity in ("nodes", "currencies", "pressure", "poll", "auto-poll", "status", "mode"):
            self.assertIn('id="' + identity + '"', html)
        self.assertIn("/api/v1/live-metrics?live=1", html)
        self.assertIn("setInterval", html)
        self.assertIn("10000", html)
        self.assertIn("element.textContent", html)
        self.assertNotIn("innerHTML", html)
        self.assertIn('aria-live="polite"', html)
        self.assert_clean(html)
        self.harvest.assert_not_called()

    def test_exports_scrub_probes_and_preserve_internal_identifiers(self):
        wan = ".".join(map(str, (8, 8, 4, 4)))
        mac = ":".join(("AA", "BB", "CC", "11", "22", "33"))
        tokens = [prefix + "syntheticfixture" for prefix in
                  ("gh" + "o_", "gh" + "p_", "gl" + "pat-", "s" + "k-")]
        supplied = catalog()
        supplied["source"] = " ".join([wan, mac, *tokens, "10.1.2.3",
                                         "172.20.1.2", "172.16.1.2", "nas.cluster.example.org"])
        worker = next(n for n in supplied["nodes"] if n.get("resource_kind") == "Node")
        worker["resource"]["metadata"]["name"] = supplied["source"]
        before = deepcopy(supplied)
        result = poller.poll_live_cluster_metrics(catalog=supplied)
        for output in (json.dumps(result), poller.render_live_metrics_markdown(catalog=supplied),
                       poller.render_live_metrics_html()):
            self.assert_clean(output)
            self.assertTrue(all(probe not in output for probe in [wan, mac, *tokens]),
                            "Unsanitized probe escaped")
        for expected in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "[REDACTED]",
                         "10.1.2.3", "172.20.1.2", "172.16.1.2", "nas.cluster.example.org"):
            self.assertIn(expected, result["node_metrics"][0]["name"])
        self.assertTrue(supplied == before, "Input was mutated")

    def test_test_file_license_lf_and_opsec(self):
        content = Path(__file__).read_bytes()
        self.assertTrue(content.startswith(b"# SPDX-License-Identifier: Apache-2.0\n"))
        self.assertNotIn(b"\r", content)
        self.assertEqual(_opsec_count(content), 0)


class CLITests(MetricsTestCase):
    def invoke(self, arguments):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = poller.main(arguments)
        self.assertEqual(code, 0)
        self.assertEqual(errors.getvalue(), "")
        self.assert_clean(output.getvalue())
        return output.getvalue()

    def test_json_and_markdown_default_offline(self):
        self.assertEqual(json.loads(self.invoke(["--json"])), poller.poll_live_cluster_metrics())
        self.assertEqual(self.invoke(["--markdown"]).strip(),
                         poller.render_live_metrics_markdown().strip())
        self.harvest.assert_not_called()

    def test_live_flag_opts_into_collection(self):
        result = json.loads(self.invoke(["--json", "--live"]))
        self.assertEqual(result["telemetry_mode"], "LIVE_KUBECTL")
        self.harvest.assert_called_once_with(timeout=6)

    def test_default_json_and_live_markdown_with_custom_ttl(self):
        self.assertEqual(json.loads(self.invoke([]))["telemetry_mode"], "SNAPSHOT_CACHE")
        markdown = self.invoke(["--markdown", "--live", "--ttl", "0"])
        self.assertIn("Telemetry mode: **LIVE_KUBECTL**", markdown)
        self.assertIn("## Per-node telemetry", markdown)
        self.harvest.assert_called_once_with(timeout=6)

    def test_invalid_arguments_exit_two_without_reflection(self):
        probe = "private_argument_marker"
        for arguments in (["--" + probe], ["--port", probe], ["--port", "0"],
                          ["--port", "65536"], ["--port"], ["--json", "--markdown"],
                          ["--serve", "--json"], ["--serve", "--markdown"],
                          ["--ttl", probe], ["--ttl", "-1"], ["--ttl", "3601"],
                          ["--ttl"], ["--json", probe], ["--mar"]):
            with self.subTest(arguments=arguments):
                output, errors = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(errors), \
                        self.assertRaises(SystemExit) as caught:
                    poller.main(arguments)
                self.assertEqual(caught.exception.code, 2)
                self.assertEqual(output.getvalue(), "")
                self.assertTrue(errors.getvalue())
                self.assertNotIn(probe, errors.getvalue())
                self.assert_clean(errors.getvalue())
        self.harvest.assert_not_called()

    def test_serve_loopback_and_interrupt_cleanup(self):
        with patch.object(poller, "ThreadingHTTPServer", create=True) as server:
            instance = server.return_value.__enter__.return_value
            instance.serve_forever.side_effect = KeyboardInterrupt
            output = self.invoke(["--serve", "--port", "8123", "--ttl", "37"])
            self.assertIn("http://127.0.0.1:8123/metrics-live", output)
            self.assertEqual(server.call_args.args[0], ("127.0.0.1", 8123))
            instance.serve_forever.assert_called_once_with()
            server.return_value.__exit__.assert_called_once()
        self.harvest.assert_not_called()


@contextmanager
def serving():
    """Obtain the public CLI's handler without depending on its private name."""
    fake = MagicMock()
    fake.return_value.__enter__.return_value.serve_forever.side_effect = KeyboardInterrupt
    with patch.object(poller, "ThreadingHTTPServer", fake, create=True), \
            redirect_stdout(io.StringIO()):
        poller.main(["--serve", "--port", "8123"])
    handler = fake.call_args.args[1]
    with ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield server.server_address
        finally:
            server.shutdown()
            thread.join(timeout=5)


def request(address, path):
    connection = HTTPConnection(*address, timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read().decode("utf-8")
    finally:
        connection.close()


class HTTPTests(MetricsTestCase):
    def test_success_routes_types_and_content(self):
        with serving() as address:
            for route, content_type in (("/", "text/html"), ("/metrics-live", "text/html"),
                                        ("/metrics-live/report.md", "text/markdown"),
                                        ("/api/v1/live-metrics?live=0", "application/json")):
                with self.subTest(route=route):
                    status, headers, body = request(address, route)
                    self.assertEqual(status, 200)
                    self.assertEqual(headers["Content-Type"], content_type + "; charset=utf-8")
                    self.assertEqual(int(headers["Content-Length"]), len(body.encode("utf-8")))
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    self.assert_clean(body)
                    if content_type == "text/html":
                        self.assertEqual(body, poller.render_live_metrics_html())
                    elif content_type == "text/markdown":
                        self.assertEqual(body.strip(), poller.render_live_metrics_markdown().strip())
                    else:
                        self.assertEqual(json.loads(body), poller.poll_live_cluster_metrics())
        self.harvest.assert_not_called()

    def test_invalid_queries_and_missing_routes_do_not_reflect_input(self):
        probe = "private_query_marker"
        with serving() as address:
            for path, expected in (("/missing/" + probe, 404),
                                   ("/api/v1/live-metrics?live=" + probe, 400),
                                   ("/api/v1/live-metrics?live=", 400),
                                   ("/api/v1/live-metrics?live=0&live=1", 400),
                                   ("/api/v1/live-metrics?unknown=" + probe, 400),
                                   ("/metrics-live?unknown=" + probe, 400),
                                   ("/?live=0", 400),
                                   ("/api/v1/live-metrics?live", 400),
                                   ("/api/v1/live-metrics?live=%", 400),
                                   ("/api/v1/live-metrics?live=%GG", 400),
                                   ("/api/v1/live-metrics?live=%FF", 400),
                                   ("/metrics-live/report.md?live=2", 400),
                                   ("/metrics-live/report.md?live=0&live=0", 400)):
                with self.subTest(path=path):
                    status, headers, body = request(address, path)
                    self.assertEqual(status, expected)
                    self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    self.assertEqual(json.loads(body), {"error": (
                        "Not found" if expected == 404 else "Invalid live metrics request")})
                    self.assertNotIn(probe, body)
                    self.assert_clean(body)
        self.harvest.assert_not_called()

    def test_http_live_opt_in_uses_mocked_harvest(self):
        with serving() as address:
            status, _, body = request(address, "/api/v1/live-metrics?live=1")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["telemetry_mode"], "LIVE_KUBECTL")
        self.harvest.assert_called_once_with(timeout=6)

    def test_http_fallback_cached_until_clear_then_live_recovery(self):
        self.harvest.side_effect = [OSError("private collection detail"), snapshot()]
        with serving() as address:
            for _ in range(2):
                status, _, body = request(address, "/api/v1/live-metrics?live=1")
                self.assertEqual(status, 200)
                metrics = json.loads(body)
                self.assertEqual(metrics["telemetry_mode"], "SNAPSHOT_FALLBACK")
                self.assertFalse(metrics["live_kubectl_active"])
                self.assertNotIn("private collection detail", body)
                self.assert_clean(body)
            self.harvest.assert_called_once_with(timeout=6)
            poller.clear_live_metrics_cache()
            status, _, body = request(address, "/api/v1/live-metrics?live=1")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["telemetry_mode"], "LIVE_KUBECTL")
            status, _, markdown = request(address, "/metrics-live/report.md?live=1")
            self.assertEqual(status, 200)
            self.assertIn("Telemetry mode: **LIVE_KUBECTL**", markdown)
            self.assert_clean(markdown)
        self.assertEqual(self.harvest.call_count, 2)

    def test_dns_rebinding_non_loopback_host_header_is_rejected(self):
        self.assertTrue(poller.validate_loopback_host_header("127.0.0.1:8088"))
        self.assertTrue(poller.validate_loopback_host_header("localhost:8104"))
        self.assertFalse(poller.validate_loopback_host_header("rebind.attacker.example:8104"))
        with serving() as address:
            connection = HTTPConnection(*address, timeout=5)
            try:
                connection.request(
                    "GET",
                    "/api/v1/live-metrics?live=1",
                    headers={"Host": "rebind.attacker.example:8104"},
                )
                response = connection.getresponse()
                body = response.read().decode("utf-8")
                self.assertEqual(response.status, 400)
                self.assertEqual(json.loads(body), {"error": "Invalid live metrics request"})
            finally:
                connection.close()
        self.harvest.assert_not_called()


if __name__ == "__main__":
    unittest.main()
