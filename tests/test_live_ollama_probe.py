# SPDX-License-Identifier: Apache-2.0
"""Offline, transport, redaction and advisory placement contracts."""

from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import live_ollama_probe as ollama


def workload(kind, name, namespace, replicas=1, ready=1):
    return {"id": f"k8s/{kind}/{namespace}/{name}", "resource_kind": kind,
            "namespace": namespace, "resource": {
                "metadata": {"name": name}, "spec": {"replicas": replicas},
                "status": {"readyReplicas": ready}}}


class OllamaProbeTests(unittest.TestCase):
    def transport(self, payload):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = (
            payload if isinstance(payload, bytes) else json.dumps(payload).encode())
        return response

    def test_offline_never_opens_network_and_returns_fresh_inventory(self):
        with patch.object(ollama, "urlopen") as opening, patch("socket.socket") as socket:
            result = ollama.probe_local_ollama_models()
            self.assertEqual(result, ollama.probe_local_ollama_models("invalid", timeout=None))
            opening.assert_not_called()
            socket.assert_not_called()
        self.assertTrue(result["example"])
        self.assertFalse(result["available"])
        self.assertEqual(len(result["models"]), 3)
        result["models"].clear()
        self.assertEqual(len(ollama.probe_local_ollama_models()["models"]), 3)

    def test_live_get_endpoint_timeout_and_empty_inventory(self):
        for models in ([], [{"name": "tiny:latest", "size": 123}]):
            response = self.transport({"models": models})
            with patch.object(ollama, "urlopen", return_value=response) as opening:
                result = ollama.probe_local_ollama_models(
                    "http://localhost:11434/", timeout=2, live_http=True)
            request = opening.call_args.args[0]
            self.assertEqual(request.full_url, "http://localhost:11434/api/tags")
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(opening.call_args.kwargs, {"timeout": 2})
            response.__enter__.return_value.read.assert_called_once_with(1_048_577)
            response.__exit__.assert_called_once()
            self.assertTrue(result["available"])
            self.assertFalse(result["example"])
            self.assertEqual(result["models"], models)

    def test_allowlisted_fields_are_sanitized(self):
        wan = ".".join(["8"] * 4)
        mac = ":".join(["AB"] * 6)
        token = "gh" + "p_" + "synthetic"
        payload = {"models": [{"name": f"model-{wan} {mac} {token}",
                               "size": 10, "digest": token, "details": {"password": "hidden"}}]}
        with patch.object(ollama, "urlopen", return_value=self.transport(payload)):
            result = ollama.probe_local_ollama_models(live_http=True)
        output = json.dumps(result)
        for sensitive in (wan, mac, token, "hidden", "digest"):
            self.assertNotIn(sensitive, output)
        self.assertIn("203.0.113.1", output)
        self.assertIn("AB:AB:AB:XX:XX:XX", output)

    def test_transport_and_provider_failures_return_marked_fixtures(self):
        for error in (URLError("private diagnostic"), TimeoutError("private diagnostic"),
                      ConnectionError("private diagnostic")):
            with patch.object(ollama, "urlopen", side_effect=error):
                result = ollama.probe_local_ollama_models(live_http=True)
            self.assertEqual(result["status"], "fallback")
            self.assertEqual(result["source"], "offline_fixture")
            self.assertTrue(result["live_http"])
            self.assertFalse(result["available"])
            self.assertNotIn("private diagnostic", json.dumps(result))
        for payload in (b"not json", b"\xff", b"x" * 1_048_577, {}, {"models": None},
                        {"models": [None]}, {"models": [{"name": ""}]},
                        {"models": [{"name": "bad", "size": True}]},
                        {"models": [{"name": "bad", "size": -1}]}):
            with self.subTest(payload_type=type(payload).__name__), patch.object(
                    ollama, "urlopen", return_value=self.transport(payload)):
                self.assertEqual(ollama.probe_local_ollama_models(live_http=True)["status"],
                                 "fallback")

    def test_invalid_live_configuration_does_not_connect(self):
        for url, timeout in (("file:///private", 3), ("http://user:pass@localhost", 3),
                             ("http://localhost?token=private", 3),
                             ("http://localhost", 0), ("http://localhost", float("nan")),
                             ("http://localhost", True)):
            with patch.object(ollama, "urlopen") as opening:
                result = ollama.probe_local_ollama_models(url, timeout, live_http=True)
                opening.assert_not_called()
            self.assertEqual(result["reason"], "invalid_configuration")

    def test_catalog_scope_readiness_and_independent_gpu_capacity(self):
        catalog = {"nodes": [workload("Deployment", "worker", "ai-infra"),
                             workload("Deployment", "scaled-down", "ai-sandbox", 0, 0),
                             workload("Deployment", "unready", "ai-sandbox", 2, 1),
                             workload("Service", "route", "ai-infra"),
                             workload("Deployment", "unrelated", "default")]}
        probe = {"source": "ollama_api_tags", "models": [
            {"name": "medium", "size": 12 * 1024 ** 3},
            {"name": "too-big", "size": 20 * 1024 ** 3},
            {"model": "unknown"}]}
        before = deepcopy((catalog, probe))
        with patch.object(ollama, "urlopen") as opening:
            result = ollama.correlate_gpu_models_with_cluster(catalog, probe)
            opening.assert_not_called()
        self.assertEqual((catalog, probe), before)
        self.assertEqual(len(result["workloads"]), 3)
        self.assertEqual([w["snapshot_ready"] for w in result["workloads"]], [True, False, False])
        self.assertEqual([g["vram_gb"] for g in result["gpu_profile"]["gpus"]], [16, 10, 8])
        mappings = result["model_mappings"]
        for mapping, expected in zip(mappings, ([True, False, False], [False] * 3, [None] * 3)):
            estimates = mapping["gpu_estimates"]
            self.assertEqual([g["file_size_within_nominal_vram"] for g in estimates], expected)
            self.assertEqual([g["ai_assigned"] for g in estimates], [True, False, False])
            self.assertFalse(mapping["placement_verified"])
            self.assertEqual(len(mapping["candidate_workload_ids"]), 3)
        self.assertIsNone(result["inference_ready"])
        json.dumps(result, allow_nan=False)

    def test_default_snapshot_includes_both_ai_namespaces(self):
        with patch.object(ollama, "urlopen") as opening:
            result = ollama.correlate_gpu_models_with_cluster()
            opening.assert_not_called()
        self.assertEqual({w["namespace"] for w in result["workloads"]},
                         {"ai-infra", "ai-sandbox"})
        self.assertEqual(result["inventory_source"], "offline_fixture")

    def test_catalog_errors_are_fixed_and_correlation_is_sanitized(self):
        for catalog in ({}, {"nodes": [None]}, "missing-private-catalog.json"):
            with self.assertRaisesRegex(ValueError, "^Unable to load cluster catalog$"):
                ollama.correlate_gpu_models_with_cluster(catalog)
        token = "s" + "k-" + "synthetic"
        result = ollama.correlate_gpu_models_with_cluster(
            {"nodes": [workload("Deployment", token, "ai-infra")]},
            {"models": [{"name": token}]})
        self.assertNotIn(token, json.dumps(result))

    def test_cli_json_text_live_flag_and_clean_catalog_failure(self):
        for arguments in (["--json"], []):
            output = io.StringIO()
            with redirect_stdout(output), patch.object(ollama, "urlopen") as opening:
                self.assertEqual(ollama.main(arguments), 0)
                opening.assert_not_called()
            if arguments:
                self.assertEqual(json.loads(output.getvalue())["ollama_probe"]["status"], "offline")
            else:
                self.assertIn("3 devices", output.getvalue())
        output = io.StringIO()
        with redirect_stdout(output), patch.object(
                ollama, "urlopen", return_value=self.transport({"models": []})) as opening:
            self.assertEqual(ollama.main(["--live-http", "--ollama-url", "http://localhost:9999",
                                          "--json"]), 0)
        self.assertEqual(opening.call_args.args[0].full_url, "http://localhost:9999/api/tags")
        self.assertTrue(json.loads(output.getvalue())["ollama_probe"]["available"])
        output = io.StringIO()
        with redirect_stdout(output), patch.object(ollama, "DEFAULT_CATALOG_PATH", "private-missing"):
            self.assertEqual(ollama.main(["--json"]), 1)
        self.assertNotIn("private-missing", output.getvalue())


if __name__ == "__main__":
    unittest.main()
