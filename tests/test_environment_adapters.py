# SPDX-License-Identifier: Apache-2.0
"""Offline adapter contracts, backend integration, CLI, and HTTP behavior."""

from contextlib import redirect_stderr, redirect_stdout
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import io
import json
from pathlib import Path
import subprocess
import sys
from threading import Thread
import unittest
from unittest.mock import patch

import environment_adapters as adapters
from opscryer_backend import KnowledgeGraphBackendEngine, validate_spatial_graph_contract


ROOT = Path(__file__).resolve().parents[1]
PROFILES = {"kubernetes", "docker_compose", "terraform", "local_host"}


class AdapterGraphTests(unittest.TestCase):
    def assert_backend_compatible(self, graph, query, target_label):
        self.assertEqual(validate_spatial_graph_contract(graph), [])
        engine = KnowledgeGraphBackendEngine(graph)
        target = next(node for node in graph["nodes"] if node["label"] == target_label)
        result = engine.search(query)
        self.assertIn(target["id"], [node["id"] for node in result["results"]])
        self.assertEqual(result["result_count"], len(result["results"]))
        path = engine.shortest_path(graph["root_id"], target["id"])
        self.assertTrue(path["path_found"])
        self.assertEqual(path["path_ids"][0], graph["root_id"])
        self.assertEqual(path["path_ids"][-1], target["id"])
        self.assertGreater(path["hop_count"], 0)
        self.assertEqual(path["hop_count"], len(path["path_ids"]) - 1)
        self.assertEqual([node["id"] for node in path["path_nodes"]], path["path_ids"])
        links = {frozenset((edge["source"], edge["target"])) for edge in graph["edges"]}
        for left, right in zip(path["path_ids"], path["path_ids"][1:]):
            self.assertIn(frozenset((left, right)), links)

    def test_default_converters_validate_and_support_backend_queries(self):
        cases = (
            (adapters.convert_docker_compose_to_graph, "postgres", "postgres"),
            (adapters.convert_terraform_resources_to_graph, "ollama", "proxmox_virtual_environment_vm.ollama"),
            (adapters.convert_local_host_to_graph, "llama3.1", "llama3.1:8b"),
        )
        for converter, query, target in cases:
            with self.subTest(converter=converter.__name__):
                self.assert_backend_compatible(converter(), query, target)

    def test_explicit_specs_validate_and_support_backend_queries(self):
        cases = (
            (adapters.convert_docker_compose_to_graph,
             {"name": "test-stack", "services": {
                 "web": {"depends_on": ["database"], "ports": ["8080:80"]},
                 "database": {"volumes": ["data:/data"]}}, "volumes": {"data": {}}},
             "database", "database"),
            (adapters.convert_terraform_resources_to_graph,
             {"workspace": "test", "resources": [
                 {"type": "test_network", "name": "private"},
                 {"type": "test_server", "name": "application", "depends_on": ["test_network.private"]}]},
             "application", "test_server.application"),
            (adapters.convert_local_host_to_graph,
             {"hostname": "test.cluster.example.org", "cpu_cores": 4, "ram_gib": 16,
              "services": ["opscryer", "ollama"], "local_models": ["testmodel"]},
             "testmodel", "testmodel"),
        )
        for converter, spec, query, target in cases:
            with self.subTest(converter=converter.__name__):
                self.assert_backend_compatible(converter(spec), query, target)


class AdapterCatalogTests(unittest.TestCase):
    def test_summary_has_all_four_profiles_without_graph_payloads(self):
        catalog = adapters.build_adapter_compatibility_catalog(None)
        self.assertEqual(set(catalog["adapters"]), PROFILES)
        self.assertEqual(catalog, adapters.build_adapter_compatibility_catalog())
        for name, entry in catalog["adapters"].items():
            with self.subTest(adapter=name):
                self.assertEqual(entry["adapter"], name)
                self.assertEqual(entry["compatibility_matrix"],
                                 adapters.ADAPTER_PROFILES[name]["compatibility_matrix"])
                self.assertNotIn("graph_catalog", entry)
                self.assertGreater(entry["node_count"], 0)
                self.assertGreater(entry["edge_count"], 0)

    def test_each_profile_has_a_valid_graph_and_matching_inventory(self):
        summary = adapters.build_adapter_compatibility_catalog()["adapters"]
        for name in sorted(PROFILES):
            with self.subTest(adapter=name):
                entry = adapters.build_adapter_compatibility_catalog(name)
                graph = entry["graph_catalog"]
                self.assertEqual(validate_spatial_graph_contract(graph), [])
                self.assertEqual(entry["node_count"], len(graph["nodes"]))
                self.assertEqual(entry["edge_count"], len(graph["edges"]))
                self.assertEqual({key: value for key, value in entry.items()
                                  if key != "graph_catalog"}, summary[name])

    def test_unknown_and_invalid_adapter_values_raise_value_error(self):
        for name in ("unknown-adapter", "", "DOCKER_COMPOSE", 42, [], {}):
            with self.subTest(adapter=name):
                with self.assertRaisesRegex(ValueError, "^Unsupported environment adapter$"):
                    adapters.build_adapter_compatibility_catalog(name)


class AdapterCliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "environment_adapters.py"), *args],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=15)

    def test_json_and_default_output(self):
        for args in ((), ("--json",)):
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), adapters.build_adapter_compatibility_catalog())
                self.assertEqual(result.stderr, "")

    def test_adapter_selects_each_profile_in_json(self):
        for name in sorted(PROFILES):
            with self.subTest(adapter=name):
                result = self.run_cli("--json", "--adapter", name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), adapters.build_adapter_compatibility_catalog(name))
                self.assertEqual(result.stderr, "")

    def test_markdown_and_selected_preview(self):
        for name in (None, *sorted(PROFILES)):
            with self.subTest(adapter=name):
                args = ["--markdown"] + (["--adapter", name] if name else [])
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, adapters.render_adapters_markdown(name))
                self.assertIn("| Environment | Adapter |", result.stdout)
                self.assertEqual(result.stdout.count("node/edge breakdown"), 1 if name else 4)
                self.assertEqual(result.stderr, "")

    def test_serve_binds_loopback_and_closes_after_interrupt(self):
        output = io.StringIO()
        with patch.object(adapters, "ThreadingHTTPServer") as server, redirect_stdout(output):
            instance = server.return_value.__enter__.return_value
            instance.serve_forever.side_effect = KeyboardInterrupt
            self.assertEqual(adapters.main(["--serve", "--port", "8123"]), 0)
            self.assertEqual(server.call_args.args[0], ("127.0.0.1", 8123))
            self.assertTrue(callable(server.call_args.args[1]))
            instance.serve_forever.assert_called_once_with()
            server.return_value.__exit__.assert_called_once()
        self.assertIn("http://127.0.0.1:8123/adapters", output.getvalue())

    def test_invalid_arguments_exit_two_without_echoing_input(self):
        marker = "private-input-marker"
        cases = (
            ["--adapter", marker], ["--" + marker], [marker],
            ["--port", marker], ["--port", "0"], ["--port", "65536"],
            ["--adapter"], ["--json", "--markdown"], ["--json", "--serve"],
            ["--markdown", "--serve"], ["--j"],
        )
        for args in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("Invalid environment adapter request", result.stderr)
                self.assertNotIn(marker, result.stdout + result.stderr)


class AdapterHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), adapters._build_adapters_handler())
        cls.addClassCleanup(cls.server.server_close)
        cls.thread = Thread(target=cls.server.serve_forever,
                            kwargs={"poll_interval": 0.01}, daemon=True)
        cls.thread.start()
        cls.addClassCleanup(cls.thread.join, 5)
        cls.addClassCleanup(cls.server.shutdown)

    def request(self, path):
        connection = HTTPConnection(*self.server.server_address, timeout=5)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode("utf-8")
        finally:
            connection.close()

    def test_adapters_route_serves_html(self):
        status, headers, body = self.request("/adapters")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn("Adapter Studio", body)
        for name in PROFILES:
            self.assertIn('data-adapter="' + name + '"', body)

    def test_api_summary_and_each_adapter(self):
        for name in (None, *sorted(PROFILES)):
            with self.subTest(adapter=name):
                path = "/api/v1/environment-adapters" + ("?adapter=" + name if name else "")
                status, headers, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
                self.assertEqual(json.loads(body), adapters.build_adapter_compatibility_catalog(name))

    def test_invalid_queries_return_400_without_echoing_or_logging_input(self):
        queries = (
            "adapter=private-input-marker", "adapter=", "private-input-marker=value",
            "adapter=terraform&adapter=local_host", "adapter=terraform&extra=value",
            "adapter", "adapter=%", "adapter=%GG", "adapter=%FF",
        )
        for query in queries:
            with self.subTest(query=query):
                logs = io.StringIO()
                with redirect_stderr(logs):
                    status, headers, body = self.request("/api/v1/environment-adapters?" + query)
                self.assertEqual(status, 400)
                self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
                self.assertEqual(json.loads(body), {"error": "Invalid environment adapter request"})
                self.assertEqual(logs.getvalue(), "")
        status, _, body = self.request("/adapters?private-input-marker=value")
        self.assertEqual(status, 400)
        self.assertNotIn("private-input-marker", body)


# -----------------------------------------------------------------------------
# Milestone 4 Feature 11: Dynamic Extensible Adapter Registry Tests
# -----------------------------------------------------------------------------

from concurrent.futures import ThreadPoolExecutor
from typing import Any
from environment_adapters import (
    BaseEnvironmentAdapter,
    register_adapter_profile,
    get_adapter_profile,
    list_adapter_profiles,
    unregister_adapter_profile,
    reset_adapter_registry,
    MockDevEnvironmentAdapter,
    PrometheusLokiEnvironmentAdapter,
    KubernetesProductionAdapter,
)


class TestEnvironmentAdapterRegistry(unittest.TestCase):
    """Test suite for BaseEnvironmentAdapter, thread-safe dynamic registry, and built-ins."""

    def setUp(self) -> None:
        reset_adapter_registry()

    def tearDown(self) -> None:
        reset_adapter_registry()

    # Test 1: Subclassing & Abstract Method Enforcement
    def test_subclassing_and_abstract_method_enforcement(self) -> None:
        """Attempting to instantiate an incomplete subclass raises TypeError."""
        class IncompleteAdapter(BaseEnvironmentAdapter):
            profile_name = "incomplete"
            label = "Incomplete"
            compatibility_matrix = {}
            # convert_to_graph is not implemented

        with self.assertRaises(TypeError):
            IncompleteAdapter()  # type: ignore

    # Test 2: register_adapter_profile & Duplicate Rejection (overwrite=False)
    def test_register_adapter_profile_and_duplicate_rejection(self) -> None:
        """Valid adapter registers; duplicate registration raises ValueError when overwrite=False."""
        class ValidAdapter(BaseEnvironmentAdapter):
            profile_name = "test_custom"
            label = "Custom Adapter"
            compatibility_matrix = {"containers": True}
            def convert_to_graph(self, spec: dict | None = None) -> dict[str, Any]:
                return {"schema_version": "1.0-spatial-graph", "nodes": [], "edges": []}

        register_adapter_profile("test_custom", ValidAdapter, overwrite=False)
        self.assertIn("test_custom", list_adapter_profiles())

        with self.assertRaisesRegex(ValueError, "already registered"):
            register_adapter_profile("test_custom", ValidAdapter, overwrite=False)

    # Test 3: register_adapter_profile with overwrite=True
    def test_register_adapter_profile_with_overwrite_true(self) -> None:
        """Registration with overwrite=True successfully replaces an existing profile."""
        class AdapterV1(BaseEnvironmentAdapter):
            profile_name = "versioned"
            label = "Version 1"
            compatibility_matrix = {}
            def convert_to_graph(self, spec=None): return {}

        class AdapterV2(BaseEnvironmentAdapter):
            profile_name = "versioned"
            label = "Version 2"
            compatibility_matrix = {}
            def convert_to_graph(self, spec=None): return {}

        register_adapter_profile("versioned", AdapterV1)
        self.assertEqual(list_adapter_profiles()["versioned"]["label"], "Version 1")

        register_adapter_profile("versioned", AdapterV2, overwrite=True)
        self.assertEqual(list_adapter_profiles()["versioned"]["label"], "Version 2")

    # Test 4: Rejection of Non-Subclasses
    def test_register_adapter_profile_rejects_non_subclasses(self) -> None:
        """Registering classes not derived from BaseEnvironmentAdapter raises TypeError."""
        class NotAnAdapter:
            profile_name = "not_an_adapter"

        with self.assertRaises(TypeError):
            register_adapter_profile("not_an_adapter", NotAnAdapter)  # type: ignore

    # Test 5: get_adapter_profile Returns Instance
    def test_get_adapter_profile_returns_correct_instance(self) -> None:
        """get_adapter_profile returns an instance of the registered class."""
        class MyServiceAdapter(BaseEnvironmentAdapter):
            profile_name = "my_service"
            label = "My Service"
            compatibility_matrix = {"containers": True}
            def convert_to_graph(self, spec=None):
                return {"schema_version": "1.0-spatial-graph", "nodes": [], "edges": []}

        register_adapter_profile("my_service", MyServiceAdapter)
        instance = get_adapter_profile("my_service")
        self.assertIsInstance(instance, MyServiceAdapter)
        self.assertEqual(instance.profile_name, "my_service")

    # Test 6: get_adapter_profile Unknown Profile Raises KeyError
    def test_get_adapter_profile_raises_keyerror_on_unknown(self) -> None:
        """Querying an unknown profile name raises KeyError with list of available profiles."""
        with self.assertRaises(KeyError) as cm:
            get_adapter_profile("nonexistent_profile_xyz")
        self.assertIn("nonexistent_profile_xyz", str(cm.exception))

    # Test 7: list_adapter_profiles Complete Metadata
    def test_list_adapter_profiles_returns_complete_metadata(self) -> None:
        """list_adapter_profiles returns label, compatibility_matrix, and class_name."""
        profiles = list_adapter_profiles()
        self.assertIn("mock_dev", profiles)
        self.assertIn("prometheus_loki", profiles)
        self.assertIn("kubernetes_production", profiles)

        mock_meta = profiles["mock_dev"]
        self.assertIn("label", mock_meta)
        self.assertIn("compatibility_matrix", mock_meta)
        self.assertIn("class_name", mock_meta)

    # Test 8: unregister_adapter_profile
    def test_unregister_adapter_profile_removes_profile(self) -> None:
        """unregister_adapter_profile removes profile and returns True, subsequent get raises KeyError."""
        class TempAdapter(BaseEnvironmentAdapter):
            profile_name = "temp"
            label = "Temporary"
            compatibility_matrix = {}
            def convert_to_graph(self, spec=None): return {}

        register_adapter_profile("temp", TempAdapter)
        self.assertTrue(unregister_adapter_profile("temp"))
        self.assertNotIn("temp", list_adapter_profiles())
        self.assertFalse(unregister_adapter_profile("temp"))  # Second removal returns False

    # Test 9: reset_adapter_registry Restores Defaults
    def test_reset_adapter_registry_restores_default_profiles(self) -> None:
        """reset_adapter_registry purges custom profiles and restores built-in profiles."""
        class ExtraAdapter(BaseEnvironmentAdapter):
            profile_name = "extra"
            label = "Extra"
            compatibility_matrix = {}
            def convert_to_graph(self, spec=None): return {}

        register_adapter_profile("extra", ExtraAdapter)
        self.assertIn("extra", list_adapter_profiles())

        reset_adapter_registry()
        self.assertNotIn("extra", list_adapter_profiles())
        self.assertIn("mock_dev", list_adapter_profiles())
        self.assertIn("prometheus_loki", list_adapter_profiles())
        self.assertIn("kubernetes_production", list_adapter_profiles())

    # Test 10: Built-in MockDevEnvironmentAdapter Schema
    def test_builtin_mock_dev_environment_adapter_produces_valid_graph(self) -> None:
        """MockDevEnvironmentAdapter produces valid graph with nodes, edges, and metadata."""
        adapter = get_adapter_profile("mock_dev")
        graph = adapter.convert_to_graph()
        self.assertIn(graph["schema_version"], ("1.0-spatial-graph", "1.0-separable-spatial-graph-contract"))
        self.assertIsInstance(graph["nodes"], list)
        self.assertIsInstance(graph["edges"], list)
        self.assertGreaterEqual(len(graph["nodes"]), 4)  # Root + 3 nodes
        node_labels = [n["label"] for n in graph["nodes"]]
        self.assertTrue(any("control-plane" in label.lower() for label in node_labels))

    # Test 11: Built-in PrometheusLokiEnvironmentAdapter Schema
    def test_builtin_prometheus_loki_environment_adapter_produces_valid_graph(self) -> None:
        """PrometheusLokiEnvironmentAdapter produces valid graph wrapping signals."""
        adapter = get_adapter_profile("prometheus_loki")
        graph = adapter.convert_to_graph()
        self.assertIn(graph["schema_version"], ("1.0-spatial-graph", "1.0-separable-spatial-graph-contract"))
        self.assertIsInstance(graph["nodes"], list)
        self.assertIsInstance(graph["edges"], list)
        self.assertGreaterEqual(len(graph["nodes"]), 2)

    # Test 12: Built-in KubernetesProductionAdapter Schema
    def test_builtin_kubernetes_production_adapter_produces_valid_graph(self) -> None:
        """KubernetesProductionAdapter produces valid production topology graph."""
        adapter = get_adapter_profile("kubernetes_production")
        graph = adapter.convert_to_graph()
        self.assertIn(graph["schema_version"], ("1.0-spatial-graph", "1.0-separable-spatial-graph-contract"))
        self.assertIsInstance(graph["nodes"], list)
        self.assertIsInstance(graph["edges"], list)
        self.assertGreaterEqual(len(graph["nodes"]), 3)

    # Test 13: Thread Safety Concurrent Registration & Retrieval
    def test_thread_safety_concurrent_registration_and_retrieval(self) -> None:
        """Concurrent multi-threaded registrations and lookups execute without race conditions."""
        def register_worker(worker_id: int) -> bool:
            class WorkerAdapter(BaseEnvironmentAdapter):
                profile_name = f"worker_{worker_id}"
                label = f"Worker {worker_id}"
                compatibility_matrix = {"worker_id": True}
                def convert_to_graph(self, spec=None): return {}

            register_adapter_profile(f"worker_{worker_id}", WorkerAdapter, overwrite=True)
            instance = get_adapter_profile(f"worker_{worker_id}")
            return instance.profile_name == f"worker_{worker_id}"

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(register_worker, i) for i in range(20)]
            results = [f.result() for f in futures]

        self.assertTrue(all(results))
        profiles = list_adapter_profiles()
        for i in range(20):
            self.assertIn(f"worker_{i}", profiles)


class TestBuiltinAdaptersContractAndFuzzing(unittest.TestCase):
    """Rigorous contract validation and spec fuzzing tests for built-in environment adapters."""

    def setUp(self) -> None:
        reset_adapter_registry()

    def tearDown(self) -> None:
        reset_adapter_registry()

    def test_all_builtin_adapters_pass_spatial_graph_contract_with_zero_errors(self) -> None:
        """Every built-in adapter profile must produce a graph that passes validate_spatial_graph_contract with 0 errors."""
        for profile in ("mock_dev", "prometheus_loki", "kubernetes_production"):
            with self.subTest(profile=profile):
                adapter = get_adapter_profile(profile)
                graph = adapter.convert_to_graph()
                errors = validate_spatial_graph_contract(graph)
                self.assertEqual(errors, [], f"Adapter '{profile}' had contract errors: {errors}")

    def test_all_builtin_adapters_load_cleanly_into_knowledge_graph_backend_engine(self) -> None:
        """Graphs from all built-in adapters must be accepted by KnowledgeGraphBackendEngine without exception."""
        for profile in ("mock_dev", "prometheus_loki", "kubernetes_production"):
            with self.subTest(profile=profile):
                adapter = get_adapter_profile(profile)
                graph = adapter.convert_to_graph()
                engine = KnowledgeGraphBackendEngine(graph)
                self.assertIsNotNone(engine)
                self.assertEqual(engine._catalog["node_count"], len(graph["nodes"]))
                # Verify search capability on the ingested graph
                first_word = graph["nodes"][0]["label"].split()[0]
                search_res = engine.search(first_word)
                self.assertGreaterEqual(search_res["result_count"], 1)

    def test_prometheus_loki_node_fields_and_domains(self) -> None:
        """Root and all child nodes in prometheus_loki graph must strictly conform to SpatialGraphContract v1."""
        adapter = get_adapter_profile("prometheus_loki")
        graph = adapter.convert_to_graph()
        root = next(n for n in graph["nodes"] if n["id"] == "obs-root")
        self.assertIn(root["domain"], ("hardware_topology", "deployments_k8s"))
        self.assertEqual(root["kind"], "company_root")
        self.assertTrue(root["primary_url"].startswith("https://"))
        self.assertGreater(len(root["drilldown_children"]), 0)

        for child in graph["nodes"][1:]:
            self.assertIn(child["domain"], ("hardware_topology", "deployments_k8s"))
            self.assertIsInstance(child["summary"], str)
            self.assertTrue(child["primary_url"].startswith("https://"))
            self.assertEqual(child["drilldown_children"], [])

    def test_kubernetes_production_node_fields_and_domains(self) -> None:
        """Root and all child nodes in kubernetes_production graph must strictly conform to SpatialGraphContract v1."""
        adapter = get_adapter_profile("kubernetes_production")
        graph = adapter.convert_to_graph()
        root = next(n for n in graph["nodes"] if n["id"] == "k8s-prod-cluster")
        self.assertEqual(root["domain"], "hardware_topology")
        self.assertTrue(root["primary_url"].startswith("https://"))
        self.assertGreater(len(root["drilldown_children"]), 0)

        for child in graph["nodes"][1:]:
            self.assertEqual(child["domain"], "deployments_k8s")
            self.assertIsInstance(child["summary"], str)
            self.assertTrue(child["primary_url"].startswith("https://"))
            self.assertEqual(child["drilldown_children"], [])

    def test_prometheus_loki_fuzzing_resilience(self) -> None:
        """PrometheusLokiEnvironmentAdapter gracefully degrades on malformed/empty/string specs without unhandled exceptions."""
        adapter = get_adapter_profile("prometheus_loki")
        fuzz_specs = [
            None,
            {},
            {"prometheus_signals": "broken_signals_string"},
            {"signals": None},
            {"metrics": [123, "not_a_dict", None]},
            {"loki_log_summaries": "corrupted"},
            {"unknown_key": "data"},
            "raw_string",
            12345,
            [1, 2, 3],
        ]
        for spec in fuzz_specs:
            with self.subTest(spec=spec):
                graph = adapter.convert_to_graph(spec)  # type: ignore[arg-type]
                self.assertIsInstance(graph, dict)
                self.assertIn("root_id", graph)
                self.assertEqual(validate_spatial_graph_contract(graph), [])
                engine = KnowledgeGraphBackendEngine(graph)
                self.assertIsNotNone(engine)

    def test_kubernetes_production_fuzzing_resilience(self) -> None:
        """KubernetesProductionAdapter gracefully degrades on empty dict and malformed specs without unhandled exceptions."""
        adapter = get_adapter_profile("kubernetes_production")
        fuzz_specs = [
            None,
            {},  # Previously crashed with ValueError: catalog must contain a nodes array
            {"ready_nodes": ["custom-worker-01"], "ingress_hosts": {"api.cluster.example.org": []}},
            {"ready_nodes": None, "not_ready_nodes": "not_a_list", "ingress_hosts": 42},
            {"nodes": "not_a_list", "edges": 999},
            {"invalid_key": "junk"},
            "raw_string",
            12345,
            [1, 2, 3],
        ]
        for spec in fuzz_specs:
            with self.subTest(spec=spec):
                graph = adapter.convert_to_graph(spec)  # type: ignore[arg-type]
                self.assertIsInstance(graph, dict)
                self.assertIn("root_id", graph)
                self.assertEqual(validate_spatial_graph_contract(graph), [])
                engine = KnowledgeGraphBackendEngine(graph)
                self.assertIsNotNone(engine)


if __name__ == "__main__":
    unittest.main()
