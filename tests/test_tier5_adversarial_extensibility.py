# SPDX-License-Identifier: Apache-2.0
"""Milestone 5 Phase 2: Tier 5 Adversarial Coverage Hardening (Extensibility & Config Whitebox).

White-box code and boundary coverage test suite targeting:
1. environment_adapters.py: registration locks, abstract enforcement, overwrite rules,
   spec fuzzing, child node schemas, thread-safe dynamic registry.
2. opscryer_config.py: 4-tier precedence, cached CLI overrides, dot-path resolution,
   YAML/JSON parsing, type coercion, secret redaction, and logging configuration.
3. system_context.py: ground-truth immutability, AST parsing resilience, scale-down
   workload guards, hallucination denylist, and dual-tier payload generation.
4. telemetry_sanitizer.py: PEM armor block stripping, credential assignment redaction,
   WAN IPv4 replacement, container type preservation, and key collision defense.
5. route_registry.py: subsystem partitioning, parameter sets, and summary isolation.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from typing import Any
import unittest
from unittest.mock import patch

# Ensure opscryer suite modules are importable
SUITE_ROOT = Path(__file__).resolve().parent.parent
if str(SUITE_ROOT) not in sys.path:
    sys.path.insert(0, str(SUITE_ROOT))

__epics__ = {
    "47": ["47D"],
    "51": ["51A", "51B", "51C", "51D"],
}

import environment_adapters as adapters
from environment_adapters import (
    ADAPTER_PROFILES,
    BaseEnvironmentAdapter,
    KubernetesProductionAdapter,
    MockDevEnvironmentAdapter,
    PrometheusLokiEnvironmentAdapter,
    build_adapter_compatibility_catalog,
    convert_docker_compose_to_graph,
    convert_local_host_to_graph,
    convert_terraform_resources_to_graph,
    get_adapter_profile,
    list_adapter_profiles,
    register_adapter_profile,
    render_adapters_html,
    render_adapters_markdown,
    reset_adapter_registry,
    unregister_adapter_profile,
)
from opscryer_backend import KnowledgeGraphBackendEngine, validate_spatial_graph_contract
import opscryer_config as config
from opscryer_config import (
    DEFAULT_CONFIG,
    _coerce_env_value,
    _is_sensitive_key,
    _load_env_config,
    _lookup_in_dict,
    _parse_scalar,
    _strip_inline_comment,
    configure_logging,
    dump_sanitized_config,
    get_config_value,
    load_unified_config,
    parse_simple_yaml,
    parse_simple_yaml_file,
    reset_config,
)
import route_registry
from route_registry import (
    API_V1_ROUTES,
    HTML_PORTAL_ROUTES,
    build_route_registry_summary,
    get_allowed_api_params,
)
import system_context
from system_context import (
    CANONICAL_KB_RUNBOOKS,
    HOMELAB_NODE_HARDWARE,
    INTENTIONAL_SCALE_DOWN_WORKLOADS,
    SYSTEM_CONTEXT_SCHEMA_VERSION,
    VERIFIED_HOMELAB_GPU_INVENTORY,
    _extract_ast_symbols_from_file,
    build_ast_jump_references,
    build_system_context,
    get_canonical_kb_runbooks,
    get_homelab_hardware_inventory,
    get_intentional_scale_down_workloads,
    get_verified_gpu_inventory,
    validate_model_output_against_context,
)
import telemetry_sanitizer as sanitizer
from telemetry_sanitizer import (
    _sanitize_text,
    build_two_act_hackathon_demo_plan,
    sanitize_live_home_telemetry_for_demo as sanitize,
)


class TestTier5EnvironmentAdaptersAdversarial(unittest.TestCase):
    """Adversarial white-box tests for environment_adapters.py."""

    def setUp(self) -> None:
        reset_adapter_registry()

    def tearDown(self) -> None:
        reset_adapter_registry()

    def test_registration_validation_boundary_conditions(self) -> None:
        """Adversarial validation of register_adapter_profile rejection paths."""
        # Non-string or empty profile_name
        for bad_name in ("", "   ", None, 123, [], {}):
            with self.subTest(bad_name=bad_name):
                class ValidAdapter(BaseEnvironmentAdapter):
                    label = "Valid"
                    def convert_to_graph(self, spec=None): return {}

                with self.assertRaises(ValueError):
                    register_adapter_profile(bad_name, ValidAdapter)  # type: ignore[arg-type]

        # Non-class adapter_cls
        with self.assertRaises(TypeError):
            register_adapter_profile("bad_cls", "not_a_class")  # type: ignore[arg-type]

        # Non-subclass of BaseEnvironmentAdapter
        class StandaloneClass:
            label = "Standalone"

        with self.assertRaises(TypeError):
            register_adapter_profile("not_subclass", StandaloneClass)  # type: ignore[arg-type]

        # BaseEnvironmentAdapter class directly
        with self.assertRaises(TypeError):
            register_adapter_profile("base_direct", BaseEnvironmentAdapter)

        # Incomplete abstract class
        class IncompleteAdapter(BaseEnvironmentAdapter):
            label = "Incomplete"
            # Missing convert_to_graph

        with self.assertRaises(TypeError):
            register_adapter_profile("incomplete", IncompleteAdapter)

        # Missing label attribute
        class NoLabelAdapter(BaseEnvironmentAdapter):
            label = ""
            def convert_to_graph(self, spec=None): return {}

        with self.assertRaises(ValueError):
            register_adapter_profile("no_label", NoLabelAdapter)

    def test_registration_duplicate_and_overwrite_matrix(self) -> None:
        """Verify strict overwrite=False rejection and seamless overwrite=True update."""
        class AdapterV1(BaseEnvironmentAdapter):
            label = "Version 1"
            def convert_to_graph(self, spec=None): return {"version": 1}

        class AdapterV2(BaseEnvironmentAdapter):
            label = "Version 2"
            def convert_to_graph(self, spec=None): return {"version": 2}

        register_adapter_profile("dyn_test", AdapterV1, overwrite=False)
        self.assertEqual(get_adapter_profile("dyn_test").label, "Version 1")

        # Duplicate without overwrite raises ValueError
        with self.assertRaisesRegex(ValueError, "already registered"):
            register_adapter_profile("dyn_test", AdapterV2, overwrite=False)

        # Overwrite replaces existing profile and clears instance cache
        register_adapter_profile("dyn_test", AdapterV2, overwrite=True)
        self.assertEqual(get_adapter_profile("dyn_test").label, "Version 2")
        self.assertEqual(get_adapter_profile("dyn_test").convert_to_graph()["version"], 2)

    def test_unregistration_and_get_profile_error_handling(self) -> None:
        """Verify unregistration return codes, non-existent lookups, and KeyError messaging."""
        # Unregister non-existent returns False
        self.assertFalse(unregister_adapter_profile("non_existent_profile_xyz"))
        self.assertFalse(unregister_adapter_profile(""))
        self.assertFalse(unregister_adapter_profile("   "))
        self.assertFalse(unregister_adapter_profile(None))  # type: ignore[arg-type]

        # Get profile with invalid names raises KeyError
        for invalid in ("", "   ", None, 123):
            with self.subTest(invalid=invalid):
                with self.assertRaises(KeyError):
                    get_adapter_profile(invalid)  # type: ignore[arg-type]

        # Get profile with unknown name lists available profiles alphabetically
        with self.assertRaises(KeyError) as ctx:
            get_adapter_profile("unknown_profile")
        err_msg = str(ctx.exception)
        self.assertIn("unknown_profile", err_msg)
        self.assertIn("Available profiles:", err_msg)
        self.assertIn("mock_dev", err_msg)

    def test_dynamic_adapter_catalog_export_integration(self) -> None:
        """Dynamic adapters integrate into build_adapter_compatibility_catalog seamlessly."""
        class CustomCloudAdapter(BaseEnvironmentAdapter):
            label = "Custom Cloud"
            description = "Custom dynamic cloud topology"
            compatibility_matrix = {"cloud": True, "containers": True}

            def convert_to_graph(self, spec=None):
                return {
                    "schema_version": "1.0-spatial-graph",
                    "root_id": "cloud-root",
                    "nodes": [
                        {"id": "cloud-root", "label": "Cloud Root", "kind": "company_root",
                         "domain": "hardware_topology", "section": "core", "summary": "Root",
                         "primary_url": "https://example.org/cloud-root", "drilldown_children": []}
                    ],
                    "edges": [],
                    "node_count": 1,
                    "edge_count": 0,
                }

        register_adapter_profile("custom_cloud", CustomCloudAdapter)
        catalog = build_adapter_compatibility_catalog("custom_cloud")
        self.assertEqual(catalog["adapter"], "custom_cloud")
        self.assertEqual(catalog["label"], "Custom Cloud")
        self.assertEqual(catalog["node_count"], 1)
        self.assertEqual(catalog["edge_count"], 0)
        self.assertIn("graph_catalog", catalog)
        self.assertEqual(catalog["graph_catalog"]["root_id"], "cloud-root")

    def test_builtin_adapters_health_check_contract(self) -> None:
        """Every built-in adapter implements health_check returning status ok and profile."""
        for profile in ("mock_dev", "prometheus_loki", "kubernetes_production"):
            with self.subTest(profile=profile):
                adapter = get_adapter_profile(profile)
                health = adapter.health_check()
                self.assertEqual(health["status"], "ok")
                self.assertEqual(health["profile"], profile)

    def test_prometheus_loki_spec_sanitization_and_domain_fallback(self) -> None:
        """PrometheusLokiEnvironmentAdapter handles malformed signals, dirty specs, and domain fallbacks."""
        adapter = get_adapter_profile("prometheus_loki")

        # Dirty spec containing non-dict items and unsupported domain
        dirty_spec = {
            "prometheus_signals": [
                "not_a_dict_1",
                {"signal_id": "sig-1", "label": "CPU Signal", "domain": "invalid_domain_name"},
                12345,
                {"signal_id": "sig-2", "label": "Memory Signal", "domain": "deployments_k8s"},
            ],
            "loki_log_summaries": [
                None,
                {"stream": "app=postgres", "label": "Error Logs", "domain": "security_compliance"},
            ],
            "telemetry_mode": "ADVERSARIAL_TEST",
        }
        graph = adapter.convert_to_graph(dirty_spec)
        self.assertEqual(validate_spatial_graph_contract(graph), [])
        self.assertEqual(graph["root_id"], "obs-root")

        # Verify fallback of invalid domain to hardware_topology
        sig1_node = next(n for n in graph["nodes"] if "sig-1" in n["id"])
        self.assertEqual(sig1_node["domain"], "hardware_topology")

        # Duplicate ID handling
        dup_spec = {
            "signals": [
                {"id": "duplicate-id", "label": "Signal A"},
                {"id": "duplicate-id", "label": "Signal B"},
                {"id": "obs-root", "label": "Colliding with Root"},
            ]
        }
        dup_graph = adapter.convert_to_graph(dup_spec)
        self.assertEqual(validate_spatial_graph_contract(dup_graph), [])
        node_ids = [n["id"] for n in dup_graph["nodes"]]
        self.assertEqual(len(node_ids), len(set(node_ids)), "Node IDs must be unique after deduplication")

    def test_kubernetes_production_empty_nodes_and_dotted_ingress(self) -> None:
        """KubernetesProductionAdapter handles whitespace node names, duplicates, and dotted ingress hosts."""
        adapter = get_adapter_profile("kubernetes_production")

        spec = {
            "ready_nodes": ["worker-1", "   ", "", "worker-1", "worker-2"],
            "not_ready_nodes": ["worker-2", "worker-3", None, "   "],
            "ingress_hosts": {
                "api.cluster.example.org": [],
                "monitoring.internal.cluster.example.org": [],
                "   ": [],
            },
        }
        graph = adapter.convert_to_graph(spec)
        self.assertEqual(validate_spatial_graph_contract(graph), [])

        node_ids = {n["id"] for n in graph["nodes"]}
        self.assertIn("k8s-prod-cluster", node_ids)
        self.assertIn("k8s-node-worker-1", node_ids)
        self.assertIn("k8s-node-worker-2", node_ids)
        self.assertIn("k8s-node-worker-3", node_ids)
        self.assertIn("k8s-ingress-api-cluster-example-org", node_ids)
        self.assertIn("k8s-ingress-monitoring-internal-cluster-example-org", node_ids)
        self.assertNotIn("k8s-node-", node_ids)
        self.assertNotIn("k8s-ingress-", node_ids)

    def test_legacy_docker_compose_unknown_dependency_and_bind_mounts(self) -> None:
        """convert_docker_compose_to_graph rejects unknown dependencies and handles Windows bind mounts."""
        # Unknown dependency raises ValueError
        bad_compose = {
            "services": {
                "web": {"depends_on": ["nonexistent_database"]}
            }
        }
        with self.assertRaisesRegex(ValueError, "unknown service"):
            convert_docker_compose_to_graph(bad_compose)

        # Windows-style bind mounts
        win_compose = {
            "name": "win-project",
            "services": {
                "app": {
                    "image": "app:v1",
                    "volumes": [
                        r"C:\mock\mount\data:/app/data",
                        "/var/run/docker.sock:/var/run/docker.sock",
                    ],
                    "ports": [8080],
                }
            }
        }
        graph = convert_docker_compose_to_graph(win_compose)
        self.assertEqual(validate_spatial_graph_contract(graph), [])
        kinds = {n["kind"] for n in graph["nodes"]}
        self.assertIn("bind_mount", kinds)

    def test_legacy_terraform_duplicate_resource_address(self) -> None:
        """convert_terraform_resources_to_graph rejects duplicate addresses and maps external deps."""
        duplicate_tf = {
            "resources": [
                {"type": "aws_instance", "name": "web", "provider": "aws"},
                {"type": "aws_instance", "name": "web", "provider": "aws"},
            ]
        }
        with self.assertRaisesRegex(ValueError, "Duplicate Terraform resource address"):
            convert_terraform_resources_to_graph(duplicate_tf)

        external_dep_tf = {
            "resources": [
                {"type": "aws_instance", "name": "worker", "provider": "aws",
                 "depends_on": ["unmanaged_vpc_resource"]}
            ]
        }
        graph = convert_terraform_resources_to_graph(external_dep_tf)
        self.assertEqual(validate_spatial_graph_contract(graph), [])
        kinds = {n["kind"] for n in graph["nodes"]}
        self.assertIn("external_resource", kinds)

    def test_concurrent_registration_and_unregistration_storm(self) -> None:
        """Thread safety: concurrent register, get, list, and unregister operations remain atomic."""
        errors: list[Exception] = []

        def worker(worker_idx: int) -> None:
            try:
                p_name = f"storm_profile_{worker_idx}"
                class DynamicWorker(BaseEnvironmentAdapter):
                    label = f"Worker {worker_idx}"
                    def convert_to_graph(self, spec=None): return {}

                for _ in range(10):
                    register_adapter_profile(p_name, DynamicWorker, overwrite=True)
                    inst = get_adapter_profile(p_name)
                    self.assertEqual(inst.label, f"Worker {worker_idx}")
                    profiles = list_adapter_profiles()
                    self.assertIn(p_name, profiles)
                    unregister_adapter_profile(p_name)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, i) for i in range(16)]
            for f in futures:
                f.result()

        self.assertEqual(errors, [], f"Thread-safety storm had errors: {errors}")

    def test_adapter_spec_type_validation_and_list_variants(self) -> None:
        """convert_docker_compose_to_graph rejects non-dict specs and convert_local_host_to_graph handles list services."""
        # Non-dict spec for docker compose
        for bad_spec in ("raw_string", 12345, [1, 2, 3]):
            with self.subTest(bad_spec=bad_spec):
                with self.assertRaises(ValueError):
                    convert_docker_compose_to_graph(bad_spec)  # type: ignore[arg-type]

        # local_host adapter with list of string service names
        spec_list_services = {
            "hostname": "test-host.cluster.example.org",
            "services": ["service_alpha", "service_beta", {"name": "service_gamma", "port": 9000}],
            "local_models": [{"name": "qwen2.5:7b"}, "phi3:latest"],
        }
        graph = convert_local_host_to_graph(spec_list_services)
        self.assertEqual(validate_spatial_graph_contract(graph), [])
        labels = {n["label"] for n in graph["nodes"]}
        self.assertIn("service_alpha", labels)
        self.assertIn("service_beta", labels)
        self.assertIn("service_gamma", labels)
        self.assertIn("qwen2.5:7b", labels)
        self.assertIn("phi3:latest", labels)

    def test_render_adapters_markdown_and_html_generation(self) -> None:
        """render_adapters_markdown and render_adapters_html produce valid, complete output."""
        md_summary = render_adapters_markdown()
        self.assertIn("# OpsCryer Multi-Platform Compatibility & Adapter Studio", md_summary)
        self.assertIn("| Environment | Adapter |", md_summary)

        md_single = render_adapters_markdown("mock_dev")
        self.assertIn("Mock Dev Topology: node/edge breakdown", md_single)

        html = render_adapters_html()
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("<title>OpsCryer — Multi-Platform Compatibility &amp; Adapter Studio</title>", html)
        self.assertIn("data-adapter=\"docker_compose\"", html)


class TestTier5OpsCryerConfigAdversarial(unittest.TestCase):
    """Adversarial white-box tests for opscryer_config.py."""

    def setUp(self) -> None:
        reset_config()

    def tearDown(self) -> None:
        reset_config()

    def test_precedence_tier1_cached_cli_overrides(self) -> None:
        """Tier 1: Cached CLI overrides strictly override dynamic env variables and config defaults."""
        env = {
            "OPSCRYER_PORT": "9000",
            "OPSCRYER_LOG_LEVEL": "WARNING",
            "OPSCRYER_NETWORK__TIMEOUT_SECONDS": "15.0",
        }
        with patch.dict(os.environ, env, clear=False):
            # Load with CLI overrides
            load_unified_config(cli_overrides={"port": 8100, "log_level": "DEBUG"})

            # Assert get_config_value returns CLI overrides, ignoring env
            self.assertEqual(get_config_value("port"), 8100)
            self.assertEqual(get_config_value("server.port"), 8100)
            self.assertEqual(get_config_value("log_level"), "DEBUG")
            self.assertEqual(get_config_value("logging.level"), "DEBUG")

            # Non-CLI overridden key falls through to dynamic env
            self.assertEqual(get_config_value("network.timeout_seconds"), 15.0)
            self.assertEqual(get_config_value("timeout"), 15.0)

    def test_dot_path_resolution_with_non_dict_intermediates(self) -> None:
        """Dot-path resolution traversing into non-dict intermediate values returns default fallback safely."""
        load_unified_config(cli_overrides={"scalar_val": 42, "dict_val": {"nested_scalar": "hello"}})

        # Intermediate 'scalar_val' is int, not dict
        self.assertEqual(get_config_value("scalar_val.sub_key", "default_fb"), "default_fb")
        self.assertEqual(get_config_value("dict_val.nested_scalar.deep_child", "fb2"), "fb2")
        self.assertIsNone(get_config_value("dict_val.nested_scalar.deep_child"))
        self.assertEqual(get_config_value("", "default_for_empty"), "default_for_empty")
        self.assertIsNone(get_config_value(None, None))  # type: ignore[arg-type]

    def test_bidirectional_alias_pair_lookups(self) -> None:
        """Verify all bidirectional alias lookups across server.port, logging.level, and network.timeout."""
        cases = [
            ("port", 8123, "server.port", 8123),
            ("server.port", 8124, "port", 8124),
            ("log_level", "ERROR", "logging.level", "ERROR"),
            ("logging.level", "DEBUG", "log_level", "DEBUG"),
            ("timeout", 12.5, "network.timeout_seconds", 12.5),
            ("timeout_seconds", 14.0, "network.timeout_seconds", 14.0),
            ("network.timeout_seconds", 18.0, "timeout", 18.0),
            ("max_retries", 7, "network.max_retries", 7),
            ("network.max_retries", 9, "max_retries", 9),
        ]
        for set_key, set_val, get_key, expected_val in cases:
            with self.subTest(set_key=set_key, get_key=get_key):
                reset_config()
                if "." in set_key:
                    sec, field = set_key.split(".")
                    load_unified_config(cli_overrides={sec: {field: set_val}})
                else:
                    load_unified_config(cli_overrides={set_key: set_val})
                self.assertEqual(get_config_value(get_key), expected_val)

    def test_yaml_inline_comments_and_quoted_hashes(self) -> None:
        """YAML parser distinguishes inline # comments from # inside quotes or URLs."""
        yaml_text = """
        url_with_hash: "https://example.org/path#section" # trailing comment
        single_quote_hash: 'Document #42' # comment
        unquoted_hash_line: simple_val # comment here
        comment_without_space: value#not_a_comment_without_space
        """
        parsed = parse_simple_yaml(yaml_text)
        self.assertEqual(parsed["url_with_hash"], "https://example.org/path#section")
        self.assertEqual(parsed["single_quote_hash"], "Document #42")
        self.assertEqual(parsed["unquoted_hash_line"], "simple_val")
        self.assertEqual(parsed["comment_without_space"], "value")

    def test_yaml_scalar_coercion_types(self) -> None:
        """Scalar parsing converts ints, negative ints, floats, scientific notation, booleans, and nulls."""
        scalars = [
            ("true", True), ("yes", True), ("on", True),
            ("false", False), ("no", False), ("off", False),
            ("null", None), ("~", None), ("none", None),
            ("0", 0), ("42", 42), ("-10", -10),
            ("3.14", 3.14), ("1e-3", 0.001), ("-2.5e2", -250.0),
            ('"quoted string"', "quoted string"),
            ("'single quoted'", "single quoted"),
        ]
        for raw, expected in scalars:
            with self.subTest(raw=raw):
                parsed = _parse_scalar(raw)
                if isinstance(expected, float):
                    self.assertAlmostEqual(parsed, expected)
                else:
                    self.assertEqual(parsed, expected)

    def test_yaml_parser_json_mode_and_indentation_jumps(self) -> None:
        """parse_simple_yaml parses JSON objects and tolerates arbitrary multi-level dedenting."""
        json_text = '{"server": {"port": 9091}, "enabled": true}'
        parsed_json = parse_simple_yaml(json_text)
        self.assertEqual(parsed_json["server"]["port"], 9091)
        self.assertIs(parsed_json["enabled"], True)

        jump_yaml = """
        core:
          deep_1:
            deep_2:
              leaf: 100
        root_leaf: 200
        """
        parsed_jump = parse_simple_yaml(jump_yaml)
        self.assertEqual(parsed_jump["core"]["deep_1"]["deep_2"]["leaf"], 100)
        self.assertEqual(parsed_jump["root_leaf"], 200)

    def test_env_variable_coercion_and_openai_aliases(self) -> None:
        """_load_env_config parses double-underscore hierarchies and OpenAI aliases."""
        env = {
            "OPSCRYER_NESTED__SUB__KEY": "nested_value",
            "OPSCRYER_PORT": "8200",
            "OPSCRYER_TIMEOUT": "7.5",
            "OPENAI_API_KEY": "mock_openai_token_123",
            "OPENAI_API_BASE": "https://api.openai.local/v1",
            "OPENAI_MODEL": "gpt-4o",
        }
        loaded = _load_env_config(env)
        self.assertEqual(loaded["nested"]["sub"]["key"], "nested_value")
        self.assertEqual(loaded["port"], 8200)
        self.assertEqual(loaded["server"]["port"], 8200)
        self.assertEqual(loaded["network"]["timeout_seconds"], 7.5)
        self.assertEqual(loaded["openai_api_key"], "mock_openai_token_123")
        self.assertEqual(loaded["openai_base_url"], "https://api.openai.local/v1")
        self.assertEqual(loaded["jev_model"], "gpt-4o")

    def test_secret_redaction_wholesale_masking(self) -> None:
        """dump_sanitized_config masks sensitive keys recursively and returns a decoupled copy."""
        cfg = {
            "api_key": "raw_secret_key",
            "client_secret": "raw_client_secret",
            "database": {
                "password": "db_password_123",
                "cert_key": "tls_private_key_data",
            },
            "tokens": ["tok1", "tok2"],
            "nested_secrets": [
                {"auth_token": "bearer_val", "public_id": "id-123"},
            ],
            "safe_value": "public_cluster",
        }
        load_unified_config(cli_overrides=cfg)
        sanitized = dump_sanitized_config()

        self.assertEqual(sanitized["api_key"], "[REDACTED]")
        self.assertEqual(sanitized["client_secret"], "[REDACTED]")
        self.assertEqual(sanitized["database"]["password"], "[REDACTED]")
        self.assertEqual(sanitized["database"]["cert_key"], "[REDACTED]")
        self.assertEqual(sanitized["tokens"], ["[REDACTED]", "[REDACTED]"])
        self.assertEqual(sanitized["nested_secrets"][0]["auth_token"], "[REDACTED]")
        self.assertEqual(sanitized["nested_secrets"][0]["public_id"], "id-123")
        self.assertEqual(sanitized["safe_value"], "public_cluster")

        # Mutating sanitized copy does not mutate active config
        sanitized["safe_value"] = "tampered"
        self.assertEqual(get_config_value("safe_value"), "public_cluster")

    def test_configure_logging_levels_and_fallback(self) -> None:
        """configure_logging handles valid strings, numbers, case insensitivity, and invalid fallbacks."""
        logger = configure_logging("debug")
        self.assertEqual(logger.level, logging.DEBUG)

        logger = configure_logging("WARNING")
        self.assertEqual(logger.level, logging.WARNING)

        logger = configure_logging("WARN")
        self.assertEqual(logger.level, logging.WARNING)

        logger = configure_logging("critical")
        self.assertEqual(logger.level, logging.CRITICAL)

        # Invalid level falls back to INFO
        logger = configure_logging("INVALID_LEVEL_STRING_XYZ")
        self.assertEqual(logger.level, logging.INFO)

        # Environment variable override
        with patch.dict(os.environ, {"OPSCRYER_LOG_LEVEL": "ERROR"}):
            logger = configure_logging()
            self.assertEqual(logger.level, logging.ERROR)

    def test_yaml_file_parsing_edge_cases_and_corrupt_files(self) -> None:
        """parse_simple_yaml_file handles missing paths, directories, empty files, and JSON suffixes."""
        # Non-existent file
        self.assertEqual(parse_simple_yaml_file("non_existent_file_path_123.yaml"), {})

        # Directory path
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertEqual(parse_simple_yaml_file(tmpdir), {})

        # Empty file
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("")
            f_path = Path(f.name)
        try:
            self.assertEqual(parse_simple_yaml_file(f_path), {})
        finally:
            f_path.unlink(missing_ok=True)

        # JSON file
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"json_key": "json_val", "port": 8300}')
            f_path = Path(f.name)
        try:
            res = parse_simple_yaml_file(f_path)
            self.assertEqual(res["json_key"], "json_val")
            self.assertEqual(res["port"], 8300)
        finally:
            f_path.unlink(missing_ok=True)

    def test_env_coercion_invalid_types_fallback(self) -> None:
        """_coerce_env_value falls back to raw string when int or float conversion fails."""
        # 'port' hint is int; invalid string falls back to raw string
        self.assertEqual(_coerce_env_value("port", "not_an_int"), "not_an_int")
        # 'timeout_seconds' hint is float; invalid string falls back to raw string
        self.assertEqual(_coerce_env_value("timeout_seconds", "not_a_float"), "not_a_float")
        # Boolean coercion
        self.assertIs(_coerce_env_value("read_only", "true"), True)
        self.assertIs(_coerce_env_value("read_only", "1"), True)
        self.assertIs(_coerce_env_value("read_only", "no"), False)

    def test_cli_overrides_kwargs_cascade(self) -> None:
        """load_unified_config merges kwargs on top of cli_overrides and synchronizes port/logging aliases."""
        cfg = load_unified_config(
            cli_overrides={"port": 8100, "log_level": "WARNING"},
            port=8500,
            log_level="ERROR",
        )
        self.assertEqual(cfg["port"], 8500)
        self.assertEqual(cfg["server"]["port"], 8500)
        self.assertEqual(cfg["log_level"], "ERROR")
        self.assertEqual(cfg["logging"]["level"], "ERROR")
        self.assertEqual(get_config_value("port"), 8500)
        self.assertEqual(get_config_value("server.port"), 8500)

    def test_auto_load_on_uninitialized_config(self) -> None:
        """get_config_value and dump_sanitized_config automatically call load_unified_config if cache is None."""
        reset_config()
        # Direct call to get_config_value without load_unified_config
        self.assertEqual(get_config_value("port"), 8088)

        reset_config()
        # Direct call to dump_sanitized_config without load_unified_config
        sanitized = dump_sanitized_config()
        self.assertEqual(sanitized["port"], 8088)

    def test_suite_line_endings_are_strictly_lf(self) -> None:
        """Verify that this adversarial test suite and all inspected source modules use 100% LF line endings."""
        files_to_check = [
            Path(__file__),
            SUITE_ROOT / "environment_adapters.py",
            SUITE_ROOT / "opscryer_config.py",
            SUITE_ROOT / "system_context.py",
            SUITE_ROOT / "telemetry_sanitizer.py",
            SUITE_ROOT / "route_registry.py",
        ]
        for f_path in files_to_check:
            with self.subTest(file=f_path.name):
                content = f_path.read_bytes()
                self.assertNotIn(b"\r", content, f"File {f_path.name} contains CRLF line endings")


class TestTier5SystemContextAdversarial(unittest.TestCase):
    """Adversarial white-box tests for system_context.py."""

    def test_ground_truth_inventory_immutability(self) -> None:
        """Ground truth getters return deep detached copies; mutations do not corrupt globals."""
        gpus = get_verified_gpu_inventory()
        self.assertEqual(gpus["total_gpu_count"], 4)
        gpus["gpus"].clear()
        self.assertEqual(len(get_verified_gpu_inventory()["gpus"]), 4)

        nodes = get_homelab_hardware_inventory()
        nodes["nodes"].clear()
        self.assertEqual(len(get_homelab_hardware_inventory()["nodes"]), 3)

        workloads = get_intentional_scale_down_workloads()
        workloads.clear()
        self.assertEqual(len(get_intentional_scale_down_workloads()), 7)

        runbooks = get_canonical_kb_runbooks()
        runbooks.clear()
        self.assertEqual(len(get_canonical_kb_runbooks()), 5)

    def test_ast_symbol_extraction_resilience(self) -> None:
        """_extract_ast_symbols_from_file handles missing files, non-py files, and syntax errors."""
        # Non-existent file
        self.assertEqual(_extract_ast_symbols_from_file(Path("missing_file_xyz.py"), "missing.py"), [])

        # Non-Python file
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"key": "value"}')
            f_path = Path(f.name)
        try:
            self.assertEqual(_extract_ast_symbols_from_file(f_path, "test.json"), [])
        finally:
            f_path.unlink(missing_ok=True)

        # Syntax error file
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("def broken_syntax(:\n  pass")
            f_path = Path(f.name)
        try:
            self.assertEqual(_extract_ast_symbols_from_file(f_path, "broken.py"), [])
        finally:
            f_path.unlink(missing_ok=True)

    def test_ast_jump_references_offline_fallback(self) -> None:
        """build_ast_jump_references provides default symbols even when target files are missing."""
        jumps = build_ast_jump_references(["non_existent_module.py"])
        self.assertIn("system_context", jumps)
        self.assertIn("opscryer_browser", jumps)
        self.assertIn("route_registry", jumps)
        self.assertIn("opscryer_backend", jumps)

        for mod, symbols in jumps.items():
            self.assertGreater(len(symbols), 0)
            for s in symbols:
                self.assertIn("symbol", s)
                self.assertIn("kind", s)
                self.assertIn("jump_ref", s)
                self.assertIn("correlated_graph_node_id", s)

    def test_validate_model_output_denylist_and_scale_guards(self) -> None:
        """validate_model_output_against_context catches hallucinated GPUs and scale-down violations."""
        # Hallucinated GPUs
        bad_models = ["We need to run on RTX 5080", "Deploy to A100 node", "H100 cluster", "Use rtx 4090"]
        for bad in bad_models:
            with self.subTest(bad=bad):
                res = validate_model_output_against_context(bad)
                self.assertFalse(res["passed"])
                self.assertEqual(res["status"], "HALLUCINATING")
                self.assertGreater(len(res["hallucinated_gpus"]), 0)

        # Unauthorized scale-up
        scale_verbs = [
            "kubectl scale deployment agentic-agent-developer --replicas=1",
            "rollout restart deployment open-webui",
            "spec:\n  replicas: 2\n  # gitlab-runner-turbo",
        ]
        for verb in scale_verbs:
            with self.subTest(verb=verb):
                res = validate_model_output_against_context(verb)
                self.assertFalse(res["passed"])
                self.assertEqual(res["status"], "VIOLATION")
                self.assertGreater(len(res["intentional_scale_down_violations"]), 0)

        # Out-of-scope files
        allowed = ["system_context.py", "opscryer_browser.py"]
        out_scope_msg = "Please edit dangerous_secret_file.yaml and secret_script.py now."
        res_scope = validate_model_output_against_context(out_scope_msg, allowed_files=allowed)
        self.assertFalse(res_scope["passed"])
        self.assertIn("dangerous_secret_file.yaml", res_scope["out_of_scope_files"])
        self.assertIn("secret_script.py", res_scope["out_of_scope_files"])

    def test_build_system_context_tiers_and_sanitization(self) -> None:
        """build_system_context generates valid schema versions and strictly sanitizes outputs."""
        for tier in ("both", "local_gpu", "frontier"):
            with self.subTest(tier=tier):
                payload = build_system_context(tier=tier)
                self.assertEqual(payload["schema_version"], SYSTEM_CONTEXT_SCHEMA_VERSION)
                self.assertIn("gpu_inventory", payload)
                self.assertIn("scale_down_workloads", payload)
                self.assertIn("active_kb_runbooks", payload)
                self.assertIn("ast_jump_references", payload)

                if tier in ("both", "local_gpu"):
                    self.assertIn("local_gpu_anti_lost_pack", payload)
                else:
                    self.assertNotIn("local_gpu_anti_lost_pack", payload)

                if tier in ("both", "frontier"):
                    self.assertIn("frontier_token_saver_brief", payload)
                else:
                    self.assertNotIn("frontier_token_saver_brief", payload)

    def test_system_context_custom_catalog_and_queries(self) -> None:
        """build_system_context handles custom queries, selected target_gpu, and synthetic catalogs."""
        synthetic_catalog = {"nodes": [{"id": "n1", "label": "Node 1"}], "edges": []}
        payload = build_system_context(
            tier="local_gpu",
            target_gpu="NVIDIA GeForce RTX 3070 Ti",
            query="Check VRAM allocation",
            catalog=synthetic_catalog,
        )
        self.assertEqual(payload["schema_version"], SYSTEM_CONTEXT_SCHEMA_VERSION)
        pack = payload["local_gpu_anti_lost_pack"]
        self.assertEqual(pack["target_hardware"], "NVIDIA GeForce RTX 3070 Ti")

    def test_ast_jump_references_empty_list_vs_none(self) -> None:
        """build_ast_jump_references returns defaults when target_files is empty or None."""
        jumps_none = build_ast_jump_references(None)
        jumps_empty = build_ast_jump_references([])
        for expected_mod in ("system_context", "opscryer_browser", "route_registry"):
            self.assertIn(expected_mod, jumps_none)
            self.assertIn(expected_mod, jumps_empty)


class TestTier5TelemetrySanitizerAdversarial(unittest.TestCase):
    """Adversarial white-box tests for telemetry_sanitizer.py."""

    def test_pem_armor_blocks_and_private_key_sanitization(self) -> None:
        """Verify comprehensive redaction of multi-line and standalone PEM armor headers/trailers."""
        pem_samples = [
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEI...\n-----END EC PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza...\n-----END OPENSSH PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "Log event: handshake failed with -----BEGIN CERTIFICATE-----MIID...-----END CERTIFICATE----- on port 443",
        ]
        for sample in pem_samples:
            with self.subTest(sample=sample[:30]):
                cleaned = _sanitize_text(sample)
                self.assertNotIn("BEGIN", cleaned)
                self.assertNotIn("END", cleaned)
                self.assertIn("[REDACTED]", cleaned)

    def test_token_and_credential_assignment_redaction(self) -> None:
        """Verify credential assignments, bearer tokens, JWTs, and platform token prefixes."""
        cases = [
            ("password = 'super_secret_pass'", "password = [REDACTED]"),
            ("passwd: my_secret_passwd", "passwd: [REDACTED]"),
            ("api_key=" + "s" + "k-live-1234567890abcdef", "api_key=[REDACTED]"),
            ("client_secret = secret_val", "client_secret = [REDACTED]"),
            ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature", "Bearer [REDACTED]"),
            ("gh" + "o_1234567890abcdefghijklmnopqrstuvwxyz", "[REDACTED]"),
            ("gh" + "p_1234567890abcdefghijklmnopqrstuvwxyz", "[REDACTED]"),
            ("gl" + "pat-1234567890abcdefghij", "[REDACTED]"),
            ("github_pat_1234567890abcdef", "[REDACTED]"),
            ("contact: admin@" + "gmail.com", "contact: [REDACTED]"),
            ("contact: admin@googlemail.com", "contact: [REDACTED]"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(sanitize(raw), expected)

    def test_mac_addresses_and_wan_ipv4_handling(self) -> None:
        """Verify MAC masking, Cisco dotted MACs, WAN replacement, and RFC1918 retention."""
        # MAC addresses
        mac_colon = ":".join(["00", "11", "22", "33", "44", "55"])
        mac_dash = "-".join(["AA", "BB", "CC", "DD", "EE", "FF"])
        mac_dot = ".".join(["0011", "2233", "4455"])
        self.assertEqual(sanitize(mac_colon), "00:11:22:XX:XX:XX")
        self.assertEqual(sanitize(mac_dash), "AA-BB-CC-XX-XX-XX")
        self.assertEqual(sanitize(mac_dot), "00:11:22:XX:XX:XX")

        # WAN IPv4 replacement (public global IPs)
        wan_ips = [
            ".".join(["8", "8", "8", "8"]),
            ".".join(["1", "1", "1", "1"]),
            ".".join(["142", "250", "190", "46"]),
        ]
        for wan in wan_ips:
            with self.subTest(wan=wan):
                self.assertEqual(sanitize(f"https://{wan}:443"), "https://203.0.113.1:443")

        # Retained non-WAN IPs (RFC 1918, loopback, CGNAT)
        retained = ["10.20.3.13", "172.20.1.1", "172.16.0.5", "127.0.0.1", "100.64.0.1"]
        for ip in retained:
            with self.subTest(ip=ip):
                self.assertEqual(sanitize(f"http://{ip}:8080"), f"http://{ip}:8080")

        # Malformed dotted numbers do not raise ValueError
        self.assertEqual(sanitize("999.999.999.999"), "999.999.999.999")

    def test_container_preservation_and_type_boundaries(self) -> None:
        """sanitize preserves container types (list stays list, tuple stays tuple) and catches non-string keys."""
        payload = {
            "list_key": ["a", "b"],
            "tuple_key": ("c", "d"),
        }
        res = sanitize(payload)
        self.assertIsInstance(res["list_key"], list)
        self.assertIsInstance(res["tuple_key"], tuple)

        # Non-string dictionary keys raise TypeError
        with self.assertRaises(TypeError):
            sanitize({123: "bad_key_type"})

        # Unsupported leaf values raise TypeError
        with self.assertRaises(TypeError):
            sanitize({"key": object()})
        with self.assertRaises(TypeError):
            sanitize({"key": b"bytes_not_allowed"})

    def test_kubernetes_secret_wholesale_redaction(self) -> None:
        """Kubernetes Secret payloads have data and stringData redacted wholesale."""
        secret_payload = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "app-tls"},
            "data": {
                "tls.crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg==",
                "tls.key": "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQo=",
            },
            "stringData": {
                "config.yaml": "secret_field: raw_value",
            },
        }
        sanitized = sanitize(secret_payload)
        self.assertEqual(sanitized["data"], "[REDACTED]")
        self.assertEqual(sanitized["stringData"], "[REDACTED]")
        self.assertEqual(sanitized["metadata"]["name"], "app-tls")

    def test_cisco_mac_and_extreme_depth_sanitization(self) -> None:
        """Cisco dotted MAC addresses are normalized and extreme nesting depth is sanitized."""
        # Cisco MACs
        cisco_mac_val = ".".join(["0011", "22aa", "bbcc"])
        cisco_sample = f"Host switch port link {cisco_mac_val} active"
        sanitized_cisco = sanitize(cisco_sample)
        self.assertEqual(sanitized_cisco, "Host switch port link 00:11:22:XX:XX:XX active")

        # Depth 40 nesting
        curr: dict[str, Any] = {"leaf": "password = raw_pass"}
        for i in range(40):
            curr = {f"level_{i}": curr}
        res = sanitize(curr)
        leaf = res
        for i in reversed(range(40)):
            leaf = leaf[f"level_{i}"]
        self.assertEqual(leaf["leaf"], "password = [REDACTED]")

    def test_key_collision_after_redaction_raises_value_error(self) -> None:
        """Telemetry object containing two keys that collide after redaction raises ValueError."""
        # Two WAN IPs that both redact to 203.0.113.1
        colliding = {
            ".".join(["8", "8", "8", "8"]): "dns_google",
            ".".join(["1", "1", "1", "1"]): "dns_cloudflare",
        }
        with self.assertRaisesRegex(ValueError, "keys collide"):
            sanitize(colliding)

    def test_kubernetes_secret_non_dict_data_redaction(self) -> None:
        """Kubernetes Secret with non-dict/non-string data values is redacted wholesale."""
        secret_non_dict = {
            "kind": "Secret",
            "metadata": {"name": "test-sec"},
            "data": 12345,
            "stringData": ["not", "a", "dict"],
        }
        sanitized = sanitize(secret_non_dict)
        self.assertEqual(sanitized["data"], "[REDACTED]")
        self.assertEqual(sanitized["stringData"], "[REDACTED]")


class TestTier5RouteRegistryAdversarial(unittest.TestCase):
    """Adversarial white-box tests for route_registry.py."""

    def test_route_registry_counts_and_subsystem_partitioning(self) -> None:
        """Route registry matches exact counts (21 HTML, 63 API) and strictly partitioned subsystems."""
        self.assertEqual(len(HTML_PORTAL_ROUTES), 21)
        self.assertEqual(len(API_V1_ROUTES), 63)

        valid_subsystems = {"core", "live", "security", "portals"}
        for r in HTML_PORTAL_ROUTES:
            self.assertIn(r["subsystem"], valid_subsystems)
            self.assertTrue(r["path"].startswith("/"))

        for path, info in API_V1_ROUTES.items():
            self.assertIn(info["subsystem"], valid_subsystems)
            self.assertTrue(path.startswith("/api/v1/"))
            self.assertIsInstance(info["allowed_params"], set)

    def test_get_allowed_api_params_immutability(self) -> None:
        """get_allowed_api_params returns independent sets; mutating them does not alter API_V1_ROUTES."""
        params_map = get_allowed_api_params()
        self.assertEqual(len(params_map), 63)

        # Mutate returned set
        params_map["/api/v1/scale-benchmark"].add("tampered_param")
        self.assertNotIn("tampered_param", API_V1_ROUTES["/api/v1/scale-benchmark"]["allowed_params"])

    def test_build_route_registry_summary_independence(self) -> None:
        """build_route_registry_summary returns correct counts and is completely decoupled."""
        summary1 = build_route_registry_summary()
        self.assertEqual(summary1["total_html_routes"], 21)
        self.assertEqual(summary1["total_api_routes"], 63)
        self.assertEqual(summary1["by_subsystem"]["core"]["api_routes"], 12)
        self.assertEqual(summary1["by_subsystem"]["live"]["api_routes"], 9)
        self.assertEqual(summary1["by_subsystem"]["security"]["api_routes"], 21)
        self.assertEqual(summary1["by_subsystem"]["portals"]["api_routes"], 21)

        # Tamper with summary1
        summary1["by_subsystem"]["core"]["api_routes"] = 999
        summary2 = build_route_registry_summary()
        self.assertEqual(summary2["by_subsystem"]["core"]["api_routes"], 12)


def main() -> int:
    suite = unittest.TestSuite()
    loader = unittest.defaultTestLoader
    test_classes = [
        TestTier5EnvironmentAdaptersAdversarial,
        TestTier5OpsCryerConfigAdversarial,
        TestTier5SystemContextAdversarial,
        TestTier5TelemetrySanitizerAdversarial,
        TestTier5RouteRegistryAdversarial,
    ]
    for tc in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(tc))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
