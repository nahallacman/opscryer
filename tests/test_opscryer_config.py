# SPDX-License-Identifier: Apache-2.0
"""Unit and boundary test suite for opscryer_config.py."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from opscryer_config import (
    DEFAULT_CONFIG,
    dump_sanitized_config,
    get_config_value,
    load_unified_config,
    parse_simple_yaml,
    reset_config,
)


class TestOpsCryerConfig(unittest.TestCase):
    """Test suite for hierarchical configuration and secret sanitization."""

    def setUp(self) -> None:
        reset_config()

    def tearDown(self) -> None:
        reset_config()

    # -----------------------------------------------------------------------
    # Tier 1: Feature Tests (Core Functionality)
    # -----------------------------------------------------------------------

    def test_default_values_loaded_cleanly(self) -> None:
        """Verify that load_unified_config returns all standard built-in defaults."""
        cfg = load_unified_config()
        self.assertEqual(cfg["port"], 8088)
        self.assertEqual(cfg["organization_name"], "Acme Cloud Engineering")
        self.assertEqual(cfg["domain_suffix"], "example.org")
        self.assertEqual(cfg["default_mode"], "STANDALONE_MOCK")
        self.assertEqual(cfg["api_base_url"], "")
        self.assertIs(cfg["read_only_public_mode"], True)
        self.assertEqual(cfg["itsm_provider_name"], "Enterprise Service Desk")
        self.assertEqual(cfg["ollama_url"], "http://localhost:11434")
        self.assertEqual(cfg["jev_provider"], "ollama")
        self.assertEqual(cfg["jev_model"], "qwen2.5-coder:7b")
        self.assertAlmostEqual(cfg["jev_min_confidence"], 0.80)
        self.assertEqual(cfg["log_level"], "INFO")
        self.assertEqual(cfg["prometheus_url"], "http://127.0.0.1:9090")
        self.assertEqual(cfg["timeout"], 5.0)

    def test_get_config_value_direct_and_fallback(self) -> None:
        """Verify direct key lookup and fallback behavior of get_config_value."""
        self.assertEqual(get_config_value("port"), 8088)
        self.assertEqual(get_config_value("nonexistent_key", 42), 42)
        self.assertIsNone(get_config_value("nonexistent_key"))

    def test_json_config_file_parsing(self) -> None:
        """Verify that standard JSON configuration files parse correctly and override defaults."""
        data = {
            "port": 9099,
            "organization_name": "JSON Override Org",
            "read_only_public_mode": False,
            "server": {"host": "10.0.0.5", "workers": 8},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(data, f)
            f_path = Path(f.name)
        try:
            cfg = load_unified_config(config_path=f_path)
            self.assertEqual(cfg["port"], 9099)
            self.assertEqual(cfg["organization_name"], "JSON Override Org")
            self.assertIs(cfg["read_only_public_mode"], False)
            self.assertEqual(get_config_value("server.host"), "10.0.0.5")
            self.assertEqual(get_config_value("server.workers"), 8)
            # Unmentioned keys retain default values
            self.assertEqual(cfg["default_mode"], "STANDALONE_MOCK")
        finally:
            f_path.unlink(missing_ok=True)

    def test_yaml_config_file_parsing(self) -> None:
        """Verify that pure stdlib YAML parser handles keys, types, comments, and nesting."""
        yaml_content = """
        # Test OpsCryer YAML Configuration
        organization_name: "YAML Test Cluster"
        port: 8888
        read_only_public_mode: false
        jev_min_confidence: 0.92
        api_base_url: "http://internal-gateway:8080" # inline comment
        network:
          ingress_host: "ops.cluster.example.org"
          tls_enabled: true
        """
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write(yaml_content)
            f_path = Path(f.name)
        try:
            cfg = load_unified_config(config_path=f_path)
            self.assertEqual(cfg["organization_name"], "YAML Test Cluster")
            self.assertEqual(cfg["port"], 8888)
            self.assertIs(cfg["read_only_public_mode"], False)
            self.assertAlmostEqual(cfg["jev_min_confidence"], 0.92)
            self.assertEqual(cfg["api_base_url"], "http://internal-gateway:8080")
            self.assertEqual(get_config_value("network.ingress_host"), "ops.cluster.example.org")
            self.assertIs(get_config_value("network.tls_enabled"), True)
        finally:
            f_path.unlink(missing_ok=True)

    def test_environment_variable_overriding(self) -> None:
        """Verify that OPSCRYER_* environment variables override defaults and file values."""
        env = {
            "OPSCRYER_PORT": "9100",
            "OPSCRYER_LOG_LEVEL": "DEBUG",
            "OPSCRYER_READ_ONLY_PUBLIC_MODE": "false",
            "OPSCRYER_JEV_MIN_CONFIDENCE": "0.88",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = load_unified_config()
            self.assertEqual(cfg["port"], 9100)
            self.assertEqual(cfg["log_level"], "DEBUG")
            self.assertIs(cfg["read_only_public_mode"], False)
            self.assertAlmostEqual(cfg["jev_min_confidence"], 0.88)

    def test_hierarchical_precedence_cascade(self) -> None:
        """Verify the 4-tier precedence: CLI > Env > File > Defaults."""
        yaml_content = "port: 8090\norganization_name: 'File Org'\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write(yaml_content)
            f_path = Path(f.name)
        try:
            # Level 1: File overrides Default
            cfg1 = load_unified_config(config_path=f_path)
            self.assertEqual(cfg1["port"], 8090)
            self.assertEqual(cfg1["organization_name"], "File Org")

            # Level 2: Env overrides File
            with patch.dict(os.environ, {"OPSCRYER_PORT": "8095"}, clear=False):
                reset_config()
                cfg2 = load_unified_config(config_path=f_path)
                self.assertEqual(cfg2["port"], 8095)
                self.assertEqual(cfg2["organization_name"], "File Org")

                # Level 3: CLI overrides Env and File
                reset_config()
                cfg3 = load_unified_config(config_path=f_path, cli_overrides={"port": 8100})
                self.assertEqual(cfg3["port"], 8100)
                self.assertEqual(cfg3["organization_name"], "File Org")
        finally:
            f_path.unlink(missing_ok=True)

    def test_dump_sanitized_config_secret_masking(self) -> None:
        """Verify that dump_sanitized_config redacts sensitive keys while preserving live values."""
        # Use dummy token strings avoiding forbidden OPSEC prefixes
        mock_openai_token = "mock_tok_live_secret_openai_value"
        mock_db_pass = "mock_db_password_xyz123"
        mock_auth_token = "mock_auth_bearer_token_789"

        with patch.dict(os.environ, {"OPSCRYER_OPENAI_API_KEY": mock_openai_token}, clear=False):
            load_unified_config(
                cli_overrides={
                    "database_password": mock_db_pass,
                    "auth": {"token": mock_auth_token},
                    "safe_setting": "public_cluster_name",
                    "secret_items": [{"api_key": "val1"}, {"other": "safe"}],
                }
            )

            # Assert live config has unredacted values
            self.assertEqual(get_config_value("openai_api_key"), mock_openai_token)
            self.assertEqual(get_config_value("database_password"), mock_db_pass)
            self.assertEqual(get_config_value("auth.token"), mock_auth_token)

            # Assert sanitized dump redacts all sensitive fields
            sanitized = dump_sanitized_config()
            self.assertEqual(sanitized["openai_api_key"], "[REDACTED]")
            self.assertEqual(sanitized["database_password"], "[REDACTED]")
            self.assertEqual(sanitized["auth"]["token"], "[REDACTED]")
            self.assertEqual(sanitized["secret_items"][0]["api_key"], "[REDACTED]")
            self.assertEqual(sanitized["secret_items"][1]["other"], "safe")
            self.assertEqual(sanitized["safe_setting"], "public_cluster_name")

            # Assert dump returns a detached copy (mutations do not affect live config)
            sanitized["safe_setting"] = "modified_value"
            self.assertEqual(get_config_value("safe_setting"), "public_cluster_name")

    # -----------------------------------------------------------------------
    # Tier 2: Boundary Value Analysis & Edge Cases
    # -----------------------------------------------------------------------

    def test_nonexistent_or_empty_config_file_fallback(self) -> None:
        """Verify graceful fallback to defaults when config path does not exist or is empty."""
        cfg_missing = load_unified_config(config_path="nonexistent_config_file_path_1234.yaml")
        self.assertEqual(cfg_missing["port"], 8088)

        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("")
            f_path = Path(f.name)
        try:
            reset_config()
            cfg_empty = load_unified_config(config_path=f_path)
            self.assertEqual(cfg_empty["port"], 8088)
        finally:
            f_path.unlink(missing_ok=True)

    def test_yaml_edge_cases_quotes_and_comments(self) -> None:
        """Verify that inline '#' inside quotes is preserved and colons in URLs are parsed cleanly."""
        yaml_content = """
        issue_title: "Bug #42 in #channel"
        ticket_ref: 'Ticket #99: high priority'
        api_url: "http://127.0.0.1:8088/api/v1" # valid trailing comment
        blank_val:
        """
        parsed = parse_simple_yaml(yaml_content)
        self.assertEqual(parsed["issue_title"], "Bug #42 in #channel")
        self.assertEqual(parsed["ticket_ref"], "Ticket #99: high priority")
        self.assertEqual(parsed["api_url"], "http://127.0.0.1:8088/api/v1")
        self.assertEqual(parsed["blank_val"], "")

    def test_yaml_scalar_type_coercion_matrix(self) -> None:
        """Verify scalar coercion across booleans, numbers, nulls, and strings."""
        yaml_content = """
        b_true1: true
        b_true2: yes
        b_true3: on
        b_false1: false
        b_false2: no
        b_false3: off
        n_null1: null
        n_null2: ~
        num_zero: 0
        num_pos: 42
        num_neg: -17
        float_val: 3.1415
        str_num: "8088"
        """
        p = parse_simple_yaml(yaml_content)
        self.assertIs(p["b_true1"], True)
        self.assertIs(p["b_true2"], True)
        self.assertIs(p["b_true3"], True)
        self.assertIs(p["b_false1"], False)
        self.assertIs(p["b_false2"], False)
        self.assertIs(p["b_false3"], False)
        self.assertIsNone(p["n_null1"])
        self.assertIsNone(p["n_null2"])
        self.assertEqual(p["num_zero"], 0)
        self.assertEqual(p["num_pos"], 42)
        self.assertEqual(p["num_neg"], -17)
        self.assertAlmostEqual(p["float_val"], 3.1415)
        self.assertEqual(p["str_num"], "8088")

    def test_environment_variable_double_underscore_nesting(self) -> None:
        """Verify that double underscores in OPSCRYER_* map to nested dictionary hierarchies."""
        env = {
            "OPSCRYER_CLUSTER__INGRESS__PORT": "443",
            "OPSCRYER_CLUSTER__INGRESS__ENABLED": "true",
            "OPSCRYER_CLUSTER__NAME": "production-eu",
        }
        with patch.dict(os.environ, env, clear=False):
            load_unified_config()
            self.assertEqual(get_config_value("cluster.ingress.port"), 443)
            self.assertIs(get_config_value("cluster.ingress.enabled"), True)
            self.assertEqual(get_config_value("cluster.name"), "production-eu")

    def test_openai_standard_env_aliases(self) -> None:
        """Verify that standard OPENAI_* environment variables are mapped to configuration keys."""
        mock_key = "mock_openai_alias_key_555"
        env = {
            "OPENAI_API_KEY": mock_key,
            "OPENAI_API_BASE": "https://custom.openai.local/v1",
            "OPENAI_MODEL": "gpt-4o-mini",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = load_unified_config()
            self.assertEqual(cfg["openai_api_key"], mock_key)
            self.assertEqual(cfg["openai_base_url"], "https://custom.openai.local/v1")
            self.assertEqual(cfg["jev_model"], "gpt-4o-mini")

    def test_get_config_value_deep_dot_notation(self) -> None:
        """Verify deep dot-notation resolution with non-existent branches returns fallback."""
        load_unified_config(cli_overrides={"a": {"b": {"c": "deep_value"}}})
        self.assertEqual(get_config_value("a.b.c"), "deep_value")
        self.assertEqual(get_config_value("a.b.missing", "fb"), "fb")
        self.assertEqual(get_config_value("a.missing.c", "fb"), "fb")
        self.assertIsNone(get_config_value("completely.missing.path"))


    # -----------------------------------------------------------------------
    # Tier 3: Empirical Challenger Stress Tests & Edge Cases
    # -----------------------------------------------------------------------

    def test_challenge_deeply_nested_yaml_and_dedenting(self) -> None:
        """Challenge: 30 levels of indentation and arbitrary dedenting back to root."""
        lines = []
        depth = 30
        for i in range(depth):
            indent = "  " * i
            lines.append(f"{indent}level_{i}:")
        lines.append(f"{'  ' * depth}leaf_value: 'found_at_bottom'")
        lines.append(f"{'  ' * 15}intermediate_sibling: 'level_15_value'")
        lines.append("root_sibling: 'back_at_root'")

        yaml_text = "\n".join(lines)
        parsed = parse_simple_yaml(yaml_text)

        curr = parsed
        for i in range(depth):
            self.assertIn(f"level_{i}", curr)
            curr = curr[f"level_{i}"]
        self.assertEqual(curr["leaf_value"], "found_at_bottom")
        self.assertEqual(parsed["root_sibling"], "back_at_root")

    def test_challenge_strange_quote_mixtures_and_escapes(self) -> None:
        """Challenge: Nested quotes, escaped characters, quotes with colons and hashes."""
        yaml_content = """
        q_single_in_double: "She said 'hello world' yesterday"
        q_double_in_single: 'It is a "quoted" string'
        q_hash_in_quotes: "SELECT * FROM db # not_a_comment"
        q_hash_single: 'Config #1234'
        q_colons: "http://example.com:8080/path/to:resource"
        q_empty_double: ""
        q_empty_single: ''
        """
        parsed = parse_simple_yaml(yaml_content)
        self.assertEqual(parsed["q_single_in_double"], "She said 'hello world' yesterday")
        self.assertEqual(parsed["q_double_in_single"], 'It is a "quoted" string')
        self.assertEqual(parsed["q_hash_in_quotes"], "SELECT * FROM db # not_a_comment")
        self.assertEqual(parsed["q_hash_single"], "Config #1234")
        self.assertEqual(parsed["q_colons"], "http://example.com:8080/path/to:resource")
        self.assertEqual(parsed["q_empty_double"], "")
        self.assertEqual(parsed["q_empty_single"], "")

    def test_challenge_malformed_comments_and_hashes(self) -> None:
        """Challenge: Comments without space, multiple hashes, trailing hashes, comments with quotes."""
        yaml_content = """
        k1: val1#comment_no_space
        k2: val2 # normal comment
        k3: val3 # comment # with # multiple # hashes
        k4: val4 # comment with "quotes" and 'apostrophes'
        k5: val5 #
        # whole line comment
           # indented whole line comment
        """
        parsed = parse_simple_yaml(yaml_content)
        self.assertEqual(parsed["k1"], "val1")
        self.assertEqual(parsed["k2"], "val2")
        self.assertEqual(parsed["k3"], "val3")
        self.assertEqual(parsed["k4"], "val4")
        self.assertEqual(parsed["k5"], "val5")

    def test_challenge_unicode_keys_and_values(self) -> None:
        """Challenge: International character sets, CJK, Cyrillic, Emoji, Arabic."""
        yaml_content = """
        локация: "Москва, Кремль"
        キー: "値"
        rocket: "🚀_launch"
        مرحبا: "عالم"
        """
        parsed = parse_simple_yaml(yaml_content)
        self.assertEqual(parsed["локация"], "Москва, Кремль")
        self.assertEqual(parsed["キー"], "値")
        self.assertEqual(parsed["rocket"], "🚀_launch")
        self.assertEqual(parsed["مرحبا"], "عالم")

    def test_challenge_huge_env_vars_and_deep_nesting(self) -> None:
        """Challenge: 30KB environment variable (Windows Win32 limit is 32,767) and deep __ nesting."""
        huge_val = "X" * 30_000
        env = {
            "OPSCRYER_HUGE_PAYLOAD": huge_val,
            "OPSCRYER_DEEP__A__B__C__D__E__F": "deeply_nested_env_val",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = load_unified_config()
            self.assertEqual(len(cfg["huge_payload"]), 30_000)
            self.assertEqual(get_config_value("deep.a.b.c.d.e.f"), "deeply_nested_env_val")

    def test_challenge_secret_masking_edge_cases(self) -> None:
        """Challenge: Mixed-case keys, substring matches, nested arrays, lists of lists, non-string scalars."""
        payload = {
            "ApiKey": "secret_key_1",
            "SECREt_TOKEN": "secret_tok_2",
            "pAssWord": "pass_3",
            "AuTH_hEaDER": "bearer_4",
            "secretary_phone": "555-1234",
            "tokenized_input": "tokens_list",
            "services": [
                {"name": "auth-service", "client_secret": "raw_sec_1", "port": 8080},
                {"name": "worker", "auth_token": "raw_tok_2", "active": True},
            ],
            "nested_lists": [
                ["safe_item", "another_safe"],
                [{"user_credential": "super_secret_cred", "count": 10}],
            ],
            "admin_password_numeric": 99887766,
            "secret_port": 8443,
            "auth_flag": True,
        }
        load_unified_config(cli_overrides=payload)
        sanitized = dump_sanitized_config()

        self.assertEqual(sanitized["ApiKey"], "[REDACTED]")
        self.assertEqual(sanitized["SECREt_TOKEN"], "[REDACTED]")
        self.assertEqual(sanitized["pAssWord"], "[REDACTED]")
        self.assertEqual(sanitized["AuTH_hEaDER"], "[REDACTED]")
        self.assertEqual(sanitized["secretary_phone"], "[REDACTED]")
        self.assertEqual(sanitized["tokenized_input"], "[REDACTED]")

        self.assertEqual(sanitized["services"][0]["client_secret"], "[REDACTED]")
        self.assertEqual(sanitized["services"][0]["name"], "auth-service")
        self.assertEqual(sanitized["services"][0]["port"], 8080)
        self.assertEqual(sanitized["services"][1]["auth_token"], "[REDACTED]")
        self.assertEqual(sanitized["services"][1]["name"], "worker")
        self.assertIs(sanitized["services"][1]["active"], True)

        self.assertEqual(sanitized["nested_lists"][0][0], "safe_item")
        self.assertEqual(sanitized["nested_lists"][1][0]["user_credential"], "[REDACTED]")
        self.assertEqual(sanitized["nested_lists"][1][0]["count"], 10)

        self.assertEqual(sanitized["admin_password_numeric"], "[REDACTED]")
        self.assertEqual(sanitized["secret_port"], "[REDACTED]")
        self.assertEqual(sanitized["auth_flag"], "[REDACTED]")

        self.assertEqual(get_config_value("ApiKey"), "secret_key_1")
        self.assertEqual(get_config_value("admin_password_numeric"), 99887766)
        self.assertEqual(get_config_value("secret_port"), 8443)

    def test_challenge_scalar_coercion_scientific_notation(self) -> None:
        """Challenge: Scientific notation, negative numbers, boolean variants, None/null."""
        yaml_content = """
        c_sci: 1e-4
        c_sci_neg: -2.5e3
        c_zero: 0
        c_neg_zero: -0
        c_bool_caps: TRUE
        c_bool_no: NO
        c_null_tilde: ~
        c_null_caps: NONE
        """
        p = parse_simple_yaml(yaml_content)
        self.assertAlmostEqual(p["c_sci"], 0.0001)
        self.assertAlmostEqual(p["c_sci_neg"], -2500.0)
        self.assertEqual(p["c_zero"], 0)
        self.assertEqual(p["c_neg_zero"], 0)
        self.assertIs(p["c_bool_caps"], True)
        self.assertIs(p["c_bool_no"], False)
        self.assertIsNone(p["c_null_tilde"])
        self.assertIsNone(p["c_null_caps"])

    def test_cli_overrides_take_precedence_over_env_vars(self) -> None:
        """Verify that CLI overrides take precedence over conflicting OPSCRYER_* environment variables."""
        env = {
            "OPSCRYER_PORT": "9000",
            "OPSCRYER_LOG_LEVEL": "WARNING",
            "OPSCRYER_NETWORK__TIMEOUT_SECONDS": "20.0",
        }
        with patch.dict(os.environ, env, clear=False):
            cfg = load_unified_config(cli_overrides={"port": 8100, "log_level": "DEBUG"})

            # Direct dictionary values reflect CLI overrides
            self.assertEqual(cfg["port"], 8100)
            self.assertEqual(cfg["log_level"], "DEBUG")

            # get_config_value returns CLI overrides, ignoring conflicting environment variables
            self.assertEqual(get_config_value("port"), 8100)
            self.assertEqual(get_config_value("server.port"), 8100)
            self.assertEqual(get_config_value("log_level"), "DEBUG")
            self.assertEqual(get_config_value("logging.level"), "DEBUG")

            # Non-overridden key falls through to dynamic environment variable
            self.assertEqual(get_config_value("network.timeout_seconds"), 20.0)
            self.assertEqual(get_config_value("timeout"), 20.0)


if __name__ == "__main__":
    unittest.main()

