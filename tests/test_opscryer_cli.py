# SPDX-License-Identifier: Apache-2.0
"""Command dispatch, report output and safe argument errors for the suite CLI."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import opscryer_cli as cli
import route_registry


class OpsCryerCLITests(unittest.TestCase):
    def invoke(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                code = cli.main(argv)
            except SystemExit as error:
                code = error.code
        return code, stdout.getvalue(), stderr.getvalue()

    def test_all_commands_in_text_and_json(self):
        cases = [
            (["doctor"], "runtime_capabilities"),
            (["metrics"], "telemetry_mode"),
            (["routes"], "html_portals"),
            (["adapters"], "adapters"),
            (["ask", "--question", "How is the cluster?"], "plain_english_answer"),
        ]
        for argv, field in cases:
            for json_mode in (False, True):
                with self.subTest(command=argv[0], json=json_mode):
                    code, output, errors = self.invoke(argv + (["--json"] if json_mode else []))
                    self.assertEqual(code, 0)
                    self.assertEqual(errors, "")
                    if json_mode:
                        self.assertIn(field, json.loads(output))
                    else:
                        self.assertTrue(output.startswith("OpsCryer " + argv[0] + "\n"))
                        self.assertIn(field + ":", output)

    def test_doctor_calls_all_readiness_providers(self):
        with patch.object(cli.platform_compat, "detect_runtime_capabilities", return_value={"ready": True}) as runtime, \
             patch.object(cli.opscryer, "get_package_architecture_map", return_value={"core": {}}) as packages, \
             patch.object(cli.route_registry, "build_route_registry_summary", return_value={"total_html_routes": 18}) as routes:
            code, output, _ = self.invoke(["doctor", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output), {
            "runtime_capabilities": {"ready": True},
            "package_architecture": {"core": {}},
            "route_registry": {"total_html_routes": 18},
        })
        for provider in (runtime, packages, routes):
            provider.assert_called_once_with()

    def test_metrics_live_is_explicit(self):
        for mode in ([], ["--json"]):
            for live in (False, True):
                with self.subTest(mode=mode, live=live), patch.object(
                    cli.live_metrics_poller, "poll_live_cluster_metrics", return_value={"health": "ok"}
                ) as poll:
                    code, _, _ = self.invoke(["metrics", *mode, *(["--live"] if live else [])])
                    self.assertEqual(code, 0)
                    poll.assert_called_once_with(allow_kubectl=live)

    def test_routes_lists_every_registered_path(self):
        for mode in ([], ["--json"]):
            with self.subTest(mode=mode), patch.object(
                cli.route_registry, "build_route_registry_summary",
                wraps=route_registry.build_route_registry_summary,
            ) as summary:
                code, output, _ = self.invoke(["routes", *mode])
                self.assertEqual(code, 0)
                summary.assert_called_once_with()
                paths = [row["path"] for row in route_registry.HTML_PORTAL_ROUTES]
                paths.extend(route_registry.API_V1_ROUTES)
                for path in paths:
                    self.assertIn(path, output)
                if mode:
                    report = json.loads(output)
                    self.assertEqual(len(report["html_portals"]), report["total_html_routes"])
                    self.assertEqual(len(report["api_endpoints"]), report["total_api_routes"])

    def test_adapter_and_persona_options_are_forwarded(self):
        for mode in ([], ["--json"]):
            for adapter in (None, "local_host"):
                with patch.object(cli.environment_adapters, "build_adapter_compatibility_catalog", return_value={}) as build:
                    argv = ["adapters", *mode]
                    if adapter:
                        argv += ["--adapter", adapter]
                    self.assertEqual(self.invoke(argv)[0], 0)
                    build.assert_called_once_with(adapter)
            for persona in (None, "sre"):
                with patch.object(cli.ticket_chat_portal, "ask_concierge_chat", return_value={}) as ask:
                    argv = ["ask", "--question", "Cluster health?", *mode]
                    if persona:
                        argv += ["--persona", persona]
                    self.assertEqual(self.invoke(argv)[0], 0)
                    ask.assert_called_once_with("Cluster health?", persona=persona or "household_user")

    def test_invalid_requests_have_fixed_error_and_no_report(self):
        cases = [[], ["untrusted-input"], ["doctor", "extra"],
                 ["doctor", "--unknown=untrusted-input"], ["metrics", "--live=yes"],
                 ["routes", "--adapter", "local_host"], ["adapters", "--adapter"],
                 ["adapters", "--adapter", "untrusted-input"], ["ask"],
                 ["ask", "--question"], ["ask", "--question", ""],
                 ["ask", "--question", "   "],
                 ["ask", "--question", "hello", "--persona", "untrusted-input"],
                 ["ask", "--quest", "hello"], ["doctor", "--js"]]
        for argv in cases:
            with self.subTest(argv=argv):
                self.assertEqual(self.invoke(argv), (2, "", cli.INVALID_REQUEST + "\n"))

    def test_provider_validation_error_does_not_echo_details(self):
        with patch.object(cli.ticket_chat_portal, "ask_concierge_chat", side_effect=ValueError("untrusted-input")):
            self.assertEqual(self.invoke(["ask", "--question", "hello"]),
                             (2, "", cli.INVALID_REQUEST + "\n"))

    def test_output_uses_telemetry_sanitizer(self):
        # Construct sensitive fixtures at runtime so source files remain clean.
        wan = ".".join(("8", "8", "4", "4"))
        mac = ":".join(("AA", "BB", "CC", "DD", "EE", "FF"))
        for mode in ([], ["--json"]):
            with patch.object(cli.live_metrics_poller, "poll_live_cluster_metrics", return_value={
                "wan": wan, "device": mac, "lan": "172.20.1.2",
            }):
                code, output, _ = self.invoke(["metrics", *mode])
            self.assertEqual(code, 0)
            self.assertNotIn(wan, output)
            self.assertNotIn(mac, output)
            self.assertIn("203.0.113.1", output)
            self.assertIn("AA:BB:CC:XX:XX:XX", output)
            self.assertIn("172.20.1.2", output)

    def test_script_exit_codes_and_help(self):
        root = Path(__file__).resolve().parents[1]
        for argv, expected in ((["routes", "--json"], 0), (["untrusted-input"], 2), (["--help"], 0)):
            with self.subTest(argv=argv):
                result = subprocess.run([sys.executable, str(root / "opscryer_cli.py"), *argv],
                                        cwd=root, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, expected)
                if expected == 2:
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, cli.INVALID_REQUEST + "\n")
                else:
                    self.assertEqual(result.stderr, "")
                    self.assertTrue(result.stdout)


if __name__ == "__main__":
    unittest.main()
