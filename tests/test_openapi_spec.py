# SPDX-License-Identifier: Apache-2.0
"""Contract coverage and HTTP integration for the API reference."""

import ast
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
import io
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen

_PKG_DIR = Path(__file__).resolve().parent.parent
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from openapi_spec import build_openapi_v3_spec, main, render_api_docs_html
from opscryer_browser import _build_frontend_handler


class OpenAPIContractTests(unittest.TestCase):
    def test_scale_node_count_contract(self):
        operation = build_openapi_v3_spec()["paths"]["/api/v1/scale-benchmark"]["get"]
        self.assertEqual(operation["parameters"], [{
            "name": "nodes", "in": "query", "required": False,
            "description": "Synthetic node count; omit to benchmark 100, 500, and 1500 nodes.",
            "schema": {"type": "integer", "minimum": 10, "maximum": 5000},
        }])

    def run_cli(self, *args):
        root = Path(__file__).resolve().parents[1]
        return subprocess.run(
            [sys.executable, str(root / "openapi_spec.py"), *args],
            cwd=root, capture_output=True, text=True, timeout=10,
        )

    def test_cli_json_export(self):
        result = self.run_cli("--json")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), build_openapi_v3_spec())

    def test_cli_invalid_arguments_exit_two_without_input_reflection(self):
        marker = "private-input-marker"
        cases = (
            ["--" + marker], [marker], ["--port", marker],
            ["--port", "-1"], ["--port", "0"], ["--port", "65536"],
            ["--port"], ["--json", "--serve"], ["--j"],
        )
        for args in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("error:", result.stderr)
                self.assertNotIn(marker, result.stdout + result.stderr)

    def test_cli_export_and_default_serving_port(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["--json"]), 0)
        self.assertEqual(json.loads(output.getvalue()), build_openapi_v3_spec())
        with patch("openapi_spec.ThreadingHTTPServer") as server, redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--serve"]), 0)
            self.assertEqual(server.call_args.args[0], ("127.0.0.1", 8106))
            server.return_value.__enter__.return_value.serve_forever.assert_called_once()

    def test_contract_matches_browser_routes_and_parameters(self):
        tree = ast.parse((Path(__file__).resolve().parents[1] / "opscryer_browser.py")
                         .read_text(encoding="utf-8"))
        assignment = next(node for node in ast.walk(tree)
                          if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == "allowed"
                                  for target in node.targets))
        allowed = {ast.literal_eval(key):
                   set() if isinstance(value, ast.Call) else set(ast.literal_eval(value))
                   for key, value in zip(assignment.value.keys, assignment.value.values)}
        spec = build_openapi_v3_spec()
        self.assertEqual(spec["openapi"], "3.1.0")
        self.assertTrue(spec["paths"])
        self.assertEqual(set(spec["paths"]), set(allowed))
        operation_ids = set()
        for path, names in allowed.items():
            operation = spec["paths"][path]["get"]
            self.assertEqual({p["name"] for p in operation["parameters"]}, names)
            self.assertIn("200", operation["responses"])
            operation_ids.add(operation["operationId"])
        self.assertEqual(len(operation_ids), len(allowed))
        spec["paths"].clear()
        self.assertEqual(len(build_openapi_v3_spec()["paths"]), len(allowed))

    def test_portal_lists_every_endpoint_and_input(self):
        html = render_api_docs_html()
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        for path, item in build_openapi_v3_spec()["paths"].items():
            self.assertIn(f'data-path="{path}"', html)
            for parameter in item["get"]["parameters"]:
                self.assertIn(f'name="{parameter["name"]}"', html)
        self.assertIn("await fetch(", html)
        self.assertNotIn('<script src=', html)

    def test_http_docs_contract_and_rejected_queries(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), _build_frontend_handler()) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                with urlopen(base + "/docs", timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers.get_content_type(), "text/html")
                    self.assertEqual(response.read().decode(), render_api_docs_html())
                with urlopen(base + "/api/v1/openapi.json", timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers.get_content_type(), "application/json")
                    self.assertEqual(json.load(response), build_openapi_v3_spec())
                for path in ("/docs?x=1", "/docs?x=", "/docs?x=1&x=2",
                             "/api/v1/openapi.json?x=1", "/api/v1/openapi.json?x=",
                             "/api/v1/openapi.json?x=1&x=2",
                             "/api/v1/openapi.json?%GG=1"):
                    with self.assertRaises(HTTPError) as caught:
                        urlopen(base + path, timeout=5)
                    self.assertEqual(caught.exception.code, 400)
                    caught.exception.close()
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
