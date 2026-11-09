# SPDX-License-Identifier: Apache-2.0
"""Registry completeness and real loopback frontend route coverage."""

import ast
import http.client
import inspect
import json
from pathlib import Path
import socketserver
import textwrap
import threading
import unittest
from urllib.parse import urlencode
import sys

_PKG_DIR = Path(__file__).resolve().parent.parent
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import opscryer_browser as browser
from route_registry import (
    API_V1_ROUTES, HTML_PORTAL_ROUTES, build_route_registry_summary,
)


class RouteRegistryTests(unittest.TestCase):
    def test_canonical_portals_and_metadata(self):
        expected = {
            "/", "/hub", "/chat", "/incidents", "/capacity", "/network",
            "/gitops", "/executive", "/simulator", "/playbooks", "/models",
            "/games", "/kb", "/jev-eval", "/storage", "/secops", "/metrics-live",
            "/adapters", "/docs", "/scale", "/tactical-deck",
        }
        self.assertIsInstance(HTML_PORTAL_ROUTES, tuple)
        self.assertEqual({route["path"] for route in HTML_PORTAL_ROUTES}, expected)
        self.assertEqual(len(HTML_PORTAL_ROUTES), len(expected))
        root = Path(browser.__file__).resolve().parent
        for route in (*HTML_PORTAL_ROUTES, *API_V1_ROUTES.values()):
            with self.subTest(route=route):
                self.assertIn(route["subsystem"], {"core", "live", "security", "portals"})
                self.assertTrue(root.joinpath(route["module"] + ".py").is_file())
                self.assertTrue(route.get("title", route.get("description")))

    def test_api_registry_matches_handler_query_table(self):
        # Inspect rather than execute the handler's local table: this catches
        # newly added endpoints and parameter changes as well as missing routes.
        tree = ast.parse(textwrap.dedent(inspect.getsource(browser._build_frontend_handler)))
        tables = [node.value for node in ast.walk(tree)
                  if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "allowed"
                          for target in node.targets)]
        self.assertEqual(len(tables), 1)
        table = tables[0]
        self.assertIsInstance(table, ast.Dict)
        expected = {}
        for key, value in zip(table.keys, table.values):
            # Empty parameter sets are written as set() in the handler.
            if isinstance(value, ast.Call):
                self.assertEqual(ast.unparse(value), "set()")
                params = set()
            else:
                params = ast.literal_eval(value)
            expected[ast.literal_eval(key)] = params
        self.assertEqual({path: route["allowed_params"]
                          for path, route in API_V1_ROUTES.items()}, expected)
        for path, route in API_V1_ROUTES.items():
            with self.subTest(path=path):
                self.assertTrue(path.startswith("/api/v1/"))
                self.assertIsInstance(route["allowed_params"], set)

    def test_summary_counts_and_independence(self):
        summary = build_route_registry_summary()
        self.assertEqual(summary["total_html_routes"], 21)
        self.assertEqual(summary["total_api_routes"], 63)
        self.assertEqual(summary["by_subsystem"], {
            "core": {"html_routes": 0, "api_routes": 12},
            "live": {"html_routes": 1, "api_routes": 9},
            "security": {"html_routes": 0, "api_routes": 21},
            "portals": {"html_routes": 20, "api_routes": 21},
        })
        json.dumps(summary)
        summary["by_subsystem"]["core"]["api_routes"] = -1
        self.assertEqual(build_route_registry_summary()["by_subsystem"]["core"]["api_routes"], 12)


class RouteRegistryHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.TCPServer(
            ("127.0.0.1", 0), browser._build_frontend_handler())
        cls.addClassCleanup(cls.server.server_close)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.addClassCleanup(cls.stop_server)

    @classmethod
    def stop_server(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def request(self, path):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=10)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read()
            if response.getheader("Content-Length") is not None:
                self.assertEqual(int(response.getheader("Content-Length")), len(body))
            return response.status, response.getheader("Content-Type"), body
        finally:
            connection.close()

    def test_every_html_portal_is_served(self):
        for route in HTML_PORTAL_ROUTES:
            with self.subTest(path=route["path"]):
                status, content_type, body = self.request(route["path"])
                self.assertEqual(status, 200)
                self.assertEqual(content_type, "text/html; charset=utf-8")
                self.assertIn("<html", body.decode("utf-8").lower())

    def test_every_api_endpoint_is_served(self):
        for path in API_V1_ROUTES:
            with self.subTest(path=path):
                if path == "/api/v1/events/stream":
                    status, content_type, body = self.request(path + "?max_events=1")
                    self.assertEqual(status, 200)
                    self.assertEqual(content_type, "text/event-stream; charset=utf-8")
                    self.assertTrue(len(body) >= 0)
                    continue
                if path == "/api/v1/graph/deflect-ticket":
                    connection = http.client.HTTPConnection(*self.server.server_address, timeout=10)
                    try:
                        body_bytes = json.dumps({"ticket_title": "deploy 3-tier scaffold"}).encode("utf-8")
                        connection.request("POST", path, body=body_bytes,
                                           headers={"Content-Length": str(len(body_bytes)),
                                                    "Content-Type": "application/json"})
                        response = connection.getresponse()
                        body = response.read()
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.getheader("Content-Type"), "application/json; charset=utf-8")
                        self.assertIsInstance(json.loads(body), dict)
                    finally:
                        connection.close()
                    continue
                # Provide required parameters where needed; other endpoints use offline defaults.
                if path in {"/api/v1/chat-concierge", "/api/v1/live-cluster-ask"}:
                    query = {"q": "What is the cluster health?"}
                elif path == "/api/v1/graph/drilldown":
                    query = {"node_id": "root-company"}
                elif path == "/api/v1/graph/shortest-path":
                    query = {"source_id": "root-company", "target_id": "proc-demo-cicd"}
                elif path == "/api/v1/graph/search":
                    query = {"q": "scaffold"}
                else:
                    query = {}
                target = path + ("?" + urlencode(query) if query else "")
                status, content_type, body = self.request(target)
                self.assertEqual(status, 200)
                self.assertEqual(content_type, "application/json; charset=utf-8")
                self.assertIsInstance(json.loads(body), dict)

    def test_every_api_endpoint_rejects_unknown_query_parameters(self):
        for path in API_V1_ROUTES:
            with self.subTest(path=path):
                status, content_type, body = self.request(path + "?unknown_parameter=1")
                self.assertEqual(status, 400)
                self.assertEqual(content_type, "application/json; charset=utf-8")
                self.assertIn("error", json.loads(body))


if __name__ == "__main__":
    unittest.main()
