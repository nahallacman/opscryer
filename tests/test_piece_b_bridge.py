# SPDX-License-Identifier: Apache-2.0
"""Unit and integration tests for Piece B HTTP Bridge & POST Dispatcher Mount."""

from __future__ import annotations

import http.client
import json
import socketserver
import threading
import unittest
from typing import Any
from urllib.parse import urlencode

from opscryer_backend import KnowledgeGraphBackendEngine
from opscryer_browser import _build_frontend_handler


class TestPieceBBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.TCPServer(
            ("127.0.0.1", 0), _build_frontend_handler())
        cls.addClassCleanup(cls.server.server_close)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.addClassCleanup(cls.stop_server)

    @classmethod
    def stop_server(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def request(self, method: str, path: str, body: Any = None,
                headers: dict[str, str] | None = None) -> tuple[int, str, Any]:
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=10)
        req_headers = dict(headers or {})
        raw_body: bytes | None = None
        if body is not None:
            if isinstance(body, (dict, list)):
                raw_body = json.dumps(body).encode("utf-8")
                req_headers.setdefault("Content-Type", "application/json")
            elif isinstance(body, str):
                raw_body = body.encode("utf-8")
            elif isinstance(body, bytes):
                raw_body = body
            req_headers.setdefault("Content-Length", str(len(raw_body) if raw_body is not None else 0))

        try:
            connection.request(method, path, body=raw_body, headers=req_headers)
            response = connection.getresponse()
            raw_data = response.read()
            content_type = response.getheader("Content-Type", "")
            try:
                parsed_data = json.loads(raw_data.decode("utf-8"))
            except Exception:
                parsed_data = raw_data
            return response.status, content_type, parsed_data
        finally:
            connection.close()

    def test_get_contract_endpoint(self):
        status, ct, data = self.request("GET", "/api/v1/contract")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        self.assertIsInstance(data, dict)
        self.assertIn("openapi", data)
        self.assertEqual(data["openapi"], "3.1.0")

    def test_get_graph_search_endpoint(self):
        status, ct, data = self.request("GET", "/api/v1/graph/search?q=scaffold&limit=5")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        self.assertIsInstance(data, dict)
        self.assertIn("results", data)
        self.assertIsInstance(data["results"], list)

    def test_get_graph_search_missing_q_returns_400(self):
        status, ct, data = self.request("GET", "/api/v1/graph/search")
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_get_graph_drilldown_endpoint(self):
        status, ct, data = self.request("GET", "/api/v1/graph/drilldown?node_id=root-company")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("node", {}).get("id"), "root-company")
        self.assertIn("children", data)

    def test_get_graph_drilldown_with_id_alias(self):
        status, ct, data = self.request("GET", "/api/v1/graph/drilldown?id=root-company")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("node", {}).get("id"), "root-company")
        self.assertIn("children", data)

    def test_get_graph_drilldown_unknown_node_returns_404(self):
        status, ct, data = self.request("GET", "/api/v1/graph/drilldown?node_id=nonexistent-node-12345")
        self.assertEqual(status, 404)
        self.assertIn("error", data)

    def test_get_graph_drilldown_missing_param_returns_400(self):
        status, ct, data = self.request("GET", "/api/v1/graph/drilldown")
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_get_graph_shortest_path_endpoint(self):
        status, ct, data = self.request(
            "GET", "/api/v1/graph/shortest-path?source_id=team-demo-platform&target_id=proc-demo-cicd")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        self.assertIsInstance(data, dict)
        self.assertTrue(data.get("path_found"))
        self.assertIn("path_ids", data)
        self.assertIn("hop_count", data)

    def test_get_graph_shortest_path_aliases(self):
        status, ct, data = self.request(
            "GET", "/api/v1/graph/shortest-path?source=team-demo-platform&target=proc-demo-cicd")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        self.assertIsInstance(data, dict)
        self.assertTrue(data.get("path_found"))
        self.assertIn("path_ids", data)

    def test_get_graph_shortest_path_missing_param_returns_400(self):
        status, ct, data = self.request("GET", "/api/v1/graph/shortest-path?source_id=team-demo-platform")
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_get_graph_jev_tree_endpoint(self):
        status, ct, data = self.request("GET", "/api/v1/graph/jev-tree")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        self.assertIsInstance(data, dict)
        self.assertIn("root_node_id", data)
        self.assertIn("nodes", data)

    def test_post_deflect_ticket_golden_path(self):
        payload = {"ticket_title": "deploy 3 tier project scaffold", "min_confidence": 0.80}
        status, ct, data = self.request("POST", "/api/v1/graph/deflect-ticket", body=payload)
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("schema_version"), "1.0-ticket-deflection")
        self.assertIn("route", data)

    def test_post_deflect_ticket_ticket_text_alias(self):
        payload = {"ticket_text": "deploy 3 tier project scaffold"}
        status, ct, data = self.request("POST", "/api/v1/graph/deflect-ticket", body=payload)
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        self.assertEqual(data.get("schema_version"), "1.0-ticket-deflection")

    def test_post_deflect_ticket_missing_content_length_returns_400(self):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=10)
        try:
            connection.request("POST", "/api/v1/graph/deflect-ticket", body=b"{}")
            response = connection.getresponse()
            body = json.loads(response.read().decode("utf-8"))
            self.assertEqual(response.status, 400)
            self.assertIn("error", body)
        finally:
            connection.close()

    def test_post_deflect_ticket_invalid_json_returns_400(self):
        status, ct, data = self.request(
            "POST", "/api/v1/graph/deflect-ticket", body="{invalid json", headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_post_deflect_ticket_non_dict_body_returns_400(self):
        status, ct, data = self.request("POST", "/api/v1/graph/deflect-ticket", body=[1, 2, 3])
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_post_deflect_ticket_rejects_query_string(self):
        status, ct, data = self.request(
            "POST", "/api/v1/graph/deflect-ticket?extra=1", body={"ticket_title": "test"})
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_post_to_get_endpoint_returns_405(self):
        status, ct, data = self.request("POST", "/api/v1/graph/search", body={"q": "scaffold"})
        self.assertEqual(status, 405)
        self.assertIn("error", data)
        self.assertEqual(data.get("allowed_method"), "GET")

    def test_post_to_unknown_endpoint_returns_404(self):
        status, ct, data = self.request("POST", "/unknown-non-api-route", body={})
        self.assertEqual(status, 404)

    def test_dependency_injection_of_backend_engine(self):
        engine = KnowledgeGraphBackendEngine()
        handler_cls = _build_frontend_handler(backend_engine=engine)
        self.assertIs(handler_cls._backend_engine, engine)
        self.assertIs(handler_cls._get_backend_engine(), engine)


if __name__ == "__main__":
    unittest.main()
