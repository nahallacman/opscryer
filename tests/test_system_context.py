# SPDX-License-Identifier: Apache-2.0
"""Unit and HTTP endpoint tests for Dual-Tier AI System Context Subsystem."""

from __future__ import annotations

import http.client
import json
import socketserver
import threading
import unittest
from typing import Any

from opscryer_browser import _build_frontend_handler
import system_context


class TestSystemContext(unittest.TestCase):
    def test_schema_version_and_contract(self):
        ctx = system_context.build_system_context()
        self.assertEqual(ctx["schema_version"], "1.0-system-context")
        self.assertIn("gpu_inventory", ctx)
        self.assertIn("scale_down_workloads", ctx)
        self.assertIn("active_kb_runbooks", ctx)
        self.assertIn("ast_jump_references", ctx)
        self.assertIn("hardware_inventory", ctx)

    def test_verified_gpu_inventory(self):
        gpus = system_context.get_verified_gpu_inventory()
        self.assertEqual(gpus["total_gpu_count"], 4)
        self.assertEqual(gpus["total_vram_gb"], 40)
        self.assertEqual(len(gpus["gpus"]), 4)

        models = [g["model"] for g in gpus["gpus"]]
        self.assertEqual(models.count("NVIDIA GeForce RTX 3080"), 1)
        self.assertEqual(models.count("NVIDIA GeForce RTX 3070 Ti"), 1)
        self.assertEqual(models.count("NVIDIA GeForce GTX 1080 Ti"), 2)

        # Anti-hallucination assertions
        denylist = gpus["hallucinated_gpu_denylist"]
        self.assertIn("RTX 5080", denylist)
        self.assertIn("RTX 4090", denylist)
        self.assertIn("H100", denylist)
        self.assertIn("A100", denylist)
        for bad_gpu in denylist:
            self.assertNotIn(bad_gpu, models)

    def test_homelab_node_hardware(self):
        hw = system_context.get_homelab_hardware_inventory()
        self.assertEqual(hw["total_nodes"], 3)
        self.assertEqual(hw["total_cpu_cores"], 28)
        self.assertEqual(hw["total_ram_gb"], 112)
        node_names = {n["node_name"] for n in hw["nodes"]}
        self.assertEqual(node_names, {"nodegamma03", "nodebeta02", "nodealpha01"})

    def test_intentional_scale_down_workloads(self):
        workloads = system_context.get_intentional_scale_down_workloads()
        self.assertEqual(len(workloads), 7)
        for wk in workloads:
            self.assertEqual(wk["replicas"], 0)
            self.assertTrue(wk["reason"].startswith("Intentionally scaled to 0/0"))

    def test_canonical_kb_runbooks(self):
        runbooks = system_context.get_canonical_kb_runbooks()
        self.assertEqual(len(runbooks), 5)
        runbook_ids = [rb["id"] for rb in runbooks]
        self.assertEqual(runbook_ids, ["kb-db-001", "kb-game-002", "kb-git-003", "kb-sec-004", "kb-stor-005"])

    def test_ast_jump_references(self):
        jumps = system_context.build_ast_jump_references()
        self.assertIsInstance(jumps, dict)
        self.assertIn("system_context", jumps)
        for mod, syms in jumps.items():
            self.assertIsInstance(syms, list)
            for s in syms:
                self.assertIn("symbol", s)
                self.assertIn("kind", s)
                self.assertIn("file", s)
                self.assertIn("line_range", s)
                self.assertIn("jump_ref", s)
                self.assertIn("correlated_graph_node_id", s)

    def test_dual_tier_payload_options(self):
        ctx_both = system_context.build_system_context(tier="both")
        self.assertIn("local_gpu_anti_lost_pack", ctx_both)
        self.assertIn("frontier_token_saver_brief", ctx_both)

        ctx_local = system_context.build_system_context(tier="local_gpu")
        self.assertIn("local_gpu_anti_lost_pack", ctx_local)
        self.assertNotIn("frontier_token_saver_brief", ctx_local)

        ctx_frontier = system_context.build_system_context(tier="frontier")
        self.assertNotIn("local_gpu_anti_lost_pack", ctx_frontier)
        self.assertIn("frontier_token_saver_brief", ctx_frontier)

    def test_validate_model_output_against_context(self):
        # Nominal test
        nominal = "We should inspect the logs of nodegamma03 and check GPU RTX 3080."
        res = system_context.validate_model_output_against_context(nominal)
        self.assertTrue(res["passed"])
        self.assertEqual(res["status"], "NOMINAL")

        # Hallucination test
        hallucination = "Let us schedule the LLM on our cluster RTX 5080 GPU."
        res_hal = system_context.validate_model_output_against_context(hallucination)
        self.assertFalse(res_hal["passed"])
        self.assertEqual(res_hal["status"], "HALLUCINATING")
        self.assertIn("RTX 5080", res_hal["hallucinated_gpus"])

        # Unauthorized scale-up test
        scale_up = "Run kubectl scale deployment agentic-agent-developer --replicas=1"
        res_scale = system_context.validate_model_output_against_context(scale_up)
        self.assertFalse(res_scale["passed"])
        self.assertIn("ai-infra/agentic-agent-developer", res_scale["intentional_scale_down_violations"])


class TestSystemContextHTTP(unittest.TestCase):
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

    def request(self, method: str, path: str, body: Any = None) -> tuple[int, str, Any]:
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=10)
        req_headers = {}
        raw_body = None
        if body is not None:
            raw_body = json.dumps(body).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
            req_headers["Content-Length"] = str(len(raw_body))
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

    def test_http_get_system_context_default(self):
        status, ct, data = self.request("GET", "/api/v1/system-context")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        self.assertEqual(data["schema_version"], "1.0-system-context")
        self.assertEqual(len(data["gpu_inventory"]), 4)
        self.assertEqual(len(data["scale_down_workloads"]), 7)
        self.assertEqual(len(data["active_kb_runbooks"]), 5)

    def test_http_get_system_context_with_query_params(self):
        status, ct, data = self.request(
            "GET", "/api/v1/system-context?tier=local_gpu&target_gpu=NVIDIA+GeForce+RTX+3080")
        self.assertEqual(status, 200)
        self.assertIn("local_gpu_anti_lost_pack", data)
        self.assertNotIn("frontier_token_saver_brief", data)

    def test_http_get_system_context_rejects_unknown_params(self):
        status, ct, data = self.request("GET", "/api/v1/system-context?unknown_param=123")
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_http_post_system_context_returns_405(self):
        status, ct, data = self.request("POST", "/api/v1/system-context", body={})
        self.assertEqual(status, 405)
        self.assertEqual(data.get("allowed_method"), "GET")


if __name__ == "__main__":
    unittest.main()
