# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for Model Context Protocol (MCP) JSON-RPC 2.0 Server Bridge."""

from __future__ import annotations

import json
import unittest

from mcp_bridge import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    PROTOCOL_VERSION,
    SERVER_NAME,
    SERVER_VERSION,
    UNAUTHORIZED_MUTATION,
    dispatch_jsonrpc_request,
    handle_mcp_api,
)


class MCPProtocolTests(unittest.TestCase):
    """Test pure-stdlib JSON-RPC 2.0 framing and error codes."""

    def test_parse_error(self):
        resp = dispatch_jsonrpc_request("not-valid-json-{{{")
        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertIsNone(resp["id"])
        self.assertEqual(resp["error"]["code"], PARSE_ERROR)

    def test_invalid_request_missing_version(self):
        req = {"id": 1, "method": "ping"}
        resp = dispatch_jsonrpc_request(req)
        self.assertEqual(resp["error"]["code"], INVALID_REQUEST)

    def test_invalid_request_missing_method(self):
        req = {"jsonrpc": "2.0", "id": 1}
        resp = dispatch_jsonrpc_request(req)
        self.assertEqual(resp["error"]["code"], INVALID_REQUEST)

    def test_method_not_found(self):
        req = {"jsonrpc": "2.0", "id": 10, "method": "unsupported/method"}
        resp = dispatch_jsonrpc_request(req)
        self.assertEqual(resp["id"], 10)
        self.assertEqual(resp["error"]["code"], METHOD_NOT_FOUND)

    def test_mcp_initialize(self):
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        }
        resp = dispatch_jsonrpc_request(req)
        self.assertEqual(resp["id"], 1)
        res = resp["result"]
        self.assertEqual(res["protocolVersion"], PROTOCOL_VERSION)
        self.assertEqual(res["serverInfo"]["name"], SERVER_NAME)
        self.assertEqual(res["serverInfo"]["version"], SERVER_VERSION)
        self.assertIn("tools", res["capabilities"])

    def test_mcp_ping(self):
        req = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
        resp = dispatch_jsonrpc_request(req)
        self.assertEqual(resp["id"], 2)
        self.assertEqual(resp["result"], {})

    def test_mcp_tools_list(self):
        req = {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
        resp = dispatch_jsonrpc_request(req)
        self.assertEqual(resp["id"], 3)
        tools = resp["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        self.assertIn("query_graph", tool_names)
        self.assertIn("get_system_context", tool_names)
        self.assertIn("evaluate_jev", tool_names)
        self.assertIn("search_ocsf_incidents", tool_names)
        self.assertIn("preview_remediation_dry_run", tool_names)
        self.assertIn("stage_action_card", tool_names)


class MCPAirlockToolExecutionTests(unittest.TestCase):
    """Test Two-Tier Capability Airlock: Tier 1 open recon with OPSEC vs Tier 2 airlocked staging."""

    def test_tier1_query_graph(self):
        req = {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "query_graph",
                "arguments": {"query": "gpu", "limit": 5},
            },
        }
        resp = dispatch_jsonrpc_request(req)
        self.assertNotIn("error", resp)
        self.assertEqual(resp["id"], 101)
        res = resp["result"]
        self.assertFalse(res["isError"])
        self.assertTrue(len(res["content"]) > 0)
        self.assertIn("hw-demo-gpu-node", res["content"][0]["text"])

    def test_tier1_get_system_context(self):
        req = {
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {
                "name": "get_system_context",
                "arguments": {"tier": "both"},
            },
        }
        resp = dispatch_jsonrpc_request(req)
        self.assertNotIn("error", resp)
        res = resp["result"]
        self.assertFalse(res["isError"])
        text = res["content"][0]["text"]
        # Asserts verified homelab GPU specs (40 GB VRAM)
        self.assertIn("RTX 3080", text)
        structured = res["structured_result"]
        actual_models = [g["model"] for g in structured["gpu_inventory"]]
        self.assertNotIn("NVIDIA GeForce RTX 5080", actual_models)

    def test_tier1_evaluate_jev(self):
        req = {
            "jsonrpc": "2.0",
            "id": 103,
            "method": "tools/call",
            "params": {
                "name": "evaluate_jev",
                "arguments": {"ticket_title": "Scaffold new 3-tier web service", "min_confidence": 0.85},
            },
        }
        resp = dispatch_jsonrpc_request(req)
        self.assertNotIn("error", resp)
        res = resp["result"]
        structured = res["structured_result"]
        self.assertIn("route", structured)
        self.assertIn("traversal_steps", structured)

    def test_tier1_evaluate_jev_empty_title_rejected(self):
        req = {
            "jsonrpc": "2.0",
            "id": 104,
            "method": "tools/call",
            "params": {
                "name": "evaluate_jev",
                "arguments": {"ticket_title": "   "},
            },
        }
        resp = dispatch_jsonrpc_request(req)
        self.assertEqual(resp["error"]["code"], INVALID_PARAMS)

    def test_tier1_search_ocsf_incidents(self):
        req = {
            "jsonrpc": "2.0",
            "id": 105,
            "method": "tools/call",
            "params": {
                "name": "search_ocsf_incidents",
                "arguments": {"limit": 5},
            },
        }
        resp = dispatch_jsonrpc_request(req)
        self.assertNotIn("error", resp)
        res = resp["result"]
        self.assertIn("matched_count", res["structured_result"])

    def test_tier1_preview_remediation_dry_run(self):
        req = {
            "jsonrpc": "2.0",
            "id": 106,
            "method": "tools/call",
            "params": {
                "name": "preview_remediation_dry_run",
                "arguments": {
                    "action_type": "restart_node",
                    "target_node_id": "nodegamma03",
                },
            },
        }
        resp = dispatch_jsonrpc_request(req)
        self.assertNotIn("error", resp)
        res = resp["result"]
        structured = res["structured_result"]
        self.assertEqual(structured["status"], "DRY_RUN_COMPLETED")
        self.assertIn("worrisomeness", structured)

    def test_tier2_stage_action_card(self):
        req = {
            "jsonrpc": "2.0",
            "id": 201,
            "method": "tools/call",
            "params": {
                "name": "stage_action_card",
                "arguments": {
                    "action_type": "restart_node",
                    "target_node_id": "nodegamma03",
                    "parameters": {"grace_period": 30},
                    "ttl_seconds": 1800.0,
                },
            },
        }
        resp = dispatch_jsonrpc_request(req)
        self.assertNotIn("error", resp)
        res = resp["result"]
        card = res["structured_result"]
        self.assertEqual(card["status"], "STAGED")
        self.assertIn("action_id", card)
        self.assertIn("parameters_sha256", card)
        self.assertIn("nonce", card)

    def test_unauthorized_direct_mutations_blocked_closed(self):
        """Any attempt to execute mutations directly without staging an Action Card must return -32001."""
        forbidden_tools = [
            "execute_action",
            "apply_action",
            "delete_node",
            "reboot_host",
            "drain_traffic",
            "restart_node",
            "kill_pod",
            "mutate_cluster",
        ]
        for f_tool in forbidden_tools:
            with self.subTest(tool=f_tool):
                req = {
                    "jsonrpc": "2.0",
                    "id": 999,
                    "method": "tools/call",
                    "params": {
                        "name": f_tool,
                        "arguments": {"node_id": "control-plane-01"},
                    },
                }
                resp = dispatch_jsonrpc_request(req)
                self.assertIn("error", resp)
                self.assertEqual(resp["error"]["code"], UNAUTHORIZED_MUTATION)
                self.assertIn("Action Card", resp["error"]["message"])


class MCPHTTPHandlerTests(unittest.TestCase):
    """Test HTTP gateway handler for /api/v1/mcp endpoint."""

    def test_get_loopback_descriptor(self):
        status, desc = handle_mcp_api("/api/v1/mcp", method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(desc["endpoint"], "/api/v1/mcp")
        self.assertEqual(desc["status"], "active")
        self.assertEqual(desc["protocol"], "JSON-RPC 2.0 / MCP")
        self.assertIn("tools", desc["capabilities"])
        self.assertTrue(desc["capabilities"]["two_tier_airlock"])

    def test_post_gateway_success(self):
        body = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "initialize",
            "params": {},
        }
        status, resp = handle_mcp_api("/api/v1/mcp", method="POST", body=body)
        self.assertEqual(status, 200)
        self.assertEqual(resp["id"], 42)
        self.assertEqual(resp["result"]["serverInfo"]["name"], SERVER_NAME)

    def test_post_gateway_missing_body(self):
        status, resp = handle_mcp_api("/api/v1/mcp", method="POST", body=None)
        self.assertEqual(status, 400)
        self.assertEqual(resp["code"], "MISSING_BODY")

    def test_post_gateway_string_body(self):
        body_str = json.dumps({"jsonrpc": "2.0", "id": 55, "method": "ping"})
        status, resp = handle_mcp_api("/api/v1/mcp", method="POST", body=body_str)
        self.assertEqual(status, 200)
        self.assertEqual(resp["id"], 55)
        self.assertEqual(resp["result"], {})


if __name__ == "__main__":
    unittest.main()
