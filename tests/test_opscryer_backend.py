# SPDX-License-Identifier: Apache-2.0
"""Contract, retrieval, API and architectural tests for standalone Piece B."""

import ast
from copy import deepcopy
import importlib.util
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
from time import perf_counter
import unittest
from unittest.mock import patch

import opscryer_backend as backend


ROOT = Path(__file__).resolve().parents[1]


def node(node_id, children=(), domain="company_org", summary=""):
    return {"id": node_id, "label": node_id, "kind": "custom_entity", "domain": domain,
            "summary": summary, "primary_url": "https://example.org/" + node_id,
            "drilldown_children": list(children)}


def graph(nodes, edges=()):
    return {"schema_version": backend.CONTRACT_VERSION, "nodes": nodes, "edges": list(edges)}


class SpatialContractTests(unittest.TestCase):
    def setUp(self):
        self.catalog = graph([node("a", ["b"]), node("b")])

    def test_shared_sample_and_custom_kinds_are_valid(self):
        sample = json.loads((ROOT / "sample-graph-data.json").read_text(encoding="utf-8"))
        self.assertEqual(backend.validate_spatial_graph_contract(sample), [])
        self.assertEqual(backend.validate_spatial_graph_contract(self.catalog), [])
        self.assertEqual(backend.KnowledgeGraphBackendEngine(self.catalog).catalog()["nodes"][0]["kind"],
                         "custom_entity")

    def test_malformed_catalogs_are_rejected_without_crashing(self):
        candidates = [None, [], {}, {**self.catalog, "schema_version": "wrong"},
                      {**self.catalog, "nodes": []}, {**self.catalog, "nodes": [None]},
                      {**self.catalog, "edges": {}}, {**self.catalog, "edges": [None]},
                      {**self.catalog, "node_count": True}, {**self.catalog, "edge_count": 7}]
        for field, value in (("id", []), ("label", ""), ("kind", None), ("domain", []),
                             ("summary", 1), ("primary_url", False), ("drilldown_children", {}),
                             ("drilldown_children", [[]]), ("drilldown_children", ["b", "b"]),
                             ("drilldown_children", ["missing"])):
            candidate = deepcopy(self.catalog)
            candidate["nodes"][0][field] = value
            candidates.append(candidate)
        candidates.append(graph([node("a"), node("a")]))
        for edge in ({"source": [], "target": "a", "relation": "link"},
                     {"source": "a", "target": "missing", "relation": "link"},
                     {"source": "a", "target": "b"}):
            candidates.append({**self.catalog, "edges": [edge]})
        for value in (float("nan"), float("inf"), object()):
            candidates.append({**self.catalog, "metadata": value})
        for index, candidate in enumerate(candidates):
            with self.subTest(case=index):
                self.assertTrue(backend.validate_spatial_graph_contract(candidate))
                if candidate is not None:  # None explicitly selects the default graph.
                    with self.assertRaises(ValueError):
                        backend.KnowledgeGraphBackendEngine(candidate)

    def test_snapshot_and_results_do_not_leak_mutable_state(self):
        engine = backend.KnowledgeGraphBackendEngine(self.catalog)
        self.catalog["nodes"][0]["drilldown_children"].clear()
        engine.catalog()["nodes"].clear()
        result = engine.drilldown("a")
        result["children"][0]["label"] = "changed"
        result["node"]["drilldown_children"].clear()
        self.assertEqual(engine.drilldown("a")["children"][0]["label"], "b")

    def test_telemetry_sanitization_preserves_lan_and_masks_public_and_mac(self):
        from ipaddress import IPv4Address
        public = str(IPv4Address(2 ** 27 + 1))
        mac = ":".join(["AA", "BB", "CC", "01", "02", "03"])
        candidate = deepcopy(self.catalog)
        candidate["nodes"][0]["summary"] = " ".join([
            public, mac, "10.20.3.1", "172.20.1.2", "172.16.1.3", "gpu.cluster.example.org"])
        engine = backend.KnowledgeGraphBackendEngine(candidate)
        serialized = json.dumps(engine.catalog())
        self.assertNotIn(public, serialized)
        self.assertNotIn(mac, serialized)
        for allowed in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "10.20.3.1", "172.20.1.2",
                        "172.16.1.3", "gpu.cluster.example.org"):
            self.assertIn(allowed, serialized)
        self.assertNotIn(public, json.dumps(engine.search(public)))

    def test_nested_json_sequences_are_sanitized_in_every_graph_response(self):
        from ipaddress import IPv4Address
        public = str(IPv4Address(2 ** 27 + 1))
        mac = ":".join(["AA", "BB", "CC", "01", "02", "03"])
        candidate = deepcopy(self.catalog)
        candidate["nodes"][0]["specs"] = ({"telemetry": (public, mac)},)
        self.assertEqual(backend.validate_spatial_graph_contract(candidate), [])
        engine = backend.KnowledgeGraphBackendEngine(candidate)
        for result in (engine.catalog(), engine.drilldown("a"), engine.search("telemetry"),
                       backend.bm25_search_nodes(candidate["nodes"], "telemetry")):
            with self.subTest(result_type=type(result).__name__):
                serialized = json.dumps(result, allow_nan=False)
                # Boolean assertions avoid echoing raw telemetry on failure.
                self.assertFalse(public in serialized)
                self.assertFalse(mac in serialized)
                self.assertIn("203.0.113.1", serialized)
                self.assertIn("AA:BB:CC:XX:XX:XX", serialized)
        self.assertEqual(candidate["nodes"][0]["specs"][0]["telemetry"], (public, mac))

    def test_catalog_node_and_edge_bounds_and_trusted_proxy_ip_resolution(self):
        self.assertEqual(
            backend.validate_spatial_graph_contract(self.catalog, max_nodes=1),
            ["nodes array exceeds max_nodes bound"],
        )
        edge_catalog = graph([node("a"), node("b")], [{"source": "a", "target": "b", "relation": "links"}])
        self.assertEqual(
            backend.validate_spatial_graph_contract(edge_catalog, max_edges=0),
            [],
        )
        self.assertEqual(
            backend.validate_spatial_graph_contract(edge_catalog, max_edges=1),
            [],
        )
        two_edges = graph(
            [node("a"), node("b")],
            [
                {"source": "a", "target": "b", "relation": "links"},
                {"source": "b", "target": "a", "relation": "links"},
            ],
        )
        self.assertEqual(
            backend.validate_spatial_graph_contract(two_edges, max_edges=1),
            ["edges array exceeds max_edges bound"],
        )
        spoofed_headers = {"X-Forwarded-For": "10.99.88.77, 172.20.1.1"}
        self.assertEqual(
            backend.resolve_trusted_client_ip("127.0.0.1", spoofed_headers, trust_proxy_headers=False),
            "127.0.0.1",
        )
        self.assertEqual(
            backend.resolve_trusted_client_ip("127.0.0.1", spoofed_headers, trust_proxy_headers=True),
            "10.99.88.77",
        )
        self.assertEqual(
            backend.resolve_trusted_client_ip(
                "127.0.0.1",
                {"X-Forwarded-For": "not-an-ip"},
                trust_proxy_headers=True,
            ),
            "127.0.0.1",
        )


class GraphTraversalTests(unittest.TestCase):
    def setUp(self):
        self.engine = backend.KnowledgeGraphBackendEngine(graph([
            node("a", ["b", "c"]), node("b", ["d", "a"]), node("c"), node("d", ["e"]),
            node("e", domain="hardware_topology"), node("isolated")
        ], [{"source": "c", "target": "e", "relation": "hosts"}]))

    def test_bfs_uses_both_link_types_and_prefers_fewer_hops(self):
        result = self.engine.shortest_path("a", "e")
        self.assertEqual(result["path_ids"], ["a", "c", "e"])
        self.assertEqual(result["hop_count"], 2)
        self.assertEqual(result["path_nodes"][-1]["domain"], "hardware_topology")
        self.assertIn("a (a) -> c (c) -> e (e)", result["ascii_lineage"])
        self.assertEqual(self.engine.shortest_path("e", "a")["path_ids"], ["e", "c", "a"])

    def test_identity_unknown_and_disconnected(self):
        result = self.engine.shortest_path("a", "a")
        self.assertTrue(result["path_found"])
        self.assertEqual(result["path_ids"], ["a"])
        self.assertEqual(result["hop_count"], 0)
        for source, target in (("a", "isolated"), ("unknown", "a"), ("a", "unknown")):
            result = self.engine.shortest_path(source, target)
            self.assertFalse(result["path_found"])
            self.assertEqual(result["path_nodes"], [])
            self.assertEqual(result["path_ids"], [])

    def test_drilldown_is_one_level_and_leaf_is_empty(self):
        self.assertEqual([n["id"] for n in self.engine.drilldown("a")["children"]], ["b", "c"])
        self.assertEqual(self.engine.drilldown("e")["children"], [])
        with self.assertRaises(KeyError):
            self.engine.drilldown("missing")


class BM25Tests(unittest.TestCase):
    def test_matches_hand_calculated_okapi_formula(self):
        nodes = [{"id": "a", "summary": "gpu gpu"}, {"id": "b", "summary": "cpu"}]
        result = backend.bm25_search_nodes(nodes, "GPU")
        # Indexed ids contribute one token: lengths 3 and 2, average 2.5.
        expected = math.log(2) * 2 * 2.5 / (2 + 1.5 * (0.25 + 0.75 * 3 / 2.5))
        self.assertEqual(len(result), 1)
        self.assertAlmostEqual(result[0]["score"], expected)
        self.assertEqual(result[0]["id"], "a")

    def test_term_frequency_length_normalization_and_deterministic_ties(self):
        nodes = [node("a", summary="gpu"), node("b", summary="gpu gpu gpu"),
                 node("c", summary="gpu " + "cpu " * 100)]
        hits = backend.bm25_search_nodes(nodes, "gpu")
        self.assertEqual([hit["id"] for hit in hits], ["b", "a", "c"])
        tied = [node("b", summary="gpu"), node("a", summary="gpu")]
        self.assertEqual([h["id"] for h in backend.bm25_search_nodes(tied, "gpu")], ["a", "b"])
        self.assertEqual(backend.bm25_search_nodes(nodes, "gpu gpu"), hits)

    def test_empty_queries_unicode_tokenization_or_matching_and_limit(self):
        nodes = [node("a", summary="GPU pipeline café"), node("b", summary="RAM")]
        for query in ("", "  ", "!!!", "absentword"):
            self.assertEqual(backend.bm25_search_nodes(nodes, query), [])
        self.assertEqual(backend.bm25_search_nodes([], "gpu"), [])
        self.assertEqual(backend.bm25_search_nodes(nodes, "CAFÉ")[0]["id"], "a")
        self.assertEqual(len(backend.bm25_search_nodes(nodes, "gpu ram")), 2)
        self.assertEqual(len(backend.bm25_search_nodes(nodes, "gpu ram", limit=1)), 1)
        result = backend.bm25_search_nodes(nodes, "gpu")
        result[0]["drilldown_children"].append("mutated")
        self.assertEqual(nodes[0]["drilldown_children"], [])

    def test_invalid_search_parameters(self):
        for kwargs in ({"limit": True}, {"limit": 0}, {"limit": 101}, {"limit": 1.5},
                       {"k1": 0}, {"k1": float("nan")}, {"b": -1}, {"b": float("inf")},
                       {"b": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                backend.bm25_search_nodes([node("a")], "gpu", **kwargs)
        with self.assertRaises(ValueError):
            backend.bm25_search_nodes([node("a")], None)


class TicketTests(unittest.TestCase):
    def setUp(self):
        self.engine = backend.KnowledgeGraphBackendEngine()

    def test_all_policy_branches_and_scaffolding_precedence(self):
        for title, policy, allowed, steps in (
            ("Scaffold new project", "playbook-demo-golden-path-3tier", True, 2),
            ("Database password", "policy-demo-zero-trust-secrets", False, 3),
            ("General operations", "policy-demo-standard-guidance", True, 3),
            ("Scaffold project secret", "playbook-demo-golden-path-3tier", True, 2),
        ):
            with self.subTest(title=title):
                result = self.engine.deflect_ticket(title)
                self.assertEqual(result["policy_id"], policy)
                self.assertEqual(result["direct_access_allowed"], allowed)
                self.assertEqual(len(result["traversal_steps"]), steps)
                self.assertTrue(result["required_it_tickets"])
                self.assertIn(result["anchor_node_id"], {n["id"] for n in self.engine.catalog()["nodes"]})

    def test_threshold_and_missing_anchor_fail_closed(self):
        self.assertEqual(self.engine.deflect_ticket("scaffold", 0.96)["route"],
                         "playbook-demo-golden-path-3tier")
        result = self.engine.deflect_ticket("scaffold", 0.97)
        self.assertEqual(result["route"], "human_escalation")
        self.assertFalse(result["direct_access_allowed"])
        custom = backend.KnowledgeGraphBackendEngine(graph([node("a")]))
        self.assertEqual(custom.deflect_ticket("scaffold")["route"], "human_escalation")
        for threshold in (True, 0.79, float("nan"), float("inf"), "0.8"):
            with self.assertRaises(ValueError):
                self.engine.deflect_ticket("scaffold", threshold)

    def test_tree_results_are_detached(self):
        tree = self.engine.jev_tree()
        tree["nodes"].clear()
        self.assertTrue(self.engine.jev_tree()["nodes"])


class APITests(unittest.TestCase):
    def setUp(self):
        self.engine = backend.KnowledgeGraphBackendEngine()

    def test_every_endpoint_and_serializability(self):
        for path, params, method, body in (
            ("/api/v1/contract", None, "GET", None),
            ("/api/v1/graph/catalog", None, "GET", None),
            ("/api/v1/graph/drilldown", {"node_id": "root-company"}, "GET", None),
            ("/api/v1/graph/shortest-path", {"source_id": "root-company", "target_id": "hw-demo-gpu-node"}, "GET", None),
            ("/api/v1/graph/jev-tree", None, "GET", None),
            ("/api/v1/graph/deflect-ticket", None, "POST", '{"ticket_title":"scaffold"}'),
            ("/api/v1/graph/search?q=GPU&limit=2", None, "GET", None),
        ):
            with self.subTest(path=path):
                status, result = backend.handle_api_request(path, params, method, body, self.engine)
                self.assertEqual(status, 200)
                json.dumps(result, allow_nan=False)
        catalog = self.engine.catalog()
        self.assertEqual({n["domain"] for n in catalog["nodes"]}, set(backend.DOMAINS))
        self.assertEqual(backend.validate_spatial_graph_contract(catalog), [])
        result = self.engine.search("GPU", 2)
        self.assertEqual(result["results"],
                         backend.bm25_search_nodes(catalog["nodes"], "GPU", 2))
        self.assertEqual(result["result_count"], len(result["results"]))
        self.assertEqual(result["results"][0]["id"], "hw-demo-gpu-node")

    def test_contract_documents_methods_parameters_and_confidence_floor(self):
        contract = self.engine.contract()
        self.assertEqual(contract["openapi"], "3.1.0")
        self.assertEqual(set(contract["paths"]), set(backend.API_METHODS))
        for path, method in backend.API_METHODS.items():
            self.assertIn(method.lower(), contract["paths"][path])
        post = contract["paths"]["/api/v1/graph/deflect-ticket"]["post"]
        schema = post["requestBody"]["content"]["application/json"]["schema"]
        self.assertEqual(schema["properties"]["min_confidence"]["minimum"], 0.80)

    def test_query_lists_and_explicit_override(self):
        status, result = self.engine.handle_api_request("/api/v1/graph/drilldown?node_id=missing",
                                                       {"node_id": ["root-company"]})
        self.assertEqual(status, 200)
        self.assertEqual(result["node"]["id"], "root-company")
        status, result = self.engine.handle_api_request("/api/v1/graph/search", {"q": "gpu", "limit": 1})
        self.assertEqual(status, 200)
        self.assertEqual(result["result_count"], 1)

    def test_invalid_requests_and_unknown_routes(self):
        for path, params, method, body, expected in (
            ("/unknown", None, "GET", None, 404),
            ("/api/v1/graph/catalog", None, "DELETE", None, 405),
            ("/api/v1/graph/drilldown", None, "GET", None, 400),
            ("/api/v1/graph/drilldown?node_id=missing", None, "GET", None, 404),
            ("/api/v1/graph/drilldown?node_id=a&node_id=b", None, "GET", None, 400),
            ("/api/v1/graph/shortest-path?source_id=root-company", None, "GET", None, 400),
            ("/api/v1/graph/search?q=gpu&limit=0", None, "GET", None, 400),
            ("/api/v1/graph/search?q=gpu&limit=1.5", None, "GET", None, 400),
            ("/api/v1/graph/search?q=gpu", {"limit": True}, "GET", None, 400),
            ("/api/v1/graph/search?q=gpu&limit=1&limit=2", None, "GET", None, 400),
            ("/api/v1/graph/search?q=", None, "GET", None, 400),
            ("/api/v1/graph/catalog", [], "GET", None, 400),
            ("/api/v1/graph/deflect-ticket", None, "POST", "{", 400),
            ("/api/v1/graph/deflect-ticket", None, "POST", [], 400),
            ("/api/v1/graph/deflect-ticket", None, "POST", {}, 400),
            ("/api/v1/graph/deflect-ticket", None, "POST", {"ticket_title": " "}, 400),
            ("/api/v1/graph/deflect-ticket", None, "POST", {"ticket_title": "gpu", "min_confidence": False}, 400),
        ):
            with self.subTest(path=path, method=method):
                status, result = self.engine.handle_api_request(path, params, method, body)
                self.assertEqual(status, expected)
                self.assertIn("error", result)


class BackendScalingTests(unittest.TestCase):
    def test_large_graph_indexes_are_ready_before_first_query_and_reused(self):
        for size in (1000, 10000):
            with self.subTest(size=size):
                nodes = [node(f"n{i:05d}", [f"n{i + 1:05d}"] if i + 1 < size else [],
                              summary="gpu pipeline " + "cpu " * (i % 3))
                         for i in range(size)]
                engine = backend.KnowledgeGraphBackendEngine(graph(nodes))
                self.assertEqual(list(engine._by_id), [n["id"] for n in nodes])
                self.assertIsNotNone(engine._search_index)
                expected = {}
                documents, lengths, average, frequencies = backend._build_search_index(nodes)
                # Independently retain the original per-document scoring formula.
                for query in ("gpu cpu GPU", "pipeline", "absentword", ""):
                    hits = []
                    for item, document, length in zip(nodes, documents, lengths):
                        score = 0.0
                        for term in sorted(set(backend._tokens(query))):
                            frequency = document[term]
                            if frequency:
                                idf = math.log(1 + (size - frequencies[term] + 0.5)
                                               / (frequencies[term] + 0.5))
                                score += idf * frequency * 2.5 / (
                                    frequency + 1.5 * (0.25 + 0.75 * length / average))
                        if score > 0:
                            hits.append({**deepcopy(item), "score": score})
                    hits.sort(key=lambda hit: (-hit["score"], hit["id"]))
                    expected[query] = hits
                with patch.object(backend, "_build_search_index",
                                  side_effect=AssertionError("Index rebuilt")), \
                        patch.object(backend, "_tokens", wraps=backend._tokens) as tokenize:
                    for query, hits in expected.items():
                        for limit in (1, 10, 100):
                            self.assertEqual(engine.search(query, limit)["results"], hits[:limit])
                    self.assertEqual(tokenize.call_count, len(expected) * 3)
                self.assertEqual(engine.shortest_path("n00000", nodes[-1]["id"])["path_ids"],
                                 [item["id"] for item in nodes])

    def test_ordered_neighbors_ties_and_nested_results_remain_detached(self):
        source = graph([node("a", ["c", "b"]), node("b", ["d"]),
                        node("c", ["d"]), node("d"), node("isolated")],
                       [{"source": left, "target": right, "relation": "link"}
                        for left, right in (("a", "b"), ("a", "a"), ("d", "a"))])
        source["nodes"][0]["specs"] = {"nested": [{"values": ["gpu"]}]}
        source["nodes"][3]["specs"] = {"nested": [{"values": ["cpu"]}]}
        engine = backend.KnowledgeGraphBackendEngine(source)
        self.assertEqual(engine._adj, {"a": ["c", "b", "a", "d"], "b": ["a", "d"],
                                       "c": ["a", "d"], "d": ["b", "c", "a"],
                                       "isolated": []})
        self.assertEqual(engine.shortest_path("b", "c")["path_ids"], ["b", "a", "c"])
        expected_catalog = engine.catalog()
        expected_search = engine.search("gpu")
        expected_path = engine.shortest_path("b", "c")
        for item in (source["nodes"][0], engine.catalog()["nodes"][0],
                     engine.drilldown("a")["node"], engine.drilldown("b")["children"][0],
                     engine.search("gpu")["results"][0]):
            item["specs"]["nested"][0]["values"].append("changed")
        path = engine.shortest_path("b", "c")
        path["path_nodes"][0]["label"] = "changed"
        path["path_ids"].clear()
        self.assertEqual(engine.catalog(), expected_catalog)
        self.assertEqual(engine.search("gpu"), expected_search)
        self.assertEqual(engine.shortest_path("b", "c"), expected_path)


class LiveSnapshotPerformanceTests(unittest.TestCase):
    def test_live_snapshot_indexes_are_reused_and_outputs_are_detached(self):
        source = json.loads((ROOT / "live-cluster-sanitized.json").read_text(encoding="utf-8"))
        original = deepcopy(source)
        self.assertEqual(len(source["nodes"]), source["node_count"])
        self.assertGreater(len(source["nodes"]), 50)
        self.assertEqual(backend.validate_spatial_graph_contract(source), [])
        started = perf_counter()
        engines = [backend.KnowledgeGraphBackendEngine(source) for _ in range(5)]
        self.assertLess(perf_counter() - started, 2.0)
        engine = engines[0]
        expected_catalog = backend._sanitize(deepcopy(source))
        expected_catalog.pop("rts_currencies", None)
        expected_catalog.pop("object_archetypes", None)
        expected_catalog.update(piece_role="PIECE_B_HEADLESS_KNOWLEDGE_GRAPH",
                                node_count=len(source["nodes"]),
                                edge_count=len(source.get("edges", [])))
        self.assertEqual(engine.catalog(), expected_catalog)
        for query in ("nodebeta02", "kubernetes gpu", "absentword", "", "GPU pipeline"):
            for limit in (1, 10, 100):
                self.assertEqual(engine.search(query, limit)["results"],
                                 backend.bm25_search_nodes(expected_catalog["nodes"], query, limit))
        expected = engine.search("nodebeta02")
        with patch.object(backend, "_build_search_index", side_effect=AssertionError("Index rebuilt")):
            started = perf_counter()
            for _ in range(30):
                self.assertEqual(engine.search("nodebeta02"), expected)
            indexed_time = perf_counter() - started
        started = perf_counter()
        for _ in range(30):
            backend.bm25_search_nodes(expected_catalog["nodes"], "nodebeta02")
        self.assertLess(indexed_time, (perf_counter() - started) * 0.7)
        source["nodes"][0]["label"] = "changed"
        expected["results"][0]["label"] = "changed"
        engine.catalog()["nodes"].clear()
        self.assertEqual(engine.catalog(), expected_catalog)
        self.assertNotEqual(engine.search("nodebeta02")["results"][0]["label"], "changed")
        self.assertNotEqual(source, original)

    def test_live_snapshot_paths_match_ordered_reference_bfs(self):
        source = json.loads((ROOT / "live-cluster-sanitized.json").read_text(encoding="utf-8"))
        engine = backend.KnowledgeGraphBackendEngine(source)
        adjacency = {n["id"]: [] for n in engine.catalog()["nodes"]}
        links = [(n["id"], child) for n in engine.catalog()["nodes"]
                 for child in n["drilldown_children"]]
        links.extend((e["source"], e["target"]) for e in engine.catalog().get("edges", []))
        for left, right in links:
            for a, b in ((left, right), (right, left)):
                if b not in adjacency[a]:
                    adjacency[a].append(b)
        self.assertEqual(engine._adjacency, adjacency)
        ids = list(adjacency)
        started = perf_counter()
        for target in ids[::32]:
            queue, paths = [ids[0]], {ids[0]: [ids[0]]}
            for current in queue:
                for neighbor in adjacency[current]:
                    if neighbor not in paths:
                        paths[neighbor] = paths[current] + [neighbor]
                        queue.append(neighbor)
            result = engine.shortest_path(ids[0], target)
            self.assertEqual(result["path_ids"], paths.get(target, []))
            expected = deepcopy(result)
            result["path_ids"].clear()
            result["path_nodes"].clear()
            self.assertEqual(engine.shortest_path(ids[0], target), expected)
        self.assertLess(perf_counter() - started, 1.0)


class HeadlessArchitectureTests(unittest.TestCase):
    def test_ast_imports_only_standard_library_without_piece_a_or_jev_dependency(self):
        source = (ROOT / "opscryer_backend.py").read_text(encoding="utf-8")
        self.assertTrue(source.startswith("# SPDX-License-Identifier: Apache-2.0\n"))
        tree = ast.parse(source)
        for item in ast.walk(tree):
            if isinstance(item, ast.Import):
                modules = [alias.name.split(".")[0] for alias in item.names]
            elif isinstance(item, ast.ImportFrom):
                self.assertEqual(item.level, 0)
                modules = [item.module.split(".")[0]]
            else:
                continue
            for module in modules:
                self.assertIn(module, sys.stdlib_module_names)
        for item in ast.walk(tree):
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Name):
                self.assertNotIn(item.func.id, ("eval", "exec", "__import__"))
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                for marker in ("<html", "<style", "<script", "document.getElementById", ".html", ".css"):
                    self.assertNotIn(marker, item.value)

    def test_load_and_dispatch_work_when_ui_and_jev_imports_and_assets_are_blocked(self):
        original_import = __import__
        original_read = Path.read_text

        def guarded_import(name, *args, **kwargs):
            if name.split(".")[0] in ("opscryer_browser", "jev_client"):
                raise AssertionError("Piece B imported Piece A")
            return original_import(name, *args, **kwargs)

        def guarded_read(path, *args, **kwargs):
            self.assertNotIn(path.suffix, (".html", ".css", ".js"))
            return original_read(path, *args, **kwargs)

        spec = importlib.util.spec_from_file_location("isolated_piece_b", ROOT / "opscryer_backend.py")
        isolated = importlib.util.module_from_spec(spec)
        with patch("builtins.__import__", side_effect=guarded_import), patch.object(Path, "read_text", guarded_read):
            spec.loader.exec_module(isolated)
            engine = isolated.KnowledgeGraphBackendEngine()
            self.assertEqual(engine.handle_api_request("/api/v1/graph/catalog")[0], 200)
            self.assertTrue(engine.search("gpu")["results"])
            self.assertTrue(engine.deflect_ticket("scaffold")["direct_access_allowed"])

    def test_cli_contract_is_json(self):
        completed = subprocess.run([sys.executable, str(ROOT / "opscryer_backend.py"), "--contract"],
                                   capture_output=True, text=True, check=True, cwd=ROOT, timeout=15)
        self.assertEqual(json.loads(completed.stdout)["openapi"], "3.1.0")

    def test_backend_runs_with_only_its_module_and_graph_exchange_file(self):
        with tempfile.TemporaryDirectory() as directory:
            standalone = Path(directory)
            for filename in ("opscryer_backend.py", "sample-graph-data.json"):
                (standalone / filename).write_bytes((ROOT / filename).read_bytes())
            program = (
                "import json; from opscryer_backend import handle_api_request; "
                "status, result = handle_api_request('/api/v1/graph/search?q=gpu'); "
                "assert status == 200; print(json.dumps(result, allow_nan=False))"
            )
            completed = subprocess.run([sys.executable, "-I", "-c",
                                        "import sys; sys.path.insert(0, sys.argv[1]); " + program,
                                        str(standalone)],
                                       cwd=standalone, capture_output=True, text=True,
                                       check=True, timeout=15)
            result = json.loads(completed.stdout)
            self.assertEqual(result["algorithm"], "BM25")
            self.assertEqual(result["results"][0]["id"], "hw-demo-gpu-node")


if __name__ == "__main__":
    unittest.main()
