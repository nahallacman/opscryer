# SPDX-License-Identifier: Apache-2.0
"""Scale benchmark exports, safe inputs, and both HTTP entry points."""

from contextlib import redirect_stderr, redirect_stdout
from http.server import ThreadingHTTPServer
import io
import json
import re
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen

import opscryer_browser
import scale_benchmark as scale
from opscryer_backend import (
    CONTRACT_VERSION,
    KnowledgeGraphBackendEngine,
    validate_spatial_graph_contract,
)


class ScaleBenchmarkTests(unittest.TestCase):
    def test_synthetic_enterprise_graph_contract_and_node_counts(self):
        for size in (10, 100, 500, 2000):
            with self.subTest(node_count=size):
                graph = scale.generate_synthetic_enterprise_graph(size)
                self.assertEqual(graph["schema_version"], CONTRACT_VERSION)
                self.assertEqual(validate_spatial_graph_contract(graph), [])
                self.assertEqual(len(graph["nodes"]), size)

    def test_benchmark_contracts_and_shortest_paths_to_hardware_leaves(self):
        report = scale.run_scalability_benchmark_suite((100, 500))
        self.assertEqual([row["node_count"] for row in report["results"]], [100, 500])
        for row in report["results"]:
            with self.subTest(node_count=row["node_count"]):
                self.assertIs(row["contract_valid"], True)
                self.assertEqual(row["shortest_path_hops"], 4)
                graph = scale.generate_synthetic_enterprise_graph(row["node_count"])
                engine = KnowledgeGraphBackendEngine(graph)
                nodes = {node["id"]: node for node in graph["nodes"]}
                edges = {frozenset((edge["source"], edge["target"]))
                         for edge in graph["edges"]}
                leaves = [node for node in graph["nodes"]
                          if node["zoom_level"] == 4 and node["kind"] == "hardware_node"]
                self.assertTrue(leaves)
                for leaf in leaves:
                    with self.subTest(target=leaf["id"]):
                        self.assertEqual(leaf["drilldown_children"], [])
                        path = engine.shortest_path("root-company", leaf["id"])
                        self.assertIs(path["path_found"], True)
                        self.assertEqual(path["hop_count"], 4)
                        self.assertEqual(path["path_ids"][0], "root-company")
                        self.assertEqual(path["path_ids"][-1], leaf["id"])
                        self.assertEqual(len(path["path_ids"]), path["hop_count"] + 1)
                        self.assertEqual([nodes[key]["zoom_level"] for key in path["path_ids"]],
                                         [0, 1, 2, 3, 4])
                        for source, target in zip(path["path_ids"], path["path_ids"][1:]):
                            self.assertIn(frozenset((source, target)), edges)

    def test_invalid_node_counts_raise_value_error(self):
        for node_count in (0, 9, 5001, "100", True, None):
            with self.subTest(node_count=node_count):
                with self.assertRaises(ValueError):
                    scale.generate_synthetic_enterprise_graph(node_count)
                with self.assertRaises(ValueError):
                    scale.run_scalability_benchmark_suite((node_count,))

    def test_markdown_and_cli_exports(self):
        markdown = scale.render_scale_benchmark_markdown((10, 100))
        self.assertIn("| Nodes | Edges |", markdown)
        self.assertIn("| 10 |", markdown)
        self.assertIn("| 100 |", markdown)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(scale.main(["--json"]), 0)
        self.assertEqual(json.loads(output.getvalue())["results"][0]["node_count"], 500)
        with redirect_stdout(io.StringIO()) as output:
            scale.main(["--markdown", "--nodes", "10"])
        self.assertIn("| 10 |", output.getvalue())

    def test_cli_exports_selected_node_count(self):
        for mode in ("--json", "--markdown"):
            with self.subTest(mode=mode), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(scale.main([mode, "--nodes", "200"]), 0)
                if mode == "--json":
                    rows = json.loads(output.getvalue())["results"]
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["node_count"], 200)
                    self.assertIs(rows[0]["contract_valid"], True)
                else:
                    self.assertIn("| Nodes | Edges |", output.getvalue())
                    self.assertIn("| 200 |", output.getvalue())

    def test_invalid_cli_never_reflects_input(self):
        marker = "private-input-marker"
        for args in (["--nodes", marker], ["--nodes", "9"], ["--nodes", "5001"],
                     ["--port", marker], ["--port", "0"], ["--port", "65536"],
                     ["--" + marker], [marker], ["--nodes"], ["--j"],
                     ["--json", "--serve"]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()) as error, \
                    redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(SystemExit) as raised:
                    scale.main(args)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn(scale._INVALID_REQUEST, error.getvalue())
                self.assertNotIn(marker, error.getvalue())
                self.assertEqual(output.getvalue(), "")

    def test_default_serve_address(self):
        with patch.object(scale, "ThreadingHTTPServer") as server, redirect_stdout(io.StringIO()):
            self.assertEqual(scale.main(["--serve"]), 0)
        self.assertEqual(server.call_args.args[0], ("127.0.0.1", 8107))
        server.return_value.__enter__.return_value.serve_forever.assert_called_once()

    def test_html_exports_contain_selected_graphs(self):
        html = scale.render_scale_benchmark_html()
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("<title>OpsCryer ??? Graph Scalability & Performance Benchmark</title>", html)
        # The surrounding script must not be closed by embedded browser HTML.
        self.assertEqual(html.count("</script>"), 1)
        documents = json.loads(re.search(r"const exportDocuments = (.*);\n", html)[1])
        for size in (100, 500, 1500, 3000):
            self.assertIn(f'value="{size}"', html)
            document = documents[str(size)]
            graph, _ = json.JSONDecoder().raw_decode(
                document.split("const STANDALONE_DEMO_DATASET = ", 1)[1])
            self.assertEqual(len(graph["nodes"]), size)
            self.assertEqual(graph["nodes"][0]["id"], "root-company")
            self.assertTrue(graph["object_archetypes"])

    def test_both_http_handlers_validate_and_run(self):
        for factory in (scale._build_scale_handler, opscryer_browser._build_frontend_handler):
            with self.subTest(handler=factory.__name__), ThreadingHTTPServer(
                    ("127.0.0.1", 0), factory()) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                base = f"http://127.0.0.1:{server.server_port}"
                try:
                    for query, counts in (("", [100, 500, 1500]), ("?nodes=250", [250]),
                                          ("?nodes=10", [10]),
                                          ("?nodes=5000", [5000])):
                        with urlopen(base + "/api/v1/scale-benchmark" + query, timeout=10) as response:
                            self.assertEqual(response.status, 200)
                            self.assertEqual(response.headers.get_content_type(), "application/json")
                            report = json.load(response)
                        self.assertEqual([r["node_count"] for r in report["results"]], counts)
                        for row in report["results"]:
                            self.assertIs(row["contract_valid"], True)
                    for query in ("?nodes=9", "?nodes=5001", "?nodes=", "?nodes=1.5",
                                  "?nodes=100&nodes=500", "?unknown=private-input-marker",
                                  "?nodes=%ZZ", "?nodes=%FF", "?nodes", "?nodes=%0A100"):
                        with self.subTest(query=query), self.assertRaises(HTTPError) as error:
                            urlopen(base + "/api/v1/scale-benchmark" + query, timeout=10)
                        self.assertEqual(error.exception.code, 400)
                        self.assertEqual(json.load(error.exception), {"error": scale._INVALID_REQUEST})
                    with urlopen(base + "/scale", timeout=10) as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.headers.get_content_type(), "text/html")
                        self.assertTrue(response.read().startswith(b"<!DOCTYPE html>"))
                    with self.assertRaises(HTTPError) as error:
                        urlopen(base + "/scale?nodes=100")
                    self.assertEqual(error.exception.code, 400)
                finally:
                    server.shutdown()
                    thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
