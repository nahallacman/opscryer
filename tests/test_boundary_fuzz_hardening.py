# SPDX-License-Identifier: Apache-2.0
"""Deterministic offline fuzz cases for HTTP and CLI rejection boundaries."""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import io
import json
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.parse import quote

import environment_adapters as adapters
from golden_path_gates import _opsec_count
import live_metrics_poller as metrics
import openapi_spec as openapi
import opscryer_browser as browser
import opscryer_cli as cli
import scale_benchmark as scale


def hostile_values():
    """Build synthetic probes at runtime and keep them out of test diagnostics."""
    marker = "private-boundary-probe"
    controls = tuple(marker + chr(code) for code in (*range(32), 127))
    tokens = tuple(left + right + marker for left, right in
                   (("gh", "o_"), ("gh", "p_"), ("gl", "pat-"), ("s", "k-")))
    return (marker, "<script>" + marker + "</script>", "../" + marker,
            "{" + marker, marker * 512, *controls, *tokens)


def invalid_queries(parameter, valid):
    """Exercise syntax, decoding, cardinality, names and typed values."""
    key = parameter or "private-boundary-probe"
    yield from ("private-boundary-probe=1", key, key + "=",
                key + "=%", key + "=%0", key + "=%GG", key + "=%FF",
                key + "=%C0%AF", key + "=%E2%82", "=private-boundary-probe",
                key + "=" + valid + "&" + key + "=" + valid,
                key + "=" + valid + "&private-boundary-probe=1",
                key + "=" + valid + "&", "&" + key + "=" + valid)
    for value in hostile_values():
        yield key + "=" + quote(value, safe="")
        yield quote(value, safe="") + "=" + valid


@contextmanager
def serving(handler):
    """Use the actual HTTP parser on an ephemeral loopback socket."""
    with ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
        thread = Thread(target=server.serve_forever,
                        kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield server.server_address
        finally:
            server.shutdown()
            thread.join(timeout=5)


class BoundaryFuzzHardeningTests(unittest.TestCase):
    def setUp(self):
        metrics.clear_live_metrics_cache()
        self.addCleanup(metrics.clear_live_metrics_cache)
        self.harvest = self.enterContext(patch.object(
            metrics.cluster_harvester, "harvest_live_k8s_cluster",
            side_effect=AssertionError("Boundary tests must remain offline")))

    def assert_private(self, output):
        # Boolean assertions deliberately avoid printing probes on failure.
        self.assertFalse(any(value in output for value in hostile_values()),
                         "Untrusted input reflected in output")
        self.assertEqual(_opsec_count(output.encode("utf-8")), 0,
                         "Output contains prohibited telemetry")

    def check_http_rejections(self, handler, route, parameter, valid, message,
                              extra_values=()):
        queries = list(invalid_queries(parameter, valid))
        queries.extend(parameter + "=" + quote(value, safe="") for value in extra_values)
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), serving(handler) as address:
            for index, query in enumerate(queries):
                with self.subTest(route=route, case=index):
                    connection = HTTPConnection(*address, timeout=5)
                    try:
                        connection.request("GET", route + "?" + query)
                        response = connection.getresponse()
                        body = response.read().decode("utf-8")
                        self.assertEqual(response.status, 400)
                        self.assertEqual(response.getheader("Content-Type"),
                                         "application/json; charset=utf-8")
                        self.assertEqual(int(response.getheader("Content-Length")),
                                         len(body.encode("utf-8")))
                        self.assert_private(body + str(response.getheaders()))
                        self.assertEqual(json.loads(body), {"error": message})
                    finally:
                        connection.close()
        self.assert_private(output.getvalue() + errors.getvalue())
        self.assertEqual((output.getvalue(), errors.getvalue()), ("", ""))
        self.harvest.assert_not_called()

    def test_standalone_http_boundaries(self):
        cases = (
            (metrics._build_live_metrics_handler(), "/api/v1/live-metrics", "live", "0",
             "Invalid live metrics request", ("2", "-1", "true", "False", "0.0", " 1")),
            (adapters._build_adapters_handler(), "/api/v1/environment-adapters", "adapter",
             "local_host", "Invalid environment adapter request", ("LOCAL_HOST", "null")),
            (scale._build_scale_handler(), "/api/v1/scale-benchmark", "nodes", "10",
             "Invalid scale benchmark request",
             ("0", "9", "5001", "-10", "+10", "10.0", "1e2", "NaN", "Infinity",
              " 10", "10 ", "\uff11\uff10", "9" * 5000)),
        )
        for handler, route, parameter, valid, message, extra in cases:
            self.check_http_rejections(handler, route, parameter, valid, message, extra)

    def test_browser_api_boundaries_including_openapi(self):
        for route, parameter, valid, message, extra in (
            ("live-metrics", "live", "0", "Invalid query parameters", ("true", "2", "-1")),
            ("environment-adapters", "adapter", "local_host",
             "Invalid environment adapter request", ("LOCAL_HOST",)),
            ("openapi.json", None, "1", "Invalid query parameters", ()),
            ("scale-benchmark", "nodes", "10", "Invalid scale benchmark request",
             ("9", "5001", "-10", "10.0", "NaN", "9" * 5000)),
        ):
            self.check_http_rejections(browser._build_frontend_handler(),
                                       "/api/v1/" + route, parameter, valid, message, extra)

    def invoke_cli(self, module, arguments):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), \
                patch("sys.argv", [module.__name__ + ".py"]):
            with self.assertRaises(SystemExit) as caught:
                module.main(arguments)
        self.assertEqual(caught.exception.code, 2)
        self.assert_private(output.getvalue() + errors.getvalue())
        self.assertEqual(output.getvalue(), "")
        return errors.getvalue()

    def test_module_cli_rejections_have_fixed_diagnostics(self):
        for module, message in ((metrics, "Invalid live metrics request"),
                                (adapters, "Invalid environment adapter request"),
                                (openapi, "Invalid OpenAPI arguments"),
                                (scale, "Invalid scale benchmark request")):
            baseline = self.invoke_cli(module, ["--port"])
            self.assertTrue(baseline.endswith("error: " + message + "\n"))
            cases = [["--port", value] for value in
                     ("0", "65536", "-1", "NaN", "1.5", *hostile_values())]
            cases.extend((["--private-boundary-probe"], ["--por", "10"],
                          ["--json", "--serve"]))
            for index, arguments in enumerate(cases):
                with self.subTest(module=module.__name__, case=index):
                    self.assertEqual(self.invoke_cli(module, arguments), baseline)
        self.harvest.assert_not_called()

    def test_unified_cli_malformed_arguments_never_reach_reports(self):
        cases = [[], ["ask"], ["ask", "--question"], ["ask", "--question", ""],
                 ["ask", "--question", " \t\r\n"], ["metrics", "--live=1"],
                 ["adapters", "--adapter"], ["ask", "--quest", "hello"],
                 ["doctor", "--js"], ["routes", "--json=1"]]
        for value in hostile_values():
            cases.extend(([value], ["doctor", "--" + value], ["metrics", value],
                          ["adapters", "--adapter", value],
                          ["ask", "--question", "hello", "--persona", value]))
        with patch.object(cli, "_report") as report:
            for index, arguments in enumerate(cases):
                with self.subTest(case=index):
                    self.assertEqual(self.invoke_cli(cli, arguments),
                                     "Invalid opscryer CLI request\n")
            report.assert_not_called()
        self.harvest.assert_not_called()

    def test_unified_cli_provider_errors_never_reflect_exception_details(self):
        for command in (["doctor"], ["metrics"], ["routes"], ["adapters"],
                        ["ask", "--question", "Cluster health?"]):
            for index, value in enumerate(hostile_values()):
                with self.subTest(command=command[0], case=index), patch.object(
                        cli, "_report", side_effect=ValueError(value)) as report:
                    self.assertEqual(self.invoke_cli(cli, command),
                                     "Invalid opscryer CLI request\n")
                    report.assert_called_once()
        self.harvest.assert_not_called()


if __name__ == "__main__":
    unittest.main()
