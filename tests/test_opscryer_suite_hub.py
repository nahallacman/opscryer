# SPDX-License-Identifier: Apache-2.0
"""Suite launchpad, portable snapshots, CLI, and public-output contracts."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from html.parser import HTMLParser
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from ipaddress import IPv4Address
import io
import json
from pathlib import Path
import re
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch

from golden_path_gates import _opsec_count
from incident_commander import DEFAULT_CATALOG_PATH
from opscryer_browser import _build_frontend_handler
import opscryer_suite_hub as hub


ENTRYPOINTS = {
    "/": ("/api/v1/dogfood-zoom", "opscryer_browser"),
    "/chat": ("/api/v1/chat-concierge", "ticket_chat_portal"),
    "/incidents": ("/api/v1/incident-commander", "incident_commander"),
    "/capacity": ("/api/v1/capacity-planner", "capacity_planner"),
    "/network": ("/api/v1/network-inspector", "network_topology_inspector"),
    "/gitops": ("/api/v1/gitops-cockpit", "gitops_release_cockpit"),
    "/executive": ("/api/v1/executive-summary", "executive_command_center"),
    "/hub": ("/api/v1/suite-catalog", "opscryer_suite_hub"),
}
BUNDLE_FILES = {
    "index.html", "chat.html", "incidents.html", "capacity.html",
    "network.html", "gitops.html", "executive.html", "hub.html",
    "suite-catalog.json",
}
CROSS_LINKS = {
    "/games": "Game Observability", "/kb": "Knowledge Explorer",
    "/metrics-live": "Live Metrics", "/adapters": "Environment Adapters",
    "/docs": "API Documentation",
}
EXTENSION_APIS = {
    "/metrics-live": "/api/v1/live-metrics",
    "/adapters": "/api/v1/environment-adapters",
    "/docs": "/api/v1/openapi.json",
}


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.navigation_links = []
        self.in_navigation = False
        self.current_link = None

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "nav":
            self.in_navigation = True
        elif tag == "a" and self.in_navigation:
            self.current_link = {"attrs": dict(attrs), "text": ""}
            self.navigation_links.append(self.current_link)

    def handle_data(self, data):
        if self.current_link is not None:
            self.current_link["text"] += data

    def handle_endtag(self, tag):
        if tag == "a":
            self.current_link = None
        elif tag == "nav":
            self.in_navigation = False


class SuiteHubTests(unittest.TestCase):
    def assert_clean(self, content):
        data = content.encode("utf-8") if isinstance(content, str) else content
        # Report counts only, so a regression cannot print sensitive values.
        self.assertEqual(_opsec_count(data), 0)

    def invoke(self, flags):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(hub.main(flags), 0)
        self.assertEqual(errors.getvalue(), "")
        self.assert_clean(output.getvalue())
        return output.getvalue()

    def assert_cli_error(self, flags):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), self.assertRaises(SystemExit) as caught:
            hub.main(flags)
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("Invalid suite hub request", errors.getvalue())
        self.assertNotIn("private-input", errors.getvalue())
        self.assert_clean(errors.getvalue())

    def assert_bundle(self, directory, manifest):
        root = Path(directory)
        self.assertEqual(manifest["schema_version"], "1.0")
        self.assertEqual(manifest["file_count"], 9)
        self.assertEqual(len(manifest["files"]), 9)
        self.assertEqual(set(manifest["files"]), BUNDLE_FILES)
        self.assertEqual({path.name for path in root.iterdir()}, BUNDLE_FILES)
        self.assert_clean(json.dumps(manifest))
        for name in manifest["files"]:
            with self.subTest(file=name):
                path = root / name
                self.assertTrue(path.is_file())
                content = path.read_bytes()
                self.assertNotIn(b"\r", content)
                self.assert_clean(content)
                text = content.decode("utf-8")
                if path.suffix == ".json":
                    self.assertEqual(json.loads(text), hub.build_suite_application_catalog())
                    continue
                self.assertTrue(text.startswith("<!DOCTYPE html>"))
                parser = PageParser()
                parser.feed(text)
                links = [attrs["href"] for tag, attrs in parser.tags
                         if tag == "a" and "href" in attrs]
                self.assertTrue(links)
                for link in links:
                    self.assertIn(link, BUNDLE_FILES)
                    self.assertTrue((root / link).is_file())
                self.assertFalse(any(tag == "script" and "src" in attrs
                                     for tag, attrs in parser.tags))
                self.assertNotIn("fetch(", text)
                self.assertNotIn('id="live-refresh"', text)
                self.assertNotIn("/incidents/pir.md", text)
                if name == "incidents.html":
                    ids = {attrs["id"] for _, attrs in parser.tags if "id" in attrs}
                    self.assertTrue({"incident-kpi-grid", "incidents-grid", "runbook-panel",
                                     "incident-evidence-json", "incident-runbooks-json"} <= ids)
                    self.assertEqual({attrs["data-severity"] for tag, attrs in parser.tags
                                      if tag == "button" and "data-severity" in attrs},
                                     {"All", "SEV-1", "SEV-2", "SEV-3", "SEV-4"})
                    self.assertEqual(set(links), BUNDLE_FILES - {"suite-catalog.json"})
                    self.assertEqual(len(links), 8)

    def test_catalog_has_all_application_api_and_cli_entrypoints(self):
        catalog = hub.build_suite_application_catalog()
        self.assertEqual(catalog["schema_version"], "1.0")
        self.assertEqual(catalog["application_count"], 8)
        apps = catalog["applications"]
        self.assertEqual(len(apps), 8)
        self.assertEqual(len({app["app_id"] for app in apps}), 8)
        self.assertEqual({app["route"]: (app["api_route"], app["cli_module"])
                          for app in apps}, ENTRYPOINTS)
        for app in apps:
            self.assertTrue(app["title"])
            self.assertTrue(app["target_audience"])
            self.assertRegex(app["epic_id"], r"^EPIC-[1-9]$")
            self.assertIs(app["ready"], True)
        self.assert_clean(json.dumps(catalog))

    def test_catalog_lists_server_extensions_separately_from_core_applications(self):
        extensions = hub.build_suite_application_catalog()["compatibility_and_live_extensions"]
        self.assertEqual(len(extensions), 3)
        self.assertEqual({app["route"]: app["api_route"] for app in extensions},
                         EXTENSION_APIS)
        for app in extensions:
            self.assertEqual(app["title"], CROSS_LINKS[app["route"]])

    def test_catalog_is_fresh_and_does_not_copy_or_mutate_input(self):
        source = {"nodes": [{"summary": "private-input"}], "edges": []}
        before = deepcopy(source)
        catalog = hub.build_suite_application_catalog(source)
        self.assertEqual(source, before)
        self.assertEqual(catalog, hub.build_suite_application_catalog())
        catalog["applications"][0]["title"] = "changed"
        catalog["applications"].pop()
        catalog["compatibility_and_live_extensions"][0]["title"] = "changed"
        catalog["compatibility_and_live_extensions"].pop()
        fresh = hub.build_suite_application_catalog(source)
        self.assertEqual(len(fresh["applications"]), 8)
        self.assertNotEqual(fresh["applications"][0]["title"], "changed")
        self.assertEqual(len(fresh["compatibility_and_live_extensions"]), 3)
        self.assertEqual(fresh["compatibility_and_live_extensions"][0]["title"],
                         "Live Metrics")

    def test_html_has_navigation_accessible_status_and_safe_embedded_catalog(self):
        html = hub.render_suite_hub_html()
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("OpsCryer Application Suite Launchpad", html)
        parser = PageParser()
        parser.feed(html)
        links = {attrs["href"] for tag, attrs in parser.tags if tag == "a"}
        self.assertEqual(links, set(ENTRYPOINTS) | set(CROSS_LINKS))
        self.assertTrue(any(attrs.get("aria-current") == "page" and
                            attrs.get("href") == "/hub" for _, attrs in parser.tags))
        self.assertTrue(any(attrs.get("role") == "status" and
                            attrs.get("aria-live") == "polite" for _, attrs in parser.tags))
        ids = [attrs["id"] for _, attrs in parser.tags if "id" in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        for identity in re.findall(r"getElementById\('([^']+)'\)", html):
            self.assertIn(identity, ids)
        embedded = re.search(r"const applications = (.*?);", html).group(1)
        self.assertEqual(json.loads(embedded), hub.build_suite_application_catalog()["applications"])
        self.assertIn("mode: 'same-origin'", html)
        self.assertIn("AbortController", html)
        for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(unsafe, html)
        self.assertFalse(any(key.startswith("on") for _, attrs in parser.tags for key in attrs))
        self.assertFalse(any(tag == "script" and "src" in attrs for tag, attrs in parser.tags))
        self.assert_clean(html)

    def test_hub_navigation_has_clean_cross_links(self):
        parser = PageParser()
        parser.feed(hub.render_suite_hub_html())
        for route, label in CROSS_LINKS.items():
            with self.subTest(route=route):
                links = [link for link in parser.navigation_links
                         if link["attrs"].get("href") == route]
                self.assertEqual(len(links), 1)
                self.assertEqual(links[0]["text"], label)
                self.assertNotIn("target", links[0]["attrs"])
                self.assertNotIn("aria-current", links[0]["attrs"])

    def test_html_escapes_catalog_text_before_embedding_in_script(self):
        catalog = hub.build_suite_application_catalog()
        attack = '</script><img src=x onerror="alert(1)"> & injected'
        catalog["applications"][0]["title"] = attack
        with patch.object(hub, "build_suite_application_catalog", return_value=catalog):
            html = hub.render_suite_hub_html()
        self.assertNotIn(attack, html)
        self.assertNotIn("<img", html)
        embedded = re.search(r"const applications = (.*?);", html).group(1)
        self.assertFalse(any(character in embedded for character in "<>&"))
        self.assertEqual(json.loads(embedded)[0]["title"], attack)

    def test_http_hub_and_catalog_endpoints(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), _build_frontend_handler()) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for route, content_type in (("/hub", "text/html"),
                                            ("/games", "text/html"),
                                            ("/kb", "text/html"),
                                            ("/metrics-live", "text/html"),
                                            ("/adapters", "text/html"),
                                            ("/docs", "text/html"),
                                            ("/api/v1/suite-catalog", "application/json")):
                    with self.subTest(route=route):
                        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                        try:
                            connection.request("GET", route)
                            response = connection.getresponse()
                            payload = response.read()
                            self.assertEqual(response.status, 200)
                            self.assertIn(content_type, response.getheader("Content-Type"))
                            self.assert_clean(payload)
                            if route == "/hub":
                                self.assertEqual(payload.decode("utf-8"), hub.render_suite_hub_html())
                            elif route == "/api/v1/suite-catalog":
                                self.assertEqual(json.loads(payload), hub.build_suite_application_catalog())
                            else:
                                self.assertTrue(payload.startswith(b"<!DOCTYPE html>"))
                        finally:
                            connection.close()
            finally:
                server.shutdown()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

    def test_export_default_bundle_and_replace_existing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "portable"
            manifest = hub.export_full_suite_static_bundle(destination)
            self.assert_bundle(destination, manifest)
            (destination / "index.html").write_text("stale", encoding="utf-8")
            self.assertEqual(hub.export_full_suite_static_bundle(destination), manifest)
            self.assert_bundle(destination, manifest)
            self.assertNotIn(str(destination), json.dumps(manifest))

    def test_export_accepts_catalog_dict_and_json_path_without_mutating_input(self):
        catalog = json.loads(Path(DEFAULT_CATALOG_PATH).read_text(encoding="utf-8"))
        before = deepcopy(catalog)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            source.write_text(json.dumps(catalog), encoding="utf-8")
            for index, value in enumerate((catalog, source)):
                destination = Path(directory) / f"bundle-{index}"
                self.assert_bundle(destination, hub.export_full_suite_static_bundle(destination, value))
        self.assertEqual(catalog, before)

    def test_export_sanitizes_sensitive_telemetry_and_preserves_lan_context(self):
        catalog = json.loads(Path(DEFAULT_CATALOG_PATH).read_text(encoding="utf-8"))
        # Assemble synthetic sensitive values at runtime; never store them in source.
        wan = str(IPv4Address(2 ** 27 + 1))
        mac = ":".join(("AA", "BB", "CC", "11", "22", "33"))
        credentials = [prefix + "syntheticcredential" for prefix in
                       ("gh" + "o_", "gh" + "p_", "gl" + "pat-", "s" + "k-")]
        catalog["suite_test_evidence"] = " ".join([
            wan, mac, *credentials, "10.1.2.3", "172.20.1.2", "172.16.1.2", "ops.cluster.example.org"])
        before = deepcopy(catalog)
        with tempfile.TemporaryDirectory() as directory:
            self.assert_bundle(directory, hub.export_full_suite_static_bundle(directory, catalog))
            text = (Path(directory) / "index.html").read_text(encoding="utf-8")
            for value in (wan, mac, *credentials):
                self.assertFalse(value in text, "Sensitive synthetic evidence leaked")
            for value in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "[REDACTED]",
                          "10.1.2.3", "172.20.1.2", "172.16.1.2", "ops.cluster.example.org"):
                self.assertIn(value, text)
        self.assertEqual(catalog, before)

    def test_cli_default_and_json_print_catalog(self):
        for flags in ([], ["--json"]):
            with self.subTest(flags=flags):
                self.assertEqual(json.loads(self.invoke(flags)), hub.build_suite_application_catalog())

    def test_cli_exports_portable_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "cli-bundle"
            manifest = json.loads(self.invoke(["--export-suite-bundle", str(destination)]))
            self.assert_bundle(destination, manifest)

    def test_cli_serve_binds_loopback_and_closes_on_interrupt(self):
        for flags, port in (([], 8095), (["--port", "18095"], 18095)):
            with self.subTest(port=port), patch.object(hub.socketserver, "TCPServer") as server:
                running = server.return_value.__enter__.return_value
                running.serve_forever.side_effect = KeyboardInterrupt
                self.assertIn(f"http://127.0.0.1:{port}/hub", self.invoke(["--serve", *flags]))
                self.assertEqual(server.call_args.args[0], ("127.0.0.1", port))
                running.serve_forever.assert_called_once_with()
                server.return_value.__exit__.assert_called_once()

    def test_cli_rejects_conflicting_modes_invalid_ports_and_unknown_flags(self):
        for flags in (["--json", "--serve"], ["--json", "--export-suite-bundle", "private-input"],
                      ["--serve", "--export-suite-bundle", "private-input"],
                      ["--export-suite-bundle"], ["--port", "0"], ["--port", "65536"],
                      ["--port", "private-input"], ["--unknown-private-input"], ["--j"]):
            with self.subTest(flags=flags):
                self.assert_cli_error(flags)

    def test_cli_export_and_server_failures_have_sanitized_errors(self):
        with patch.object(hub, "export_full_suite_static_bundle",
                          side_effect=ValueError("private-input")):
            self.assert_cli_error(["--export-suite-bundle", "private-input"])
        with patch.object(hub.socketserver, "TCPServer", side_effect=OSError("private-input")):
            self.assert_cli_error(["--serve"])

    def test_cli_help_lists_supported_flags(self):
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as caught:
            hub.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        for flag in ("--json", "--export-suite-bundle", "--serve", "--port"):
            self.assertIn(flag, output.getvalue())
        self.assert_clean(output.getvalue())

    def test_test_source_has_spdx_lf_and_zero_opsec_violations(self):
        source = Path(__file__).read_bytes()
        self.assertTrue(source.startswith(b"# SPDX-License-Identifier: Apache-2.0\n"))
        self.assertNotIn(b"\r", source)
        self.assert_clean(source)


if __name__ == "__main__":
    unittest.main()
