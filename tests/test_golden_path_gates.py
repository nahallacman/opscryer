# SPDX-License-Identifier: Apache-2.0
"""Exercise real Git fixtures and keep sensitive test values off disk here."""

from copy import deepcopy
from ipaddress import IPv4Address
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import golden_path_gates as gates


ROOT = Path(__file__).resolve().parents[1]


class TestPublicCliEntrypoints(unittest.TestCase):
    FILENAMES = ("opscryer_showcase.py", "opscryer_browser.py",
                 "ticket_chat_portal.py", "live_advisor.py", "demo_rehearsal.py",
                 "chat_walkthrough.py", "live_e2e_runner.py")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for filename in self.FILENAMES:
            self.write(filename, 'def main():\n    raise AssertionError("must not run")\n'
                       'if __name__ == "__main__":\n    main()\n')

    def write(self, filename, source):
        (self.root / filename).write_text(gates.SPDX_HEADER + "\n" + source,
                                          encoding="utf-8")

    def test_real_public_entrypoints_pass(self):
        report = gates.verify_public_cli_entrypoints()
        self.assertTrue(report["passed"], report)
        self.assertEqual(set(report["entrypoints"]), set(self.FILENAMES))

    def test_explicit_root_and_default_root_do_not_invoke_main(self):
        report = gates.verify_public_cli_entrypoints(str(self.root))
        self.assertTrue(report["passed"], report)
        for result in report["entrypoints"].values():
            self.assertEqual(result, {"exists": True, "callable_main": True, "passed": True})
        with patch.object(gates, "__file__", str(self.root / "golden_path_gates.py")):
            self.assertEqual(gates.verify_public_cli_entrypoints(), report)

    def test_missing_script_or_directory_fails_only_affected_entrypoint(self):
        path = self.root / self.FILENAMES[0]
        path.unlink()
        for directory in (False, True):
            with self.subTest(directory=directory):
                if directory:
                    path.mkdir()
                report = gates.verify_public_cli_entrypoints(self.root)
                self.assertFalse(report["passed"])
                self.assertEqual(report["entrypoints"][path.name],
                                 {"exists": False, "callable_main": False, "passed": False})
                self.assertTrue(all(result["passed"] for name, result
                                    in report["entrypoints"].items() if name != path.name))

    def test_missing_noncallable_or_overwritten_main_fails(self):
        for source in ("value = 1\n", "main = None\n",
                       "def main():\n    pass\nmain = 42\n"):
            with self.subTest(source=source):
                self.write(self.FILENAMES[0], source)
                report = gates.verify_public_cli_entrypoints(self.root)
                self.assertFalse(report["passed"])
                self.assertEqual(report["entrypoints"][self.FILENAMES[0]],
                                 {"exists": True, "callable_main": False, "passed": False})

    def test_load_failures_are_sanitized_and_other_checks_continue(self):
        for source in ("def main(:\n", 'raise RuntimeError("sensitive details")\n',
                       'raise SystemExit("sensitive details")\n',
                       "import nonexistent_opscryer_fixture_dependency\n"):
            with self.subTest(source=source):
                self.write(self.FILENAMES[0], source)
                original_path = gates.sys.path[:]
                report = gates.verify_public_cli_entrypoints(self.root)
                self.assertEqual(gates.sys.path, original_path)
                self.assertFalse(report["passed"])
                self.assertFalse(report["entrypoints"][self.FILENAMES[0]]["callable_main"])
                self.assertTrue(report["entrypoints"][self.FILENAMES[-1]]["passed"])
                self.assertNotIn("sensitive", json.dumps(report))


class TestCommitSubject(unittest.TestCase):
    def test_valid_subjects_and_length_boundary(self):
        for subject in ("feat: add gates", "fix(epic-6)!: enforce locks",
                        "ci(test/unit): run tests", "revert: undo change",
                        "docs: " + "a" * 94):
            with self.subTest(subject=subject):
                self.assertTrue(gates.validate_conventional_commit_subject(subject))

    def test_invalid_subjects(self):
        for subject in (None, 42, "", "Feat: gates", "feat: Add gates",
                        "feat(API): add gates", "unknown: gates", "feat:add gates",
                        "feat: ", " feat: add gates", "feat: add gates ",
                        "feat(): add gates", "feat: add\ngates", "feat: add\rgates",
                        "feat: add\tgates", "feat: add\x00gates", "docs: " + "a" * 95):
            with self.subTest(subject=subject):
                self.assertFalse(gates.validate_conventional_commit_subject(subject))


class TestEpicLocks(unittest.TestCase):
    def test_existing_nine_epic_manifest_is_disjoint(self):
        epics = gates._manifest_epics(ROOT)
        self.assertEqual(len(epics), 9)
        original = deepcopy(epics)
        self.assertTrue(gates.verify_epic_lock_disjointness(epics))
        self.assertEqual(epics, original)

    def test_overlap_and_portable_path_aliases(self):
        for first, second in (("a.py", "a.py"), ("src/", "src/file.py"),
                              ("src/file.py", "src"), ("SRC/a.py", "src\\a.py"),
                              ("src/*.py", "src/new.py"), ("**/*.py", "new.py")):
            with self.subTest(first=first, second=second):
                self.assertFalse(gates.verify_epic_lock_disjointness([
                    {"id": "one", "locked_scopes": [first]},
                    {"id": "two", "locked_scopes": [second]}]))

    def test_distinct_siblings_and_path_component_boundaries(self):
        self.assertTrue(gates.verify_epic_lock_disjointness([
            {"id": "one", "locked_scopes": ["src/a.py", "tests/test_a.py"]},
            {"id": "two", "locked_scopes": ["src/b.py", "src-other/"]}]))

    def test_malformed_input_fails_closed(self):
        for epics in (None, {}, [], [None], [{}],
                      [{"id": "one", "locked_scopes": []}],
                      [{"id": "one", "locked_scopes": "a.py"}],
                      [{"id": "same", "locked_scopes": ["a"]},
                       {"id": "SAME", "locked_scopes": ["b"]}]):
            self.assertFalse(gates.verify_epic_lock_disjointness(epics))
        for scope in (None, "", "../secret", "/absolute", "C:\\file", "a/../b",
                      "a//b", "./a", " a"):
            self.assertFalse(gates.verify_epic_lock_disjointness([
                {"id": "one", "locked_scopes": [scope]}]))


@unittest.skipUnless(shutil.which("git"), "Git is required for pre-push fixtures")
class TestSixGateAudit(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "--quiet")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "user.name", "Gate Tests")
        self.git("config", "user.email", "gates@example.invalid")
        self.write("module.py", (gates.SPDX_HEADER + "\nvalue = 1\n").encode())
        for filename in ("sample-graph-data.json", "CODEX_OVERNIGHT_SWARM_TASKS.md"):
            self.write(filename, (ROOT / filename).read_bytes().replace(b"\r\n", b"\n"))
        self.git("add", ".")
        self.git("-c", "core.hooksPath=", "commit", "--quiet", "-m", "test: add fixture")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def audit(self):
        return gates.run_six_gate_prepush_audit(self.root)

    def assert_failed_gate(self, name):
        report = self.audit()
        self.assertFalse(report["passed"])
        self.assertEqual({key for key, gate in report["gates"].items() if not gate["passed"]}, {name})
        return report

    def test_clean_checkout_passes_all_six_gates(self):
        report = self.audit()
        self.assertTrue(report["passed"], report)
        self.assertEqual(len(report["gates"]), 6)
        with patch.object(gates, "__file__", str(self.root / "golden_path_gates.py")):
            self.assertEqual(gates.run_six_gate_prepush_audit(), report)

    def test_crlf_uses_tracked_worktree_bytes_only(self):
        self.write("untracked.txt", b"not tracked\r\n")
        self.assertTrue(self.audit()["passed"])
        self.write("module.py", (gates.SPDX_HEADER + "\r\n").encode())
        report = self.assert_failed_gate("crlf")
        self.assertEqual(report["gates"]["crlf"]["violations"], 1)

    def test_opsec_includes_hidden_binary_and_environment_files(self):
        payload = (str(IPv4Address(0x08080808)).encode() + b" "
                   + b":".join([b"AA", b"BB", b"CC", b"DD", b"EE", b"FF"]) + b" "
                   + b"gh" + b"p_" + b"synthetic_value")
        self.write(".hidden/payload.bin", b"\x00\xff" + payload)
        self.write(".env.local", b"")
        self.write(".env", b"")
        report = self.assert_failed_gate("opsec")
        self.assertEqual(report["gates"]["opsec"]["violations"], 5)
        self.assertNotIn(payload.decode(), json.dumps(report))
        self.assertNotIn("payload.bin", json.dumps(report))

    def test_allowed_network_values_and_environment_template(self):
        self.write(".env.example", b"10.0.0.1 172.20.1.1 172.16.0.1 172.31.255.254 "
                   b"127.0.0.1 100.64.0.1 host.cluster.example.org 203.0.113.1 AA:BB:CC:XX:XX:XX")
        self.write("__pycache__/ignored.py", b"cache")
        self.assertTrue(self.audit()["passed"])

    def test_opsec_token_families_and_mac_formats(self):
        for prefix in (b"gh" + b"o_", b"gh" + b"p_", b"gl" + b"pat-", b"s" + b"k-"):
            for delimiter in (b"", b" ", b"=", b"\"", b"\x00", b"-"):
                self.assertEqual(gates._opsec_count(delimiter + prefix + b"synthetic"), 1)
        for separator in (b":", b"-"):
            self.assertEqual(gates._opsec_count(separator.join(
                [b"AA", b"BB", b"CC", b"DD", b"EE", b"FF"])), 1)
        self.assertEqual(gates._opsec_count(b".".join([b"AABB", b"CCDD", b"EEFF"])), 1)

    def test_opsec_allows_risk_register_identifiers(self):
        self.write("page.html", b'<table id="platform-risk-register"></table>')
        self.assertTrue(self.audit()["passed"])

    def test_spdx_checks_untracked_files_and_actual_header_position(self):
        self.write("nested/new.py", b'value = "# SPDX-License-Identifier: Apache-2.0"\n')
        self.assert_failed_gate("spdx")
        self.write("nested/new.py", ("#!/usr/bin/env python\n" + gates.SPDX_HEADER + "\n").encode())
        self.assertTrue(self.audit()["passed"])

    def test_graph_syntax_and_reference_errors(self):
        for content in (b"{", b"null", b"{}"):
            self.write("sample-graph-data.json", content)
            self.assert_failed_gate("graph_contract")
        catalog = json.loads((ROOT / "sample-graph-data.json").read_text(encoding="utf-8"))
        catalog["nodes"][0]["drilldown_children"].append("unknown-child")
        self.write("sample-graph-data.json", json.dumps(catalog).encode())
        self.assert_failed_gate("graph_contract")

    def test_actual_head_subject_is_validated(self):
        self.git("-c", "core.hooksPath=", "commit", "--quiet", "--allow-empty", "-m", "bad subject")
        self.assert_failed_gate("commit_subject")

    def test_manifest_overlap_missing_epic_and_missing_manifest(self):
        filename = "CODEX_OVERNIGHT_SWARM_TASKS.md"
        original = (self.root / filename).read_text(encoding="utf-8")
        epics = gates._manifest_epics(self.root)
        self.write(filename, original.replace(epics[1]["locked_scopes"][0],
                                             epics[0]["locked_scopes"][0]).encode())
        self.assert_failed_gate("epic_locks")
        self.write(filename, original.split("## EPIC-9")[0].encode())
        self.assert_failed_gate("epic_locks")
        (self.root / filename).unlink()
        report = self.audit()
        self.assertFalse(report["gates"]["epic_locks"]["passed"])

    def test_missing_git_and_missing_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            report = gates.run_six_gate_prepush_audit(directory)
        self.assertFalse(report["passed"])
        for name in ("crlf", "commit_subject", "graph_contract", "epic_locks"):
            self.assertGreater(report["gates"][name]["errors"], 0)
        (self.root / "module.py").unlink()
        report = self.assert_failed_gate("crlf")
        self.assertTrue(report["gates"]["commit_subject"]["passed"])

    def test_missing_head_does_not_fail_tracked_file_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "-C", str(root), "init", "--quiet"], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            report = gates.run_six_gate_prepush_audit(root)
        self.assertTrue(report["gates"]["crlf"]["passed"])
        self.assertFalse(report["gates"]["commit_subject"]["passed"])
        self.assertEqual(report["gates"]["commit_subject"]["errors"], 1)

    def test_unreadable_files_do_not_produce_success(self):
        with patch.object(gates, "_public_files", side_effect=OSError("sensitive details")):
            report = self.audit()
        self.assertFalse(report["gates"]["opsec"]["passed"])
        self.assertFalse(report["gates"]["spdx"]["passed"])
        self.assertNotIn("sensitive", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
