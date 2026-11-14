# SPDX-License-Identifier: Apache-2.0
"""Walkthrough coverage, real policy boundaries and safe transcript exports."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from html import unescape
from ipaddress import IPv4Address
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import chat_walkthrough as chat
from cluster_diff_engine import summarize_live_cluster_health
from golden_path_gates import _opsec_count


class ChatWalkthroughTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads(Path(chat.__file__).with_name(
            "live-cluster-sanitized.json").read_text(encoding="utf-8"))

    def test_five_ordered_turns_real_policies_and_diagnostics(self):
        report = chat.run_multi_persona_chat_walkthrough()
        self.assertTrue(report["simulation"])
        self.assertEqual(report["summary"], {"total": 5, "allowed": 4, "blocked": 1})
        turns = report["turns"]
        self.assertEqual([t["turn"] for t in turns], [1, 2, 3, 4, 5])
        self.assertEqual([t["persona"] for t in turns],
                         ["household_user", "developer", "developer", "sre", "executive"])
        for turn in turns:
            response = turn["response"]
            self.assertEqual(response["persona"], turn["persona"])
            self.assertTrue(response["plain_english_answer"])
            if turn["turn"] != 3:
                self.assertEqual(response["status"], "ok")
                self.assertTrue(response["ticket_card"])
                self.assertTrue(response["suggested_next_steps"])
                self.assertTrue(response["cited_node_ids"])
        household = turns[0]["response"]["household_triage"]
        self.assertEqual(household["reason"], "multiple_layer_symptoms")
        self.assertTrue(household["clarifying_questions"])
        self.assertEqual(len(household["diagnostics"]), 3)
        self.assertTrue(turns[1]["response"]["ticket_card"]["direct_access_allowed"])
        blocked = turns[2]["response"]
        self.assertTrue(blocked["airlock_blocked"])
        self.assertIsNone(blocked["ticket_card"])
        self.assertEqual(blocked["live_cluster_facts"], {})
        self.assertEqual(blocked["cited_node_ids"], [])
        facts = turns[3]["response"]["live_cluster_facts"]
        self.assertIn("nodebeta02", facts["not_ready_nodes"])
        self.assertGreater(facts["failed_pods_by_namespace"]["gitlab"]["count"], 0)
        controls = turns[4]["response"]["oscal_posture"]["controls"]
        self.assertTrue(controls)
        self.assertTrue(all(c["status"] == "not_assessed" for c in controls))
        self.assertEqual(json.loads(json.dumps(report, allow_nan=False)), report)
        self.assertEqual(_opsec_count(json.dumps(report).encode()), 0)

    def test_custom_snapshot_path_immutability_and_fresh_results(self):
        catalog = deepcopy(self.catalog)
        catalog["source"] = "walkthrough_test_snapshot"
        before = deepcopy(catalog)
        report = chat.run_multi_persona_chat_walkthrough(catalog)
        self.assertEqual(catalog, before)
        for turn in report["turns"]:
            if not turn["response"]["airlock_blocked"]:
                self.assertEqual(turn["response"]["live_cluster_facts"],
                                 summarize_live_cluster_health(catalog))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            self.assertEqual(chat.run_multi_persona_chat_walkthrough(path), report)
        report["turns"].clear()
        self.assertEqual(len(chat.run_multi_persona_chat_walkthrough(catalog)["turns"]), 5)

    def test_markdown_summary_and_turn_details(self):
        report = chat.run_multi_persona_chat_walkthrough()
        before = deepcopy(report)
        markdown = chat.render_walkthrough_markdown(report)
        self.assertTrue(markdown.startswith("# OpsCryer multi-persona chat walkthrough\n"))
        self.assertIn("| Turn | Persona | Status Badge | Airlock Blocked | Policy ID |", markdown)
        self.assertEqual(markdown.count("\n## Turn "), 5)
        self.assertEqual(markdown.count("<summary>Policy, diagnostics and cited evidence</summary>"), 5)
        answers = [line.removeprefix("**Assistant:** ") for line in markdown.splitlines()
                   if line.startswith("**Assistant:** ")]
        self.assertEqual(len(answers), len(report["turns"]))
        for turn, answer in zip(report["turns"], answers):
            response = turn["response"]
            self.assertIn(turn["message"], markdown)
            self.assertEqual(response["plain_english_answer"],
                             unescape(re.sub(r"\\(.)", r"\1", answer)))
            policy = (response["ticket_card"] or {}).get("policy_id")
            if policy:
                self.assertIn(json.dumps(policy), markdown)
        self.assertIn("| Yes | N/A |", markdown)
        for field in ("household_triage", "cited_node_ids", "oscal_posture", "not_assessed"):
            self.assertIn(field, markdown)
        self.assertIn("not compliance certification", markdown)
        self.assertEqual(_opsec_count(markdown.encode()), 0)
        self.assertEqual(report, before)
        with patch.object(chat, "run_multi_persona_chat_walkthrough", return_value=report) as run:
            self.assertEqual(chat.render_walkthrough_markdown(), markdown)
        run.assert_called_once_with()

    def test_markdown_sanitizes_supplied_results_and_escapes_layout(self):
        report = chat.run_multi_persona_chat_walkthrough()
        wan = str(IPv4Address(2 ** 27 + 1))
        mac = ":".join(["AA", "BB", "CC", "01", "02", "03"])
        token = "gh" + "p_" + "synthetic_value"
        dirty = " ".join((wan, mac, token, "10.1.2.3", "game.cluster.example.org"))
        report["notice"] = dirty
        turn = report["turns"][0]
        turn["persona"] = "person|name\n<script>"
        turn["message"] = dirty
        response = turn["response"]
        response["status_badge"] = dirty
        response["plain_english_answer"] = dirty
        response["ticket_card"]["policy_id"] = "policy|id\nline"
        response["suggested_next_steps"] = [dirty]
        response["cited_node_ids"] = [dirty, "~~~\n</details>"]
        before = deepcopy(report)
        markdown = chat.render_walkthrough_markdown(report)
        for raw in (wan, mac, token):
            self.assertNotIn(raw, markdown)
        for safe in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "10.1.2.3", "game.cluster.example.org"):
            self.assertIn(safe, markdown)
        self.assertIn("person\\|name<br>&lt;script&gt;", markdown)
        self.assertIn("policy\\|id<br>line", markdown)
        self.assertIn("~~~~~~json", markdown)
        self.assertEqual(_opsec_count(markdown.encode()), 0)
        self.assertEqual(report, before)

    def test_cli_markdown_with_default_and_custom_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(self.catalog), encoding="utf-8")
            for flags in ([], ["--catalog", str(path)]):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(chat.main([*flags, "--markdown"]), 0)
                self.assertEqual(output.getvalue(), chat.render_walkthrough_markdown() + "\n")

    def test_cli_rejects_conflicting_export_formats(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exit_code:
            chat.main(["--json", "--markdown"])
        self.assertEqual(exit_code.exception.code, 2)

    def test_each_turn_uses_concierge_and_forwards_catalog(self):
        with patch.object(chat, "ask_concierge_chat", wraps=chat.ask_concierge_chat) as ask:
            chat.run_multi_persona_chat_walkthrough(self.catalog)
        self.assertEqual(ask.call_count, 5)
        for call in ask.call_args_list:
            self.assertIs(call.kwargs["catalog"], self.catalog)
        self.assertEqual([c.kwargs["persona"] for c in ask.call_args_list],
                         ["household_user", "developer", "developer", "sre", "executive"])

    def test_export_boundary_redacts_all_response_fields(self):
        wan = str(IPv4Address(2 ** 27 + 1))
        mac = ":".join(["AA", "BB", "CC", "01", "02", "03"])
        token = "gh" + "p_" + "synthetic_value"
        dirty = " ".join((wan, mac, token, "10.1.2.3", "game.cluster.example.org"))
        response = {"status": "ok", "airlock_blocked": False,
                    "status_badge": "DEGRADED", "plain_english_answer": dirty,
                    "ticket_card": {"policy_id": dirty}, "cited_node_ids": [dirty]}
        before = deepcopy(response)
        with patch.object(chat, "ask_concierge_chat", return_value=deepcopy(response)):
            report = chat.run_multi_persona_chat_walkthrough()
        for encoded in (json.dumps(report), chat.render_transcript(report)):
            for raw in (wan, mac, token):
                self.assertNotIn(raw, encoded)
            for safe in ("203.0.113.1", "AA:BB:CC:XX:XX:XX", "10.1.2.3", "game.cluster.example.org"):
                self.assertIn(safe, encoded)
        self.assertEqual(response, before)

    def test_cli_json_and_human_transcript_with_custom_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(self.catalog), encoding="utf-8")
            for flags in ([], ["--json"]):
                with redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(chat.main(["--catalog", str(path), *flags]), 0)
                if flags:
                    self.assertEqual(json.loads(output.getvalue()),
                                     chat.run_multi_persona_chat_walkthrough(self.catalog))
                else:
                    for text in ("Turn 1 [household_user]", "Turn 5 [executive]",
                                 "BLOCKED_BY_AIRLOCK", "Evidence:", "OSCAL"):
                        self.assertIn(text, output.getvalue())

    def test_invalid_catalogs_fail_without_disclosing_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-catalog.json"
            for content in (None, "private-malformed-content", '{"nodes": []}'):
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                for flag in ("--json", "--markdown"):
                    with redirect_stdout(io.StringIO()) as out, \
                            redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit) as exit_code:
                        chat.main(["--catalog", str(path), flag])
                    self.assertEqual(exit_code.exception.code, 2)
                    self.assertEqual(out.getvalue(), "")
                    self.assertNotIn(str(path), err.getvalue())
                    self.assertNotIn("private-malformed-content", err.getvalue())


if __name__ == "__main__":
    unittest.main()
