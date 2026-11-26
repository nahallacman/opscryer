# SPDX-License-Identifier: Apache-2.0
"""Tests for repo-native .ai/ hygiene and 7-level design/plan classification."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import graph_layers
from scripts import ci_verify


class AiProjectHygieneTests(unittest.TestCase):
    """Ensure OpsCryer enforces its own lowercase .ai/ standards without stray homelab skills."""

    def test_repo_ai_hygiene_passes_and_excludes_unrelated_skills(self) -> None:
        report = ci_verify.verify_ai_project_hygiene(_REPO_ROOT)
        self.assertTrue(report["passed"], msg=report)
        self.assertGreaterEqual(report["checked"], 8)
        self.assertEqual(report["violations"], 0)
        self.assertEqual(report["passed_count"], report["checked"])

        skills_dir = _REPO_ROOT / ".ai" / "skills"
        skill_names = sorted(p.name for p in skills_dir.iterdir() if p.is_dir())
        self.assertIn("opscryer_ui_and_layout_development", skill_names)
        self.assertIn("opscryer_verification_and_opsec", skill_names)
        self.assertNotIn("authentik_configuration", skill_names)
        self.assertNotIn("game_server_steam_probe_and_recovery", skill_names)

    def test_graph_layers_classifies_ai_design_and_plans_as_requirements(self) -> None:
        cat = graph_layers.harvest_workspace_truth_graph(_REPO_ROOT)
        by_src = {
            str(n.get("source_path") or ""): n
            for n in cat.get("nodes", [])
            if isinstance(n, dict)
        }
        self.assertIn(".ai/design/architecture.md", by_src)
        self.assertIn(".ai/plans/roadmap.md", by_src)
        self.assertEqual(
            graph_layers.classify_node_graph_level(by_src[".ai/design/architecture.md"]),
            "requirement",
        )
        self.assertEqual(
            graph_layers.classify_node_graph_level(by_src[".ai/plans/roadmap.md"]),
            "requirement",
        )


if __name__ == "__main__":
    unittest.main()
