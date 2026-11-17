# SPDX-License-Identifier: Apache-2.0
"""Tests for OpsCryer zero-Brain predumped Hydrogen cast bridge and HTTP endpoints."""

from __future__ import annotations

from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib import error, request

import model_tier_copilot
from opscryer.bridge import (
    handle_hydrogen_cast_request,
    resolve_target_context_from_catalog,
)
from opscryer_backend import KnowledgeGraphBackendEngine
from opscryer_browser import _build_frontend_handler


def _write_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text.replace("\r\n", "\n"))


def _seed_bundle(bundle_dir: Path) -> None:
    anchor = {
        "schema_version": "brain-context-anchor/v1",
        "skills_mode": "predumped_standalone",
        "runtime_brain_checks_required": 0,
        "skill_id": "deploy-k8s",
        "name": "Deploy to K8s (Personal)",
        "source_tier": "personal",
        "version": "2.0.0",
        "category": "platform",
        "description": "Personal override deployment verification skill.",
        "keywords": ["deploy-k8s", "deploy", "k8s", "deployment", "pod", "rollout"],
        "target_placeholder": "{target}",
        "default_playbook": "k8s-deploy-rollout",
        "subgraph_slice": {"nodes": {}, "edges": []},
        "jev_anchors": [],
        "command_templates": [
            "kubectl rollout status {target} --timeout=60s",
            "kubectl get pods -l app={target} -o wide",
        ],
        "verification_checks": [
            "Verify target pods report Ready=True cleanly.",
        ],
        "stop_conditions": [
            "Never query Central Brain at runtime in predumped standalone mode.",
        ],
    }
    _write_lf(
        bundle_dir / "skills" / "deploy-k8s" / "references" / "context_anchor.json",
        json.dumps(anchor, indent=2) + "\n",
    )
    manifest = {
        "schema_version": "brain-predumped-bundle/v1",
        "skills_mode": "predumped_standalone",
        "runtime_brain_checks_required": 0,
        "graph_revision": "test-rev-opscryer",
        "skill_count": 1,
        "skills": [
            {
                "id": "deploy-k8s",
                "name": "Deploy to K8s (Personal)",
                "source_tier": "personal",
                "version": "2.0.0",
                "category": "platform",
                "description": "Personal override deployment verification skill.",
                "keywords": ["deploy-k8s", "deploy", "k8s", "deployment", "pod", "rollout"],
                "default_playbook": "k8s-deploy-rollout",
                "skill_md_path": "skills/deploy-k8s/SKILL.md",
                "context_anchor_path": "skills/deploy-k8s/references/context_anchor.json",
                "estimated_anchor_tokens": 130,
            }
        ],
    }
    _write_lf(bundle_dir / "bundle-manifest.json", json.dumps(manifest, indent=2) + "\n")


class HydrogenPredumpedCastTests(unittest.TestCase):
    """Validate zero-Brain Hydrogen casts via OpsCryer bridge and HTTP routes."""

    def test_bridge_cast_validation_airlock_and_catalog_staging(self) -> None:
        with tempfile.TemporaryDirectory(prefix="opscryer-cast-") as tmp:
            bundle_dir = Path(tmp) / "bundle"
            _seed_bundle(bundle_dir)

            catalog = {
                "nodes": {
                    "root-company": {
                        "id": "root-company",
                        "label": "Company Root",
                        "kind": "organization",
                        "domain": "company_org",
                        "health": "healthy",
                    },
                    "deploy/agy-ai-orchestrator": {
                        "id": "deploy/agy-ai-orchestrator",
                        "label": "agy-ai-orchestrator",
                        "kind": "deployment",
                        "domain": "deployments_k8s",
                        "health": "degraded",
                    },
                }
            }

            ctx = resolve_target_context_from_catalog("deploy/agy-ai-orchestrator", catalog=catalog)
            self.assertTrue(ctx["matched"])
            self.assertEqual(ctx["health"], "degraded")

            status, payload = handle_hydrogen_cast_request(
                {"target": "deploy/agy-ai-orchestrator"},
                catalog=catalog,
                predumped_bundle_dir=bundle_dir,
            )
            self.assertEqual(status, 200)
            self.assertEqual(payload["skills_mode"], "predumped_standalone")
            self.assertEqual(payload["brain_checks_performed"], 0)
            self.assertEqual(payload["model_tier"], "hydrogen")
            self.assertTrue(payload["within_token_budget"])
            self.assertLessEqual(payload["estimated_prompt_tokens"], 400)
            self.assertTrue(payload["catalog_context"]["matched"])

            real_catalog = KnowledgeGraphBackendEngine()._catalog
            real_target = next(
                n["id"]
                for n in real_catalog["nodes"]
                if isinstance(n, dict) and n.get("id") and n["id"] != "root-company"
            )
            stage_status, stage_payload = handle_hydrogen_cast_request(
                {"target": real_target, "dispatch_mode": "stage_action_card"},
                catalog=real_catalog,
                predumped_bundle_dir=bundle_dir,
            )
            self.assertEqual(stage_status, 200)
            self.assertEqual(stage_payload["brain_checks_performed"], 0)
            self.assertTrue(stage_payload["staged_action_card"]["staged"])
            self.assertEqual(stage_payload["staged_action_card"]["card"]["action_type"], "restart_node")

            list_status, list_payload = handle_hydrogen_cast_request(
                {"action": "list_predumped_harnesses"},
                catalog=catalog,
                predumped_bundle_dir=bundle_dir,
            )
            self.assertEqual(list_status, 200)
            self.assertEqual(list_payload["brain_checks_performed"], 0)
            self.assertEqual(list_payload["skill_count"], 1)

            bad_status, bad_payload = handle_hydrogen_cast_request(
                {"target": "bad;whoami"},
                catalog=catalog,
                predumped_bundle_dir=bundle_dir,
            )
            self.assertEqual(bad_status, 400)
            self.assertEqual(bad_payload["error"], "invalid_target")

            sec_status, sec_payload = handle_hydrogen_cast_request(
                {"target": "deploy/app", "query": "dump secret password token"},
                catalog=catalog,
                predumped_bundle_dir=bundle_dir,
            )
            self.assertEqual(sec_status, 403)
            self.assertTrue(sec_payload["airlock_blocked"])

            meta = model_tier_copilot.build_predumped_hydrogen_cast_metadata()
            self.assertEqual(meta["runtime_brain_checks_required"], 0)
            self.assertEqual(meta["endpoint"], "/api/v1/cast/hydrogen")
            self.assertTrue(meta["configurable_model_replacement"])
            self.assertEqual(meta["cutoff_survival_tier"], "zero_token_cutoff")
            self.assertIn("openai_compatible", meta["supported_providers"])
            self.assertIn("zero_token_cutoff", meta["default_fallback_chain"])

    def test_loopback_http_routes_handle_target_only_hydrogen_casts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="opscryer-http-cast-") as tmp:
            bundle_dir = Path(tmp) / "bundle"
            _seed_bundle(bundle_dir)

            handler_cls = _build_frontend_handler("")
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with patch.dict(os.environ, {"MESHWORKS_PREDUMP_DIR": str(bundle_dir)}):
                    for endpoint in ("/api/v1/cast/hydrogen", "/api/v1/nanomachine-swarm/cast"):
                        req = request.Request(
                            f"http://127.0.0.1:{port}{endpoint}",
                            data=json.dumps({"target": "deploy/agy-ai-orchestrator"}).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        )
                        with request.urlopen(req, timeout=10) as resp:
                            self.assertEqual(resp.status, 200)
                            body = json.loads(resp.read().decode("utf-8"))
                        self.assertEqual(body["skills_mode"], "predumped_standalone")
                        self.assertEqual(body["brain_checks_performed"], 0)
                        self.assertEqual(body["model_tier"], "hydrogen")
                        self.assertEqual(body["target"], "deploy/agy-ai-orchestrator")

                    # List configured cast models over HTTP without Brain checks.
                    list_req = request.Request(
                        f"http://127.0.0.1:{port}/api/v1/cast/hydrogen",
                        data=json.dumps({"action": "list_cast_models"}).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with request.urlopen(list_req, timeout=10) as resp:
                        self.assertEqual(resp.status, 200)
                        catalog_body = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(catalog_body["brain_checks_performed"], 0)
                    self.assertEqual(catalog_body["default_tier"], "hydrogen")
                    self.assertIn("openai_compatible", catalog_body["supported_providers"])

                    # Swap Hydrogen model + provider purely via env vars without touching predumped skills.
                    with patch.dict(
                        os.environ,
                        {
                            "MESHWORKS_PREDUMP_DIR": str(bundle_dir),
                            "MESHWORKS_HYDROGEN_MODEL": "qwen3-coder:2b",
                            "MESHWORKS_HYDROGEN_PROVIDER": "openai_compatible",
                        },
                    ):
                        swap_req = request.Request(
                            f"http://127.0.0.1:{port}/api/v1/cast/hydrogen",
                            data=json.dumps({"target": "deploy/agy-ai-orchestrator"}).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        )
                        with request.urlopen(swap_req, timeout=10) as resp:
                            self.assertEqual(resp.status, 200)
                            swap_body = json.loads(resp.read().decode("utf-8"))
                        self.assertEqual(swap_body["brain_checks_performed"], 0)
                        self.assertEqual(swap_body["model_tier"], "hydrogen")
                        self.assertEqual(swap_body["provider"], "openai_compatible")
                        self.assertEqual(swap_body["model_name"], "qwen3-coder:2b")

                    # Simulate service cutoff & offline local backends -> automatic downgrade to zero_token_cutoff.
                    cutoff_req = request.Request(
                        f"http://127.0.0.1:{port}/api/v1/cast/hydrogen",
                        data=json.dumps(
                            {
                                "target": "deploy/agy-ai-orchestrator",
                                "model_tier": "cloud_flash_lite",
                                "service_cutoff": True,
                                "unavailable_providers": ["ollama", "openai_compatible"],
                            }
                        ).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with request.urlopen(cutoff_req, timeout=10) as resp:
                        self.assertEqual(resp.status, 200)
                        cutoff_body = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(cutoff_body["brain_checks_performed"], 0)
                    self.assertEqual(cutoff_body["model_tier"], "zero_token_cutoff")
                    self.assertEqual(cutoff_body["provider"], "deterministic_cutoff")
                    self.assertFalse(cutoff_body["llm_inference_required"])
                    self.assertEqual(cutoff_body["cost_per_1k_usd"], 0.0)
                    self.assertTrue(cutoff_body["model_resolution"]["failover_occurred"])

                    # Reject unsupported provider names with HTTP 400.
                    bad_prov_req = request.Request(
                        f"http://127.0.0.1:{port}/api/v1/cast/hydrogen",
                        data=json.dumps({"target": "deploy/app", "provider": "invalid_provider"}).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with self.assertRaises(error.HTTPError) as prov_ctx:
                        request.urlopen(bad_prov_req, timeout=10)
                    self.assertEqual(prov_ctx.exception.code, 400)
                    prov_ctx.exception.close()

                    bad_req = request.Request(
                        f"http://127.0.0.1:{port}/api/v1/cast/hydrogen",
                        data=json.dumps({"target": "bad;whoami"}).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with self.assertRaises(error.HTTPError) as ctx:
                        request.urlopen(bad_req, timeout=10)
                    self.assertEqual(ctx.exception.code, 400)
                    ctx.exception.close()

                    # Verify standalone stdlib fallback also supplies model_resolution when sibling meshworks is absent.
                    with patch("opscryer.bridge.hydrogen_cast._ensure_sibling_meshworks_on_path", return_value=False):
                        sa_status, sa_body = handle_hydrogen_cast_request(
                            {
                                "target": "deploy/agy-ai-orchestrator",
                                "model_tier": "cloud_flash_lite",
                                "service_cutoff": True,
                                "unavailable_providers": ["ollama", "openai_compatible"],
                            },
                            predumped_bundle_dir=bundle_dir,
                        )
                    self.assertEqual(sa_status, 200)
                    self.assertEqual(sa_body["model_tier"], "zero_token_cutoff")
                    self.assertEqual(sa_body["provider"], "deterministic_cutoff")
                    self.assertTrue(sa_body["model_resolution"]["failover_occurred"])
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
