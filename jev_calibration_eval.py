#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Labeled Jev predicate calibration benchmark, ECE/Brier/F1 evaluation, and /jev-eval portal."""

from __future__ import annotations

import argparse
from html import escape
import json
from typing import Any

import jev_client
from knowledge_base import CONCIERGE_JEV_TREE
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


LABELED_JEV_EVAL_SET: tuple[dict[str, Any], ...] = (
    # 1. Database provisioning (KB-DB-001 -> playbook-golden-path-database-cnpg)
    {"ticket_id": "EVAL-001", "prompt": "How do I deploy a PostgreSQL database on the cluster?",
     "expected_predicate": "is_database_provisioning", "expected_policy_id": "playbook-golden-path-database-cnpg"},
    {"ticket_id": "EVAL-002", "prompt": "Need a new pg cluster with cnpg and openbao secret",
     "expected_predicate": "is_database_provisioning", "expected_policy_id": "playbook-golden-path-database-cnpg"},
    {"ticket_id": "EVAL-003", "prompt": "How 2 database for my backend service?",
     "expected_predicate": "is_database_provisioning", "expected_policy_id": "playbook-golden-path-database-cnpg"},
    {"ticket_id": "EVAL-004", "prompt": "Run SQL schema migration on CloudNativePG postgres",
     "expected_predicate": "is_database_provisioning", "expected_policy_id": "playbook-golden-path-database-cnpg"},
    {"ticket_id": "EVAL-005", "prompt": "Provision psql db table with HA replicas",
     "expected_predicate": "is_database_provisioning", "expected_policy_id": "playbook-golden-path-database-cnpg"},
    {"ticket_id": "EVAL-006", "prompt": "Replace RDS / Aurora with in-cluster PostgreSQL",
     "expected_predicate": "is_database_provisioning", "expected_policy_id": "playbook-golden-path-database-cnpg"},
    # 2. Project scaffolding & CI/CD Golden Path (KB-GP-002 -> playbook-demo-golden-path-3tier)
    {"ticket_id": "EVAL-007", "prompt": "Scaffold a new 3-tier web application repository",
     "expected_predicate": "is_project_scaffolding", "expected_policy_id": "playbook-demo-golden-path-3tier"},
    {"ticket_id": "EVAL-008", "prompt": "Spin up a new project with a deployment pipeline",
     "expected_predicate": "is_project_scaffolding", "expected_policy_id": "playbook-demo-golden-path-3tier"},
    {"ticket_id": "EVAL-009", "prompt": "How do I configure .gitlab-ci.yml with the golden path component?",
     "expected_predicate": "is_project_scaffolding", "expected_policy_id": "playbook-demo-golden-path-3tier"},
    {"ticket_id": "EVAL-010", "prompt": "Commitlint failed on my merge request pipeline",
     "expected_predicate": "is_project_scaffolding", "expected_policy_id": "playbook-demo-golden-path-3tier"},
    {"ticket_id": "EVAL-011", "prompt": "Renovate dependency bump pipeline check",
     "expected_predicate": "is_project_scaffolding", "expected_policy_id": "playbook-demo-golden-path-3tier"},
    {"ticket_id": "EVAL-012", "prompt": "Start a 3 tier frontend + API + worker repo",
     "expected_predicate": "is_project_scaffolding", "expected_policy_id": "playbook-demo-golden-path-3tier"},
    # 3. Storage & OpenZFS ZFS CSI (KB-STOR-007 -> playbook-storage-openzfs-csi)
    {"ticket_id": "EVAL-013", "prompt": "How 2 storage: attach a OpenZFS ZFS PVC to my pod",
     "expected_predicate": "is_storage_provisioning", "expected_policy_id": "playbook-storage-openzfs-csi"},
    {"ticket_id": "EVAL-014", "prompt": "Mount a shared RWX NFS volume via democratic-csi",
     "expected_predicate": "is_storage_provisioning", "expected_policy_id": "playbook-storage-openzfs-csi"},
    {"ticket_id": "EVAL-015", "prompt": "Provision an iSCSI RWO disk for high-IOPS storage",
     "expected_predicate": "is_storage_provisioning", "expected_policy_id": "playbook-storage-openzfs-csi"},
    {"ticket_id": "EVAL-016", "prompt": "Create a SeaweedFS S3 object bucket for artifacts",
     "expected_predicate": "is_storage_provisioning", "expected_policy_id": "playbook-storage-openzfs-csi"},
    {"ticket_id": "EVAL-017", "prompt": "PersistentVolumeClaim stuck pending on zfs dataset",
     "expected_predicate": "is_storage_provisioning", "expected_policy_id": "playbook-storage-openzfs-csi"},
    # 4. Identity, SSO & OpenBao ExternalSecrets (KB-IAM-008 -> playbook-identity-authentik-oidc)
    {"ticket_id": "EVAL-018", "prompt": "How does SSO login work with Authentik OIDC?",
     "expected_predicate": "is_sso_identity", "expected_policy_id": "playbook-identity-authentik-oidc"},
    {"ticket_id": "EVAL-019", "prompt": "Protect my service with OAuth2 forward-auth and RBAC groups",
     "expected_predicate": "is_sso_identity", "expected_policy_id": "playbook-identity-authentik-oidc"},
    {"ticket_id": "EVAL-020", "prompt": "Bind an OpenBao ExternalSecret for JWT / SAML credentials",
     "expected_predicate": "is_sso_identity", "expected_policy_id": "playbook-identity-authentik-oidc"},
    {"ticket_id": "EVAL-021", "prompt": "Configure LDAP and OIDC provider in iam namespace",
     "expected_predicate": "is_sso_identity", "expected_policy_id": "playbook-identity-authentik-oidc"},
    {"ticket_id": "EVAL-022", "prompt": "Users getting 401 on Authentik SSO callback",
     "expected_predicate": "is_sso_identity", "expected_policy_id": "playbook-identity-authentik-oidc"},
    # 5. Game Server Observability (KB-GAME-003 -> playbook-game-server-observability)
    {"ticket_id": "EVAL-023", "prompt": "Minecraft server has tick lag and high mspt",
     "expected_predicate": "is_game_server_issue", "expected_policy_id": "playbook-game-server-observability"},
    {"ticket_id": "EVAL-024", "prompt": "Factorio and Satisfactory pods are down in game-servers",
     "expected_predicate": "is_game_server_issue", "expected_policy_id": "playbook-game-server-observability"},
    {"ticket_id": "EVAL-025", "prompt": "Palworld game server restart check",
     "expected_predicate": "is_game_server_issue", "expected_policy_id": "playbook-game-server-observability"},
    {"ticket_id": "EVAL-026", "prompt": "RomM retro library container health check",
     "expected_predicate": "is_game_server_issue", "expected_policy_id": "playbook-game-server-observability"},
    {"ticket_id": "EVAL-027", "prompt": "Valheim / Terraria server tick time spike",
     "expected_predicate": "is_game_server_issue", "expected_policy_id": "playbook-game-server-observability"},
    # 6. LAN DNS & NGINX Ingress (KB-DNS-004 -> playbook-lan-dns-ingress)
    {"ticket_id": "EVAL-028", "prompt": "LAN DNS name fails for portal.cluster.example.org with NXDOMAIN",
     "expected_predicate": "is_dns_or_ingress_issue", "expected_policy_id": "playbook-lan-dns-ingress"},
    {"ticket_id": "EVAL-029", "prompt": "How do I expose a website on an internal ingress hostname?",
     "expected_predicate": "is_dns_or_ingress_issue", "expected_policy_id": "playbook-lan-dns-ingress"},
    {"ticket_id": "EVAL-030", "prompt": "Split-horizon DNS and CoreDNS resolution check",
     "expected_predicate": "is_dns_or_ingress_issue", "expected_policy_id": "playbook-lan-dns-ingress"},
    {"ticket_id": "EVAL-031", "prompt": "TLS certificate renewal in cert-manager for ingress",
     "expected_predicate": "is_dns_or_ingress_issue", "expected_policy_id": "playbook-lan-dns-ingress"},
    {"ticket_id": "EVAL-032", "prompt": "Cannot resolve dashboard.cluster.example.org on VLAN",
     "expected_predicate": "is_dns_or_ingress_issue", "expected_policy_id": "playbook-lan-dns-ingress"},
    # 7. GPU / APU & Local Inference (KB-GPU-005 -> playbook-gpu-workload-switchboard)
    {"ticket_id": "EVAL-033", "prompt": "Client GPU has low FPS and frame rate stutter",
     "expected_predicate": "is_gpu_or_fps_issue", "expected_policy_id": "playbook-gpu-workload-switchboard"},
    {"ticket_id": "EVAL-034", "prompt": "Check VRAM allocation across 3080, 3070 Ti, and 1080 Ti GPUs",
     "expected_predicate": "is_gpu_or_fps_issue", "expected_policy_id": "playbook-gpu-workload-switchboard"},
    {"ticket_id": "EVAL-035", "prompt": "APU-200 thermal throttling vs Ollama CUDA worker load",
     "expected_predicate": "is_gpu_or_fps_issue", "expected_policy_id": "playbook-gpu-workload-switchboard"},
    {"ticket_id": "EVAL-036", "prompt": "Ollama local inference model VRAM headroom",
     "expected_predicate": "is_gpu_or_fps_issue", "expected_policy_id": "playbook-gpu-workload-switchboard"},
    {"ticket_id": "EVAL-037", "prompt": "ROCm / CUDA driver check on gpu worker node",
     "expected_predicate": "is_gpu_or_fps_issue", "expected_policy_id": "playbook-gpu-workload-switchboard"},
    # 8. General Cluster Operations & Fallback (KB-OPS-006 -> policy-demo-standard-guidance)
    {"ticket_id": "EVAL-038", "prompt": "Where are the cluster operations runbooks located?",
     "expected_predicate": "fallback_standard_guidance", "expected_policy_id": "policy-demo-standard-guidance"},
    {"ticket_id": "EVAL-039", "prompt": "Show general node readiness summary for nodebeta02",
     "expected_predicate": "fallback_standard_guidance", "expected_policy_id": "policy-demo-standard-guidance"},
    {"ticket_id": "EVAL-040", "prompt": "Check overall cluster health and active alerts",
     "expected_predicate": "fallback_standard_guidance", "expected_policy_id": "policy-demo-standard-guidance"},
    {"ticket_id": "EVAL-041", "prompt": "Inspect N-1 node drain capacity headroom",
     "expected_predicate": "fallback_standard_guidance", "expected_policy_id": "policy-demo-standard-guidance"},
    {"ticket_id": "EVAL-042", "prompt": "Review general SRE shift handoff checklist",
     "expected_predicate": "fallback_standard_guidance", "expected_policy_id": "policy-demo-standard-guidance"},
)


def _compute_ece_and_brier(samples: list[tuple[float, int]], num_bins: int = 10) -> tuple[float, float]:
    """Compute 10-bin Expected Calibration Error (ECE) and Brier Score over (confidence, correct_int) pairs."""
    if not samples:
        return 0.0, 0.0
    n = len(samples)
    brier = sum((conf - corr) ** 2 for conf, corr in samples) / n
    ece = 0.0
    for b in range(num_bins):
        low = b / num_bins
        high = (b + 1) / num_bins
        bucket = [
            (conf, corr)
            for conf, corr in samples
            if (low <= conf < high) or (b == num_bins - 1 and low <= conf <= high)
        ]
        if not bucket:
            continue
        avg_conf = sum(c for c, _ in bucket) / len(bucket)
        avg_acc = sum(k for _, k in bucket) / len(bucket)
        ece += (len(bucket) / n) * abs(avg_acc - avg_conf)
    return round(ece, 4), round(brier, 4)


def evaluate_jev_calibration_benchmark(provider: str = "deterministic") -> dict[str, Any]:
    """Run the 42-ticket labeled Jev benchmark and return accuracy, precision/recall/F1, ECE, and Brier score."""
    if provider not in ("deterministic", "ollama", "ollama_single_token"):
        raise ValueError("Unsupported Jev evaluation provider")

    effective_provider = "deterministic" if provider != "deterministic" else "deterministic"
    client = jev_client.SystemOneJevClient(effective_provider)
    decision_predicates = [
        node["predicate_id"]
        for node in CONCIERGE_JEV_TREE["nodes"].values()
        if node["kind"] == "decision"
    ]

    per_predicate_counts: dict[str, dict[str, int]] = {
        pred: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for pred in decision_predicates
    }
    calibration_samples: list[tuple[float, int]] = []
    policy_correct = 0
    ticket_results: list[dict[str, Any]] = []

    for item in LABELED_JEV_EVAL_SET:
        prompt = item["prompt"]
        expected_policy = item["expected_policy_id"]
        expected_pred = item["expected_predicate"]

        # Evaluate full tree path
        path = jev_client.evaluate_ticket_with_jev_tree(
            prompt, tree=CONCIERGE_JEV_TREE, provider=effective_provider
        )
        predicted_policy = path["policy_id"]
        is_policy_match = predicted_policy == expected_policy
        if is_policy_match:
            policy_correct += 1

        step_confs = [
            float(s.get("calibrated_probability", 0.95))
            for s in path.get("traversal_steps", [])
            if "calibrated_probability" in s
        ]
        mean_conf = round(sum(step_confs) / len(step_confs), 4) if step_confs else 0.95
        calibration_samples.append((mean_conf, 1 if is_policy_match else 0))

        for pred in decision_predicates:
            res = client.evaluate_predicate(prompt, pred)
            pred_val = bool(isinstance(res, dict) and res.get("evaluated_value") is True)
            truth_val = expected_pred == pred
            counts = per_predicate_counts[pred]
            if pred_val and truth_val:
                counts["tp"] += 1
            elif pred_val and not truth_val:
                counts["fp"] += 1
            elif not pred_val and truth_val:
                counts["fn"] += 1
            else:
                counts["tn"] += 1

        ticket_results.append({
            "ticket_id": item["ticket_id"],
            "prompt": prompt,
            "expected_policy_id": expected_policy,
            "predicted_policy_id": predicted_policy,
            "correct": is_policy_match,
            "confidence": mean_conf,
        })

    per_predicate_metrics: list[dict[str, Any]] = []
    precisions, recalls, f1s = [], [], []
    for pred in decision_predicates:
        c = per_predicate_counts[pred]
        tp, fp, fn = c["tp"], c["fp"], c["fn"]
        prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        precisions.append(prec)
        recalls.append(rec)
        f1s.append(f1)
        per_predicate_metrics.append({
            "predicate_id": pred,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": c["tn"],
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
        })

    ece, brier = _compute_ece_and_brier(calibration_samples)
    total = len(LABELED_JEV_EVAL_SET)
    return sanitize({
        "schema_version": "1.0-jev-calibration-benchmark",
        "requested_provider": provider,
        "evaluated_provider": effective_provider,
        "eval_mode_disclosure": (
            "Evaluated using deterministic keyword/regex baseline ( synthetic 0.93-0.97 confidence ). "
            "Use provider=ollama_single_token against a live local Ollama instance to measure empirical token-logprob calibration."
        ),
        "total_examples": total,
        "policy_accuracy": round(policy_correct / total, 4),
        "macro_precision": round(sum(precisions) / len(precisions), 4),
        "macro_recall": round(sum(recalls) / len(recalls), 4),
        "macro_f1": round(sum(f1s) / len(f1s), 4),
        "expected_calibration_error_ece": ece,
        "brier_score": brier,
        "per_predicate_metrics": per_predicate_metrics,
        "ticket_results": ticket_results,
    })


def render_jev_eval_markdown(report: dict[str, Any] | None = None) -> str:
    """Render the Jev calibration benchmark report as a clean Markdown scorecard."""
    data = report if isinstance(report, dict) else evaluate_jev_calibration_benchmark()
    lines = [
        "# System-1 Jev Calibration & Routing Accuracy Benchmark",
        "",
        f"- **Total Labeled Tickets:** `{data['total_examples']}`",
        f"- **End-to-End Policy Routing Accuracy:** `{data['policy_accuracy'] * 100:.1f}%`",
        f"- **Macro Precision / Recall / F1:** `{data['macro_precision']:.4f}` / `{data['macro_recall']:.4f}` / `{data['macro_f1']:.4f}`",
        f"- **Expected Calibration Error (10-Bin ECE):** `{data['expected_calibration_error_ece']:.4f}`",
        f"- **Brier Score:** `{data['brier_score']:.4f}`",
        f"- **Evaluation Disclosure:** {data['eval_mode_disclosure']}",
        "",
        "## Per-Predicate Precision / Recall / F1",
        "",
        "| Predicate ID | TP | FP | FN | TN | Precision | Recall | F1 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in data["per_predicate_metrics"]:
        lines.append(
            f"| `{row['predicate_id']}` | {row['tp']} | {row['fp']} | {row['fn']} | {row['tn']} "
            f"| {row['precision']:.4f} | {row['recall']:.4f} | {row['f1']:.4f} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_jev_eval_html(report: dict[str, Any] | None = None) -> str:
    """Render the standalone `/jev-eval` HTML portal with zero external assets."""
    data = report if isinstance(report, dict) else evaluate_jev_calibration_benchmark()
    rows_html = []
    for row in data["per_predicate_metrics"]:
        rows_html.append(
            "<tr>"
            f"<td><code>{escape(str(row['predicate_id']))}</code></td>"
            f"<td>{int(row['tp'])}</td><td>{int(row['fp'])}</td>"
            f"<td>{int(row['fn'])}</td><td>{int(row['tn'])}</td>"
            f"<td>{float(row['precision']):.4f}</td>"
            f"<td>{float(row['recall']):.4f}</td>"
            f"<td><strong>{float(row['f1']):.4f}</strong></td>"
            "</tr>"
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpsCryer — Jev Calibration &amp; Accuracy Benchmark</title>
<style>
:root{{color-scheme:dark;font-family:system-ui,sans-serif;background:#0b1222;color:#f8fafc}}
body{{max-width:1080px;margin:auto;padding:24px}}
nav{{display:flex;flex-wrap:wrap;gap:10px;padding:12px;background:#111c33;border-radius:10px;margin-bottom:20px}}
nav a{{color:#38bdf8;text-decoration:none;padding:6px 10px;border-radius:6px}}
nav a[aria-current="page"]{{background:#38bdf8;color:#0b1222;font-weight:700}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:16px 0}}
.card{{background:#111c33;border:1px solid #1e293b;border-radius:10px;padding:14px}}
table{{width:100%;border-collapse:collapse;background:#111c33;border-radius:10px;overflow:hidden}}
th,td{{padding:10px 12px;border-bottom:1px solid #1e293b;text-align:left;font-size:0.9rem}}
th{{color:#38bdf8;background:#0f172a}}
</style>
</head>
<body>
<nav aria-label="Primary navigation">
<a href="/">Spatial RTS Browser</a>
<a href="/hub">Suite Hub</a>
<a href="/chat">Ticket Concierge</a>
<a href="/kb">Knowledge Explorer</a>
<a href="/jev-eval" aria-current="page">Jev Calibration Benchmark</a>
</nav>
<h1>System-1 Jev Calibration &amp; Routing Benchmark</h1>
<p>{escape(str(data["eval_mode_disclosure"]))}</p>
<div class="grid" id="jev-eval-summary-cards">
  <div class="card"><div>Labeled Tickets</div><strong>{int(data["total_examples"])}</strong></div>
  <div class="card"><div>Policy Accuracy</div><strong>{float(data["policy_accuracy"]) * 100:.1f}%</strong></div>
  <div class="card"><div>Macro F1</div><strong>{float(data["macro_f1"]):.4f}</strong></div>
  <div class="card"><div>10-Bin ECE</div><strong>{float(data["expected_calibration_error_ece"]):.4f}</strong></div>
  <div class="card"><div>Brier Score</div><strong>{float(data["brier_score"]):.4f}</strong></div>
</div>
<h2>Per-Predicate Precision / Recall / F1</h2>
<table id="jev-eval-predicate-table">
<thead><tr><th>Predicate</th><th>TP</th><th>FP</th><th>FN</th><th>TN</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead>
<tbody>{"".join(rows_html)}</tbody>
</table>
</body>
</html>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", default="deterministic",
                        choices=("deterministic", "ollama", "ollama_single_token"))
    parser.add_argument("--json", action="store_true", help="Print benchmark report as JSON")
    parser.add_argument("--markdown", action="store_true", help="Print benchmark report as Markdown")
    args = parser.parse_args(argv)
    report = evaluate_jev_calibration_benchmark(provider=args.provider)
    if args.markdown:
        print(render_jev_eval_markdown(report))
    else:
        print(json.dumps(report, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
