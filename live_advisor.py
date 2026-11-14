# SPDX-License-Identifier: Apache-2.0
"""Airlock-gated operational answers grounded in a cluster catalog snapshot."""

import argparse
import json
from pathlib import Path
import re

import incident_commander
import jev_client
import chaos_blast_radius
import oidc_rbac_verifier
import openbao_kms_provenance
import security_airlock
from cluster_diff_engine import summarize_live_cluster_health
from opscryer_backend import KnowledgeGraphBackendEngine
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")


def _category(question):
    text = question.casefold()
    for category, pattern in (
        ("policy_triage", r"\b(policy|policies|triage|permission|permissions|jev|access)\b"),
        ("pod_failures", r"\b(pods?|crashloopbackoff|crash|failed|failures?|pending)\b"),
        ("workload_routing", r"\b(ingress|services?|routing|routes?|workloads?|deployments?)\b|\.cluster\.example\.org\b"),
        ("node_health", r"\b(nodes?|notready|cpu|ram|memory|hotspots?)\b"),
    ):
        if re.search(pattern, text):
            return category
    return "cluster_overview"


def _kind(node):
    return node.get("resource_kind", node.get("resource", {}).get("kind"))


def _evidence_path(engine, hits, nodes):
    if not hits:
        return None
    source = hits[0]["id"]
    path = engine.shortest_path(source, "cluster-home")
    if path["path_found"]:
        return path
    host_name = hits[0].get("resource", {}).get("spec", {}).get("nodeName")
    targets = [n["id"] for n in nodes if _kind(n) == "Node" and (
        n["id"] == source or (host_name and
        n.get("resource", {}).get("metadata", {}).get("name", n.get("label")) == host_name))]
    # Explicit hosting edges also support catalogs without Kubernetes spec data.
    for edge in engine.catalog().get("edges", []):
        if edge.get("relation") == "runs_on_hardware" and edge["source"] == source:
            targets.extend(n["id"] for n in nodes
                           if n["id"] == edge["target"] and _kind(n) == "Node")
    for target in sorted(set(targets)):
        hosting_path = engine.shortest_path(source, target)
        if hosting_path["path_found"]:
            return hosting_path
    return path


def _security_posture(snapshot):
    """Compose offline evidence without asserting live security enforcement."""
    try:
        provenance = openbao_kms_provenance.audit_openbao_secret_provenance(snapshot)
    except ValueError:
        # Graph-valid catalogs may lack the resource metadata this audit needs.
        provenance = {"status": "invalid_catalog", "zero_plaintext_leakage": False}
    return {
        "openbao_provenance": provenance,
        "oidc_posture": oidc_rbac_verifier.audit_cluster_ingress_oidc_posture(snapshot),
        "chaos_isolation": chaos_blast_radius.verify_all_six_chaos_planes(snapshot),
    }


def _prepare_advisor_context(catalog):
    if catalog is None:
        catalog = DEFAULT_CATALOG_PATH
    if isinstance(catalog, (str, Path)):
        catalog = json.loads(Path(catalog).read_text(encoding="utf-8"))
    engine = KnowledgeGraphBackendEngine(catalog)
    snapshot = engine.catalog()
    facts = summarize_live_cluster_health(snapshot)
    posture = _security_posture(snapshot)
    base_cited = {n["id"] for n in snapshot["nodes"]
                  if _kind(n) in {"Node", "Pod", "Deployment", "Ingress"}}
    return engine, snapshot, facts, posture, base_cited


def answer_operational_question(question, catalog=None, tree=None,
                                provider="deterministic",
                                ollama_url="http://localhost:11434",
                                model="qwen2.5-coder:7b", min_confidence=0.80,
                                _context=None):
    """Gate first, then combine snapshot health, BM25, graph paths and Jev.

    ``catalog`` accepts a graph dict or a JSON file path. No telemetry is polled
    and commands are suggestions only. Missing retrieval paths are explicit;
    Jev's access decisions and confidence escalation are preserved verbatim
    except for telemetry redaction. Security posture is offline snapshot evidence;
    provider coverage limits and unverified live controls remain explicit.
    """
    airlock = security_airlock.evaluate_code_search_airlock(question)
    if airlock["airlock_blocked"] is True:
        return {"status": "blocked_by_airlock", "airlock_blocked": True,
                "cited_node_ids": []}

    engine, snapshot, facts, posture, base_cited = (
        _prepare_advisor_context(catalog) if _context is None else _context
    )
    hits = engine.search(question, limit=5)["results"]
    path = _evidence_path(engine, hits, snapshot["nodes"])
    routing = jev_client.evaluate_ticket_with_jev_tree(
        question, tree=tree, provider=provider, ollama_url=ollama_url,
        model=model, min_confidence=min_confidence)
    category = _category(question)
    counts = facts["node_counts"]
    pods = facts["pod_counts"]
    deployments = facts["deployment_counts"]
    summary = (
        f"Catalog snapshot ({facts['source']}, example={facts['example']}): "
        f"{counts['ready']}/{counts['total']} nodes Ready; "
        f"{counts['not_ready']} NotReady; {len(facts['node_hotspots'])} node hotspots; "
        f"{pods['failed']} failed and {pods['pending']} pending pods; "
        f"{deployments['degraded']} degraded deployments; "
        f"{len(facts['ingress_hosts'])} cluster.example.org ingress hosts. "
        "These observations do not establish a root cause."
    )
    if not hits:
        summary += " No BM25 matches for this question."
    elif not path["path_found"]:
        summary += " No path to cluster-home or a hosting Node was found."
    summary += f" Jev route: {routing['route']}; policy: {routing['policy_id']}."
    # All health contributors are cited because live_facts covers the snapshot.
    cited = set(base_cited)
    cited.update(hit["id"] for hit in hits)
    if path:
        cited.update(path["path_ids"])
    commands = {
        "node_health": ["kubectl get nodes -o wide", "kubectl top nodes"],
        "pod_failures": ["kubectl get pods --all-namespaces -o wide",
                         "kubectl get events --all-namespaces --sort-by=.metadata.creationTimestamp"],
        "workload_routing": ["kubectl get ingress,services,endpointslices --all-namespaces",
                             "kubectl get deployments --all-namespaces"],
        "cluster_overview": ["kubectl get nodes -o wide",
                             "kubectl get pods --all-namespaces"],
        "policy_triage": ["kubectl auth can-i --list"],
    }
    return sanitize({"status": "ok", "airlock_blocked": False,
                     "question_category": category, "summary": summary,
                     "live_facts": facts, "cited_node_ids": sorted(cited),
                     "bm25_hits": hits, "shortest_path": path,
                     "jev_routing": routing,
                     "security_posture": posture,
                     "recommended_kubectl_commands": commands[category]})


def get_advisor_incident_brief(catalog=None) -> dict:
    """Return node-health advice and incident triage in separate result fields.

    ``catalog`` accepts a graph dict, JSON file path, or the bundled snapshot.
    Both providers retain their complete response contracts; this optional
    composition performs no live collection or command execution.
    """
    return {
        "advisor": answer_operational_question("manifest node health", catalog=catalog),
        "incidents": incident_commander.build_active_incidents_catalog(catalog=catalog),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--question", required=True, metavar="TEXT")
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--json", action="store_true", help="Print all evidence as JSON")
    args = parser.parse_args(argv)
    try:
        result = answer_operational_question(args.question, catalog=args.catalog)
        encoded = json.dumps(result, indent=2, allow_nan=False)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        parser.error("unable to answer from a valid cluster catalog")
    if args.json:
        print(encoded)
    elif result["status"] == "blocked_by_airlock":
        print("blocked_by_airlock")
    else:
        print(result["summary"])
        print("Cited nodes: " + ", ".join(result["cited_node_ids"]))
        for command in result["recommended_kubectl_commands"]:
            print(command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
