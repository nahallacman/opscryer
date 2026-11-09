# SPDX-License-Identifier: Apache-2.0
"""Offline six-plane chaos simulation over the sanitized cluster graph.

Faults represent namespace-local service disruption, not physical node loss.
Workload ownership and routing edges carry disruption in either direction;
assumed plane barriers block crossings. Containment edges do not carry faults.
Hardware placement is reported as shared risk, never treated as dedicated
hardware isolation. Success proves only this model, not live cluster controls.
Reports use catalog node ordinals and fixed namespace names to avoid echoing
arbitrary resource metadata, credentials, or telemetry. Inputs are read only.
"""

import argparse
import json
from pathlib import Path


DEFAULT_CATALOG = Path(__file__).resolve().with_name("live-cluster-sanitized.json")
PLANE_NAMESPACES = {
    "control_plane": ("kube-system", "kube-public", "kube-node-lease",
                      "kubernetes-dashboard", "metallb-system", "monitoring",
                      "ingress-nginx", "envoy-gateway-system", "istio-system"),
    "ai_gpu_plane": ("ai-infra", "ai-sandbox"),
    "gitops_ci_plane": ("argocd", "gitlab", "harbor", "devops-tools", "dev-envs",
                        "ansible-semaphore", "e2e-testing"),
    "zero_trust_iam_plane": ("iam", "security", "cert-manager", "tailscale-system"),
    "storage_plane": ("storage-system", "local-path-storage", "cnpg-system",
                      "elastic-system", "rabbitmq-system"),
    "household_gaming_plane": ("gaming", "game-servers", "media"),
}
PLANES = tuple(PLANE_NAMESPACES)
FAULTS = dict(zip(PLANES, (
    "namespace_api_disruption", "gpu_workload_unavailable", "reconciliation_stalled",
    "identity_service_unavailable", "storage_service_unavailable", "game_service_unavailable")))
_NAMESPACE_PLANE = {ns: plane for plane, names in PLANE_NAMESPACES.items() for ns in names}
_PROPAGATING = {"routes_to", "owns_workload"}


def _load(catalog):
    """Validate graph identity and edges without reflecting input in errors."""
    try:
        if catalog is None or isinstance(catalog, (str, Path)):
            catalog = json.loads(Path(DEFAULT_CATALOG if catalog is None else catalog)
                                 .read_text(encoding="utf-8"))
        if not isinstance(catalog, dict) or not isinstance(catalog.get("nodes"), list):
            raise ValueError
        json.dumps(catalog, allow_nan=False)
        nodes = catalog["nodes"]
        edges = catalog.get("edges", [])
        if not isinstance(edges, list):
            raise ValueError
        identities, namespaces, hardware, owners = {}, set(), set(), {}
        namespace_indexes = set()
        for index, node in enumerate(nodes):
            if not isinstance(node, dict):
                raise ValueError
            identity = node.get("id")
            if not isinstance(identity, str) or not identity or identity in identities:
                raise ValueError
            identities[identity] = index
            resource = node.get("resource")
            if resource is None:
                continue
            if not isinstance(resource, dict) or not isinstance(resource.get("kind"), str):
                raise ValueError
            metadata = resource.get("metadata")
            if (not isinstance(metadata, dict) or
                    not isinstance(metadata.get("name"), str) or not metadata["name"]):
                raise ValueError
            kind = resource["kind"]
            namespace = metadata.get("namespace", node.get("namespace"))
            if namespace is not None and not isinstance(namespace, str):
                raise ValueError
            if ("namespace" in node and "namespace" in metadata and
                    node["namespace"] != namespace):
                raise ValueError
            if kind == "Namespace":
                namespace = metadata["name"]
                namespaces.add(namespace)
                namespace_indexes.add(index)
            elif kind == "Node":
                hardware.add(index)
            owners[index] = _NAMESPACE_PLANE.get(namespace)
        adjacency = {i: set() for i in range(len(nodes))}
        placements = []
        for edge in edges:
            if not isinstance(edge, dict):
                raise ValueError
            source, target, relation = (edge.get(k) for k in ("source", "target", "relation"))
            if (not all(isinstance(v, str) for v in (source, target, relation)) or
                    source not in identities or target not in identities):
                raise ValueError
            a, b = identities[source], identities[target]
            if relation in _PROPAGATING:
                adjacency[a].add(b)
                adjacency[b].add(a)
            elif relation == "runs_on_hardware":
                if b not in hardware:
                    raise ValueError
                placements.append((a, b))
        return owners, namespaces, hardware, adjacency, placements, namespace_indexes
    except (OSError, ValueError, TypeError, RecursionError):
        raise ValueError("Invalid cluster catalog") from None


def _simulate(plane, graph):
    owners, namespaces, hardware, adjacency, placements, namespace_indexes = graph
    members = {p: {i for i, owner in owners.items() if owner == p} for p in PLANES}
    observed = {p: sorted(set(PLANE_NAMESPACES[p]) & namespaces) for p in PLANES}
    # Namespace declarations alone are not workload fault-injection evidence.
    candidates = members[plane] - namespace_indexes
    targets = {min(candidates)} if candidates else set()
    affected, pending, blocked = set(targets), list(targets), set()
    while pending:
        source = pending.pop()
        for target in adjacency[source]:
            if owners.get(target) != plane:
                blocked.add((source, target))
            elif target not in affected:
                affected.add(target)
                pending.append(target)
    missing = [p for p in PLANES if not observed[p] or
               not (members[p] - namespace_indexes)]
    escaped = sorted(i for i in affected if owners.get(i) != plane)
    unchanged = {p: sorted(members[p] - affected) for p in PLANES if p != plane}
    contained = bool(targets and hardware and not missing and not escaped and
                     all(set(unchanged[p]) == members[p] for p in unchanged))
    target_hosts = {b for a, b in placements if a in affected}
    shared_hosts = sorted(target_hosts & {b for a, b in placements if owners.get(a) != plane})
    return {
        "plane": plane, "fault": FAULTS[plane], "simulation_only": True,
        "live_enforcement_verified": False,
        "status": "contained" if contained else "insufficient_evidence",
        "blast_radius_contained": contained,
        "observed_namespaces": observed[plane], "hardware_node_indexes": sorted(hardware),
        "injected_node_indexes": sorted(targets), "affected_node_indexes": sorted(affected),
        "escaped_node_indexes": escaped, "unaffected_planes": unchanged,
        "blocked_cross_plane_edges": [{"source_index": a, "target_index": b}
                                      for a, b in sorted(blocked)],
        "shared_hardware_node_indexes": shared_hosts,
        "missing_planes": missing,
        "assumptions": ["Namespace-local faults only; hardware remains available.",
                        "Plane barriers block routing and ownership fault propagation.",
                        "Shared control, identity and storage services remain dependencies; "
                        "application-level failures are outside this model."],
    }


def simulate_six_plane_chaos_fault(plane, catalog=None):
    """Return a deterministic containment report for one plane.

    Accept a graph dict, JSON path, or None for the bundled snapshot. Invalid
    planes raise ValueError; malformed catalogs return a failed report. Missing
    hardware, namespace declarations, or workload coverage cannot pass.
    """
    if not isinstance(plane, str) or plane not in PLANES:
        raise ValueError("Unsupported chaos plane")
    try:
        return _simulate(plane, _load(catalog))
    except ValueError:
        return {"plane": plane, "status": "invalid_catalog", "simulation_only": True,
                "blast_radius_contained": False, "live_enforcement_verified": False}


def verify_all_six_chaos_planes(catalog=None):
    """Load once and verify all six modeled faults against the same snapshot."""
    try:
        graph = _load(catalog)
        reports = {p: _simulate(p, graph) for p in PLANES}
    except ValueError:
        reports = {p: {"plane": p, "status": "invalid_catalog",
                       "blast_radius_contained": False, "simulation_only": True,
                       "live_enforcement_verified": False} for p in PLANES}
    passed = sum(r["blast_radius_contained"] for r in reports.values())
    return {"status": "contained" if passed == 6 else "failed",
            "blast_radius_contained": passed == 6, "verified_plane_count": passed,
            "plane_count": 6, "simulation_only": True,
            "live_enforcement_verified": False, "planes": reports}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plane", choices=PLANES)
    mode.add_argument("--verify-all", action="store_true")
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    args = parser.parse_args(argv)
    report = (verify_all_six_chaos_planes(args.catalog) if args.verify_all else
              simulate_six_plane_chaos_fault(args.plane, args.catalog))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("Chaos simulation: " + report["status"])
        if args.verify_all:
            print(f"Contained planes: {report['verified_plane_count']}/6")
        else:
            print("Plane: " + args.plane)
        print("Offline model only; live isolation is unverified.")
    return 0 if report["blast_radius_contained"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
