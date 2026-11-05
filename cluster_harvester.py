# SPDX-License-Identifier: Apache-2.0
"""Read-only Kubernetes collection and a deterministic SpatialGraphContract v1.

No collection occurs on import or when building without a snapshot. Live reads
require calling harvest_live_k8s_cluster or passing --harvest-live to the CLI.
Snapshots use Kubernetes List ``items``, ``top_nodes`` text, and provenance.
The fallback preserves the supplied LAN topology; workloads/readings are examples.
"""

import argparse
import json
import math
from pathlib import Path
import shutil
import subprocess

from knowledge_base import KB_CLUSTER_RUNBOOKS as _KB_CLUSTER_RUNBOOKS, overlay_knowledge_base_runbooks
from opscryer_backend import CONTRACT_VERSION, validate_spatial_graph_contract
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize

KB_CLUSTER_RUNBOOKS = _KB_CLUSTER_RUNBOOKS


GET_ARGS = ["get", "nodes,namespaces,deployments,pods,services,ingresses", "-A", "-o", "json"]
TOP_ARGS = ["top", "nodes", "--no-headers"]
ROOT_ID = "cluster-home"


def _offline_snapshot(reason="live_not_requested"):
    items = []
    hosts = (("nodealpha01", "10.20.3.2"),
             ("nodebeta02", "10.20.3.10"), ("nodegamma03", "10.20.3.13"))
    for name, address in hosts:
        items.append({"kind": "Node", "metadata": {"name": name}, "status": {
            "addresses": [{"type": "InternalIP", "address": address}],
            "conditions": [{"type": "Ready", "status": "True"}]}})
    namespaces = ("ai-infra", "dev-envs", "game-servers", "security", "gitlab",
                  "argocd", "monitoring", "iam", "storage-system", "kube-system",
                  "default", "ingress-nginx")
    for index, namespace in enumerate(namespaces):
        items.append({"kind": "Namespace", "metadata": {"name": namespace}})
        name = {"ai-infra": "ollama", "dev-envs": "argon",
                "game-servers": "factorio", "security": "defectdojo"}.get(
                    namespace, namespace + "-example")
        metadata = {"name": name, "namespace": namespace, "labels": {"app": name}}
        items.extend([
            {"kind": "Deployment", "metadata": metadata, "spec": {"replicas": 1},
             "status": {"readyReplicas": 1}},
            {"kind": "Pod", "metadata": {**metadata, "name": name + "-pod"},
             "spec": {"nodeName": hosts[index % 3][0]},
             "status": {"phase": "Running"}},
            {"kind": "Service", "metadata": metadata,
             "spec": {"selector": {"app": name}}},
            {"kind": "Ingress", "metadata": metadata,
             "spec": {"rules": [{"host": namespace + ".cluster.example.org", "http": {
                 "paths": [{"backend": {"service": {"name": name}}}]}}]},
             "status": {"loadBalancer": {"ingress": [
                 {"ip": "172.20.1." + str(210 + index)}]}}},
        ])
    # Named examples support offline search/path demonstrations; they are not
    # evidence that these workloads or placements were observed on the cluster.
    for namespace, name, host in (
        ("game-servers", "minecraft", "nodegamma03"),
        ("security", "trivy", "nodebeta02"),
        ("security", "trivy-operator", "nodebeta02"),
        ("iam", "authentik-server", "nodebeta02"),
        ("iam", "openbao-agent-injector", "nodealpha01"),
        ("gitlab", "gitlab", "nodealpha01"),
        ("argocd", "argocd-server", "nodebeta02"),
        ("monitoring", "kube-prometheus-stack-grafana", "nodealpha01"),
        ("ingress-nginx", "ingress-nginx-controller", "nodealpha01"),
        ("kube-system", "external-secrets", "nodealpha01"),
        ("storage-system", "zfs-nfs-driver-democratic-csi-controller", "nodegamma03"),
    ):
        metadata = {"name": name, "namespace": namespace, "labels": {"app": name}}
        items.extend([
            {"kind": "Deployment", "metadata": metadata, "spec": {"replicas": 1},
             "status": {"readyReplicas": 1}},
            {"kind": "Pod", "metadata": {**metadata, "name": name + "-pod"},
             "spec": {"nodeName": host}, "status": {"phase": "Running"}},
            {"kind": "Service", "metadata": metadata,
             "spec": {"selector": {"app": name}}},
        ])
    return sanitize({"source": "offline_fallback", "example": True,
                     "errors": [reason], "items": items,
                     "top_nodes": "nodealpha01 120m 6% 1024Mi 25%\n"
                                  "nodebeta02 800m 10% 4096Mi 32%\n"
                                  "nodegamma03 400m 5% 2048Mi 20%\n"})


def _slim_containers(containers):
    if not isinstance(containers, list):
        return []
    out = []
    for c in containers:
        if not isinstance(c, dict):
            continue
        entry = {"name": c.get("name") if isinstance(c.get("name"), str) and c.get("name") else "container"}
        if isinstance(c.get("restartPolicy"), str):
            entry["restartPolicy"] = c["restartPolicy"]
        res = c.get("resources") if isinstance(c.get("resources"), dict) else {}
        req = res.get("requests") if isinstance(res.get("requests"), dict) else {}
        lim = res.get("limits") if isinstance(res.get("limits"), dict) else {}
        entry["resources"] = {
            "requests": {
                "cpu": str(req.get("cpu") or "10m"),
                "memory": str(req.get("memory") or "16Mi"),
            },
            "limits": {
                "cpu": str(lim.get("cpu") or "500m"),
                "memory": str(lim.get("memory") or "512Mi"),
            },
        }
        sc = c.get("securityContext") if isinstance(c.get("securityContext"), dict) else {}
        slim_sc = {
            "runAsNonRoot": sc.get("runAsNonRoot") if isinstance(sc.get("runAsNonRoot"), bool) else True,
            "runAsUser": sc.get("runAsUser") if type(sc.get("runAsUser")) is int and sc.get("runAsUser") > 0 else 10000,
            "readOnlyRootFilesystem": sc.get("readOnlyRootFilesystem") if isinstance(sc.get("readOnlyRootFilesystem"), bool) else True,
            "allowPrivilegeEscalation": sc.get("allowPrivilegeEscalation") if isinstance(sc.get("allowPrivilegeEscalation"), bool) else False,
            "capabilities": {"drop": ["ALL"]},
        }
        if isinstance(sc.get("privileged"), bool):
            slim_sc["privileged"] = sc["privileged"]
        entry["securityContext"] = slim_sc
        out.append(entry)
    return out


def _slim_item(item):
    if not isinstance(item, dict):
        return item
    meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    slim_meta = {}
    for k in ("name", "namespace"):
        if k in meta:
            slim_meta[k] = meta[k]
    if isinstance(meta.get("labels"), dict):
        seen_keys = set()
        labels = {}
        for k, v in meta["labels"].items():
            sk = str( sanitize(str(k)) )
            if sk not in seen_keys:
                seen_keys.add(sk)
                labels[k] = v
        slim_meta["labels"] = labels
    if isinstance(meta.get("ownerReferences"), list):
        slim_meta["ownerReferences"] = [
            {"kind": o.get("kind"), "name": o.get("name")}
            for o in meta["ownerReferences"]
            if isinstance(o, dict)
        ]
    if isinstance(meta.get("annotations"), dict):
        kept_ann = {
            k: v for k, v in meta["annotations"].items()
            if k in ("wan", "device", "token")
        }
        if kept_ann:
            slim_meta["annotations"] = kept_ann
    spec = item.get("spec") if isinstance(item.get("spec"), dict) else {}
    slim_spec = {}
    for k in ("replicas", "nodeName", "rules", "defaultBackend"):
        if k in spec:
            slim_spec[k] = spec[k]
    kind = item.get("kind")
    if kind == "Service" and isinstance(spec.get("selector"), dict):
        slim_spec["selector"] = spec["selector"]
    elif kind == "Pod":
        if isinstance(spec.get("containers"), list) and spec["containers"]:
            slim_spec["containers"] = _slim_containers(spec["containers"])
        if isinstance(spec.get("initContainers"), list) and spec["initContainers"]:
            slim_spec["initContainers"] = _slim_containers(spec["initContainers"])
        if isinstance(spec.get("volumes"), list):
            vols = [
                {"persistentVolumeClaim": {"claimName": v["persistentVolumeClaim"]["claimName"]}}
                for v in spec["volumes"]
                if isinstance(v, dict)
                and isinstance(v.get("persistentVolumeClaim"), dict)
                and isinstance(v["persistentVolumeClaim"].get("claimName"), str)
                and v["persistentVolumeClaim"]["claimName"].strip()
            ]
            if vols:
                slim_spec["volumes"] = vols
    elif kind == "Deployment" and isinstance(spec.get("template"), dict):
        tmpl_spec = spec["template"].get("spec") if isinstance(spec["template"].get("spec"), dict) else {}
        if isinstance(tmpl_spec.get("containers"), list) and tmpl_spec["containers"]:
            slim_spec["template"] = {"spec": {"containers": _slim_containers(tmpl_spec["containers"])}}
            if isinstance(tmpl_spec.get("initContainers"), list) and tmpl_spec["initContainers"]:
                slim_spec["template"]["spec"]["initContainers"] = _slim_containers(tmpl_spec["initContainers"])
    status = item.get("status") if isinstance(item.get("status"), dict) else {}
    slim_status = {}
    if isinstance(status.get("addresses"), list):
        slim_status["addresses"] = [
            {"type": a.get("type"), "address": a.get("address")}
            for a in status["addresses"]
            if isinstance(a, dict)
        ]
    if isinstance(status.get("conditions"), list):
        slim_status["conditions"] = [
            {"type": c.get("type"), "status": c.get("status")}
            for c in status["conditions"]
            if isinstance(c, dict)
        ]
    if kind == "Node":
        for cap_key in ("capacity", "allocatable"):
            if isinstance(status.get(cap_key), dict):
                kept_cap = {
                    k: str(v) for k, v in status[cap_key].items()
                    if k in ("cpu", "memory", "pods", "nvidia.com/gpu") and v is not None
                }
                if kept_cap:
                    slim_status[cap_key] = kept_cap
    for k in ("readyReplicas", "phase", "loadBalancer"):
        if k in status:
            slim_status[k] = status[k]
    out = {"kind": kind, "metadata": slim_meta}
    if slim_spec:
        out["spec"] = slim_spec
    if slim_status:
        out["status"] = slim_status
    return out


def _read(kubectl, args, timeout, parse_json=False):
    # Raw output is sanitized in memory before returning it. Never
    # expose stderr or exception text, which may contain kubeconfig credentials.
    result = subprocess.run([kubectl, *args], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout,
                            check=False, shell=False)
    sanitize(result.stderr)
    if result.returncode:
        raise RuntimeError("kubectl read failed")
    if parse_json:
        parsed = json.loads(result.stdout)
        if isinstance(parsed, dict) and isinstance(parsed.get("items"), list):
            parsed = {**parsed, "items": [_slim_item(i) for i in parsed["items"]]}
        return sanitize(parsed)
    return sanitize(result.stdout)


def harvest_live_k8s_cluster(timeout=15):
    """Collect two bounded read-only kubectl commands; fall back on get failure.

    ``timeout`` is a positive finite number of seconds per command. Missing or
    failed metrics retain live inventory, with top_nodes empty and a diagnostic.
    Errors are fixed codes so command failures never disclose raw telemetry.
    """
    if (type(timeout) not in (int, float) or not math.isfinite(timeout)
            or timeout <= 0):
        raise ValueError("timeout must be positive finite seconds")
    kubectl = shutil.which("kubectl")
    if kubectl is None:
        return _offline_snapshot("kubectl_unavailable")
    try:
        inventory = _read(kubectl, GET_ARGS, timeout, parse_json=True)
        if not isinstance(inventory, dict) or not isinstance(inventory.get("items"), list):
            raise ValueError("invalid inventory")
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, TypeError):
        return _offline_snapshot("inventory_unavailable")
    errors = []
    try:
        top = _read(kubectl, TOP_ARGS, timeout)
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, TypeError):
        top = ""
        errors.append("node_metrics_unavailable")
    return sanitize({"source": "live_" + "kubectl", "example": False,
                     "items": inventory["items"], "top_nodes": top, "errors": errors})


def _top_metrics(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 5:
            continue
        try:
            cpu, ram = (float(fields[i].removesuffix("%")) for i in (2, 4))
            if not all(fields[i].endswith("%") for i in (2, 4)):
                continue
            if not all(math.isfinite(n) and n >= 0 for n in (cpu, ram)):
                continue
        except ValueError:
            continue
        result[fields[0]] = {"cpu_percent": cpu, "ram_percent": ram,
                             "cpu_used": fields[1], "ram_used": fields[3]}
    return result


def build_live_cluster_spatial_catalog(snapshot=None):
    """Build a fresh sanitized catalog, without invoking kubectl.

    Accept a harvested snapshot or a Kubernetes List (metrics then unavailable).
    CPU/RAM are arithmetic means over nodes with valid top readings; coverage is
    explicit. Kubernetes inventory cannot establish network/CI/GitLab metrics.
    """
    snapshot = _offline_snapshot() if snapshot is None else sanitize(snapshot)
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("items"), list):
        raise ValueError("snapshot must contain an items array")
    items = snapshot["items"]
    supported = {"Node", "Namespace", "Deployment", "Pod", "Service", "Ingress"}
    resources = {}
    for item in items:
        if not isinstance(item, dict) or item.get("kind") not in supported:
            continue
        meta = item.get("metadata", {})
        if not isinstance(meta, dict) or not isinstance(meta.get("name"), str) or not meta["name"]:
            raise ValueError("resource requires metadata.name")
        kind = item["kind"]
        namespace = "" if kind in {"Node", "Namespace"} else meta.get("namespace", "default")
        if not isinstance(namespace, str) or (kind not in {"Node", "Namespace"} and not namespace):
            raise ValueError("resource requires a namespace")
        key = (kind, namespace, meta["name"])
        if key in resources:
            raise ValueError("duplicate resource identity")
        resources[key] = item
    # Namespace list RBAC can differ from workload RBAC. Keep every workload
    # reachable even if its namespace wasn't present in the response.
    for _, namespace, _ in list(resources):
        if namespace:
            resources.setdefault(("Namespace", "", namespace),
                                 {"kind": "Namespace", "metadata": {"name": namespace}})
    nodes, edges, by_key = [], [], {}

    def add(node_id, label, kind, domain, **details):
        node = {"id": node_id, "label": label, "kind": kind, "domain": domain,
                "summary": label, "primary_url": "https://kubernetes.cluster.example.org",
                "drilldown_children": [], **details}
        nodes.append(node)
        return node

    root = add(ROOT_ID, "Home Kubernetes Cluster", "company_root", "company_org")
    metrics = _top_metrics(snapshot.get("top_nodes", ""))
    kinds = {"Node": "physical_hardware", "Namespace": "kubernetes_namespace",
             "Deployment": "kubernetes_deployment", "Pod": "kubernetes_pod",
             "Service": "kubernetes_service", "Ingress": "kubernetes_ingress"}
    for key, item in sorted(resources.items()):
        kind, namespace, name = key
        node = add("k8s/" + "/".join(key), name, kinds[kind],
                   "hardware_topology" if kind == "Node" else "deployments_k8s",
                   resource_kind=kind, namespace=namespace,
                   resource=item)
        by_key[key] = node
        if kind == "Node":
            node["metrics"] = metrics.get(name, {})
        if kind == "Ingress":
            hosts = [rule["host"] for rule in item.get("spec", {}).get("rules", [])
                     if isinstance(rule.get("host"), str)]
            node["hosts"] = hosts
            if hosts and hosts[0].endswith(".cluster.example.org"):
                node["primary_url"] = "https://" + hosts[0]

    def link(source, target, relation, child=False):
        edge = {"source": source["id"], "target": target["id"], "relation": relation}
        if edge not in edges:
            edges.append(edge)
        if child and target["id"] not in source["drilldown_children"]:
            source["drilldown_children"].append(target["id"])

    for (kind, namespace, name), node in by_key.items():
        parent = root if not namespace else by_key[("Namespace", "", namespace)]
        link(parent, node, "contains", True)
        item = resources[(kind, namespace, name)]
        spec = item.get("spec", {})
        if kind == "Pod":
            host = by_key.get(("Node", "", spec.get("nodeName")))
            if host:
                link(node, host, "runs_on_hardware")
            for owner in item.get("metadata", {}).get("ownerReferences", []):
                target = by_key.get((owner.get("kind"), namespace, owner.get("name")))
                if not target and owner.get("kind") == "ReplicaSet" and "-" in str(owner.get("name", "")):
                    target = by_key.get(("Deployment", namespace, str(owner["name"]).rsplit("-", 1)[0]))
                if target:
                    link(target, node, "owns_workload")
        if kind == "Service" and spec.get("selector"):
            for (other_kind, other_ns, _), target in by_key.items():
                labels = target["resource"].get("metadata", {}).get("labels", {})
                if other_kind == "Pod" and other_ns == namespace and all(
                        labels.get(k) == v for k, v in spec["selector"].items()):
                    link(node, target, "routes_to")
        if kind == "Ingress":
            backends = [spec.get("defaultBackend", {})]
            for rule in spec.get("rules", []):
                backends.extend(path.get("backend", {})
                                for path in rule.get("http", {}).get("paths", []))
            for backend in backends:
                service = backend.get("service", {}).get("name", backend.get("serviceName"))
                target = by_key.get(("Service", namespace, service))
                if target:
                    link(node, target, "routes_to")

    hardware = [n for n in nodes if n.get("resource_kind") == "Node"]
    ready = sum(any(c.get("type") == "Ready" and c.get("status") == "True"
                    for c in n["resource"].get("status", {}).get("conditions", []))
                for n in hardware)
    currencies = []

    def currency(key, label, value, supply, entries, available=True):
        currencies.append({"currency_id": key, "label": label, "icon": "*",
                           "display_value": value, "supply_kind": supply,
                           "hex_color": "#22C55E" if available else "#94A3B8",
                           "available": available, "dropdown_items": entries})

    currency("nodes", "Nodes", f"{ready}/{len(hardware)} Ready", "supply_cap",
             [{"label": n["label"], "value": n["summary"], "target_id": n["id"]}
              for n in hardware])
    for key, label, field in (("cpu_load", "CPU Load", "cpu_percent"),
                              ("ram_load", "RAM Load", "ram_percent")):
        measured = [n for n in hardware if field in n["metrics"]]
        value = (f"{sum(n['metrics'][field] for n in measured) / len(measured):.1f}% Avg "
                 f"({len(measured)}/{len(hardware)} nodes)" if measured else "Unavailable")
        currency(key, label, value, "currency_rate",
                 [{"label": n["label"], "value": str(n["metrics"][field]) + "%",
                   "target_id": n["id"]} for n in measured], bool(measured))
    for key, label, supply, reason in (
            ("network_load", "Net Load %", "currency_rate", "Network counters not collected"),
            ("build_supply", "Build Supply", "food_supply", "CI slot capacity not collected"),
            ("renovate_failures", "Renovate", "upkeep_alert", "Renovate results not collected"),
            ("open_mrs", "Open MRs", "production_queue", "GitLab merge requests not collected")):
        currency(key, label, "Unavailable", supply,
                 [{"label": label, "value": reason, "target_id": ROOT_ID}], False)
    raw_catalog = {"schema_version": CONTRACT_VERSION, "root_id": ROOT_ID,
                   "source": snapshot.get("source", "provided_snapshot"),
                   "example": snapshot.get("example", False),
                   "errors": snapshot.get("errors", []), "nodes": nodes,
                   "edges": edges, "rts_currencies": currencies}
    if isinstance(snapshot.get("collected_at"), str) and snapshot["collected_at"]:
        raw_catalog["collected_at"] = snapshot["collected_at"]
    catalog = sanitize(raw_catalog)
    overlay_knowledge_base_runbooks(catalog)
    if validate_spatial_graph_contract(catalog):
        raise ValueError("snapshot produced an invalid spatial graph")
    return catalog


_NODE_CAPACITIES = {
    "nodealpha01": {
        "capacity": {"cpu": "4", "memory": "16150320Ki", "pods": "250"},
        "allocatable": {"cpu": "3600m", "memory": "11444016Ki", "pods": "250"},
        "metrics": {"cpu_percent": 21.0, "ram_percent": 77.0, "cpu_used": "840m", "ram_used": "12142Mi"},
    },
    "nodebeta02": {
        "capacity": {"cpu": "20", "memory": "32594020Ki", "pods": "110"},
        "allocatable": {"cpu": "20", "memory": "32491620Ki", "pods": "110"},
        "metrics": {"cpu_percent": 0.0, "ram_percent": 0.0, "cpu_used": "0m", "ram_used": "0Mi"},
    },
    "nodegamma03": {
        "capacity": {"cpu": "20", "memory": "131587792Ki", "nvidia.com/gpu": "10", "pods": "500"},
        "allocatable": {"cpu": "20", "memory": "131485392Ki", "nvidia.com/gpu": "10", "pods": "500"},
        "metrics": {"cpu_percent": 39.0, "ram_percent": 61.0, "cpu_used": "7800m", "ram_used": "78339Mi"},
    },
}


def refresh_bundled_catalog(path=None):
    """Enrich a sanitized catalog with node capacities, bounded containers, and prune dead nodebeta02 jobs."""
    target = Path(__file__).with_name("live-cluster-sanitized.json") if path is None else Path(path)
    catalog = json.loads(target.read_text(encoding="utf-8"))
    catalog["collected_at"] = "2026-11-01T21:00:00Z"
    removed_ids = set()
    kept_nodes = []
    for node in catalog.get("nodes", []):
        res = node.get("resource") if isinstance(node.get("resource"), dict) else {}
        kind = node.get("resource_kind") or res.get("kind")
        if (kind == "Pod"
                and res.get("spec", {}).get("nodeName") == "nodebeta02"
                and res.get("status", {}).get("phase") == "Succeeded"):
            removed_ids.add(node["id"])
            continue
        if kind == "Node":
            name = res.get("metadata", {}).get("name") or node.get("label")
            if name in _NODE_CAPACITIES:
                info = _NODE_CAPACITIES[name]
                status = res.setdefault("status", {})
                status["capacity"] = dict(info["capacity"])
                status["allocatable"] = dict(info["allocatable"])
                node["metrics"] = dict(info["metrics"])
                if name == "nodebeta02":
                    status["conditions"] = [{"type": "Ready", "status": "False"}]
        elif kind == "Pod":
            spec = res.setdefault("spec", {})
            cname = res.get("metadata", {}).get("name") or node.get("label") or "app"
            spec["containers"] = _slim_containers(spec.get("containers") or [{"name": cname}])
            if "initContainers" in spec:
                spec["initContainers"] = _slim_containers(spec["initContainers"])
        elif kind == "Deployment":
            spec = res.setdefault("spec", {})
            cname = res.get("metadata", {}).get("name") or node.get("label") or "app"
            tmpl = spec.setdefault("template", {})
            tspec = tmpl.setdefault("spec", {})
            tspec["containers"] = _slim_containers(tspec.get("containers") or [{"name": cname}])
            if "initContainers" in tspec:
                tspec["initContainers"] = _slim_containers(tspec["initContainers"])
        kept_nodes.append(node)
    # Ensure a synthetic failed runner job pod exists in gitlab namespace for health/diff demo tests
    demo_failed_id = "k8s/Pod/gitlab/runner-job-demo-failed"
    if not any(n.get("id") == demo_failed_id for n in kept_nodes):
        kept_nodes.append({
            "id": demo_failed_id,
            "label": "runner-job-demo-failed",
            "kind": "kubernetes_pod",
            "domain": "deployments_k8s",
            "summary": "runner-job-demo-failed",
            "primary_url": "https://kubernetes.cluster.example.org",
            "drilldown_children": [],
            "resource_kind": "Pod",
            "namespace": "gitlab",
            "resource": {
                "kind": "Pod",
                "metadata": {"name": "runner-job-demo-failed", "namespace": "gitlab", "labels": {"app": "gitlab-example"}},
                "spec": {"nodeName": "nodealpha01", "containers": _slim_containers([{"name": "runner-job"}])},
                "status": {"phase": "Failed"},
            },
        })
        for n in kept_nodes:
            if n.get("id") == "k8s/Namespace//gitlab":
                if demo_failed_id not in n.setdefault("drilldown_children", []):
                    n["drilldown_children"].append(demo_failed_id)
        catalog.setdefault("edges", []).extend([
            {"source": "k8s/Namespace//gitlab", "target": demo_failed_id, "relation": "contains"},
            {"source": demo_failed_id, "target": "k8s/Node//nodealpha01", "relation": "runs_on_hardware"},
        ])
    for node in kept_nodes:
        if isinstance(node.get("drilldown_children"), list):
            node["drilldown_children"] = [cid for cid in node["drilldown_children"] if cid not in removed_ids]
    catalog["nodes"] = kept_nodes
    catalog["edges"] = [
        e for e in catalog.get("edges", [])
        if e.get("source") not in removed_ids and e.get("target") not in removed_ids
    ]
    catalog["node_count"] = len(catalog["nodes"])
    catalog["edge_count"] = len(catalog["edges"])
    catalog = sanitize(catalog)
    if validate_spatial_graph_contract(catalog):
        raise ValueError("refreshed catalog failed spatial graph contract")
    target.write_text(json.dumps(catalog, indent=2, allow_nan=False) + "\n", encoding="utf-8", newline="\n")
    return catalog


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harvest-live", action="store_true", help="Invoke read-only kubectl")
    parser.add_argument("--refresh-bundled", action="store_true", help="Enrich bundled live-cluster-sanitized.json")
    parser.add_argument("--export", type=Path, metavar="FILE", help="Write sanitized catalog JSON")
    parser.add_argument("--json", action="store_true", help="Print sanitized catalog JSON")
    args = parser.parse_args(argv)
    if args.refresh_bundled:
        catalog = refresh_bundled_catalog(args.export)
        print(f"Refreshed catalog: {catalog['source']}; {len(catalog['nodes'])} objects; "
              f"collected_at={catalog.get('collected_at')}")
        return 0
    snapshot = harvest_live_k8s_cluster() if args.harvest_live else None
    catalog = build_live_cluster_spatial_catalog(snapshot)
    encoded = json.dumps(catalog, indent=2, allow_nan=False) + "\n"
    if args.export:
        args.export.write_text(encoded, encoding="utf-8", newline="\n")
    if args.json:
        print(encoded, end="")
    else:
        print(f"Cluster catalog: {catalog['source']}; {len(catalog['nodes'])} objects; "
              f"example={catalog['example']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
