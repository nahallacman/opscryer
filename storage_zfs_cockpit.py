# SPDX-License-Identifier: Apache-2.0
"""Read-only storage topology from an offline, sanitized cluster graph."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
from html import escape
from pathlib import Path
import re
from urllib.parse import urlsplit

from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")
_ERROR = "Invalid storage cockpit catalog"
_CLASSES = ("openzfs-iscsi-csi", "zfs-nfs")
_INVALID_REQUEST = "Invalid storage cockpit request"


def render_storage_cockpit_markdown(catalog=None) -> str:
    """Export sanitized snapshot evidence with literal, escaped table cells."""
    data = summarize_storage_topology(catalog)

    def cell(value):
        if value is None:
            value = "Unknown"
        elif isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, sort_keys=True)
        value = escape(" ".join(str(value).split()), quote=False)
        return re.sub(r"([\\`*_{}\[\]()#+!|~])", r"\\\1", value)

    lines = ["# OpenZFS ZFS, Democratic-CSI & CloudNativePG Storage Cockpit", "",
             cell(data["notice"]), ""]

    def table(title, headers, rows):
        lines.extend(["## " + title, ""])
        for row in (headers, ["---"] * len(headers)):
            lines.append("| " + " | ".join(row) + " |")
        count = 0
        for row in rows:
            lines.append("| " + " | ".join(cell(v) for v in row) + " |")
            count += 1
        if not count:
            lines.append("| " + " | ".join(["No observations"] + [""] * (len(headers) - 1)) + " |")
        lines.append("")

    table("Snapshot provenance", ["Field", "Value"], [
        ("Source", data["source"]), ("Example", data["example"]),
        *data["provenance"].items()])
    table("Storage classes / OpenZFS ZFS context",
          ["Class", "Observed", "Context", "Provisioner", "Claim IDs", "Workload IDs"],
          ((c["name"], c["observed"], c["context"], c["provisioner"],
            c["claim_ids"], c["workload_ids"]) for c in data["storage_classes"]))
    for key, title in (("democratic_csi", "ZFS / Democratic-CSI controllers and nodes"),
                       ("seaweedfs", "SeaweedFS"), ("cloudnativepg", "CloudNativePG")):
        table(title, ["Namespace", "Kind", "Name", "Role", "Protocol", "Phase", "Ready", "Node"],
              ((r["namespace"], r["kind"], r["name"], r["role"], r["protocol"],
                r["phase"], r["ready_condition"], r["node_name"])
               for r in data["components"][key]))
    table("Persistent volume claims", ["Namespace", "Name", "Class", "Phase", "Requested", "Capacity", "Volume"],
          ((r["namespace"], r["name"], r["storage_class"], r["phase"],
            r["requested_storage"], r["capacity"], r["volume_name"])
           for r in data["persistent_volume_claims"]))
    table("Persistent volumes", ["Name", "Class", "Phase", "Capacity", "Claim"],
          ((r["name"], r["storage_class"], r["phase"], r["capacity"], r["claim_ref"])
           for r in data["persistent_volumes"]))
    table("Stateful workloads", ["Namespace", "Kind", "Name", "Claims", "Claim templates", "Storage", "WAL storage"],
          ((r["namespace"], r["kind"], r["name"], r["claims"], r["claim_templates"],
            r["storage"], r["wal_storage"]) for r in data["stateful_workloads"]))
    table("Storage lineage", ["Source", "Relation", "Target"],
          ((r["source"], r["relation"], r["target"]) for r in data["lineage"]))
    table("Operator portals", ["Portal", "URL"], data["links"].items())
    return "\n".join(lines)


def render_storage_cockpit_html(catalog=None) -> str:
    """Render an offline bento cockpit; catalog values only become DOM text."""
    data = summarize_storage_topology(catalog)
    payload = (json.dumps(data, ensure_ascii=True, allow_nan=False)
               .replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e"))
    return r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>OpsCryer | Storage Cockpit</title>
<style>
:root { color-scheme: dark; font-family: system-ui, sans-serif; background: #0b1120; color: #e2e8f0; }
* { box-sizing: border-box; }
body { max-width: 1440px; margin: auto; padding: 24px; line-height: 1.6; }
nav, #storage-filter-buttons { display: flex; flex-wrap: wrap; gap: 12px; }
a { color: #7dd3fc; } [aria-current="page"] { font-weight: bold; }
header, section { margin: 24px 0; }
.bento { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr)); gap: 16px; }
article, .notice { background: #131e32; border: 1px solid #334155; border-radius: 18px; padding: 20px; }
article h3 { color: #a5f3fc; margin-top: 0; }
p, li, h3 { overflow-wrap: anywhere; white-space: pre-line; }
.notice { border-left: 4px solid #fbbf24; }
button { background: #17253b; color: #e2e8f0; border: 1px solid #64748b; border-radius: 24px; padding: 10px 18px; cursor: pointer; font: inherit; }
button[aria-pressed="true"] { background: #155e75; border-color: #67e8f9; }
:focus-visible { outline: 3px solid #fbbf24; outline-offset: 4px; }
.muted { color: #b0bed1; }
</style>
</head>
<body>
<nav aria-label="Main navigation">
<a href="/">Overview</a><a href="/chat">Chat</a><a href="/incidents">Incidents</a>
<a href="/capacity">Capacity</a><a href="/network">Network</a><a href="/gitops">GitOps</a>
<a href="/storage" aria-current="page">Storage</a>
</nav>
<main>
<header><p class="muted">OpsCryer / Storage</p>
<h1>OpenZFS ZFS, Democratic-CSI &amp; CloudNativePG Storage Cockpit</h1>
<p id="storage-provenance"></p><p id="storage-notice" class="notice"></p></header>
<noscript>Enable JavaScript to display the embedded storage snapshot and class filters.</noscript>
<section aria-labelledby="storage-classes-heading"><h2 id="storage-classes-heading">Storage classes</h2>
<div id="storage-filter-buttons" role="group" aria-label="Filter by storage class"></div>
<p id="storage-filter-status" role="status" aria-live="polite"></p>
<div id="storage-class-grid" class="bento"></div></section>
<section aria-labelledby="storage-csi-heading"><h2 id="storage-csi-heading">OpenZFS ZFS / Democratic-CSI</h2>
<div id="storage-csi-grid" class="bento"></div></section>
<section aria-labelledby="storage-stateful-heading"><h2 id="storage-stateful-heading">SeaweedFS &amp; CloudNativePG</h2>
<div id="storage-stateful-grid" class="bento"></div></section>
<section aria-labelledby="storage-claims-heading"><h2 id="storage-claims-heading">Claims &amp; volumes</h2>
<div id="storage-claims-grid" class="bento"></div></section>
<section aria-labelledby="storage-lineage-heading"><h2 id="storage-lineage-heading">Storage lineage</h2>
<ul id="storage-lineage"></ul></section>
</main>
<script id="storage-cockpit-data" type="application/json">''' + payload + r'''</script>
<script>
"use strict";
const data = JSON.parse(document.getElementById("storage-cockpit-data").textContent);
const get = id => document.getElementById(id);
function add(parent, tag, text) {
    const element = document.createElement(tag);
    element.textContent = text;
    parent.appendChild(element);
    return element;
}
function value(v) {
    return v === null || v === undefined ? "Unknown" :
        typeof v === "object" ? JSON.stringify(v) : String(v);
}
function card(grid, title, fields) {
    const item = add(grid, "article", "");
    add(item, "h3", title);
    for (const [label, v] of fields) add(item, "p", label + ": " + value(v));
}
get("storage-notice").textContent = data.notice;
get("storage-provenance").textContent = "Source: " + value(data.source) +
    " | Collected: " + value(data.provenance.collected_at) +
    " | Offline snapshot | Example: " + value(data.example);
for (const error of data.provenance.errors) add(get("storage-notice"), "p", value(error));
let selected = "all";
const buttons = [];
for (const name of ["all", ...data.storage_classes.map(c => c.name)]) {
    const button = add(get("storage-filter-buttons"), "button", name === "all" ? "All storage classes" : name);
    button.type = "button";
    button.addEventListener("click", () => { selected = name; render(); });
    buttons.push([name, button]);
}
function render() {
    for (const [name, button] of buttons) button.setAttribute("aria-pressed", String(name === selected));
    for (const id of ["storage-class-grid", "storage-csi-grid", "storage-stateful-grid", "storage-claims-grid", "storage-lineage"]) get(id).textContent = "";
    const classes = data.storage_classes.filter(c => selected === "all" || c.name === selected);
    const ids = new Set(classes.flatMap(c => [...c.workload_ids, ...c.claim_ids]));
    const matches = row => selected === "all" || ids.has(row.node_id);
    for (const c of classes) card(get("storage-class-grid"), c.name, [
        ["Configuration context", c.context], ["StorageClass observed", c.observed],
        ["Provisioner", c.provisioner], ["Claims", c.claim_ids.length],
        ["Workloads", c.workload_ids.length], ["ZFS pool health", "Unknown; not collected"]]);
    // CSI protocol is configuration context, not an observed workload-to-class binding.
    const protocol = selected === "openzfs-iscsi-csi" ? "iscsi" : selected === "zfs-nfs" ? "nfs" : null;
    for (const row of data.components.democratic_csi.filter(r => !protocol || r.protocol === protocol || r.protocol === null)) {
        card(get("storage-csi-grid"), row.name, [["Namespace / kind", row.namespace + " / " + row.kind],
            ["Role", row.role], ["Protocol context", row.protocol], ["Phase", row.phase],
            ["Ready condition", row.ready_condition], ["Node", row.node_name]]);
    }
    const stateful = new Map(data.stateful_workloads.map(r => [r.node_id, r]));
    const shown = new Set();
    for (const [group, label] of [["seaweedfs", "SeaweedFS"], ["cloudnativepg", "CloudNativePG"]]) {
        for (const row of data.components[group].filter(matches)) {
            shown.add(row.node_id);
            const workload = stateful.get(row.node_id);
            card(get("storage-stateful-grid"), label + " / " + row.name, [
                ["Namespace / kind", row.namespace + " / " + row.kind], ["Role", row.role],
                ["Phase", row.phase], ["Ready condition", row.ready_condition],
                ["Claims", workload ? workload.claims : null],
                ["Storage", workload ? workload.storage : null], ["WAL storage", workload ? workload.wal_storage : null]]);
        }
    }
    for (const row of data.stateful_workloads.filter(r => matches(r) && !shown.has(r.node_id))) {
        card(get("storage-stateful-grid"), row.name, [["Kind", row.kind], ["Namespace", row.namespace],
            ["Claims", row.claims], ["Claim templates", row.claim_templates], ["Storage", row.storage], ["WAL storage", row.wal_storage]]);
    }
    for (const row of [...data.persistent_volume_claims, ...data.persistent_volumes].filter(r => selected === "all" || r.storage_class === selected)) {
        ids.add(row.node_id);
        card(get("storage-claims-grid"), row.name, [["Kind", row.kind], ["Namespace", row.namespace],
            ["Storage class", row.storage_class], ["Phase", row.phase], ["Capacity", row.capacity],
            ["Requested", row.requested_storage], ["Binding", row.volume_name || row.claim_ref]]);
    }
    for (const edge of data.lineage.filter(e => selected === "all" || ids.has(e.source) || ids.has(e.target.node_id))) {
        add(get("storage-lineage"), "li", edge.source + " → " + edge.relation + " → " + value(edge.target) +
            (edge.target.node_id ? "" : " (unresolved reference)"));
    }
    for (const id of ["storage-csi-grid", "storage-stateful-grid", "storage-claims-grid", "storage-lineage"]) {
        if (!get(id).children.length) add(get(id), id === "storage-lineage" ? "li" : "p", "No observations for this filter; health is unknown.");
    }
    get("storage-filter-status").textContent = "Showing: " + (selected === "all" ? "all storage classes" : selected) +
        ". CSI cards show protocol context; unknown protocols remain visible.";
}
render();
</script>
</body>
</html>'''


def _validate(catalog):
    """Validate JSON, graph identities, and the resource shapes we inspect."""
    def json_value(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ValueError
                json_value(child)
        elif isinstance(value, list):
            for child in value:
                json_value(child)
        elif value is not None and type(value) not in (str, bool, int, float):
            raise ValueError
        elif type(value) is float and not math.isfinite(value):
            raise ValueError

    def shape(value, context=None):
        # These Kubernetes fields are consumed below, including nested templates.
        maps = {"metadata", "spec", "status", "labels", "template",
                "persistentVolumeClaim", "resources", "requests", "claimRef",
                "walStorage", "volumeClaimTemplate"}
        lists = {"ownerReferences", "conditions", "volumes", "volumeClaimTemplates"}
        strings = {"name", "namespace", "kind", "apiVersion", "nodeName", "phase",
                   "storageClassName", "storageClass", "claimName", "volumeName",
                   "provisioner"}
        required = {"ownerReferences": ("name", "kind"),
                    "persistentVolumeClaim": ("claimName",)}
        for key in required.get(context, ()):
            if not isinstance(value.get(key), str) or not value[key].strip():
                raise ValueError
        for key, child in value.items():
            if key == "status" and context == "conditions":
                if not isinstance(child, str):
                    raise ValueError
            elif key == "storage" and isinstance(child, dict):
                shape(child, key)
            elif key in maps:
                if not isinstance(child, dict):
                    raise ValueError
                shape(child, key)
            elif key in lists:
                if not isinstance(child, list) or any(not isinstance(v, dict) for v in child):
                    raise ValueError
                for entry in child:
                    shape(entry, key)
            elif key in strings and not isinstance(child, str):
                raise ValueError
        labels = value.get("labels", {})
        if any(not isinstance(v, str) for v in labels.values()):
            raise ValueError

    json_value(catalog)
    if not isinstance(catalog, dict) or not isinstance(catalog.get("nodes"), list):
        raise ValueError
    identities, resources = set(), set()
    for node in catalog["nodes"]:
        if not isinstance(node, dict):
            raise ValueError
        identity = node.get("id")
        if not isinstance(identity, str) or not identity.strip() or identity in identities:
            raise ValueError
        identities.add(identity)
        for key in ("resource_kind", "namespace", "label"):
            if key in node and not isinstance(node[key], str):
                raise ValueError
        if "resource" not in node:
            continue
        resource = node["resource"]
        if not isinstance(resource, dict):
            raise ValueError
        shape(resource)
        kind = node.get("resource_kind", resource.get("kind"))
        if not isinstance(kind, str) or not kind:
            raise ValueError
        if "kind" in resource and resource["kind"] != kind:
            raise ValueError
        if kind == "Cluster" and not isinstance(resource.get("spec", {}).get("storage", {}), dict):
            raise ValueError
        metadata = resource.get("metadata", {})
        if ("namespace" in metadata and "namespace" in node
                and metadata["namespace"] != node["namespace"]):
            raise ValueError
        name = metadata.get("name", node.get("label", identity))
        if not name.strip():
            raise ValueError
        key = (kind, metadata.get("namespace", node.get("namespace", "default")), name)
        if key in resources:
            raise ValueError
        resources.add(key)
    edges = catalog.get("edges", [])
    if not isinstance(edges, list):
        raise ValueError
    for edge in edges:
        if (not isinstance(edge, dict)
                or any(not isinstance(edge.get(k), str) or not edge[k]
                       for k in ("source", "target", "relation"))
                or edge["source"] not in identities or edge["target"] not in identities):
            raise ValueError


def _load_catalog(catalog):
    try:
        if catalog is None or isinstance(catalog, (str, Path)):
            catalog = json.loads(Path(DEFAULT_CATALOG_PATH if catalog is None else catalog)
                                 .read_text(encoding="utf-8"))
        _validate(catalog)
        snapshot = sanitize(catalog)
        _validate(snapshot)
        return snapshot
    except (OSError, ValueError, TypeError, RecursionError):
        raise ValueError(_ERROR) from None


def summarize_storage_topology(catalog=None) -> dict:
    """Summarize a graph dict or JSON path without collection or input mutation.

    Pod phase and Ready condition are independent observations. Owner references,
    PVC mounts, claim templates and PV bindings retain unresolved references;
    missing objects never imply healthy storage or an observed OpenZFS backend.
    Lists follow graph ID order. Storage class descriptions are configuration
    context, not evidence that a class or ZFS pool was collected.
    """
    snapshot = _load_catalog(catalog)
    records = []
    for node in sorted(snapshot["nodes"], key=lambda n: n["id"]):
        resource = node.get("resource", {})
        metadata = resource.get("metadata", {})
        records.append((node, resource, {
            "node_id": node["id"],
            "kind": node.get("resource_kind", resource.get("kind")),
            "namespace": metadata.get("namespace", node.get("namespace", "default")),
            "name": metadata.get("name", node.get("label", node["id"])),
        }))
    index = {(row["kind"], row["namespace"], row["name"]): row["node_id"]
             for _, _, row in records}

    def reference(kind, namespace, name):
        return {"kind": kind, "namespace": namespace, "name": name,
                "node_id": index.get((kind, namespace, name))}

    components = {"democratic_csi": [], "seaweedfs": [], "cloudnativepg": []}
    claims, volumes, stateful, lineage = [], [], [], []
    classes = {name: {"name": name, "observed": False, "node_id": None,
                      "provisioner": None, "claim_ids": [], "workload_ids": [],
                      "context": "OpenZFS SCALE ZFS " + (
                          "iSCSI block storage" if name == "openzfs-iscsi-csi"
                          else "NFS shared storage")} for name in _CLASSES}
    for node, resource, row in records:
        kind, namespace, name = row["kind"], row["namespace"], row["name"]
        metadata, spec, status = (resource.get(k, {}) for k in ("metadata", "spec", "status"))
        labels = metadata.get("labels", {})
        owners = [reference(o.get("kind"), namespace, o.get("name"))
                  for o in metadata.get("ownerReferences", [])]
        for owner in owners:
            lineage.append({"relation": "owned_by", "source": row["node_id"],
                            "target": owner})
        evidence = " ".join([name, *labels.values()]).lower()
        group = role = None
        if namespace == "storage-system" and ("democratic" in evidence or "zfs" in evidence):
            group = "democratic_csi"
            role = "controller" if "controller" in evidence else "node" if "node" in evidence else "unknown"
        elif namespace == "storage" and "seaweed" in evidence:
            group = "seaweedfs"
            role = next((r for r in ("master", "volume", "filer", "s3") if r in evidence), "unknown")
        elif (namespace == "cnpg-system" or "cnpg.io/cluster" in labels
              or "cloudnative-pg" in evidence
              or (kind == "Cluster" and "postgresql.cnpg.io" in resource.get("apiVersion", ""))):
            group = "cloudnativepg"
            role = "operator" if namespace == "cnpg-system" else "database"
        details = dict(row, owners=owners, phase=status.get("phase"),
                       ready_condition=next((c.get("status") for c in status.get("conditions", [])
                                             if c.get("type") == "Ready"), None),
                       node_name=spec.get("nodeName"))
        if group and kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet", "Cluster"}:
            components[group].append(dict(details, role=role,
                protocol="iscsi" if "iscsi" in evidence else "nfs" if "nfs" in evidence else None))
        if kind == "Pod" and labels.get("cnpg.io/cluster"):
            lineage.append({"relation": "member_of_cluster", "source": row["node_id"],
                            "target": reference("Cluster", namespace, labels["cnpg.io/cluster"])})
        if kind == "StorageClass" and name in classes:
            classes[name].update(observed=True, node_id=row["node_id"],
                                 provisioner=resource.get("provisioner"))
        if kind in {"PersistentVolumeClaim", "PersistentVolume"}:
            entry = dict(row, phase=status.get("phase"),
                         storage_class=spec.get("storageClassName"),
                         capacity=status.get("capacity", spec.get("capacity")),
                         requested_storage=spec.get("resources", {}).get("requests", {}).get("storage"))
            if kind == "PersistentVolumeClaim":
                entry["volume_name"] = spec.get("volumeName")
                claims.append(entry)
                if entry["storage_class"] in classes:
                    classes[entry["storage_class"]]["claim_ids"].append(row["node_id"])
                if entry["volume_name"]:
                    lineage.append({"relation": "bound_to", "source": row["node_id"],
                                    "target": reference("PersistentVolume", "default", entry["volume_name"])})
            else:
                entry["claim_ref"] = spec.get("claimRef")
                volumes.append(entry)
        pod_spec = spec.get("template", {}).get("spec", {}) if kind != "Pod" else spec
        mounts = [v["persistentVolumeClaim"].get("claimName")
                  for v in pod_spec.get("volumes", []) if "persistentVolumeClaim" in v]
        templates = spec.get("volumeClaimTemplates", [])
        is_stateful = (kind in {"StatefulSet", "Cluster"} or bool(mounts)
                       or any(o["kind"] in {"StatefulSet", "Cluster"} for o in owners)
                       or (group == "cloudnativepg" and role == "database"))
        if is_stateful:
            stateful.append(dict(details, claims=[reference("PersistentVolumeClaim", namespace, n)
                                                 for n in mounts], claim_templates=templates,
                                 storage=spec.get("storage"), wal_storage=spec.get("walStorage")))
            for claim in mounts:
                lineage.append({"relation": "uses_claim", "source": row["node_id"],
                                "target": reference("PersistentVolumeClaim", namespace, claim)})
            class_names = {t.get("spec", {}).get("storageClassName") for t in templates}
            storage = spec.get("storage", {}) if kind == "Cluster" else {}
            class_names.add(storage.get("storageClass"))
            class_names.add(spec.get("walStorage", {}).get("storageClass"))
            for class_name in class_names & classes.keys():
                classes[class_name]["workload_ids"].append(row["node_id"])
    claim_classes = {c["node_id"]: c["storage_class"] for c in claims}
    for edge in lineage:
        class_name = claim_classes.get(edge["target"]["node_id"])
        if edge["relation"] == "uses_claim" and class_name in classes:
            classes[class_name]["workload_ids"].append(edge["source"])
    relevant = {w["node_id"] for w in stateful}
    relevant.update(row["node_id"] for rows in components.values() for row in rows)
    for edge in sorted(snapshot.get("edges", []),
                       key=lambda e: (e["source"], e["target"], e["relation"])):
        if edge["relation"] == "owns_workload" and edge["target"] in relevant:
            lineage.append({"relation": "owns_workload", "source": edge["source"],
                            "target": {"node_id": edge["target"]}})
    for entry in classes.values():
        entry["workload_ids"] = sorted(set(entry["workload_ids"]))
    return sanitize({
        "source": snapshot.get("source", "provided_catalog"),
        "example": snapshot.get("example", False),
        "provenance": {"mode": "offline_snapshot", "live_collection": False,
                       "collected_at": snapshot.get("collected_at"),
                       "errors": snapshot.get("errors", [])},
        "components": components, "persistent_volume_claims": claims,
        "persistent_volumes": volumes, "stateful_workloads": stateful,
        "lineage": lineage, "storage_classes": list(classes.values()),
        "links": {"grafana_storage": "https://grafana.cluster.example.org/dashboards",
                  "argocd": "https://argocd.cluster.example.org/applications",
                  "runbookgate": "https://runbookgate.cluster.example.org"},
        "notice": "Snapshot observations only. Missing PVCs, storage classes, capacity, "
                  "ZFS pool health and bindings are unknown; no live storage checks performed.",
    })


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error(_INVALID_REQUEST)


def _build_storage_cockpit_handler(catalog=None):
    """Serve the offline storage cockpit without logging request input."""
    class StorageCockpitRequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _send(self, status, body, content_type):
            body = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def send_error(self, code, message=None, explain=None):
            self._send(code, '{"error":"Invalid HTTP request"}', "application/json")

        def do_GET(self):
            try:
                url = urlsplit(self.path)
                if url.path not in {"/", "/storage", "/api/v1/storage-cockpit"}:
                    self._send(404, '{"error":"Not found"}', "application/json")
                    return
                if url.query:
                    raise ValueError(_INVALID_REQUEST)
                if url.path in {"/", "/storage"}:
                    body = render_storage_cockpit_html(catalog=catalog)
                    content_type = "text/html"
                else:
                    body = json.dumps(summarize_storage_topology(catalog=catalog),
                        indent=2, allow_nan=False)
                    content_type = "application/json"
            except (ValueError, TypeError, KeyError):
                self._send(400, json.dumps({"error": _INVALID_REQUEST}), "application/json")
                return
            except Exception:
                self._send(503, '{"error":"Storage cockpit unavailable"}',
                           "application/json")
                return
            self._send(200, body, content_type)

    return StorageCockpitRequestHandler


def main(argv=None) -> int:
    """Export a sanitized storage snapshot or serve it on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="storage_zfs_cockpit", description=__doc__,
                                 allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--markdown", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--port", type=int, default=8101)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error(_INVALID_REQUEST)
    try:
        catalog = _load_catalog(args.catalog)
        data = summarize_storage_topology(catalog)
        if args.serve:
            with ThreadingHTTPServer(("127.0.0.1", args.port),
                                     _build_storage_cockpit_handler(catalog)) as server:
                print(f"Storage cockpit: http://127.0.0.1:{args.port}/storage", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.markdown:
            print(render_storage_cockpit_markdown(catalog), end="")
        else:
            print(json.dumps(data, indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        parser.error(_INVALID_REQUEST)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
