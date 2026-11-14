# SPDX-License-Identifier: Apache-2.0
"""Piece B: stdlib-only knowledge graph, BM25 retrieval and JSON API dispatch.

No web server is required. ``handle_api_request(path, params, method, body)``
returns ``(http_status, json_serializable_payload)`` for an HTTP adapter to send.
Validation returns a list of errors (empty means valid); constructors reject
invalid catalogs. Custom entity kinds are supported within the four domains.
"""

from collections import Counter, deque
from copy import deepcopy
from functools import lru_cache
import importlib
from ipaddress import IPv4Address, ip_address
import json
import math
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit


CONTRACT_VERSION = "1.0-separable-spatial-graph-contract"
MAX_CATALOG_NODES = 50000
MAX_CATALOG_EDGES = 200000
DOMAINS = ("company_org", "processes_workflows", "deployments_k8s", "hardware_topology")
NODE_FIELDS = ("id", "label", "kind", "domain", "summary", "primary_url")
SEARCH_FIELDS = ("id", "label", "kind", "domain", "summary", "steps", "workloads", "specs")
API_METHODS = {
    "/api/v1/contract": "GET",
    "/api/v1/graph/catalog": "GET",
    "/api/v1/graph/drilldown": "GET",
    "/api/v1/graph/shortest-path": "GET",
    "/api/v1/graph/jev-tree": "GET",
    "/api/v1/graph/deflect-ticket": "POST",
    "/api/v1/graph/search": "GET",
    "/api/v1/graph/delta": "GET",
}


def _publish_event_safe(topic, event_type, data=None):
    try:
        importlib.import_module("event_stream").publish_event(topic, event_type, data)
    except Exception:
        pass


def _sanitize(value):
    """Scrub public WAN addresses and hardware identifiers before returning data."""
    if isinstance(value, dict):
        return {_sanitize(key): _sanitize(item) for key, item in value.items()}
    # JSON encoders also accept tuples; normalize them so nested telemetry is
    # scrubbed just as it is in arrays loaded from the exchange file.
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if not isinstance(value, str):
        return value

    return _sanitize_text(value)


@lru_cache(maxsize=8192)
def _sanitize_text(value):
    if "." not in value and ":" not in value and "-" not in value:
        return value

    def address(match):
        try:
            return "203.0.113.1" if IPv4Address(match[0]).is_global else match[0]
        except ValueError:
            return match[0]

    value = re.sub(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", address, value)
    return re.sub(r"\b([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})"
                  r"(?:[:-][0-9a-f]{2}){3}\b",
                  lambda m: ":".join(m.groups()).upper() + ":XX:XX:XX", value,
                  flags=re.IGNORECASE)


def resolve_trusted_client_ip(remote_addr, headers=None, trust_proxy_headers=False):
    """Return remote_addr unless trust_proxy_headers is explicitly True.

    Prevents unauthenticated clients from spoofing X-Forwarded-For headers when
    the server is not deployed behind a trusted reverse proxy.
    """
    fallback = str(remote_addr or "127.0.0.1").strip() or "127.0.0.1"
    if trust_proxy_headers is not True or not isinstance(headers, dict):
        return fallback
    forwarded = ""
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == "x-forwarded-for" and isinstance(value, str):
            forwarded = value
            break
    if not forwarded.strip():
        return fallback
    candidate = forwarded.split(",", 1)[0].strip()
    try:
        return str(ip_address(candidate))
    except ValueError:
        return fallback


def validate_spatial_graph_contract(catalog, max_nodes=MAX_CATALOG_NODES, max_edges=MAX_CATALOG_EDGES):
    """Return structural/reference errors without echoing untrusted field values."""
    errors = []
    if not isinstance(catalog, dict):
        return ["catalog must be an object"]
    if catalog.get("schema_version") != CONTRACT_VERSION:
        errors.append("unsupported schema_version")
    nodes, edges = catalog.get("nodes"), catalog.get("edges", [])
    if not isinstance(nodes, list) or not nodes:
        return errors + ["nodes must be a nonempty array"]
    if type(max_nodes) is int and max_nodes > 0 and len(nodes) > max_nodes:
        return errors + ["nodes array exceeds max_nodes bound"]
    if not isinstance(edges, list):
        errors.append("edges must be an array")
        edges = []
    elif type(max_edges) is int and max_edges > 0 and len(edges) > max_edges:
        return errors + ["edges array exceeds max_edges bound"]
    ids = set()
    for index, node in enumerate(nodes):
        prefix = f"nodes[{index}]"
        if not isinstance(node, dict):
            errors.append(prefix + " must be an object")
            continue
        for field in NODE_FIELDS:
            value = node.get(field)
            if not isinstance(value, str) or (field != "summary" and not value.strip()):
                errors.append(prefix + "." + field + " must be a string")
        node_id = node.get("id")
        if isinstance(node_id, str):
            if node_id in ids:
                errors.append(prefix + " has duplicate id")
            ids.add(node_id)
        if node.get("domain") not in DOMAINS:
            errors.append(prefix + " has unsupported domain")
        children = node.get("drilldown_children")
        if not isinstance(children, list) or any(not isinstance(c, str) or not c for c in children):
            errors.append(prefix + ".drilldown_children must be an array of ids")
        elif len(set(children)) != len(children):
            errors.append(prefix + " has duplicate children")
    for index, node in enumerate(nodes):
        if isinstance(node, dict) and isinstance(node.get("drilldown_children"), list):
            if any(isinstance(c, str) and c not in ids for c in node["drilldown_children"]):
                errors.append(f"nodes[{index}] has unknown child")
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"edges[{index}] must be an object")
            continue
        for field in ("source", "target"):
            if not isinstance(edge.get(field), str) or edge[field] not in ids:
                errors.append(f"edges[{index}] has unknown {field}")
        if not isinstance(edge.get("relation"), str) or not edge["relation"].strip():
            errors.append(f"edges[{index}] requires relation")
    for field, count in (("node_count", len(nodes)), ("edge_count", len(edges))):
        if field in catalog and (type(catalog[field]) is not int or catalog[field] != count):
            errors.append(field + " does not match array length")
    try:
        json.dumps(catalog, allow_nan=False)
    except (ValueError, TypeError, OverflowError, RecursionError):
        errors.append("catalog must contain finite JSON data")
    return errors


def _tokens(text):
    return re.findall(r"[^\W_]+", text.casefold(), flags=re.UNICODE)


def bm25_search_nodes(nodes, query, limit=10, k1=1.5, b=0.75):
    """Rank node objects using Okapi BM25; return node fields plus ``score``.

    Search uses SEARCH_FIELDS, OR term matching, unique query terms, positive
    Robertson IDF, document length normalization and id-based tie breaking.
    No model or embedding provider is contacted. Empty/unmatched queries return [].
    """
    if not isinstance(query, str):
        raise ValueError("query must be a string")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("limit must be an integer from 1 to 100")
    if (type(k1) not in (int, float) or not math.isfinite(k1) or k1 <= 0
            or type(b) not in (int, float) or not math.isfinite(b) or not 0 <= b <= 1):
        raise ValueError("invalid BM25 parameters")
    if not isinstance(nodes, list) or any(not isinstance(node, dict) for node in nodes):
        raise ValueError("nodes must be an array of objects")
    terms = set(_tokens(query))
    if not terms or not nodes:
        return []
    return _rank_bm25(nodes, terms, limit, k1, b, _build_search_index(nodes))


def _build_search_index(nodes):
    documents = [Counter(_tokens(" ".join(
        json.dumps(node.get(field, ""), ensure_ascii=False) for field in SEARCH_FIELDS
    ))) for node in nodes]
    lengths = [sum(doc.values()) for doc in documents]
    average = sum(lengths) / len(documents) if documents else 0
    frequencies = Counter(term for doc in documents for term in doc)
    return documents, lengths, average, frequencies


def _rank_bm25(nodes, terms, limit, k1, b, index):
    documents, lengths, average, frequencies = index
    if not average:
        return []
    # Preserve sorted-term floating point accumulation while sharing IDF work.
    weighted_terms = [(term, math.log(1 + (len(nodes) - frequencies[term] + 0.5)
                                    / (frequencies[term] + 0.5)))
                      for term in sorted(terms)]
    hits = []
    for node, doc, length in zip(nodes, documents, lengths):
        score = 0.0
        for term, idf in weighted_terms:
            frequency = doc[term]
            if frequency:
                score += idf * frequency * (k1 + 1) / (
                    frequency + k1 * (1 - b + b * length / average))
        if score > 0:
            hits.append((score, node))
    hits.sort(key=lambda hit: (-hit[0], str(hit[1].get("id", ""))))
    # Only selected results need detached copies, even when every node matches.
    return _sanitize([{**deepcopy(node), "score": score} for score, node in hits[:limit]])


def _jev_tree():
    nodes = {}
    decisions = (
        ("node-demo-check-scaffolding", "is_project_scaffolding", "leaf-demo-golden-path",
         "node-demo-check-credentials", "proc-demo-cicd"),
        ("node-demo-check-credentials", "is_credential_access", "leaf-demo-zero-trust-secret",
         "leaf-demo-standard-guidance", "proc-demo-secret-policy"),
    )
    for node_id, predicate, yes, no, anchor in decisions:
        nodes[node_id] = dict(node_id=node_id, kind="decision", predicate_id=predicate,
                              true_branch=yes, false_branch=no, anchor_node_id=anchor)
    for node_id, policy, allowed, ticket, anchor in (
        ("leaf-demo-golden-path", "playbook-demo-golden-path-3tier", True,
         "IT-DEMO-GP-01", "proc-demo-cicd"),
        ("leaf-demo-zero-trust-secret", "policy-demo-zero-trust-secrets", False,
         "IT-DEMO-DB-01", "proc-demo-secret-policy"),
        ("leaf-demo-standard-guidance", "policy-demo-standard-guidance", True,
         "IT-DEMO-OPS-01", "deploy-demo-k8s"),
    ):
        nodes[node_id] = dict(node_id=node_id, kind="leaf", policy_id=policy,
                              direct_access_allowed=allowed, required_it_tickets=[ticket],
                              anchor_node_id=anchor)
    return {"schema_version": "1.0-system-one-decision-tree",
            "root_node_id": "node-demo-check-scaffolding", "default_min_confidence": 0.80,
            "nodes": nodes}


class KnowledgeGraphBackendEngine:
    """Own a validated graph snapshot; all public results are detached copies."""

    def __init__(self, catalog=None):
        if catalog is None:
            catalog = json.loads(Path(__file__).with_name("sample-graph-data.json").read_text(
                encoding="utf-8"))
        errors = validate_spatial_graph_contract(catalog)
        if errors:
            raise ValueError("; ".join(errors))
        # Only graph data is needed from the shared exchange file.
        self._catalog = _sanitize(deepcopy(catalog))
        self._catalog.pop("rts_currencies", None)
        self._catalog.pop("object_archetypes", None)
        self._catalog["piece_role"] = "PIECE_B_HEADLESS_KNOWLEDGE_GRAPH"
        self._catalog["node_count"] = len(catalog["nodes"])
        self._catalog["edge_count"] = len(catalog.get("edges", []))
        errors = validate_spatial_graph_contract(self._catalog)
        if errors:
            raise ValueError("sanitization produced an invalid graph")
        self._by_id = {node["id"]: node for node in self._catalog["nodes"]}
        self._search_index = _build_search_index(self._catalog["nodes"])
        self._adj = {node_id: [] for node_id in self._by_id}
        # Retain the existing private names as aliases to the same indexes.
        self._nodes = self._by_id
        self._adjacency = self._adj
        neighbors = {node_id: set() for node_id in self._nodes}
        links = [(node["id"], child) for node in self._nodes.values()
                 for child in node["drilldown_children"]]
        links.extend((edge["source"], edge["target"]) for edge in self._catalog.get("edges", []))
        for source, target in links:
            for left, right in ((source, target), (target, source)):
                if right not in neighbors[left]:
                    neighbors[left].add(right)
                    self._adj[left].append(right)

    def catalog(self):
        return deepcopy(self._catalog)

    def drilldown(self, node_id):
        if not isinstance(node_id, str) or node_id not in self._nodes:
            raise KeyError("unknown node")
        node = self._nodes[node_id]
        return deepcopy({"schema_version": CONTRACT_VERSION, "node": node,
                         "children": [self._nodes[child] for child in node["drilldown_children"]]})

    def shortest_path(self, source_id, target_id):
        """Find a minimum-hop undirected path over explicit and containment links."""
        if not isinstance(source_id, str) or not isinstance(target_id, str):
            raise ValueError("path endpoints must be strings")
        result = {"schema_version": CONTRACT_VERSION, "source_id": _sanitize(source_id),
                  "target_id": _sanitize(target_id), "path_found": False, "hop_count": 0,
                  "path_ids": [], "path": [], "path_nodes": [], "ascii_lineage": ""}
        if source_id not in self._nodes or target_id not in self._nodes:
            return result
        queue, parents = deque([source_id]), {source_id: None}
        while queue:
            current = queue.popleft()
            if current == target_id:
                break
            for neighbor in self._adj[current]:
                if neighbor not in parents:
                    parents[neighbor] = current
                    queue.append(neighbor)
        if target_id not in parents:
            return result
        path, current = [], target_id
        while current is not None:
            path.append(current)
            current = parents[current]
        path.reverse()
        path_nodes = [{field: self._nodes[node_id][field] for field in ("id", "label", "domain", "kind")}
                      for node_id in path]
        result.update(path_found=True, hop_count=len(path) - 1, path_ids=path, path=path, path_nodes=path_nodes,
                      ascii_lineage=" -> ".join(f"{n['label']} ({n['id']})" for n in path_nodes))
        return result

    def search(self, query, limit=10):
        if not isinstance(query, str):
            raise ValueError("query must be a string")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer from 1 to 100")
        terms = set(_tokens(query))
        hits = []
        if terms:
            hits = _rank_bm25(self._catalog["nodes"], terms, limit, 1.5, 0.75,
                              self._search_index)
        return {"schema_version": CONTRACT_VERSION, "query": _sanitize(query),
                "algorithm": "BM25", "results": hits, "result_count": len(hits)}

    def jev_tree(self):
        return _jev_tree()

    def deflect_ticket(self, ticket_title, min_confidence=0.80):
        """Deterministic demo policy traversal; probabilities are synthetic.

        Missing graph anchors or an unmet confidence threshold fail closed.
        Results describe policy guidance and never execute provisioning actions.
        """
        if not isinstance(ticket_title, str) or not ticket_title.strip():
            raise ValueError("ticket_title must be a nonempty string")
        if (type(min_confidence) not in (int, float) or not 0.80 <= min_confidence <= 1):
            raise ValueError("min_confidence must be between 0.80 and 1")
        tree, steps = self.jev_tree(), []
        current = tree["root_node_id"]
        keywords = {
            "is_project_scaffolding": ("3 tier", "3-tier", "scaffold", "spin up", "new project", "pipeline"),
            "is_credential_access": ("password", "credential", "secret", "break-glass", "database access"),
        }
        while True:
            node = tree["nodes"][current]
            if node["anchor_node_id"] not in self._nodes:
                break
            if node["kind"] == "leaf":
                steps.append({key: node[key] for key in ("node_id", "kind", "policy_id", "anchor_node_id")})
                res = {"schema_version": CONTRACT_VERSION, "route": node["policy_id"],
                       **{key: deepcopy(node[key]) for key in (
                           "policy_id", "direct_access_allowed", "required_it_tickets", "anchor_node_id")},
                       "traversal_steps": steps}
                _publish_event_safe("jev", "ticket_deflected", {
                    "ticket_title": ticket_title,
                    "route": res["route"],
                    "policy_id": res["policy_id"],
                    "direct_access_allowed": res["direct_access_allowed"],
                })
                return res
            predicate = node["predicate_id"]
            value = any(word in ticket_title.casefold() for word in keywords[predicate])
            probability = ((0.96 if value else 0.94) if predicate == "is_project_scaffolding"
                           else (0.97 if value else 0.93))
            steps.append({"node_id": current, "predicate_id": predicate, "evaluated_value": value,
                          "calibrated_probability": probability, "anchor_node_id": node["anchor_node_id"]})
            if probability < min_confidence:
                break
            current = node["true_branch" if value else "false_branch"]
        esc = {"schema_version": CONTRACT_VERSION, "route": "human_escalation",
               "policy_id": None, "direct_access_allowed": False, "required_it_tickets": [],
               "anchor_node_id": None, "traversal_steps": steps}
        _publish_event_safe("jev", "ticket_deflected", {
            "ticket_title": ticket_title,
            "route": "human_escalation",
            "policy_id": None,
            "direct_access_allowed": False,
        })
        return esc

    def add_node(self, node):
        if not isinstance(node, dict) or "id" not in node:
            raise ValueError("node must be a dictionary containing at least an 'id'")
        nid = str(node["id"])
        if nid in self._nodes:
            raise ValueError(f"node with id '{nid}' already exists")
        sanitized = _sanitize(deepcopy(node))
        sanitized.setdefault("drilldown_children", [])
        self._catalog["nodes"].append(sanitized)
        self._catalog["node_count"] = len(self._catalog["nodes"])
        self._by_id[nid] = sanitized
        self._adj[nid] = []
        for child in sanitized["drilldown_children"]:
            if child in self._adj and nid not in self._adj[child]:
                self._adj[child].append(nid)
                self._adj[nid].append(child)
        self._search_index = _build_search_index(self._catalog["nodes"])
        _publish_event_safe("graph", "node_added", {"node": deepcopy(sanitized)})
        return deepcopy(sanitized)

    def update_node(self, node):
        if not isinstance(node, dict) or "id" not in node:
            raise ValueError("node must be a dictionary containing at least an 'id'")
        nid = str(node["id"])
        if nid not in self._nodes:
            raise KeyError(f"unknown node '{nid}'")
        target = self._by_id[nid]
        sanitized = _sanitize(deepcopy(node))
        target.update(sanitized)
        self._search_index = _build_search_index(self._catalog["nodes"])
        _publish_event_safe("graph", "node_updated", {"node": deepcopy(target)})
        return deepcopy(target)

    def remove_node(self, node_id):
        if not isinstance(node_id, str) or node_id not in self._nodes:
            raise KeyError(f"unknown node '{node_id}'")
        old_node = self._by_id[node_id]
        self._catalog["nodes"] = [n for n in self._catalog["nodes"] if n["id"] != node_id]
        self._catalog["node_count"] = len(self._catalog["nodes"])
        self._by_id.pop(node_id, None)
        self._catalog["edges"] = [e for e in self._catalog.get("edges", [])
                                  if e.get("source") != node_id and e.get("target") != node_id]
        self._catalog["edge_count"] = len(self._catalog["edges"])
        self._adj.pop(node_id, None)
        for neighbors in self._adj.values():
            if node_id in neighbors:
                neighbors.remove(node_id)
        for n in self._catalog["nodes"]:
            if node_id in n.get("drilldown_children", []):
                n["drilldown_children"] = [c for c in n["drilldown_children"] if c != node_id]
        self._search_index = _build_search_index(self._catalog["nodes"])
        _publish_event_safe("graph", "node_removed", {"node_id": node_id, "node": deepcopy(old_node)})
        return deepcopy(old_node)

    def add_edge(self, edge):
        if not isinstance(edge, dict) or "source" not in edge or "target" not in edge:
            raise ValueError("edge must be a dictionary containing 'source' and 'target'")
        source = str(edge["source"])
        target = str(edge["target"])
        if source not in self._nodes or target not in self._nodes:
            raise KeyError(f"source or target node not found: source='{source}', target='{target}'")
        sanitized = _sanitize(deepcopy(edge))
        self._catalog.setdefault("edges", []).append(sanitized)
        self._catalog["edge_count"] = len(self._catalog["edges"])
        if target not in self._adj[source]:
            self._adj[source].append(target)
        if source not in self._adj[target]:
            self._adj[target].append(source)
        _publish_event_safe("graph", "edge_added", {"edge": deepcopy(sanitized)})
        return deepcopy(sanitized)

    def remove_edge(self, source, target, relation=None):
        if not isinstance(source, str) or not isinstance(target, str):
            raise ValueError("source and target must be strings")
        edges = self._catalog.get("edges", [])
        matched = False
        remaining = []
        for e in edges:
            if not matched and e.get("source") == source and e.get("target") == target:
                if relation is None or e.get("relation") == relation:
                    matched = True
                    continue
            remaining.append(e)
        if not matched:
            raise KeyError(f"edge not found: source='{source}', target='{target}'")
        self._catalog["edges"] = remaining
        self._catalog["edge_count"] = len(remaining)
        has_link = any((e.get("source") == source and e.get("target") == target) or
                       (e.get("source") == target and e.get("target") == source)
                       for e in remaining)
        s_node = self._nodes.get(source, {})
        t_node = self._nodes.get(target, {})
        if not has_link and target not in s_node.get("drilldown_children", []) and source not in t_node.get("drilldown_children", []):
            if target in self._adj.get(source, []):
                self._adj[source].remove(target)
            if source in self._adj.get(target, []):
                self._adj[target].remove(source)
        _publish_event_safe("graph", "edge_removed", {"source": source, "target": target, "relation": relation})
        return {"source": source, "target": target, "relation": relation}

    def delta(self, since_seq=0):
        return importlib.import_module("event_stream").get_delta(since_seq=since_seq)

    def contract(self):
        """Return an OpenAPI 3.1 description of the transport-neutral API."""
        parameters = {
            "drilldown": [("node_id", "string", True)],
            "shortest-path": [("source_id", "string", True), ("target_id", "string", True)],
            "search": [("q", "string", True), ("limit", "integer", False)],
            "delta": [("since_seq", "integer", False)],
        }
        paths = {}
        for path, method in API_METHODS.items():
            operation = {"responses": {str(status): {"description": description} for status, description in (
                (200, "JSON result"), (400, "Invalid request"), (404, "Not found"), (405, "Method not allowed"))}}
            operation["parameters"] = [
                {"name": name, "in": "query", "required": required, "schema": {
                    "type": kind, **({"minimum": 1, "maximum": 100} if kind == "integer" else {})}}
                for name, kind, required in parameters.get(path.rsplit("/", 1)[-1], [])]
            if method == "POST":
                operation["requestBody"] = {"required": True, "content": {"application/json": {
                    "schema": {"type": "object", "required": ["ticket_title"], "properties": {
                        "ticket_title": {"type": "string", "minLength": 1},
                        "min_confidence": {"type": "number", "minimum": 0.80, "maximum": 1}}}}}}
            paths[path] = {method.lower(): operation}
        return {"openapi": "3.1.0", "info": {"title": "OpsCryer Piece B", "version": CONTRACT_VERSION},
                "schema_version": CONTRACT_VERSION, "domains": list(DOMAINS), "paths": paths,
                "components": {"schemas": {"SpatialGraphNode": {
                    "type": "object", "required": list(NODE_FIELDS) + ["drilldown_children"],
                    "properties": {**{field: {"type": "string"} for field in NODE_FIELDS},
                                   "domain": {"enum": list(DOMAINS)},
                                   "drilldown_children": {"type": "array", "uniqueItems": True,
                                                          "items": {"type": "string"}}}}}}}

    def handle_api_request(self, path, params=None, method="GET", body=None):
        """Dispatch a path/URL; explicit params override URL query parameters."""
        if not isinstance(path, str) or not isinstance(method, str):
            return 400, {"error": "invalid request"}
        try:
            url = urlsplit(path)
            if url.path not in API_METHODS:
                return 404, {"error": "unknown endpoint"}
            if method.upper() != API_METHODS[url.path]:
                return 405, {"error": "method not allowed", "allowed_method": API_METHODS[url.path]}
            query = parse_qs(url.query, keep_blank_values=True)
            if params is not None:
                if not isinstance(params, dict):
                    raise ValueError("params must be an object")
                query.update(params)

            def argument(name):
                value = query.get(name)
                if isinstance(value, list):
                    if len(value) != 1:
                        raise ValueError("ambiguous argument")
                    value = value[0]
                if not isinstance(value, str) or not value.strip():
                    raise ValueError("missing argument")
                return value

            endpoint = url.path.rsplit("/", 1)[-1]
            if endpoint == "contract":
                result = self.contract()
            elif endpoint == "catalog":
                result = self.catalog()
            elif endpoint == "drilldown":
                result = self.drilldown(argument("node_id"))
            elif endpoint == "shortest-path":
                result = self.shortest_path(argument("source_id"), argument("target_id"))
            elif endpoint == "jev-tree":
                result = self.jev_tree()
            elif endpoint == "search":
                limit = query.get("limit", "10")
                if isinstance(limit, list):
                    if len(limit) != 1:
                        raise ValueError("ambiguous limit")
                    limit = limit[0]
                if type(limit) is not int and (not isinstance(limit, str) or not limit.isdecimal()):
                    raise ValueError("invalid limit")
                result = self.search(argument("q"), int(limit))
            elif endpoint == "delta":
                raw_since = query.get("since_seq", ["0"])
                if isinstance(raw_since, list):
                    if len(raw_since) != 1:
                        raise ValueError("ambiguous since_seq")
                    raw_since = raw_since[0]
                if type(raw_since) is not int and (not isinstance(raw_since, str) or not raw_since.isdecimal()):
                    raise ValueError("invalid since_seq")
                result = self.delta(int(raw_since))
            else:
                if isinstance(body, (str, bytes)):
                    body = json.loads(body)
                if not isinstance(body, dict):
                    raise ValueError("body must be an object")
                result = self.deflect_ticket(body.get("ticket_title"), body.get("min_confidence", 0.80))
            return 200, result
        except KeyError:
            return 404, {"error": "unknown node"}
        except (ValueError, TypeError, OverflowError):
            return 400, {"error": "invalid request parameters or body"}


def handle_api_request(path, params=None, method="GET", body=None, engine=None):
    """Convenience dispatcher; pass an engine to reuse a graph snapshot."""
    backend = engine if engine is not None else KnowledgeGraphBackendEngine()
    return backend.handle_api_request(path, params, method, body)


def main(argv=None):
    """Query a validated exchange file, or the bundled demo catalog by default."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, metavar="PATH",
                        help="load a SpatialGraphContract JSON catalog")
    query = parser.add_mutually_exclusive_group()
    query.add_argument("--contract", action="store_true", help="print the OpenAPI 3.1 contract")
    query.add_argument("--search", metavar="QUERY", help="retrieve graph nodes with BM25")
    query.add_argument("--shortest-path", nargs=2, metavar=("SOURCE_ID", "TARGET_ID"),
                       help="find a minimum-hop path between catalog entity IDs")
    options = parser.parse_args(argv)
    try:
        catalog = (json.loads(options.catalog.read_text(encoding="utf-8"))
                   if options.catalog is not None else None)
        backend = KnowledgeGraphBackendEngine(catalog)
    except (OSError, ValueError, RecursionError):
        # File contents and OS diagnostics may contain sensitive telemetry.
        parser.error("unable to load a valid graph catalog")
    if options.search is not None:
        result = backend.search(options.search)
    elif options.shortest_path is not None:
        result = backend.shortest_path(*options.shortest_path)
    else:
        result = backend.contract() if options.contract else backend.catalog()
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
