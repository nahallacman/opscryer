# SPDX-License-Identifier: Apache-2.0
"""Offline infrastructure adapters for SpatialGraphContract v1.

Inputs are parsed data, never files or live infrastructure. Catalogs are fresh,
sanitized snapshots; no provider credentials or network connections are needed.
"""

import abc
import argparse
from copy import deepcopy
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

from opscryer_backend import CONTRACT_VERSION, DOMAINS, validate_spatial_graph_contract
from opscryer_browser import build_standalone_demo_dataset, build_standalone_rts_currencies
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo


_INVALID_REQUEST = "Invalid environment adapter request"


ADAPTER_PROFILES = {
    "kubernetes": {
        "label": "Kubernetes", "description": "Bundled Kubernetes reference catalog",
        "input_format": "SpatialGraphContract v1 reference dataset",
        "compatibility_matrix": {"containers": True, "networks": True,
                                 "storage": True, "local_models": True, "requires_cluster": True},
    },
    "docker_compose": {
        "label": "Docker Compose", "description": "Single-host container projects",
        "input_format": "Parsed Compose specification",
        "compatibility_matrix": {"containers": True, "networks": True,
                                 "storage": True, "local_models": True, "requires_cluster": False},
    },
    "terraform": {
        "label": "Terraform / OpenTofu", "description": "Hybrid-cloud infrastructure resources",
        "input_format": "Resource list, state, or JSON plan",
        "compatibility_matrix": {"containers": True, "networks": True,
                                 "storage": True, "local_models": True, "requires_cluster": False},
    },
    "local_host": {
        "label": "Local host", "description": "Developer laptop or homelab bare metal with Ollama",
        "input_format": "Host hardware, services, and local models",
        "compatibility_matrix": {"containers": False, "networks": True,
                                 "storage": True, "local_models": True, "requires_cluster": False},
    },
}

_INITIAL_ADAPTER_PROFILES = deepcopy(ADAPTER_PROFILES)
_LEGACY_ADAPTER_PROFILES: tuple[str, ...] = (
    "kubernetes",
    "docker_compose",
    "terraform",
    "local_host",
)


class BaseEnvironmentAdapter(abc.ABC):
    """Abstract base class for OpsCryer environment topology adapters."""

    profile_name: str = ""
    label: str = ""
    compatibility_matrix: dict[str, bool] = {}

    def __init__(self) -> None:
        if not getattr(self, "profile_name", None):
            self.profile_name = getattr(self.__class__, "profile_name", "")
        if not getattr(self, "label", None):
            self.label = getattr(self.__class__, "label", self.profile_name)
        if not getattr(self, "compatibility_matrix", None):
            self.compatibility_matrix = dict(getattr(self.__class__, "compatibility_matrix", {}))

    @abc.abstractmethod
    def convert_to_graph(self, spec: dict[str, Any] | None = None) -> dict[str, Any]:
        """Convert environment telemetry or raw topology into standard OpsCryer spatial graph dict.

        Must return a dict conforming to schema '1.0-separable-spatial-graph-contract' or '1.0-spatial-graph'.
        """
        raise NotImplementedError

    def health_check(self) -> dict[str, Any]:
        """Optional health/readiness check for the adapter."""
        return {"status": "ok", "profile": self.profile_name}


_REGISTRY_LOCK = threading.Lock()
_ADAPTER_REGISTRY: dict[str, type[BaseEnvironmentAdapter]] = {}
_ADAPTER_INSTANCES: dict[str, BaseEnvironmentAdapter] = {}


def _register_profile_unlocked(
    profile_name: str,
    adapter_cls: type[BaseEnvironmentAdapter],
    overwrite: bool = False,
) -> None:
    if not isinstance(profile_name, str) or not profile_name.strip():
        raise ValueError("profile_name must be a non-empty string")
    profile_name = profile_name.strip()

    if not isinstance(adapter_cls, type):
        raise TypeError(f"adapter_cls must be a class, got {type(adapter_cls).__name__}")
    if not issubclass(adapter_cls, BaseEnvironmentAdapter):
        raise TypeError(f"{adapter_cls.__name__} must be a subclass of BaseEnvironmentAdapter")
    if adapter_cls is BaseEnvironmentAdapter:
        raise TypeError("Cannot register BaseEnvironmentAdapter directly")
    if getattr(adapter_cls, "__abstractmethods__", None):
        abstract_names = ", ".join(sorted(list(adapter_cls.__abstractmethods__)))
        raise TypeError(
            f"Cannot register abstract class {adapter_cls.__name__} with unimplemented methods: {abstract_names}"
        )
    if not getattr(adapter_cls, "label", None):
        raise ValueError(f"Class {adapter_cls.__name__} must define a non-empty 'label' attribute")

    if profile_name in _ADAPTER_REGISTRY and not overwrite:
        raise ValueError(f"Adapter profile '{profile_name}' is already registered")

    _ADAPTER_REGISTRY[profile_name] = adapter_cls
    _ADAPTER_INSTANCES.pop(profile_name, None)
    ADAPTER_PROFILES[profile_name] = {
        "label": getattr(adapter_cls, "label", profile_name),
        "description": getattr(adapter_cls, "description", f"Dynamic adapter: {profile_name}"),
        "compatibility_matrix": getattr(adapter_cls, "compatibility_matrix", {}),
        "input_format": getattr(adapter_cls, "input_format", "Dynamic topology spec"),
    }


def register_adapter_profile(
    profile_name: str,
    adapter_cls: type[BaseEnvironmentAdapter],
    overwrite: bool = False,
) -> None:
    """Register an adapter class under a unique profile name. Thread-safe."""
    with _REGISTRY_LOCK:
        _register_profile_unlocked(profile_name, adapter_cls, overwrite=overwrite)


def get_adapter_profile(profile_name: str) -> BaseEnvironmentAdapter:
    """Return a cached or new adapter instance for profile_name. Thread-safe."""
    if not isinstance(profile_name, str) or not profile_name.strip():
        raise KeyError(f"Invalid profile name '{profile_name}'")
    profile_name = profile_name.strip()

    with _REGISTRY_LOCK:
        if profile_name not in _ADAPTER_REGISTRY:
            available = sorted(list(_ADAPTER_REGISTRY.keys()))
            raise KeyError(
                f"Adapter profile '{profile_name}' not found. Available profiles: {available}"
            )
        if profile_name not in _ADAPTER_INSTANCES:
            cls = _ADAPTER_REGISTRY[profile_name]
            _ADAPTER_INSTANCES[profile_name] = cls()
        return _ADAPTER_INSTANCES[profile_name]


def list_adapter_profiles() -> dict[str, dict[str, Any]]:
    """Return dictionary of profile metadata. Thread-safe."""
    with _REGISTRY_LOCK:
        result: dict[str, dict[str, Any]] = {}
        for name, cls in sorted(_ADAPTER_REGISTRY.items()):
            result[name] = {
                "label": getattr(cls, "label", name),
                "compatibility_matrix": dict(getattr(cls, "compatibility_matrix", {})),
                "class_name": cls.__name__,
            }
        return result


def unregister_adapter_profile(profile_name: str) -> bool:
    """Unregister an adapter profile. Thread-safe."""
    if not isinstance(profile_name, str) or not profile_name.strip():
        return False
    profile_name = profile_name.strip()

    with _REGISTRY_LOCK:
        if profile_name in _ADAPTER_REGISTRY:
            del _ADAPTER_REGISTRY[profile_name]
            _ADAPTER_INSTANCES.pop(profile_name, None)
            ADAPTER_PROFILES.pop(profile_name, None)
            return True
        return False


class MockDevEnvironmentAdapter(BaseEnvironmentAdapter):
    """Adapter generating a mock 3-node cluster topology for offline dev testing."""

    profile_name = "mock_dev"
    label = "Mock Dev Topology"
    compatibility_matrix = {
        "mock": True,
        "k8s": False,
        "baremetal": True,
        "slurm": False,
        "containers": True,
        "networks": True,
        "storage": True,
        "local_models": True,
    }

    def convert_to_graph(self, spec: dict[str, Any] | None = None) -> dict[str, Any]:
        nodes = [
            {
                "id": "mock-cluster",
                "label": "Mock Development Cluster",
                "kind": "company_root",
                "domain": "hardware_topology",
                "section": "core",
                "summary": "Root mock cluster for local development",
                "primary_url": "https://example.org/opscryer/mock-cluster",
                "drilldown_children": ["mock-node-control-plane", "mock-node-worker-1", "mock-node-worker-2"],
                "specs": {"type": "cluster"},
            },
            {
                "id": "mock-node-control-plane",
                "label": "mock-control-plane-01",
                "kind": "hardware_node",
                "domain": "deployments_k8s",
                "section": "control-plane",
                "summary": "Mock Kubernetes Control Plane",
                "primary_url": "https://example.org/opscryer/mock-node-control-plane",
                "drilldown_children": [],
                "specs": {"cpu": "4", "memory": "16Gi"},
            },
            {
                "id": "mock-node-worker-1",
                "label": "mock-worker-01",
                "kind": "hardware_node",
                "domain": "deployments_k8s",
                "section": "worker",
                "summary": "Mock Kubernetes Worker Node 1",
                "primary_url": "https://example.org/opscryer/mock-node-worker-1",
                "drilldown_children": [],
                "specs": {"cpu": "8", "memory": "32Gi"},
            },
            {
                "id": "mock-node-worker-2",
                "label": "mock-worker-02",
                "kind": "hardware_node",
                "domain": "deployments_k8s",
                "section": "worker",
                "summary": "Mock Kubernetes Worker Node 2",
                "primary_url": "https://example.org/opscryer/mock-node-worker-2",
                "drilldown_children": [],
                "specs": {"cpu": "8", "memory": "32Gi"},
            },
            {
                "id": "mock-svc-api",
                "label": "opscryer-api",
                "kind": "service",
                "domain": "deployments_k8s",
                "section": "workloads",
                "summary": "OpsCryer Core API Service",
                "primary_url": "https://example.org/opscryer/mock-svc-api",
                "drilldown_children": [],
                "specs": {"port": 8080},
            },
            {
                "id": "mock-svc-ingress",
                "label": "ingress-nginx",
                "kind": "service",
                "domain": "deployments_k8s",
                "section": "ingress",
                "summary": "Ingress Controller",
                "primary_url": "https://example.org/opscryer/mock-svc-ingress",
                "drilldown_children": [],
                "specs": {"port": 443},
            },
            {
                "id": "mock-svc-postgres",
                "label": "postgres-cluster",
                "kind": "service",
                "domain": "deployments_k8s",
                "section": "storage",
                "summary": "Postgres Database Store",
                "primary_url": "https://example.org/opscryer/mock-svc-postgres",
                "drilldown_children": [],
                "specs": {"port": 5432},
            },
        ]
        edges = [
            {"source": "mock-cluster", "target": "mock-node-control-plane", "relation": "contains"},
            {"source": "mock-cluster", "target": "mock-node-worker-1", "relation": "contains"},
            {"source": "mock-cluster", "target": "mock-node-worker-2", "relation": "contains"},
            {"source": "mock-node-worker-1", "target": "mock-svc-api", "relation": "runs"},
            {"source": "mock-node-worker-1", "target": "mock-svc-ingress", "relation": "runs"},
            {"source": "mock-node-worker-2", "target": "mock-svc-postgres", "relation": "runs"},
            {"source": "mock-svc-ingress", "target": "mock-svc-api", "relation": "routes_to"},
            {"source": "mock-svc-api", "target": "mock-svc-postgres", "relation": "depends_on"},
        ]
        metadata = {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "cluster_type": "mock_dev",
            "healthy": True,
        }
        return {
            "schema_version": CONTRACT_VERSION,
            "root_id": "mock-cluster",
            "profile": self.profile_name,
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "metadata": metadata,
        }


def _clean_signals_spec(spec: Any) -> dict[str, Any] | None:
    """Safely sanitize signals payload ensuring lists contain only dicts."""
    if not isinstance(spec, dict):
        return None
    signal_keys = ("prometheus_signals", "signals", "metrics", "loki_log_summaries", "logs")
    if not any(k in spec for k in signal_keys):
        return None

    cleaned: dict[str, Any] = {}
    for k in ("prometheus_signals", "signals", "metrics"):
        if k in spec:
            val = spec[k]
            if isinstance(val, (list, tuple)):
                cleaned[k] = [item for item in val if isinstance(item, dict)]
            else:
                cleaned[k] = []
    for k in ("loki_log_summaries", "logs"):
        if k in spec:
            val = spec[k]
            if isinstance(val, (list, tuple)):
                cleaned[k] = [item for item in val if isinstance(item, dict)]
            else:
                cleaned[k] = []
    if "telemetry_mode" in spec and isinstance(spec["telemetry_mode"], str):
        cleaned["telemetry_mode"] = spec["telemetry_mode"]
    return cleaned


class PrometheusLokiEnvironmentAdapter(BaseEnvironmentAdapter):
    """Adapter transforming Prometheus metrics and Loki log streams into a spatial graph."""

    profile_name = "prometheus_loki"
    label = "Prometheus/Loki Observability"
    compatibility_matrix = {
        "prometheus": True,
        "loki": True,
        "k8s": True,
        "baremetal": True,
        "containers": True,
        "networks": True,
        "storage": False,
    }

    def convert_to_graph(self, spec: dict[str, Any] | None = None) -> dict[str, Any]:
        from prometheus_loki_adapter import query_sanitized_observability_signals, signals_to_graph

        cleaned_signals = _clean_signals_spec(spec)
        signals = cleaned_signals if cleaned_signals is not None else None

        base_graph = None
        if signals is not None:
            try:
                cand = signals_to_graph(signals)
                if isinstance(cand, dict) and isinstance(cand.get("nodes"), list):
                    base_graph = cand
            except Exception:
                base_graph = None

        if base_graph is None:
            signals = query_sanitized_observability_signals(allow_live_http=False)
            try:
                base_graph = signals_to_graph(signals)
            except Exception:
                base_graph = {"nodes": [], "edges": []}

        raw_nodes = list(base_graph.get("nodes", []))
        edges = list(base_graph.get("edges", []))
        child_nodes: list[dict[str, Any]] = []
        seen_ids = {"obs-root"}

        for idx, n in enumerate(raw_nodes):
            if not isinstance(n, dict):
                continue
            n_id = str(n.get("id") or f"obs-signal-{idx}").strip()
            if n_id in seen_ids:
                n_id = f"{n_id}-{idx}"
            seen_ids.add(n_id)

            n_label = str(n.get("label") or n_id).strip()
            n_kind = str(n.get("kind") or "observability_metric").strip()
            n_domain = n.get("domain")
            if not isinstance(n_domain, str) or n_domain not in DOMAINS:
                n_domain = "hardware_topology"

            child_nodes.append({
                **n,
                "id": n_id,
                "label": n_label,
                "kind": n_kind,
                "domain": n_domain,
                "summary": n.get("summary") if isinstance(n.get("summary"), str) else f"{n_kind.replace('_', ' ')}: {n_label}",
                "primary_url": n.get("primary_url") if isinstance(n.get("primary_url"), str) and n.get("primary_url") else f"https://example.org/opscryer/{n_id}",
                "drilldown_children": [],
            })

        root_node = {
            "id": "obs-root",
            "label": "Observability Root",
            "kind": "company_root",
            "domain": "hardware_topology",
            "section": "monitoring",
            "summary": "Observability signal collector hub",
            "primary_url": "https://example.org/opscryer/obs-root",
            "drilldown_children": [n["id"] for n in child_nodes],
        }

        nodes = [root_node] + child_nodes
        for n in child_nodes:
            edges.append({"source": "obs-root", "target": n["id"], "relation": "monitors"})

        return {
            "schema_version": CONTRACT_VERSION,
            "root_id": "obs-root",
            "profile": self.profile_name,
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "metadata": {
                "telemetry_mode": signals.get("telemetry_mode", "SNAPSHOT_FIXTURE") if isinstance(signals, dict) else "SNAPSHOT_FIXTURE",
                "node_count": len(nodes),
                "edge_count": len(edges),
            },
        }


class KubernetesProductionAdapter(BaseEnvironmentAdapter):
    """Adapter constructing live production Kubernetes topology graph from health facts."""

    profile_name = "kubernetes_production"
    label = "Kubernetes Production"
    compatibility_matrix = {
        "k8s": True,
        "baremetal": False,
        "slurm": False,
        "cluster_facts": True,
        "containers": True,
        "networks": True,
        "storage": True,
    }

    def convert_to_graph(self, spec: dict[str, Any] | None = None) -> dict[str, Any]:
        from cluster_diff_engine import summarize_live_cluster_health

        health = None
        if isinstance(spec, dict):
            # Case A: spec is already a cluster health facts dictionary
            if any(k in spec for k in ("ready_nodes", "not_ready_nodes", "ingress_hosts", "node_counts", "pod_counts", "deployment_counts")):
                raw_ready = spec.get("ready_nodes")
                ready_list = [str(n) for n in raw_ready if n] if isinstance(raw_ready, (list, tuple)) else []
                raw_not_ready = spec.get("not_ready_nodes")
                not_ready_list = [str(n) for n in raw_not_ready if n] if isinstance(raw_not_ready, (list, tuple)) else []
                raw_ingress = spec.get("ingress_hosts")
                ingress_dict = {str(k): v for k, v in raw_ingress.items() if str(k).strip()} if isinstance(raw_ingress, dict) else {}
                health = {
                    "source": spec.get("source", "provided_cluster_health_spec"),
                    "ready_nodes": ready_list,
                    "not_ready_nodes": not_ready_list,
                    "ingress_hosts": ingress_dict,
                    "node_counts": spec.get("node_counts") if isinstance(spec.get("node_counts"), dict) else {
                        "total": len(ready_list) + len(not_ready_list),
                        "ready": len(ready_list),
                        "not_ready": len(not_ready_list),
                    },
                    "pod_counts": spec.get("pod_counts") if isinstance(spec.get("pod_counts"), dict) else {},
                    "deployment_counts": spec.get("deployment_counts") if isinstance(spec.get("deployment_counts"), dict) else {},
                    "node_hotspots": spec.get("node_hotspots") if isinstance(spec.get("node_hotspots"), list) else [],
                }
            # Case B: spec is a cluster spatial catalog containing a "nodes" list
            elif isinstance(spec.get("nodes"), list):
                try:
                    health = summarize_live_cluster_health(spec)
                except Exception:
                    health = None

        # Case C: Fallback to default sanitized cluster catalog if spec is None, {}, or unparseable
        if health is None:
            try:
                health = summarize_live_cluster_health(None)
            except Exception:
                health = {
                    "source": "fallback_cluster_health",
                    "ready_nodes": ["node-control-plane", "node-worker-1", "node-worker-2"],
                    "not_ready_nodes": [],
                    "ingress_hosts": {"opscryer.cluster.example.org": []},
                    "node_counts": {"total": 3, "ready": 3, "not_ready": 0},
                    "pod_counts": {},
                    "deployment_counts": {},
                    "node_hotspots": [],
                }

        root_node = {
            "id": "k8s-prod-cluster",
            "label": "Production Kubernetes Cluster",
            "kind": "company_root",
            "domain": "hardware_topology",
            "section": "core",
            "summary": "Live production Kubernetes cluster topology",
            "primary_url": "https://example.org/opscryer/k8s-prod-cluster",
            "drilldown_children": [],
        }
        nodes = [root_node]
        edges = []
        seen_ids = {"k8s-prod-cluster"}

        ready_nodes = health.get("ready_nodes", [])
        if isinstance(ready_nodes, list):
            for name in ready_nodes:
                clean_name = str(name).strip()
                if not clean_name:
                    continue
                n_id = f"k8s-node-{clean_name}"
                if n_id in seen_ids:
                    continue
                seen_ids.add(n_id)
                root_node["drilldown_children"].append(n_id)
                nodes.append({
                    "id": n_id,
                    "label": clean_name,
                    "kind": "hardware_node",
                    "domain": "deployments_k8s",
                    "section": "nodes",
                    "summary": f"Ready cluster node: {clean_name}",
                    "primary_url": f"https://example.org/opscryer/{n_id}",
                    "drilldown_children": [],
                    "status": "ready",
                })
                edges.append({"source": "k8s-prod-cluster", "target": n_id, "relation": "contains"})

        not_ready_nodes = health.get("not_ready_nodes", [])
        if isinstance(not_ready_nodes, list):
            for name in not_ready_nodes:
                clean_name = str(name).strip()
                if not clean_name:
                    continue
                n_id = f"k8s-node-{clean_name}"
                if n_id in seen_ids:
                    continue
                seen_ids.add(n_id)
                root_node["drilldown_children"].append(n_id)
                nodes.append({
                    "id": n_id,
                    "label": clean_name,
                    "kind": "hardware_node",
                    "domain": "deployments_k8s",
                    "section": "nodes",
                    "summary": f"NotReady cluster node: {clean_name}",
                    "primary_url": f"https://example.org/opscryer/{n_id}",
                    "drilldown_children": [],
                    "status": "not_ready",
                })
                edges.append({"source": "k8s-prod-cluster", "target": n_id, "relation": "contains"})

        ingress_hosts = health.get("ingress_hosts", {})
        if isinstance(ingress_hosts, dict):
            for host in sorted(ingress_hosts.keys()):
                clean_host = str(host).strip()
                if not clean_host:
                    continue
                ing_id = f"k8s-ingress-{clean_host.replace('.', '-')}"
                if ing_id in seen_ids:
                    continue
                seen_ids.add(ing_id)
                root_node["drilldown_children"].append(ing_id)
                nodes.append({
                    "id": ing_id,
                    "label": clean_host,
                    "kind": "service",
                    "domain": "deployments_k8s",
                    "section": "ingress",
                    "summary": f"Ingress host: {clean_host}",
                    "primary_url": f"https://example.org/opscryer/{ing_id}",
                    "drilldown_children": [],
                })
                edges.append({"source": "k8s-prod-cluster", "target": ing_id, "relation": "exposes"})

        return {
            "schema_version": CONTRACT_VERSION,
            "root_id": "k8s-prod-cluster",
            "profile": self.profile_name,
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "metadata": {
                "source": health.get("source", "live_cluster_summary"),
                "node_counts": health.get("node_counts"),
                "pod_counts": health.get("pod_counts"),
                "deployment_counts": health.get("deployment_counts"),
                "hotspots": health.get("node_hotspots"),
            },
        }


def _register_builtin_profiles_unlocked() -> None:
    _register_profile_unlocked("mock_dev", MockDevEnvironmentAdapter, overwrite=True)
    _register_profile_unlocked("prometheus_loki", PrometheusLokiEnvironmentAdapter, overwrite=True)
    _register_profile_unlocked("kubernetes_production", KubernetesProductionAdapter, overwrite=True)


with _REGISTRY_LOCK:
    _register_builtin_profiles_unlocked()


def reset_adapter_registry() -> None:
    """Reset registry to default built-in profiles. Thread-safe."""
    with _REGISTRY_LOCK:
        _ADAPTER_REGISTRY.clear()
        _ADAPTER_INSTANCES.clear()
        ADAPTER_PROFILES.clear()
        ADAPTER_PROFILES.update(deepcopy(_INITIAL_ADAPTER_PROFILES))
        _register_builtin_profiles_unlocked()


class _Graph:
    def __init__(self, root_id, label, adapter):
        self.adapter = adapter
        self.nodes = []
        self.edges = []
        self.root = self.add(label, "environment", node_id=root_id)

    def add(self, label, kind, domain="deployments_k8s", parent=None, node_id=None, **specs):
        # Generated IDs keep untrusted names and redactions out of reference keys.
        node_id = node_id or f"{self.adapter}-{len(self.nodes)}"
        node = {"id": node_id, "label": str(label), "kind": kind, "domain": domain,
                "summary": f"{kind.replace('_', ' ')}: {label}",
                "primary_url": "https://example.org/opscryer/" + node_id,
                "drilldown_children": [], "specs": specs}
        self.nodes.append(node)
        if parent is not None:
            next(n for n in self.nodes if n["id"] == parent)["drilldown_children"].append(node_id)
            self.link(parent, node_id, "contains")
        return node_id

    def link(self, source, target, relation):
        edge = {"source": source, "target": target, "relation": relation}
        if edge not in self.edges:
            self.edges.append(edge)

    def finish(self):
        currencies = build_standalone_rts_currencies()
        for currency in currencies:
            currency["display_value"] = (str(len(self.nodes)) if currency["currency_id"] == "nodes"
                                         else "Not measured")
            currency["dropdown_items"] = [{"label": self.nodes[0]["label"],
                                            "value": "Inventory only", "target_id": self.root}]
        return _validated({"schema_version": CONTRACT_VERSION, "root_id": self.root,
                           "adapter": self.adapter, "rts_currencies": currencies,
                           "nodes": self.nodes, "edges": self.edges,
                           "node_count": len(self.nodes), "edge_count": len(self.edges)})


def _validated(catalog):
    catalog = sanitize_live_home_telemetry_for_demo(catalog)
    errors = validate_spatial_graph_contract(catalog)
    if errors:
        raise ValueError("Invalid adapter graph: " + "; ".join(errors))
    return catalog


def _input(spec, default):
    if spec is None:
        spec = default
    if not isinstance(spec, dict):
        raise ValueError("Adapter specification must be an object")
    return sanitize_live_home_telemetry_for_demo(spec)


def _names(value):
    """Names from Compose short arrays or long mappings."""
    if isinstance(value, (dict, list, tuple)):
        return list(value)
    if value is None:
        return []
    raise ValueError("Expected an array or object of references")


def convert_docker_compose_to_graph(spec: dict | None = None) -> dict:
    """Map services, dependency conditions, networks, mounts, and exposed ports."""
    spec = _input(spec, {
        "name": "opscryer-three-tier",
        "services": {
            "frontend": {"image": "nginx:alpine", "depends_on": ["api"],
                         "ports": ["8080:80"], "networks": ["frontend"]},
            "api": {"image": "opscryer-api:demo", "depends_on": {
                "postgres": {"condition": "service_healthy"}, "redis": {}, "ollama": {}},
                "ports": ["8081:8080"], "networks": ["frontend", "backend"]},
            "postgres": {"image": "postgres:16", "volumes": ["pgdata:/var/lib/postgresql/data"],
                         "networks": ["backend"]},
            "redis": {"image": "redis:7", "volumes": ["redisdata:/data"], "networks": ["backend"]},
            "ollama": {"image": "ollama/ollama:latest", "ports": ["11434:11434"],
                       "volumes": ["models:/root/.ollama"], "networks": ["backend"]},
        }, "networks": {"frontend": {}, "backend": {"internal": True}},
        "volumes": {"pgdata": {}, "redisdata": {}, "models": {}},
    })
    graph = _Graph("compose-project", spec.get("name") or "Compose project", "docker_compose")
    networks, volumes, services = {}, {}, {}

    def network(name, config=None):
        if name not in networks:
            networks[name] = graph.add(name, "compose_network", parent=graph.root, config=config)
        return networks[name]

    def volume(name, config=None, kind="compose_volume"):
        if name not in volumes:
            volumes[name] = graph.add(name, kind, "hardware_topology", graph.root, config=config)
        return volumes[name]

    for name, config in (spec.get("networks") or {}).items():
        network(name, config)
    for name, config in (spec.get("volumes") or {}).items():
        volume(name, config)
    service_specs = spec.get("services") or {}
    for name, config in service_specs.items():
        services[name] = graph.add(name, "compose_service", parent=graph.root, config=config or {})
    for name, config in service_specs.items():
        config = config or {}
        source = services[name]
        for dependency in _names(config.get("depends_on")):
            if dependency not in services:
                raise ValueError("Compose dependency references an unknown service")
            graph.link(source, services[dependency], "depends_on")
        for name in _names(config.get("networks")) or ["default"]:
            graph.link(source, network(name), "connected_to")
        for mount in config.get("volumes") or []:
            if isinstance(mount, str):
                # Split from the right to preserve Windows drive letters.
                parts = mount.rsplit(":", 2)
                if len(parts) == 3 and parts[-1].startswith("/"):
                    parts = [":".join(parts[:2]), parts[2]]
                source_name = parts[0] if len(parts) > 1 else None
                kind = "bind_mount" if source_name and ("/" in source_name or "\\" in source_name) else "compose_volume"
            else:
                source_name = mount.get("source")
                kind = "bind_mount" if mount.get("type") == "bind" else "compose_volume"
            if source_name:
                target = volume(source_name, kind=kind)
            else:
                target = graph.add("Anonymous volume", "compose_volume", "hardware_topology", source)
            graph.link(source, target, "mounts")
        for port in config.get("ports") or []:
            target = graph.add(str(port), "published_port", parent=source, port=port)
            graph.link(source, target, "exposes")
    return graph.finish()


def _terraform_resources(spec):
    """Flatten direct resources, raw state instances, and nested show-JSON modules."""
    def module_resources(module):
        yield from module.get("resources", [])
        for child in module.get("child_modules", []):
            yield from module_resources(child)

    if "resources" in spec:
        resources = spec["resources"]
    elif "resource_changes" in spec and "planned_values" not in spec:
        resources = [dict(resource, values=resource.get("change", {}).get("after") or {})
                     for resource in spec["resource_changes"]]
    else:
        values = spec.get("planned_values", spec.get("values", {}))
        resources = list(module_resources(values.get("root_module", {})))
    for resource in resources:
        base = resource.get("address") or ".".join(filter(None, (
            resource.get("module"), "data" if resource.get("mode") == "data" else None,
            resource["type"], resource["name"])))
        if "instances" in resource:
            for instance in resource["instances"]:
                import json
                suffix = "[" + json.dumps(instance["index_key"]) + "]" if "index_key" in instance else ""
                yield dict(resource, address=base + suffix, values=instance.get("attributes", {}),
                           depends_on=instance.get("dependencies", resource.get("depends_on", [])))
        else:
            yield dict(resource, address=base)


def convert_terraform_resources_to_graph(spec: dict | None = None) -> dict:
    """Convert Terraform/OpenTofu resources without invoking providers or apply."""
    spec = _input(spec, {"workspace": "hybrid-homelab", "resources": [
        {"type": "aws_vpc", "name": "cloud", "provider": "aws"},
        {"type": "aws_instance", "name": "api", "provider": "aws", "depends_on": ["aws_vpc.cloud"]},
        {"type": "azurerm_virtual_network", "name": "edge", "provider": "azurerm"},
        {"type": "proxmox_virtual_environment_vm", "name": "ollama", "provider": "proxmox",
         "depends_on": ["openzfs_dataset.models"], "values": {"cpu_cores": 8, "ram_gib": 32}},
        {"type": "openzfs_dataset", "name": "models", "provider": "openzfs"},
        {"type": "openzfs_share_nfs", "name": "models", "provider": "openzfs",
         "depends_on": ["openzfs_dataset.models"]},
    ]})
    graph = _Graph("tf-workspace", spec.get("workspace") or "Terraform workspace", "terraform")
    resources = list(_terraform_resources(spec))
    ids, providers = {}, {}
    for resource in resources:
        address = resource["address"]
        if address in ids:
            raise ValueError("Duplicate Terraform resource address")
        provider = resource.get("provider") or resource.get("provider_name") or "unspecified"
        if provider not in providers:
            providers[provider] = graph.add(provider, "terraform_provider", parent=graph.root)
        ids[address] = graph.add(address, resource["type"], "hardware_topology",
                                 providers[provider], resource=resource)
    for resource in resources:
        for dependency in resource.get("depends_on", resource.get("dependencies", [])) or []:
            # Dependencies outside a partial export remain explicit inventory nodes.
            targets = [node_id for address, node_id in ids.items()
                       if address == dependency or address.startswith(dependency + "[")]
            if not targets:
                ids[dependency] = graph.add(dependency, "external_resource", parent=graph.root)
                targets = [ids[dependency]]
            for target in targets:
                graph.link(ids[resource["address"]], target, "depends_on")
    return graph.finish()


def convert_local_host_to_graph(spec: dict | None = None) -> dict:
    """Show local OpsCryer services and Ollama models on a single host."""
    spec = _input(spec, {"hostname": "developer.cluster.example.org", "cpu_cores": 8, "ram_gib": 32,
                         "gpu_model": "Laptop GPU (8 GiB)",
                         "local_models": ["llama3.1:8b", "qwen2.5-coder:7b"],
                         "services": {"opscryer": {"port": 8088}, "ollama": {"port": 11434}}})
    graph = _Graph("host-local", spec.get("hostname") or "Local host", "local_host")
    graph.nodes[0]["domain"] = "hardware_topology"
    graph.add("CPU", "cpu", "hardware_topology", graph.root, cores=spec.get("cpu_cores"))
    graph.add("RAM", "memory", "hardware_topology", graph.root, ram_gib=spec.get("ram_gib"))
    gpu = None
    if spec.get("gpu_model"):
        gpu = graph.add(spec["gpu_model"], "gpu", "hardware_topology", graph.root)
    services = {}
    service_specs = spec.get("services") or {}
    if isinstance(service_specs, list):
        service_specs = {item if isinstance(item, str) else item["name"]:
                         {} if isinstance(item, str) else item for item in service_specs}
    for name, config in service_specs.items():
        services[name] = graph.add(name, "local_service", parent=graph.root, config=config)
        graph.link(services[name], graph.root, "runs_on")
    models = spec.get("local_models") or []
    ollama = next((node_id for name, node_id in services.items() if name.lower() == "ollama"), None)
    if models and ollama is None:
        ollama = graph.add("Ollama", "local_service", parent=graph.root)
        graph.link(ollama, graph.root, "runs_on")
    for model in models:
        label = model.get("name", "Local model") if isinstance(model, dict) else model
        node_id = graph.add(label, "local_model", parent=ollama, model=model)
        graph.link(ollama, node_id, "serves_model")
        if gpu:
            graph.link(node_id, gpu, "can_use")
    if ollama:
        for name, node_id in services.items():
            if "opscryer" in name.lower():
                graph.link(node_id, ollama, "inference_via")
    return graph.finish()


def build_adapter_compatibility_catalog(adapter: str | None = None) -> dict:
    """Return one generated catalog or an inventory summary for all adapters."""
    if adapter is not None and (not isinstance(adapter, str) or (adapter not in ADAPTER_PROFILES and adapter not in _ADAPTER_REGISTRY)):
        raise ValueError("Unsupported environment adapter")
    builders = {"kubernetes": build_standalone_demo_dataset,
                "docker_compose": convert_docker_compose_to_graph,
                "terraform": convert_terraform_resources_to_graph,
                "local_host": convert_local_host_to_graph}

    def entry(name, include_graph=False):
        if name in builders:
            catalog = builders[name]()
            if name == "kubernetes":
                catalog["root_id"] = "root-company"
                catalog = _validated(catalog)
        elif name in _ADAPTER_REGISTRY:
            inst = get_adapter_profile(name)
            catalog = inst.convert_to_graph()
        else:
            catalog = {"nodes": [], "edges": []}
        profile_meta = ADAPTER_PROFILES.get(name, {})
        result = {"adapter": name, **deepcopy(profile_meta),
                  "node_count": len(catalog.get("nodes", [])), "edge_count": len(catalog.get("edges", []))}
        if include_graph:
            result["graph_catalog"] = catalog
        return result

    if adapter is not None:
        return entry(adapter, include_graph=True)
    return {"schema_version": CONTRACT_VERSION,
            "adapters": {name: entry(name) for name in _LEGACY_ADAPTER_PROFILES}}


def render_adapters_markdown(adapter: str | None = None) -> str:
    """Render compatibility and graph inventories, optionally for one preview."""
    selected = build_adapter_compatibility_catalog(adapter) if adapter is not None else None
    entries = build_adapter_compatibility_catalog()["adapters"]
    lines = ["# OpsCryer Multi-Platform Compatibility & Adapter Studio", "",
             "Offline reference inventories exported as SpatialGraphContract v1.", "",
             "| Environment | Adapter | Containers | Networks | Storage | Local models | Requires cluster | Nodes | Edges |",
             "| --- | --- | --- | --- | --- | --- | --- | ---: | ---: |"]
    for name, entry in entries.items():
        label = "Local Laptop / Systemd Host" if name == "local_host" else entry["label"]
        capabilities = entry["compatibility_matrix"]
        flags = ["Yes" if capabilities[key] else "No" for key in
                 ("containers", "networks", "storage", "local_models", "requires_cluster")]
        lines.append("| " + " | ".join([label, name, *flags, str(entry["node_count"]),
                                        str(entry["edge_count"])]) + " |")
    previews = [selected] if selected is not None else [
        build_adapter_compatibility_catalog(name) for name in entries]
    for entry in previews:
        graph = entry["graph_catalog"]
        label = ("Local Laptop / Systemd Host" if entry["adapter"] == "local_host"
                 else entry["label"])
        lines.extend(["", f"## {label}: node/edge breakdown", "",
                      f"Nodes: {entry['node_count']} | Edges: {entry['edge_count']}", "",
                      "| Node kind | Count |", "| --- | ---: |"])
        for field, records in (("kind", graph["nodes"]), ("relation", graph["edges"])):
            if field == "relation":
                lines.extend(["", "| Edge relation | Count |", "| --- | ---: |"])
            counts = {}
            for record in records:
                value = record.get(field, "unknown")
                counts[value] = counts.get(value, 0) + 1
            for value, count in sorted(counts.items()):
                lines.append(f"| {escape(value).replace('|', '&#124;')} | {count} |")
    return "\n".join(lines) + "\n"


def render_adapters_html() -> str:
    """Return the standalone Adapter Studio with an API-backed graph preview."""
    entries = build_adapter_compatibility_catalog()["adapters"]
    initial = build_adapter_compatibility_catalog("docker_compose")
    rows = []
    for name, entry in entries.items():
        label = "Local Laptop / Systemd Host" if name == "local_host" else entry["label"]
        flags = "".join("<td>" + ("Yes" if entry["compatibility_matrix"][key] else "No") + "</td>"
                        for key in ("containers", "networks", "storage", "local_models", "requires_cluster"))
        rows.append(f"<tr><th scope=\"row\">{escape(label)}</th>{flags}"
                    f"<td>{entry['node_count']}</td><td>{entry['edge_count']}</td></tr>")
    # Escape script delimiters even if a future reference dataset contains HTML.
    payload = json.dumps(initial).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    return r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpsCryer — Multi-Platform Compatibility &amp; Adapter Studio</title>
<style>
:root { color-scheme: dark; font-family: system-ui, sans-serif; background: #101827; color: #edf3ff; }
body { max-width: 1200px; margin: auto; padding: 24px; }
nav, .selectors { display: flex; flex-wrap: wrap; gap: 12px; margin: 20px 0; }
a { color: #8fd5ff; } button { padding: 10px 16px; border: 1px solid #83bbef;
border-radius: 6px; background: #20334c; color: inherit; cursor: pointer; }
button[aria-pressed="true"] { background: #235e85; } button:disabled { opacity: .6; cursor: wait; }
button:focus-visible, a:focus-visible { outline: 3px solid #ffd580; outline-offset: 3px; }
.table-wrap { overflow-x: auto; margin: 16px 0 28px; }
table { border-collapse: collapse; width: 100%; } th, td { text-align: left;
padding: 10px; border-bottom: 1px solid #394b64; overflow-wrap: anywhere; }
caption { text-align: left; font-weight: bold; padding: 8px 0; }
#status { min-height: 1.5em; } textarea { box-sizing: border-box; width: 100%; min-height: 180px; }
</style>
</head>
<body>
<nav aria-label="Main navigation">
<a href="/">Spatial RTS Browser</a><a href="/hub">Hub</a><a href="/chat">Chat</a>
<a href="/metrics-live">Live metrics</a><a href="/adapters" aria-current="page">Adapters</a>
<a href="/kb">Knowledge base</a><a href="/storage">Storage</a><a href="/secops">SecOps</a>
</nav>
<main>
<h1>OpsCryer Multi-Platform Compatibility &amp; Adapter Studio</h1>
<p>Explore offline reference inventories for four supported environments and paste their
SpatialGraphContract v1 JSON directly into the <a href="/">Spatial RTS Browser</a>.</p>
<div class="table-wrap"><table><caption>Environment compatibility</caption>
<thead><tr><th scope="col">Environment</th><th scope="col">Containers</th><th scope="col">Networks</th>
<th scope="col">Storage</th><th scope="col">Local models</th><th scope="col">Requires cluster</th>
<th scope="col">Nodes</th><th scope="col">Edges</th></tr></thead><tbody>''' + "".join(rows) + r'''</tbody></table></div>
<div class="selectors" role="group" aria-label="Select environment adapter">
<button type="button" data-adapter="docker_compose" aria-pressed="true">Docker Compose</button>
<button type="button" data-adapter="terraform" aria-pressed="false">Terraform / OpenTofu</button>
<button type="button" data-adapter="local_host" aria-pressed="false">Local Laptop / Systemd Host</button>
<button type="button" data-adapter="kubernetes" aria-pressed="false">Kubernetes</button>
</div>
<h2 id="preview-title">Graph preview</h2>
<p id="counts"></p>
<button type="button" id="copy-graph">Copy SpatialGraphContract v1 JSON</button>
<p id="status" role="status" aria-live="polite"></p>
<div id="copy-fallback" hidden><label for="graph-json">Copy this JSON into the Spatial RTS Browser:</label>
<textarea id="graph-json" readonly></textarea></div>
<div class="table-wrap"><table><caption>Live node preview</caption>
<thead><tr><th scope="col">ID</th><th scope="col">Label</th><th scope="col">Kind</th>
<th scope="col">Domain</th></tr></thead><tbody id="nodes"></tbody></table></div>
<div class="table-wrap"><table><caption>Live edge preview</caption>
<thead><tr><th scope="col">Source</th><th scope="col">Target</th><th scope="col">Relation</th>
</tr></thead><tbody id="edges"></tbody></table></div>
<noscript>Enable JavaScript to load graph previews and copy JSON. The compatibility table is available above.</noscript>
</main>
<script id="initial-adapter" type="application/json">''' + payload + r'''</script>
<script>
'use strict';
let graph = null;
let requestVersion = 0;
const status = document.getElementById('status');
const copyButton = document.getElementById('copy-graph');
const selectors = [...document.querySelectorAll('[data-adapter]')];
function tableRows(id, records, keys) {
  const rows = records.map(record => {
    const row = document.createElement('tr');
    keys.forEach(key => {
      const cell = document.createElement('td');
      cell.textContent = String(record[key] ?? '');
      row.appendChild(cell);
    });
    return row;
  });
  document.getElementById(id).replaceChildren(...rows);
}
function preview(entry) {
  const next = entry.graph_catalog;
  if (!next || !Array.isArray(next.nodes) || !Array.isArray(next.edges)) {
    throw new Error('Invalid adapter graph');
  }
  graph = next;
  const button = selectors.find(item => item.dataset.adapter === entry.adapter);
  document.getElementById('preview-title').textContent = (button ? button.textContent : entry.label) + ' graph preview';
  document.getElementById('counts').textContent = `${graph.nodes.length} nodes / ${graph.edges.length} edges`;
  tableRows('nodes', graph.nodes, ['id', 'label', 'kind', 'domain']);
  tableRows('edges', graph.edges, ['source', 'target', 'relation']);
  selectors.forEach(item => item.setAttribute('aria-pressed', String(item === button)));
  document.getElementById('copy-fallback').hidden = true;
}
selectors.forEach(button => button.addEventListener('click', async () => {
  const version = ++requestVersion;
  copyButton.disabled = true;
  status.textContent = 'Loading ' + button.textContent + '…';
  document.getElementById('copy-fallback').hidden = true;
  try {
    const response = await fetch('/api/v1/environment-adapters?adapter=' + encodeURIComponent(button.dataset.adapter));
    if (!response.ok) throw new Error('Adapter request failed');
    const entry = await response.json();
    if (version !== requestVersion) return;
    if (entry.adapter !== button.dataset.adapter) throw new Error('Unexpected adapter');
    preview(entry);
    status.textContent = 'Preview updated.';
  } catch (error) {
    if (version === requestVersion) status.textContent = 'Unable to load adapter. The previous preview is still displayed; try again.';
  } finally {
    if (version === requestVersion) copyButton.disabled = false;
  }
}));
copyButton.addEventListener('click', async () => {
  const json = JSON.stringify(graph, null, 2);
  try {
    await navigator.clipboard.writeText(json);
    status.textContent = 'SpatialGraphContract v1 JSON copied. Paste it into the Spatial RTS Browser.';
  } catch (error) {
    document.getElementById('copy-fallback').hidden = false;
    const textarea = document.getElementById('graph-json');
    textarea.value = json;
    textarea.focus();
    textarea.select();
    status.textContent = 'Clipboard unavailable. Copy the selected JSON manually.';
  }
});
preview(JSON.parse(document.getElementById('initial-adapter').textContent));
</script>
</body>
</html>
'''


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error(_INVALID_REQUEST)


def _build_adapters_handler():
    """Serve offline adapter previews without logging request input."""
    class AdaptersRequestHandler(BaseHTTPRequestHandler):
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
            self._send(code, json.dumps({"error": _INVALID_REQUEST}), "application/json")

        def do_GET(self):
            try:
                url = urlsplit(self.path)
                if url.path not in {"/", "/adapters", "/api/v1/environment-adapters"}:
                    self._send(404, '{"error":"Not found"}', "application/json")
                    return
                if url.path in {"/", "/adapters"}:
                    if url.query:
                        raise ValueError(_INVALID_REQUEST)
                    body = render_adapters_html()
                    content_type = "text/html"
                else:
                    if re.search(r"%(?![0-9a-fA-F]{2})", url.query):
                        raise ValueError(_INVALID_REQUEST)
                    query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True,
                                     max_num_fields=1, errors="strict")
                    if set(query) - {"adapter"}:
                        raise ValueError(_INVALID_REQUEST)
                    body = json.dumps(build_adapter_compatibility_catalog(
                        query.get("adapter", [None])[0]), indent=2, allow_nan=False)
                    content_type = "application/json"
            except (ValueError, TypeError, KeyError):
                self._send(400, json.dumps({"error": _INVALID_REQUEST}), "application/json")
                return
            self._send(200, body, content_type)

    return AdaptersRequestHandler


def main(argv=None) -> int:
    """Export adapter inventories or serve the studio on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="environment_adapters", description=__doc__,
                                 allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--markdown", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--adapter", metavar="NAME")
    parser.add_argument("--port", type=int, default=8105)
    args = parser.parse_args(argv)
    if (not 1 <= args.port <= 65535
            or args.adapter is not None and args.adapter not in ADAPTER_PROFILES):
        parser.error(_INVALID_REQUEST)
    try:
        if args.serve:
            with ThreadingHTTPServer(("127.0.0.1", args.port),
                                     _build_adapters_handler()) as server:
                print(f"Environment adapters: http://127.0.0.1:{args.port}/adapters", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.markdown:
            print(render_adapters_markdown(args.adapter), end="")
        else:
            print(json.dumps(build_adapter_compatibility_catalog(args.adapter),
                             indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        parser.error(_INVALID_REQUEST)
    return 0


__all__ = [
    "ADAPTER_PROFILES",
    "BaseEnvironmentAdapter",
    "MockDevEnvironmentAdapter",
    "PrometheusLokiEnvironmentAdapter",
    "KubernetesProductionAdapter",
    "register_adapter_profile",
    "get_adapter_profile",
    "list_adapter_profiles",
    "unregister_adapter_profile",
    "reset_adapter_registry",
    "convert_docker_compose_to_graph",
    "convert_terraform_resources_to_graph",
    "convert_local_host_to_graph",
    "build_adapter_compatibility_catalog",
    "render_adapters_markdown",
    "render_adapters_html",
]


if __name__ == "__main__":
    raise SystemExit(main())
