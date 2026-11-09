---
name: opscryer_three_tool_suite
description: Operating guide for the decoupled 3-Tool Operations & Knowledge Suite (OpsCryer Visual Cockpits, The Brain / Jev Graph + MetricPluginRegistry, and The Swarm PlaybookExecutionEngine & SwarmAIGraphAndPlaybookPipeline).
---

# OpsCryer 3-Tool Operations & Knowledge Suite (`opscryer_three_tool_suite`)

This skill defines the operating procedures, CLI entrypoints, and extension contracts for the decoupled 3-Tool Architecture (`opscryer_abstraction.py`):

1. **Tool 1 — OpsCryer (`opscryer`)**: Fast visual spatial cockpits, topology search, and optional support-ticket deflection HUD (`opscryer_browser.py` + `build_three_tool_ecosystem_contract()`).
2. **Tool 2 — The Brain (`brain`)**: Authoritative Knowledge Graph, System One Jev deterministic decision tree, and the extensible `MetricPluginRegistry` (`evaluate_jev_with_live_plugins()`).
3. **Tool 3 — The Swarm (`swarm`)**: Persistent multi-agent development and playbook execution environment (`PlaybookExecutionEngine` + `SwarmAIGraphAndPlaybookPipeline`) that runs deterministic remediation playbooks, inspects live telemetry plugins, and proposes structured playbook reworks (`propose_playbook_rework`) or graph expansions (`propose_graph_coverage_expansion`) when fallback/unmatched states occur.

---

## 1. Quick Verification & CLI Usage

### Verify All Bundled Skills & 3-Tool Suite
```bash
python import_work_suite.py --verify
```

### Print Compact AI Digest & Plugin/RAMCache Demo
```bash
python opscryer_abstraction.py --ai-brief
python opscryer_abstraction.py --demo-plugin-and-ramcache
```

### Launch the Standalone Visual Browser (Offline-First)
```bash
python opscryer_browser.py --serve --host 127.0.0.1 --port 8088
```

---

## 2. Extending Live Telemetry Plugins (Tool 2: The Brain)

Decisions in **The Brain** remain 100% deterministic (`ai_invoked: False`) without requiring an AI model in the hot path. Live metrics flow through `MetricPluginRegistry` into `evaluate_jev_with_live_plugins(...)`.

To register a custom metrics plugin at work (e.g., Prometheus, Datadog, Kubernetes API, or custom HTTP health probes):

```python
from opscryer_abstraction import (
    MetricPluginRegistry,
    evaluate_jev_with_live_plugins,
)

registry = MetricPluginRegistry()
registry.register_plugin(
    plugin_id="work_k8s_health",
    provider_fn=lambda path, ctx: {
        "value": 1.0,
        "status": "HEALTHY",
        "source": "work-k8s-probe",
    },
    description="Live Kubernetes workload readiness probe",
)

result = evaluate_jev_with_live_plugins(
    query="minecraft pod ready status check",
    plugin_registry=registry,
)
```

---

## 3. Running & Reworking Playbooks (Tool 3: The Swarm)

When **The Brain** encounters an unmatched incident (`UNCOVERED_BY_DECISION_GRAPH`) or `PlaybookExecutionEngine.execute_and_verify_playbook(...)` flags a playbook as `NEEDS_REWORK`, `SwarmAIGraphAndPlaybookPipeline` synthesizes a 6-gate validated `GraphCoverageExpansionProposal` or `PlaybookReworkProposal` for promotion back into **The Brain**.

---

## 4. Importing Into a Work Repository

Use `import_work_suite.py` to install the 3-Tool Suite and all portable `.ai/skills/` into any target repository:

```bash
# Full import (skills + 3-tool suite)
python import_work_suite.py --target /path/to/work-repo

# Import only AI skills (.ai/skills + .agents/skills.json)
python import_work_suite.py --target /path/to/work-repo --mode skills-only

# Verify bundle integrity and list available skills
python import_work_suite.py --verify
```
