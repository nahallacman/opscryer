---
name: automated_testing
description: Automated Testing Philosophy
---

# AI SKILL: Automated Testing Philosophy
**Purpose:** Defines the strict architectural philosophy for writing automated tests across the repository, ensuring tests act as a true source of truth rather than a fragile approximation.

## 1. End-to-End (E2E) Priority
Automated tests should be the ultimate source of truth to prove our assumptions of a problem are correct.
- **Rule:** Always prefer to do things "for real" instead of faking or mocking it. 
- **Rule:** If a script relies on external infrastructure (like OpenBao, Keycloak, or a Kubernetes cluster), the tests should ideally authenticate against a real testing environment rather than mocking the network call.

## 2. Strict Limits on Mocks and Fakes
Faking infrastructure logic can lead to false confidence where tests pass but production fails due to integration mismatches.
- **Rule:** Mocks and fakes are **only** acceptable for figuring out parsing errors, syntax edge-cases, or isolating pure functional logic without side-effects.
- **Rule:** Faking must **never** be used as a substitute for validating a complex workflow (like SSO authentication, database connections, or secret retrieval). If an integration is critical, it must be tested against real infrastructure.

## 3. Test as Validation (Test-Driven Infrastructure)
When an agent is unsure if an architectural component (like Vault OIDC) is fully operational, the agent must not assume it is broken or functioning based on documentation alone.
- **Rule:** The agent must write an automated E2E test to physically probe the infrastructure. The success or failure of that test becomes the definitive source of truth for the current state of the cluster.

## 4. Test-to-Epic Traceability
To ensure that we can track which tests are verifying which architectural milestones, all automated tests must be explicitly linked to an Epic (and optionally Phases) from the Master Roadmap (`Master_Roadmap.md`).

### Multi-Epic & Multi-Phase Mapping
Tests often verify capabilities that evolve across multiple epics (e.g. Epic 47 and Epic 51). **Never overwrite an existing epic tag when updating tests for a new epic; always append the new epic to preserve historical roadmap coverage.**

- **Module-Level Variable (Preferred):** Declare `__epics__` at the top of the test file using a list of dicts mapping each epic to its list of phases:
  ```python
  __epics__ = [
      {"epic": "47", "phases": ["47D"]},
      {"epic": "51", "phases": ["51A", "51B", "51C", "51D"]},
  ]
  ```
  Or compact dictionary format:
  ```python
  __epics__ = {
      "47": ["47D"],
      "51": ["51A", "51B", "51C", "51D"]
  }
  ```
  *(Legacy single-value tags `__epic__ = "1"` and `__phase__ = "1A"` remain supported for single-epic files).*

- **Decorator Syntax (Classes & Functions):** Use `@epic` with `phases=[...]` or stack multiple `@epic` decorators from `tests.epic_tracer`:
  ```python
  from tests.epic_tracer import epic, epics

  # Stacked decorators across epics
  @epic(epic="47", phases=["55", "56", "67"])
  @epic(id="51", phase="51A")
  def test_viewport_scroll(self):
      pass

  # Or unified @epics decorator:
  @epics([
      {"epic": "47", "phases": ["47D"]},
      {"epic": "51", "phases": ["51A", "51B"]}
  ])
  class TestVisualDiff(unittest.TestCase):
      pass
  ```

- **Traceability Report Generation:**
  Generate the living markdown matrix by executing:
  ```bash
  python tests/generate_traceability_report.py
  ```
  This updates `tests/TEST_COVERAGE.md` with naturally sorted epics, guaranteeing no tests or milestones are lost.

## 5. Anti-Fragility, Dynamic Source-of-Truth Contracts & Zero Magic-Number Snapshots (User Directive #33)
Tests must verify **behavioral invariants, structural schemas, and state-machine properties**—never brittle point-in-time catalog sizes that break whenever a human operator adds a project, node, dashboard, or rule.
- **Rule 5A (No Magic-Number Catalog Counts):** Never hardcode exact catalog lengths (e.g., `assertEqual(len(urls), 9)`, `assertEqual(project_count, 4)`, `assertEqual(total_nodes, 8)`) when testing extensible registries. Instead, assert `len(items) == len(SOURCE_CATALOG)` and `len(items) >= 1`, plus per-item schema invariants (e.g., every kiosk URL contains `kiosk=1`, every project has a valid `/d/<uid>` Grafana link).
- **Rule 5B (Dependency Injection for Catalogs & Configs):** Every auditor, hub, or verifier function MUST accept optional injected catalogs/fixtures (`projects_override=None`, `nodes_override=None`, `themes_override=None`) so unit tests can verify both the live repository default AND mutated `N+1` / `N-1` / edge-case topologies in isolation.
- **Rule 5C (Per-Feature & Per-Pillar Fault Isolation):** Multi-pillar confidence suites and live demo showcases MUST isolate each check inside a fault boundary (`try...except Exception`) and avoid chaining unrelated rollups (`Script C -> Script B -> Script A`) so a change in one subsystem only flags that single subsystem rather than cascading across the entire test suite.


