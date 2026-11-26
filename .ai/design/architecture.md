<!-- SPDX-License-Identifier: Apache-2.0 -->
# OpsCryer — Architecture & Design

## 1. Mission & 3-Tool Suite Role
OpsCryer is the **Visual & Gateway Plane** alongside **Central Brain** (Knowledge Core & State Plane) and **Meshworks** (Agent Execution & Training Plane):
- **Core Goal**: Allow any engineer in an organization to visually browse their Knowledge Graph, retrieve operational links and context rapidly, and inspect live infrastructure metrics side by side.
- **Minimal Default UI With Opt-In Complexity**: Default views stay uncluttered (`focused` preset: layer navigation, main canvas, unit console inspector; collapsed-by-default Ask Brain drawer; experimental addons like Nanomachine Swarm disabled unless opted in).
- **Org-Wide Default Inheritance (`workspace_layout.py`)**: Uncustomized users automatically inherit deployment `OPSCRYER_DEFAULT_LAYOUT_JSON` / `OPSCRYER_DEFAULT_LAYOUT_FILE` updates while customized browsers retain personal overrides with a one-click reset.

## 2. Unified 3-View Canvas & 7-Level Taxonomy
- **Three Switchable Views (`?view=local_links|boxes|world_map`)**:
  - `Local Links` (`#inline-local-links-stage`): Close-up ancestor/hub/neighbor graph with curved SVG links and clickable technical deep-links.
  - `Layer Boxes` (`#rts-main-box-pane`): Encapsulated level-by-level topology cards.
  - `Spatial Map` (`#inline-world-map-stage` & `/world-map`): Unified `2D Orthographic`, `2.5D Elevation`, and `3D Volumetric` projections sharing selection, search, and SVG unit plates.
- **7-Level Knowledge Graph Classification (`graph_layers.py`)**: Deterministically maps entities into `project`, `feature`, `dependency`, `requirement`, `test`, `deployment`, and `contract`, including `.ai/design/` and `.ai/plans/` requirements.

## 3. Full-Truth Mode, Positive Pass Evidence & Configurable Datasets
- **Full-Truth Default (`OPSCRYER_TRUTH_MODE=1`)**: Preserves honest `Unavailable` metrics and explicit disconnected banners rather than substituting synthetic starter graphs on live failures.
- **Positive Pass Evidence**: Test and verification nodes record explicit `passed`, `failed`, `errors`, `executed`, and `verification_state` (`VERIFIED_PASS` | `FAILED` | `UNVERIFIED_NOT_RUN`), never painting zero-run suites green.
- **Modular Dataset Tree Sidebar (`dataset_tree_store.py`)**: Normalized flat store + Euler-tour DFS intervals + `Uint8Array` bitmask toggles optional datasets (`dogfood_3tool`, `architecture_rationale`) cleanly without mutating live telemetry.

## 4. User-Delegated Credentials & Brain Proxy (`opscryer_browser.py`)
- **Pass-Through Header Sanitization**: `_extract_brain_delegated_headers()` forwards bounded (`<=4096` byte, CR/LF/NUL-free) `X-Brain-Delegated-Tokens`, `X-Brain-Delegated-Token`, and `X-Brain-Delegated-Provider` headers through `_proxy_brain_json_request()` across `/api/v1/graph/catalog`, `/api/v1/live-cluster-ask`, `/api/v1/datasets/tree`, `/api/v1/graph/levels`, and `/api/v1/world-map/layout` without caching tokens server-side.
- **Tab-Isolated Browser Sign-In**: `#brain-auth-banner` (hidden until `auth_required_sources` arrive) and `<dialog id="brain-auth-dialog">` store short-lived tokens strictly in `sessionStorage` (`opscryer.brain.delegatedTokens.v1`) and accept same-origin `opscryer:setDelegatedToken` `postMessage` updates.

## 5. System-1 Deterministic Core Boundary
Routing, search, filtering, layout, and policy checks run deterministically offline (`System-1 Decision Tree`), using external TypeSafe System-1 publications strictly as prior-art inspiration rather than hosted model calls.
