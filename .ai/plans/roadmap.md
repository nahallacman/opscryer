<!-- SPDX-License-Identifier: Apache-2.0 -->
# OpsCryer — Active Roadmap

## Stage 1 — Foundations Shipped (`gitlab/main`)
- [x] **Unified 3-View Canvas & 7-Level Breakdown**: `Local Links`, `Layer Boxes`, and `2D`/`2.5D`/`3D` Spatial Map sharing 7-level selection stats and technical deep-links.
- [x] **Full-Truth Mode & Positive Pass Evidence**: Live Brain/K8s/Harbor telemetry with zero synthetic live fallbacks and explicit executed/passed verification tracking.
- [x] **Minimal Default Loadout & Org Inheritance (`workspace_layout.py`)**: Clean `focused` default with opt-in panels/plugins and uncustomized user inheritance.
- [x] **Collapsed Ask Brain Drawer & Deep-Link Inspector**: On-demand Ask Brain query drawer wired to Brain `/api/v1/ask` plus 1-click node control-plane links.
- [x] **Interactive `auth_required` Sign-In UI & Proxy**: `#brain-auth-banner`, `<dialog id="brain-auth-dialog">`, `sessionStorage` isolation, and per-request Brain header forwarding.
- [x] **Repo-Native `.ai/` Cleanup & Hygiene Gate (`scripts/ci_verify.py`)**: Removed unrelated copied skills and enforced strict `.ai/` + `golden_path_gates.py` verification.

## Stage 2 — Queued & Experimental Work
- [ ] **Backstage OAuth2 PKCE Popup Flow**: Wire Backstage `OAuthApi` popup login directly into `window.postMessage({type: "opscryer:setDelegatedToken", ...})` for seamless zero-paste sign-in.
- [ ] **Standalone `/nodes` Live Host Metrics Parity**: Render per-node CPU/RAM/GPU telemetry from `OPSCRYER_TELEMETRY_API_URL` with explicit `UNAVAILABLE_NO_EXPORTER` states.
- [ ] **Separate 2D Map vs. 2.5D Spatial View**: Decouple standalone 2D World Map exploration from the 2.5D elevated canvas as top-level views.
- [ ] **Live UI Discoverability & Opt-In Plugin Audit**: Verify browser E2E toggle coverage for optional plugins (including opt-in experimental addons) while preserving a minimal default viewport.
