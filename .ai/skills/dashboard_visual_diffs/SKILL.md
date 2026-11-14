---
name: "dashboard_visual_diffs"
description: Rules, standards, and automation procedures for capturing targeted, diff-focused dashboard screenshots and visual comparisons in CI/CD and MR reviews.
---

# AI Skill: Dashboard Visual Diffs & Targeted Scope Capture

**Purpose:** This skill defines the mandatory protocol for capturing, comparing, and validating Grafana dashboard visual changes in Merge Requests (Epic 47 & Epic 51). It ensures that visual evidence in MR reports captures the *actual modified panels and telemetry*, eliminating useless blind top-of-page captures.

---

## 1. The Core Invariant

> [!IMPORTANT]
> **Rule: Capture the Changes that Matter, Not Just the Top of the Page**
> Automated visual diff tools, CI jobs (`capture-visual-diff`), and AI agents MUST NOT blindly capture a static `(x=0, y=0)` top-of-page 1080p viewport when the modified panels reside elsewhere on the dashboard.
> The capture pipeline MUST detect which panels were modified, scroll the headless browser to those exact rows, wait for DOM and query hydration, and capture the focused section.

---

## 2. Why Blind Captures Fail

Large production dashboards (such as **NOC God Mode**) span thousands of vertical pixels across dozens of rows:
- Row 1 (`y = 0`): Executive Summary & Hardware Cockpit
- Row 2 (`y = 15`): Core Kubernetes Compute & Capacity
- Row 3 (`y = 45`): OpenZFS Storage Fleet & ZFS
- Row 4 (`y = 75`): BGP, MetalLB & Network Topology
- Row 5 (`y = 102`): **Dedicated Game Servers & Simulation Fleet**
- Row 6 (`y = 130`): AI Gateway & LLM Orchestration
- Row 7 (`y = 144`): Container Registry, Logs & Reliability

A blind 1920x1080 screenshot captures only `y = 0` to `y ~ 30`. Any change made to panels in rows below `y = 30` will be completely invisible in the comparison screenshot, creating a false impression of zero diffs or missing features.

---

## 3. Targeted Capture Protocol & Algorithm

Whenever generating or debugging dashboard visual diffs:

### Step 1: Git Diff Inspection & Structural Comparison
Compare the branch against `main` for touched dashboard definitions:
- **Structural AST/JSON Diffing (`extract_structural_focus_targets`)**: Compare `git show origin/main:grafana/<file>.yaml` against the local JSON tree (`_normalize_panel_for_diff`) to detect modified panels even when only `targets`, `overrides`, or `description` change without altering the panel `"title"`.
- **Never Hardcode Unrelated Fallbacks**: Do not hardcode a static row fallback (such as `"AI Gateway"`). Always compute `focus_fallback` dynamically from the nearest preceding `type: "row"` heading (`gridPos.y <= panel.gridPos.y`) in the dashboard JSON.

### Step 2: Target Coordinate & Element Resolution
From the modified panel definitions, extract:
1. **Primary Panel Title (`focus_target`)**: The topmost modified non-row panel title (ordered by `gridPos.y`, `gridPos.x`).
2. **All Modified Panel Titles (`changed_panels`)**: Complete list of modified panel titles so every changed panel in the viewport receives visual diff highlighting.
3. **Parent Row Heading (`focus_fallback`)**: The parent row title containing the modified panel (e.g., `"Dedicated Game Servers & Simulation Fleet"`).

### Step 3: Target-First Incremental Scroll & React-Virtualized Hydration
Grafana uses `react-virtualized` and custom inner scroll containers (`.scrollbar-view`, `[data-testid="scrollbar-view"]`) to unmount offscreen panels.
1. **Scroll Both Window & Inner Scroll Containers**: Helper functions (`scrollAllTo`, `scrollAllBy`) must scroll both `window` and all `.scrollbar-view` / `overflowY: auto|scroll` containers simultaneously.
2. **Exhaust Target Search Before Fallback**: Incrementally scroll down in 20 steps of 550px looking **exclusively** for `focus_target`. Only if `focus_target` is still not mounted after scanning the entire dashboard should the script perform a secondary pass for `focus_fallback`. Never check `focus_fallback` on Step 1 before scrolling, or an upper row will hijack the scroll position.
3. **Center & Hydrate**: Call `scrollIntoView({behavior: 'instant', block: 'center'})` plus `scrollAllBy(-120)` header offset, then wait for Prometheus/Loki query execution and a 1.0s GPU compositor settle buffer.

### Step 4: Multi-Panel Visual Diff Highlighting
1. Inject high-contrast `#10b981` (emerald green) borders (`box-shadow`) and `★ CHANGED IN MR` badges over all panels in `changed_panels` (plus `focus_target`) visible in the preview viewport.
2. **Preserve `.react-grid-item` Absolute Positioning**: Grafana's `react-grid-layout` positions `.react-grid-item` containers using `position: absolute` (from the CSS stylesheet) combined with `transform: translate(Xpx, Ypx)`. Never unconditionally set `container.style.position = 'relative'` on `.react-grid-item`, as inline `position: relative` overrides `position: absolute` and forces highlighted panels into vertical block flow (causing panels on the same row to stair-step diagonally 1 per line). Only set `container.style.position = 'relative'` when `window.getComputedStyle(container).position === 'static'`.
3. Stitch the production baseline and preview side-by-side with clear labels.

---

## 4. Headless Browser Initialization & CDP Resilience

In containerized CI environments (such as Alpine Linux on Kubernetes runners):
1. **CDP `returnByValue: True` Requirement**: Every `Runtime.evaluate` call that returns a JavaScript object (`scroll_hydration_js`, `inspect_queries_js`, `highlight_js`) MUST set `"returnByValue": True` in its CDP parameters. Without it, Chrome returns a remote `objectId` handle instead of serializing `result.result.value`, causing Python to read `{}` and silently drop scroll diagnostics and panel query health counts.
2. **CDP Port Polling Over Rigid Sleep**: Headless Chromium can take 1.5 to 3.5 seconds on cold start to allocate user directories and bind to `--remote-debugging-port`. The capture script must actively poll the `http://127.0.0.1:{port}/json` endpoint with retries rather than relying on a fixed `time.sleep()`, preventing instantaneous `[Errno 111] Connection refused` failures.
3. **Automatic Capture Retries**: If either the preview or baseline capture encounters an intermittent transport or rendering failure, the pipeline must retry the capture once before declaring failure.
4. **Never Disguise Failures as Diffs**: If preview capture fails, the automation MUST NEVER silently copy the baseline image into the diff artifact. Marking the status explicitly as `failed (preview capture failed)` ensures reviewers are never misled by false identical visual reports.

---

## 5. Developer & Reviewer Guidelines

- When reviewing MR visual diff comments, if the modified section is lower down, verify that the report includes focused captures of the relevant rows.
- If an automated capture fails to focus on the modified section, capture and attach a focused manual CDP screenshot to the MR or walkthrough artifact.
