---
name: opscryer_ui_and_layout_development
description: "Conventions for editing OpsCryer browser HTML/JS, regenerating index.html with LF endings, running node --check, and preserving route and layout contracts."
---
# OpsCryer UI, Proxy & Layout Development

## 1. Inline `<script>` Compaction Safety (`opscryer_browser.py`)
- `render_standalone_browser_html()` compacts inline `<script>` lines onto a single line separated by spaces.
- Never place `//` single-line comments inside embedded JS; always use `/* ... */` block comments.
- Prefer DOM APIs (`document.createElement`, `textContent`, `replaceChildren`) over `innerHTML` when rendering backend strings or links.
- Validate external `login_url` or link targets strictly for `http:`, `https:`, or single-slash relative paths without embedded credentials.

## 2. Regenerating `index.html` & Verification
- After changing embedded HTML/CSS/JS in `opscryer_browser.py`, regenerate `index.html` with `encoding="utf-8", newline="\n"` via `render_standalone_browser_html()`.
- Always extract `<script>` blocks and run `node --check` before committing (`test_generated_index_html_has_delegated_signin_ui_and_valid_js` enforces this in CI).
- Preserve all routes declared in `route_registry.py` and keep `OPSCRYER_TRUTH_MODE=1` free of synthetic fallbacks unless explicit `?demo=1` preview is requested.

## 3. Minimal Loadout & User-Delegated Auth
- Keep optional plugins/drawers (Ask Brain drawer, experimental addons) disabled or collapsed by default (`focused` preset in `workspace_layout.py`).
- Forward `X-Brain-Delegated-Tokens` only via `_extract_brain_delegated_headers()` (`<=4096` bytes, no CR/LF/NUL) and store browser tokens solely in tab-scoped `sessionStorage`.
