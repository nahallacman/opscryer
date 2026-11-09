# SPDX-License-Identifier: Apache-2.0
"""Sanitized, read-only Jev policy and multi-persona ticket demonstrations."""

import argparse
from copy import deepcopy
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

import jev_client
from opscryer_backend import KnowledgeGraphBackendEngine
import security_airlock
import ticket_chat_portal
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")
PERSONAS = ("household_user", "developer", "sre", "executive")
CANONICAL_PROMPTS = (
    *ticket_chat_portal.QUICK_REPLIES,
    "Manifest scaffold a new 3-tier project pipeline",
    "Manifest nodebeta02 NotReady and failed pods: what should we do?",
)
BLOCKED_PROMPT = "Manifest database password access"
_INVALID_CATALOG = "Invalid playbook studio catalog"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(_INVALID_CATALOG)
        result[key] = value
    return result


def _snapshot(catalog):
    """Validate before redaction, including numbers in opaque credential fields."""
    try:
        if catalog is None:
            catalog = DEFAULT_CATALOG_PATH
        if isinstance(catalog, (str, Path)):
            catalog = json.loads(Path(catalog).read_text(encoding="utf-8"),
                                 object_pairs_hook=_unique_object)
        if not isinstance(catalog, dict):
            raise ValueError(_INVALID_CATALOG)
        json.dumps(catalog, allow_nan=False)
        detached = deepcopy(catalog)
        KnowledgeGraphBackendEngine(detached)
        return KnowledgeGraphBackendEngine(sanitize(detached)).catalog()
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise ValueError(_INVALID_CATALOG) from None


def build_playbook_studio_catalog(catalog=None) -> dict:
    """Export policy metadata and offline concierge examples from a fresh snapshot.

    Accept a graph dict, JSON path, or None for the bundled sanitized cluster.
    L0..L4 describe the explanatory workflow, not five predicate nodes: Jev's
    actual predicates and branch order are preserved in ``decision_tree.nodes``.
    Persona affects presentation only. No tickets or system actions are executed.
    """
    snapshot = _snapshot(catalog)
    tree = jev_client.build_standalone_demo_jev_tree()
    decision_tree = {
        **tree,
        "levels": [
            {"level": "L0", "stage": "security_airlock",
             "description": "Gate manifest and dependency intent before diagnostics."},
            {"level": "L1", "stage": "is_project_scaffolding",
             "node_id": tree["root_node_id"]},
            {"level": "L2", "stage": "is_credential_access",
             "description": "Evaluated only on the scaffolding false branch."},
            {"level": "L3", "stage": "policy_leaf",
             "description": "Preserve the selected policy and direct-access decision."},
            {"level": "L4", "stage": "ticket_resolution",
             "description": "Present required IT tickets and diagnostic suggestions."},
        ],
        "predicate_routing_rules": {
            "required_fields": ["predicate_id", "evaluated_value", "calibrated_probability"],
            "additional_fields_allowed": False,
            "predicate_id": "Must match the requested predicate exactly.",
            "evaluated_value": "Must be a boolean; true routes true_branch, false routes false_branch.",
            "calibrated_probability": "Must be a finite number in [0, 1] at or above the threshold.",
        },
        "confidence_threshold": tree["default_min_confidence"],
        "confidence_note": "Provider-reported confidence is not measured calibration.",
        "fail_closed": {
            "route": jev_client.HUMAN_ESCALATION,
            "direct_access_allowed": False,
            "required_it_tickets": [],
            "conditions": ["invalid or low-confidence predicate", "provider failure",
                           "invalid tree or branch", "cycle or incomplete traversal"],
        },
    }
    templates = [
        {key: node[key] for key in (
            "node_id", "policy_id", "direct_access_allowed", "required_it_tickets", "anchor_node_id")}
        for node in tree["nodes"].values() if node["kind"] == "leaf"
    ]
    try:
        advisor_ctx = ticket_chat_portal.live_advisor._prepare_advisor_context(snapshot)
        prepared_prompts = {
            prompt: ticket_chat_portal._prepare_concierge_prompt(
                prompt, catalog=snapshot, _advisor_context=advisor_ctx)
            for prompt in CANONICAL_PROMPTS
        }
        matrix = [
            {"prompt": prompt, "persona": persona,
             "response": ticket_chat_portal.ask_concierge_chat(
                 prompt, persona=persona, catalog=snapshot,
                 _prepared=prepared_prompts[prompt])}
            for prompt in CANONICAL_PROMPTS for persona in PERSONAS
        ]
        airlock = security_airlock.evaluate_code_search_airlock(BLOCKED_PROMPT, catalog=snapshot)
        matrix.append({
            "prompt": BLOCKED_PROMPT, "persona": "household_user",
            "status_code": airlock["status_code"],
            "airlock_blocked": airlock["airlock_blocked"],
            "reason": airlock["reason"],
            "response": ticket_chat_portal.ask_concierge_chat(
                BLOCKED_PROMPT, persona="household_user", catalog=snapshot),
        })
        result = sanitize({
            "schema_version": "1.0", "read_only": True,
            "decision_tree": decision_tree, "ticket_templates": templates,
            "personas": list(PERSONAS), "playbook_Matrix": matrix,
        })
        json.dumps(result, allow_nan=False)
        return result
    except (ValueError, TypeError, KeyError, AttributeError, IndexError,
            RecursionError, OverflowError):
        raise ValueError(_INVALID_CATALOG) from None


def render_playbook_studio_markdown(catalog=None) -> str:
    """Render sanitized policy evidence with escaped, single-line table cells."""
    data = sanitize(build_playbook_studio_catalog(catalog))

    def text(value):
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, allow_nan=False)
        value = sanitize("unknown" if value is None else str(value))
        value = " ".join(value.split())
        value = "".join(char for char in value if char.isprintable())
        return re.sub(r"([\\`*_{}\[\]()#+.!|>~$-])", r"\\\1", escape(value, quote=True))

    def row(values):
        return "| " + " | ".join(text(value) for value in values) + " |"

    tree = data["decision_tree"]
    lines = [
        "# Jev Decision Tree & Ticket Playbook Studio", "",
        "Read-only snapshot. No tickets are filed and no system actions are executed.", "",
        "## Decision Tree Levels", "",
        "| Level | Stage | Details |", "| --- | --- | --- |",
    ]
    for level in tree["levels"]:
        lines.append(row((level["level"], level["stage"],
                          level.get("description", level.get("node_id")))))
    lines.extend(["", "## Predicate Routing", "",
                  "Confidence threshold: " + text(tree["confidence_threshold"]),
                  text(tree["confidence_note"]), ""])
    for node_id, node in tree["nodes"].items():
        lines.append("- " + text(node_id) + ": " + text(node))
    lines.extend(["", "Routing rules: " + text(tree["predicate_routing_rules"]),
                  "", "Fail closed: " + text(tree["fail_closed"]),
                  "", "## Ticket Templates", ""])
    for template in data["ticket_templates"]:
        lines.append("- " + text(template))
    lines.extend([
        "", "## Persona Comparison", "",
        "Personas change presentation only; access permissions follow the same policy.", "",
        "| Prompt | Persona | Status | Response | Ticket policy | Suggested next steps | Citations |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ])
    for item in data["playbook_Matrix"]:
        response = item["response"]
        lines.append(row((item["prompt"], item["persona"], response["status_badge"],
                          response["plain_english_answer"], response["ticket_card"],
                          response["suggested_next_steps"], response["cited_node_ids"])))
    lines.extend(["", "## Airlock Verification", "",
                  "| Prompt | HTTP status | Airlock blocked | Reason | Response status |",
                  "| --- | --- | --- | --- | --- |"])
    for item in data["playbook_Matrix"]:
        if "airlock_blocked" in item:
            lines.append(row((item["prompt"], item["status_code"], item["airlock_blocked"],
                              item["reason"], item["response"]["status"])))
    return "\n".join(lines) + "\n"


def render_playbook_studio_html(catalog=None) -> str:
    """Render an offline studio; all dynamic evidence enters the DOM as text."""
    data = sanitize(build_playbook_studio_catalog(catalog))
    evidence = (json.dumps(data, allow_nan=False)
                .replace("&", "\\u0026").replace("<", "\\u003c")
                .replace(">", "\\u003e"))
    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Jev Decision Tree &amp; Ticket Playbook Studio</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#090e1a;color:#e5ecf8}
*{box-sizing:border-box}body{margin:0}main,nav{max-width:1440px;margin:auto;padding:24px}
nav{display:flex;flex-wrap:wrap;gap:12px 22px;border-bottom:1px solid #2a3850}
a{color:#a9c9ff;text-underline-offset:4px}nav a[aria-current]{color:#fff;font-weight:700}
h1{font-size:clamp(2rem,4vw,3rem)}h2{font-size:1.4rem}h3{font-size:1.1rem}
p,li{line-height:1.6;overflow-wrap:anywhere}.muted{color:#a8b7ce}
section{margin-top:28px}.card{background:#121c2d;border:1px solid #34445c;
border-radius:16px;padding:20px;border-top:3px solid #80daca;min-width:0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:16px}
#playbook-persona-buttons{display:flex;flex-wrap:wrap;gap:10px}
button{font:inherit;color:inherit;background:#1b2940;border:1px solid #536987;
border-radius:10px;padding:12px;cursor:pointer}button:hover{border-color:#a9c9ff}
button[aria-pressed="true"]{background:#29446b;border-color:#80daca}
button:focus-visible,a:focus-visible{outline:3px solid #80daca;outline-offset:4px}
@media(max-width:600px){main,nav{padding:16px}}
</style></head><body>
<nav aria-label="Main navigation"><a href="/">Home</a><a href="/chat">Chat</a>
<a href="/incidents">Incidents</a><a href="/capacity">Capacity</a>
<a href="/network">Network</a><a href="/gitops">GitOps</a>
<a href="/executive">Executive</a><a href="/hub">Suite Hub</a>
<a href="/simulator">Simulator</a><a href="/playbooks" aria-current="page">Playbooks</a></nav>
<main><header><p class="muted">READ-ONLY / OFFLINE POLICY STUDIO</p>
<h1>Jev Decision Tree &amp; Ticket Playbook Studio</h1>
<p>Explore policy routing and compare persona responses. No tickets are filed and no system actions are executed.</p>
<p>Personas change presentation only; access permissions follow the same policy.</p></header>
<section aria-labelledby="tree-title"><h2 id="tree-title">Decision Tree: L0 to L4</h2>
<div id="playbook-tree-grid" class="grid"></div><p id="playbook-routing"></p></section>
<section aria-labelledby="templates-title"><h2 id="templates-title">Ticket Templates</h2>
<div id="playbook-template-grid" class="grid"></div></section>
<section aria-labelledby="persona-title"><h2 id="persona-title">Persona Comparison</h2>
<div id="playbook-persona-buttons" role="group" aria-label="Filter by persona"></div>
<p id="playbook-status" role="status" aria-live="polite"></p>
<div id="playbook-matrix-grid" class="grid"></div></section>
<section aria-labelledby="airlock-title"><h2 id="airlock-title">Airlock Verification</h2>
<div id="playbook-airlock-grid" class="grid"></div></section>
<noscript><p>Enable JavaScript to explore decision tree evidence and filter persona responses.</p></noscript>
</main>
<script id="playbook-data" type="application/json">""" + evidence + """</script>
<script>
"use strict";
(() => {
  const data = JSON.parse(document.getElementById("playbook-data").textContent);
  function display(value) {
    if (value === null || value === undefined) return "None";
    return typeof value === "object" ? JSON.stringify(value) : String(value);
  }
  function add(parent, tag, value) {
    const element = document.createElement(tag);
    if (value !== undefined) element.textContent = display(value);
    parent.appendChild(element);
    return element;
  }
  function card(parent, title) {
    const element = add(parent, "article");
    element.className = "card";
    add(element, "h3", title);
    return element;
  }
  function details(parent, values) {
    Object.entries(values).forEach(([key, value]) => add(parent, "p", key + ": " + display(value)));
  }
  const tree = data.decision_tree;
  const treeGrid = document.getElementById("playbook-tree-grid");
  tree.levels.forEach(level => {
    const element = card(treeGrid, level.level + " / " + level.stage);
    if (level.description) add(element, "p", level.description);
    if (level.node_id) add(element, "p", "Node: " + level.node_id);
  });
  Object.entries(tree.nodes).forEach(([id, node]) => details(card(treeGrid, id), node));
  const routing = document.getElementById("playbook-routing");
  routing.textContent = "Confidence threshold: " + tree.confidence_threshold + ". " + tree.confidence_note;
  details(card(treeGrid, "Predicate routing rules"), tree.predicate_routing_rules);
  details(card(treeGrid, "Fail closed"), tree.fail_closed);
  const templates = document.getElementById("playbook-template-grid");
  data.ticket_templates.forEach(template => details(card(templates, template.policy_id), template));
  const buttons = document.getElementById("playbook-persona-buttons");
  const matrix = document.getElementById("playbook-matrix-grid");
  function select(persona) {
    Array.from(buttons.children).forEach(button => {
      button.setAttribute("aria-pressed", String(button.dataset.persona === persona));
    });
    matrix.textContent = "";
    const items = data.playbook_Matrix.filter(item => persona === "all" || item.persona === persona);
    items.forEach(item => {
      const response = item.response;
      const element = card(matrix, item.prompt);
      add(element, "p", "Persona: " + item.persona + " / " + response.status_badge);
      add(element, "p", response.plain_english_answer);
      add(element, "p", "Ticket policy: " + display(response.ticket_card));
      add(element, "h4", "Suggested next steps");
      const steps = add(element, "ul");
      response.suggested_next_steps.forEach(step => add(steps, "li", step));
      add(element, "p", "Citations: " + display(response.cited_node_ids));
    });
    document.getElementById("playbook-status").textContent = items.length + " responses / " + persona;
  }
  ["all", ...data.personas].forEach(persona => {
    const button = add(buttons, "button", persona === "all" ? "All personas" : persona);
    button.type = "button";
    button.dataset.persona = persona;
    button.setAttribute("aria-pressed", "false");
    button.addEventListener("click", () => select(persona));
  });
  const airlock = document.getElementById("playbook-airlock-grid");
  data.playbook_Matrix.filter(item => "airlock_blocked" in item).forEach(item => {
    details(card(airlock, item.prompt), {
      "HTTP status": item.status_code, "Airlock blocked": item.airlock_blocked,
      "Reason": item.reason, "Response status": item.response.status,
      "Ticket policy": item.response.ticket_card
    });
  });
  select("all");
})();
</script></body></html>
"""


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error("Invalid playbook studio request")


def _build_playbook_handler(catalog=None):
    """Serve read-only playbooks without logging or echoing request input."""
    class PlaybookRequestHandler(BaseHTTPRequestHandler):
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
                if url.path not in {"/", "/playbooks", "/api/v1/playbook-studio",
                                    "/playbooks/studio.md"}:
                    self._send(404, '{"error":"Not found"}', "application/json")
                    return
                if url.query:
                    raise ValueError("Invalid query")
                if url.path in {"/", "/playbooks"}:
                    body = render_playbook_studio_html(catalog)
                    content_type = "text/html"
                elif url.path == "/playbooks/studio.md":
                    body = render_playbook_studio_markdown(catalog)
                    content_type = "text/markdown"
                else:
                    body = json.dumps(build_playbook_studio_catalog(catalog),
                                      indent=2, allow_nan=False)
                    content_type = "application/json"
            except (ValueError, TypeError, KeyError):
                self._send(400, '{"error":"Invalid playbook studio request"}',
                           "application/json")
                return
            except Exception:
                self._send(503, '{"error":"Playbook studio unavailable"}',
                           "application/json")
                return
            self._send(200, body, content_type)

    return PlaybookRequestHandler


def main(argv=None) -> int:
    """Export offline playbooks or serve the studio on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="playbook_studio", description=__doc__,
                                 allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--markdown", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--port", type=int, default=8097)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("Invalid port")
    try:
        catalog = _snapshot(args.catalog)
        if args.serve:
            with ThreadingHTTPServer(("127.0.0.1", args.port),
                                     _build_playbook_handler(catalog)) as server:
                print(f"Playbook studio: http://127.0.0.1:{args.port}/playbooks", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.markdown:
            print(render_playbook_studio_markdown(catalog), end="")
        else:
            print(json.dumps(build_playbook_studio_catalog(catalog),
                             indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        parser.error("Unable to complete request")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
