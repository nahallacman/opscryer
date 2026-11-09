# SPDX-License-Identifier: Apache-2.0
"""Airlock-gated ticket concierge, standalone webpage and loopback HTTP server."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

import gpu_and_household_triage
import jev_client
from knowledge_base import (
    CONCIERGE_JEV_TREE,
    KNOWLEDGE_BASE_ARTICLES,
    POLICY_TO_ARTICLE_ID,
)
import live_advisor
import security_airlock
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


PERSONAS = ("household_user", "developer", "executive", "sre")
QUICK_REPLIES = (
    "Manifest game server pods are down",
    "How do I deploy a database?",
    "Manifest LAN DNS name fails for game.cluster.example.org",
    "Manifest client GPU has low FPS",
)

_POLICY_TO_ARTICLE_ID = POLICY_TO_ARTICLE_ID


def _traverse_concierge_jev_tree(message: str) -> dict:
    """Evaluate CONCIERGE_JEV_TREE via SystemOneJevClient without calling mocked module wrappers."""
    client = jev_client.SystemOneJevClient("deterministic")
    nodes = CONCIERGE_JEV_TREE["nodes"]
    current = CONCIERGE_JEV_TREE["root_node_id"]
    breadcrumbs = []
    visited = set()
    while current not in visited and current in nodes:
        visited.add(current)
        node = nodes[current]
        if node["kind"] == "leaf":
            return {"policy_id": node["policy_id"], "breadcrumbs": breadcrumbs}
        res = client.evaluate_predicate(message, node["predicate_id"])
        route = jev_client.predicate_route(res, node["predicate_id"], 0.80)
        if route not in ("true_branch", "false_branch"):
            break
        breadcrumbs.append({
            "node_id": current,
            "branch": route,
            "confidence": res["calibrated_probability"],
        })
        current = node[route]
    return {"policy_id": "policy-demo-standard-guidance", "breadcrumbs": breadcrumbs}


def resolve_knowledge_article(message: str, advice: dict | None = None) -> dict:
    """Resolve a vague user question via Jev predicate evaluation + deterministic tree traversal."""
    jev_path = _traverse_concierge_jev_tree(message)
    target_id = _POLICY_TO_ARTICLE_ID.get(jev_path.get("policy_id"), "KB-OPS-006")
    by_id = {a["article_id"]: a for a in KNOWLEDGE_BASE_ARTICLES}
    if target_id != "KB-OPS-006" and target_id in by_id:
        article = {k: v for k, v in by_id[target_id].items() if k != "pattern"}
        article["jev_policy_id"] = jev_path["policy_id"]
        article["jev_breadcrumbs"] = jev_path["breadcrumbs"]
        return article
    text = message.casefold()
    for candidate in KNOWLEDGE_BASE_ARTICLES[:-1]:
        if re.search(candidate["pattern"], text, re.IGNORECASE):
            article = {k: v for k, v in candidate.items() if k != "pattern"}
            article["jev_policy_id"] = jev_path["policy_id"]
            article["jev_breadcrumbs"] = jev_path["breadcrumbs"]
            return article
    hits = (advice or {}).get("bm25_hits") or []
    if hits and hits[0].get("score", 0) > 0:
        top = hits[0]
        ns = top.get("namespace") or "default"
        name = top.get("name") or top.get("id", "workload")
        kind = top.get("kind") or "Resource"
        return {
            "article_id": f"KB-LIVE-{ns.upper()[:8]}",
            "title": f"Live Workload Operations Runbook: {name} ({kind} in {ns})",
            "category": f"Live Cluster Workload ({ns})",
            "summary": (
                f"Matched live cluster {kind} '{name}' in namespace '{ns}' (status: {top.get('status', 'Unknown')}). "
                f"Inspect pod readiness, logs, and upstream dependencies in the Spatial RTS Graph."
            ),
            "steps": [
                f"Inspect {kind} {name} in namespace {ns} and check recent Kubernetes events.",
                f"Open https://grafana.cluster.example.org/explore to review container logs and CPU/RAM telemetry for {ns}/{name}.",
            ],
            "reference_snippet": (
                f"kubectl get pods,svc,ingress -n {ns}\n"
                f"kubectl describe {kind.lower()} {name} -n {ns}"
            ),
            "focused_citations": [h["id"] for h in hits[:4] if "id" in h],
            "jev_policy_id": jev_path["policy_id"],
            "jev_breadcrumbs": jev_path["breadcrumbs"],
        }
    article = {k: v for k, v in KNOWLEDGE_BASE_ARTICLES[-1].items() if k != "pattern"}
    article["jev_policy_id"] = jev_path["policy_id"]
    article["jev_breadcrumbs"] = jev_path["breadcrumbs"]
    return article


def _blocked(persona):
    return {"status": "blocked_by_airlock", "airlock_blocked": True,
            "persona": persona, "status_badge": "BLOCKED_BY_AIRLOCK",
            "plain_english_answer":
                "I cannot process that request under the current safety policy. "
                "Please ask a manifest, deployment, database, or dependency question without sensitive information.",
            "matched_article": None,
            "ticket_card": None, "household_triage": {}, "live_cluster_facts": {},
            "cited_node_ids": [], "focused_citations": [], "suggested_next_steps": [],
            "quick_reply_chips": list(QUICK_REPLIES)}


def _health_badge(facts, ticket):
    if (ticket["route"] != "leaf" or ticket["required_it_tickets"]
            or not ticket["direct_access_allowed"]):
        return "ACTION_REQUIRED"
    if (facts.get("node_counts", {}).get("not_ready", 0)
            or facts.get("pod_counts", {}).get("failed", 0)
            or facts.get("pod_counts", {}).get("pending", 0)
            or facts.get("pod_counts", {}).get("other", 0)
            or facts.get("deployment_counts", {}).get("degraded", 0)
            or facts.get("node_hotspots")):
        return "DEGRADED"
    if not facts.get("node_counts", {}).get("total", 0):
        return "ACTION_REQUIRED"
    return "HEALTHY"


def _prepare_concierge_prompt(message, catalog=None, _advisor_context=None):
    triage = gpu_and_household_triage.triage_household_game_ticket(message)
    routing = jev_client.evaluate_ticket_with_jev_tree(message)
    advice = live_advisor.answer_operational_question(
        message, catalog=catalog, _context=_advisor_context)
    return triage, routing, advice


def ask_concierge_chat(message, persona="household_user", catalog=None, _prepared=None):
    """Compose sanitized diagnostics and policy; no actions or tickets are executed.

    Validation errors never contain supplied values. The airlock runs before
    diagnostics, policy evaluation or catalog access. Personas change presentation
    only, never access permissions. HEALTHY describes the supplied snapshot only.
    """
    if not isinstance(persona, str) or persona not in PERSONAS:
        raise ValueError("Unsupported persona")
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Message must be a nonempty string")
    airlock = security_airlock.evaluate_code_search_airlock(message)
    if airlock.get("airlock_blocked") is not False:
        return _blocked(persona)

    triage, routing, advice = (
        _prepare_concierge_prompt(message, catalog=catalog)
        if _prepared is None else _prepared
    )
    if advice.get("airlock_blocked") is not False or advice.get("status") != "ok":
        return _blocked(persona)
    ticket = {key: routing[key] for key in (
        "policy_id", "required_it_tickets", "direct_access_allowed", "route", "anchor_node_id")}
    facts = advice["live_facts"]
    badge = _health_badge(facts, ticket)
    article = resolve_knowledge_article(message, advice)
    counts = facts.get("node_counts", {})
    pods = facts.get("pod_counts", {})
    answer = (
        f"[{article['article_id']}: {article['title']}] {article['summary']} "
        f"The cluster snapshot shows {counts.get('ready', 0)} of "
        f"{counts.get('total', 0)} computers ready, {pods.get('failed', 0)} failed "
        f"game or service tasks and {pods.get('pending', 0)} waiting tasks. "
        "This is snapshot evidence, not a confirmed cause or a live health check. "
    )
    if ticket["route"] != "leaf":
        answer += "A person must review the request before access can be granted. "
    elif ticket["required_it_tickets"] or not ticket["direct_access_allowed"]:
        answer += "Follow the ticket policy below before requesting access. "
    else:
        answer += "The ticket policy allows direct access for this request. "
    answer += "No ticket has been filed and no system changes have been made."
    if persona in ("developer", "sre"):
        answer += " " + advice["summary"]
    elif persona == "executive":
        answer += " Use the resolution card to coordinate the responsible team."

    steps = list(article["steps"])
    for item in (triage["clarifying_questions"] or triage["diagnostics"][0]["checks"]):
        if item not in steps:
            steps.append(item)
    if ticket["route"] != "leaf":
        steps.insert(0, "Ask the IT team to review this request; direct access is denied.")
    elif ticket["required_it_tickets"]:
        steps.insert(0, "Request the IT tickets listed in the resolution card.")
    if persona in ("developer", "sre"):
        steps.extend(advice.get("recommended_kubectl_commands", []))
    raw_cited = list(advice.get("cited_node_ids", []))
    focused = [c for c in article["focused_citations"] if c in raw_cited] or raw_cited[:6]
    return sanitize({
        "status": "ok", "airlock_blocked": False, "persona": persona,
        "plain_english_answer": answer, "status_badge": badge,
        "matched_article": article,
        "jev_evaluation_mode": "deterministic_keyword_fallback",
        "ticket_card": ticket, "household_triage": triage,
        "live_cluster_facts": facts, "cited_node_ids": raw_cited,
        "telemetry_mode": "LIVE_KUBECTL" if facts.get("source") == "live_kubectl" else "SNAPSHOT_CACHE",
        "telemetry_freshness": "Live cluster metrics (" + str(facts.get("source", "snapshot")) + ")",
        "focused_citations": focused,
        "suggested_next_steps": steps, "quick_reply_chips": list(QUICK_REPLIES),
    })


def render_concierge_chat_html():
    """Return a self-contained page; all dynamic content is rendered as text."""
    return r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpsCryer Ticket Concierge</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#101827;color:#edf4ff}
body{max-width:980px;margin:auto;padding:24px}h1{margin-bottom:8px}
nav{display:flex;flex-wrap:wrap;gap:8px;padding:12px;background:#1b2940;border-radius:14px;margin-bottom:24px}
nav a{color:#b4ddff;padding:10px 14px;border-radius:8px;text-decoration:none}
nav a:hover{background:#263954;text-decoration:underline}
nav a[aria-current="page"]{background:#b4ddff;color:#101827;font-weight:600}
nav a:focus-visible{outline:3px solid #ffd484;outline-offset:2px}
main{display:grid;grid-template-columns:2fr 1fr;gap:20px}
section,aside{background:#1b2940;padding:20px;border-radius:14px}
label{display:block;margin:12px 0 6px}input,select,button{font:inherit;padding:12px;
border:1px solid #8096b8;border-radius:8px}input,select{background:#101827;color:inherit}
input{box-sizing:border-box;width:100%}button{background:#b4ddff;color:#101827;cursor:pointer}
button:disabled{opacity:.6}button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #ffd484}
#chat-messages{min-height:220px;max-height:440px;overflow:auto}
.message{padding:12px;background:#263954;border-radius:8px;white-space:pre-wrap}
#quick-prompt-chips{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
#quick-prompt-chips button{font-size:.85rem}#live-status-banner{padding:14px;background:#263954;
border-radius:8px;margin:16px 0}#chat-send-btn{margin-top:10px}pre{white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:700px){main{grid-template-columns:1fr}body{padding:12px}}
</style>
</head>
<body>
<nav aria-label="Primary navigation">
<a href="/">Spatial RTS Browser</a>
<a href="/chat" aria-current="page">Ticket &amp; Operations Concierge Portal</a>
<a href='/metrics-live'>Live Metrics Stream</a>
</nav>
<h1>Ticket Concierge</h1>
<p>Tell us what is happening. Get a diagnostic plan and an IT routing card.</p>
<p>Ask a deployment, database, pipeline, manifest, or dependency question (for example: "How do I deploy a database?"). Do not include sensitive information.</p>
<div id="live-status-banner" role="status">Ready · Snapshot evidence is shown after a question.</div>
<main><section aria-label="Chat">
<label for="persona-select">Your view</label>
<select id="persona-select">
<option value="household_user">Household user</option><option value="developer">Developer</option>
<option value="executive">Executive</option><option value="sre">SRE</option></select>
<div id="quick-prompt-chips" aria-label="Quick questions"></div>
<form id="chat-form"><label for="chat-input">Your question</label>
<input id="chat-input" autocomplete="off" maxlength="4000" required placeholder="How do I deploy a database?">
<button id="chat-send-btn" type="submit">Send question</button></form>
<div id="matched-article-card" class="message" style="margin:16px 0">Ask a question above to resolve the matching Knowledge Base runbook article.</div>
<div id="chat-messages" role="log" aria-live="polite"></div>
</section><aside aria-label="Ticket resolution">
<h2>Ticket resolution</h2><div id="ticket-resolution-card">No policy evaluated yet.</div>
<h2>Suggested next steps</h2><ul id="next-steps"></ul>
<h2>Cluster snapshot facts</h2><pre id="cluster-facts">No snapshot loaded.</pre>
<h2>Evidence references</h2><ul id="citations"></ul>
</aside></main>
<script>
'use strict';
const byId = id => document.getElementById(id);
function element(tag, text) {
  const node = document.createElement(tag);
  node.textContent = String(text);
  return node;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function list(id, values) {
  const target = byId(id); clear(target);
  for (const value of values) target.appendChild(element('li', value));
}
function chips(values) {
  const target = byId('quick-prompt-chips'); clear(target);
  for (const value of values) {
    const button = element('button', value); button.type = 'button';
    button.addEventListener('click', () => { byId('chat-input').value = value; byId('chat-input').focus(); });
    target.appendChild(button);
  }
}
const offline = {
  status_badge: 'OFFLINE',
  plain_english_answer: 'The concierge is unavailable. No safety check or ticket policy has been evaluated. Start the local server and retry. If you need help now, contact your IT team without sharing sensitive information.',
  matched_article: null,
  ticket_card: null, live_cluster_facts: {}, cited_node_ids: [],
  suggested_next_steps: ['Check whether all players are affected.', 'Check whether the problem is server availability, hostname resolution or client frame rate.'],
  quick_reply_chips: ['Manifest game server pods are down', 'How do I deploy a database?', 'Manifest LAN DNS name fails for game.cluster.example.org', 'Manifest client GPU has low FPS']
};
function render(result) {
  const message = element('p', result.plain_english_answer); message.className = 'message';
  byId('chat-messages').appendChild(message);
  message.scrollIntoView({block: 'nearest'});
  byId('live-status-banner').textContent = result.status_badge + (result.telemetry_mode
    ? ' · ' + result.telemetry_mode + '; no actions executed.'
    : ' · Snapshot evidence only; no actions executed.');
  const articleBox = byId('matched-article-card'); clear(articleBox);
  if (result.matched_article) {
    const art = result.matched_article;
    articleBox.appendChild(element('h3', art.article_id + ' · ' + art.title));
    articleBox.appendChild(element('p', 'Category: ' + art.category));
    if (Array.isArray(art.jev_breadcrumbs) && art.jev_breadcrumbs.length) {
      const trail = art.jev_breadcrumbs.map(b => b.node_id + '=' + (b.branch === 'true_branch' ? 'true' : 'false') + ' (' + b.confidence + ')').join(' -> ');
      articleBox.appendChild(element('p', 'Jev Decision Path: ' + trail + ' -> ' + (art.jev_policy_id || 'leaf')));
    }
    articleBox.appendChild(element('p', art.summary));
    if (Array.isArray(art.steps) && art.steps.length) {
      const stepsList = document.createElement('ol');
      for (const stepText of art.steps) stepsList.appendChild(element('li', stepText));
      articleBox.appendChild(stepsList);
    }
    if (art.reference_snippet) {
      articleBox.appendChild(element('pre', art.reference_snippet));
    }
  } else {
    articleBox.appendChild(element('p', 'No Knowledge Base article resolved for this request.'));
  }
  const card = byId('ticket-resolution-card'); clear(card);
  if (result.ticket_card) {
    for (const key of ['policy_id', 'required_it_tickets', 'direct_access_allowed', 'route', 'anchor_node_id']) {
      card.appendChild(element('p', key.replaceAll('_', ' ') + ': ' + JSON.stringify(result.ticket_card[key])));
    }
  } else { card.appendChild(element('p', 'No ticket policy evaluated. Direct access is not granted.')); }
  list('next-steps', result.suggested_next_steps || []);
  const citedList = (result.focused_citations && result.focused_citations.length)
    ? result.focused_citations
    : (result.cited_node_ids || []).slice(0, 8);
  list('citations', citedList);
  const facts = result.live_cluster_facts || {};
  const compactFacts = facts.node_counts ? {
    source: facts.source,
    node_counts: facts.node_counts,
    ready_nodes: facts.ready_nodes,
    not_ready_nodes: facts.not_ready_nodes,
    pod_counts: facts.pod_counts,
    deployment_counts: facts.deployment_counts,
    node_hotspots: facts.node_hotspots
  } : facts;
  byId('cluster-facts').textContent = JSON.stringify(compactFacts, null, 2);
  chips(result.quick_reply_chips || offline.quick_reply_chips);
}
byId('chat-form').addEventListener('submit', async event => {
  event.preventDefault();
  const input = byId('chat-input'); const message = input.value.trim();
  if (!message || byId('chat-send-btn').disabled) return;
  byId('chat-send-btn').disabled = true;
  byId('live-status-banner').textContent = 'Checking safety policy and snapshot evidence…';
  // Do not copy potentially sensitive question text into the transcript.
  const params = new URLSearchParams({q: message, persona: byId('persona-select').value});
  input.value = '';
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch('/api/v1/chat-concierge?' + params.toString(), {
      signal: controller.signal, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer'
    });
    if (!response.ok && response.status !== 403) throw new Error('Concierge unavailable');
    const result = await response.json();
    if (!['ok', 'blocked_by_airlock'].includes(result.status) || typeof result.plain_english_answer !== 'string') {
      throw new Error('Invalid concierge response');
    }
    render(result);
  } catch (_) { render(offline); }
  finally { clearTimeout(timeout); byId('chat-send-btn').disabled = false; input.focus(); }
});
chips(offline.quick_reply_chips);
</script>
</body></html>'''


class ConciergeRequestHandler(BaseHTTPRequestHandler):
    """Serve the portal and JSON API without logging potentially sensitive URLs."""

    def log_message(self, format, *args):
        pass

    def _send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            url = urlsplit(self.path)
            if url.path == "/":
                self._send(200, render_concierge_chat_html().encode("utf-8"), "text/html; charset=utf-8")
                return
            if url.path != "/api/v1/chat-concierge":
                self._send(404, b'{"error":"Not found"}', "application/json")
                return
            query = parse_qs(url.query, keep_blank_values=True, max_num_fields=4)
            if (set(query) - {"q", "persona"} or len(query.get("q", [])) != 1
                    or len(query.get("persona", ["household_user"])) != 1):
                raise ValueError("Invalid request")
            result = ask_concierge_chat(query["q"][0], query.get("persona", ["household_user"])[0])
            body = json.dumps(result, allow_nan=False).encode("utf-8")
        except ValueError:
            self._send(400, b'{"error":"Invalid concierge request"}', "application/json")
            return
        except Exception:
            self._send(503, b'{"error":"Concierge unavailable"}', "application/json")
            return
        self._send(200, body, "application/json; charset=utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ask", metavar="TEXT")
    parser.add_argument("--persona", default="household_user", metavar="PERSONA")
    parser.add_argument("--export-html", type=Path, metavar="FILE")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--port", type=int, default=8089)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.persona not in PERSONAS or not 1 <= args.port <= 65535:
        parser.error("Unsupported persona or port")
    if args.ask is None and args.export_html is None and not args.serve:
        parser.error("Use --ask, --export-html or --serve")
    try:
        if args.ask is not None:
            result = ask_concierge_chat(args.ask, args.persona)
            print(json.dumps(result, indent=2, allow_nan=False) if args.json
                  else result["status_badge"] + ": " + result["plain_english_answer"])
        if args.export_html is not None:
            args.export_html.write_text(render_concierge_chat_html(), encoding="utf-8")
        if args.serve:
            with ThreadingHTTPServer(("127.0.0.1", args.port), ConciergeRequestHandler) as server:
                print(f"Ticket concierge: http://127.0.0.1:{args.port}", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
    except (OSError, ValueError, TypeError, KeyError):
        parser.error("Unable to complete concierge request")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
