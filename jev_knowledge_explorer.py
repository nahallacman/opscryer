# SPDX-License-Identifier: Apache-2.0
"""Read-only knowledge articles and deterministic concierge routing evidence."""

import argparse
from copy import deepcopy
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import unicodedata
from urllib.parse import parse_qs, urlsplit

import jev_client
from opscryer_backend import validate_spatial_graph_contract
import ticket_chat_portal
from telemetry_sanitizer import sanitize_live_home_telemetry_for_demo as sanitize


DEFAULT_CATALOG_PATH = Path(__file__).with_name("live-cluster-sanitized.json")
SAMPLE_QUERIES = (
    "How 2 database?",
    "How 2 storage?",
    "How does SSO work?",
    "Minecraft server lagging",
    "How do I expose a website?",
    "GPU low FPS",
)
_INVALID_CATALOG = "Invalid knowledge explorer catalog"
_INVALID_QUERY = "Invalid knowledge explorer query"
_INVALID_REQUEST = "Invalid knowledge explorer request"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(_INVALID_CATALOG)
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(_INVALID_CATALOG)


def _snapshot(catalog):
    """Validate both sides of redaction, including opaque credential values."""
    try:
        if catalog is None:
            catalog = DEFAULT_CATALOG_PATH
        if isinstance(catalog, (str, Path)):
            catalog = json.loads(
                Path(catalog).read_text(encoding="utf-8"),
                object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        if not isinstance(catalog, dict):
            raise ValueError(_INVALID_CATALOG)
        detached = deepcopy(catalog)
        if validate_spatial_graph_contract(detached):
            raise ValueError(_INVALID_CATALOG)
        snapshot = sanitize(detached)
        if validate_spatial_graph_contract(snapshot):
            raise ValueError(_INVALID_CATALOG)
        return snapshot
    except (OSError, ValueError, TypeError, KeyError, AttributeError,
            RecursionError, OverflowError):
        raise ValueError(_INVALID_CATALOG) from None


def _evaluate_query(query, tree):
    """Return every predicate score and the ordered, selected decision path."""
    client = jev_client.SystemOneJevClient("deterministic")
    probabilities = [
        client.evaluate_predicate(query, node["predicate_id"])
        for node in tree["nodes"].values() if node["kind"] == "decision"
    ]
    path = jev_client.explain_jev_decision_path(
        query, tree=tree, provider="deterministic")
    leaf = next((deepcopy(node) for node in tree["nodes"].values()
                 if node["kind"] == "leaf"
                 and node["policy_id"] == path["policy_id"]), None)
    return {
        "query": query,
        "predicate_probabilities": probabilities,
        **path,
        "resolved_policy": leaf,
        "knowledge_article": deepcopy(ticket_chat_portal.resolve_knowledge_article(query)),
    }


def build_jev_knowledge_catalog(query=None, catalog=None) -> dict:
    """Export all articles, sample query evidence and an optional query result.

    ``catalog`` accepts a graph dict, JSON Path/string, or None for the bundled
    sanitized cluster. Invalid catalogs raise a fixed ValueError before any
    query evaluation. Caller data and shared article/tree constants are detached.

    ``query_result`` is None when no query is supplied. Each evaluation includes
    all predicate probabilities, decision-only breadcrumbs in traversal order,
    the complete selected leaf policy, and the concierge's resolved article.
    Scores express deterministic provider confidence, not measured calibration.
    No model service is contacted and no tickets or system actions are executed.
    """
    snapshot = _snapshot(catalog)
    if query is not None and (
            not isinstance(query, str) or not query.strip()
            or any(unicodedata.category(char) == "Cc" for char in query)):
        raise ValueError(_INVALID_QUERY)
    tree = deepcopy(ticket_chat_portal.CONCIERGE_JEV_TREE)
    result = sanitize({
        "schema_version": "1.0",
        "read_only": True,
        "catalog_summary": {
            "node_count": len(snapshot["nodes"]),
            "edge_count": len(snapshot.get("edges", [])),
        },
        "decision_tree": tree,
        "confidence_note": "Provider-reported confidence is not measured calibration.",
        "knowledge_articles": deepcopy(list(ticket_chat_portal.KNOWLEDGE_BASE_ARTICLES)),
        "sample_queries": [_evaluate_query(sample, tree) for sample in SAMPLE_QUERIES],
        "query_result": None if query is None else _evaluate_query(query, tree),
    })
    json.dumps(result, allow_nan=False)
    return result


def _markdown_cell(value):
    """Keep untrusted text in one literal Markdown table cell or heading."""
    text = escape(" ".join(str(value).split()), quote=True)
    return re.sub(r"([\\`*_{}\[\]()#+.!|~\-])", r"\\\1", text)


def _snippet_language(snippet):
    return "yaml" if snippet.startswith(("apiVersion:", "include:")) else "bash"


def render_jev_knowledge_markdown(query=None, catalog=None) -> str:
    """Export sanitized routing evidence and every runbook as Markdown."""
    data = build_jev_knowledge_catalog(query=query, catalog=catalog)
    lines = ["# Jev Knowledge Base & Intent Resolution Explorer", "",
             "Read-only snapshot; no tickets or system actions are executed.",
             data["confidence_note"], "", "## Jev Decision Tree Nodes", ""]

    def table(headers, rows):
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("| " + " | ".join("---" for _ in headers) + " |")
        for row in rows:
            lines.append("| " + " | ".join(_markdown_cell(cell) for cell in row) + " |")
        lines.append("")

    table(["Node", "Kind", "Predicate", "True branch", "False branch", "Policy",
           "Direct access", "Required IT tickets", "Anchor"], (
        [node["node_id"], node["kind"], node.get("predicate_id", ""),
         node.get("true_branch", ""), node.get("false_branch", ""),
         node.get("policy_id", ""), node.get("direct_access_allowed", ""),
         ", ".join(node.get("required_it_tickets", [])), node["anchor_node_id"]]
        for node in data["decision_tree"]["nodes"].values()))
    evaluations = list(data["sample_queries"])
    if data["query_result"] is not None:
        evaluations.append(data["query_result"])
    lines.extend(["## Predicate Probability Matrix", ""])
    table(["Query", "Predicate", "Evaluated value", "Provider confidence"], (
        [result["query"], score["predicate_id"], score["evaluated_value"],
         score["calibrated_probability"]]
        for result in evaluations for score in result["predicate_probabilities"]))
    lines.extend(["## Shorthand Query Resolutions", ""])
    table(["Query", "Article", "Policy", "Breadcrumb path", "Direct access",
           "Required IT tickets", "Explanation"], (
        [result["query"], result["knowledge_article"]["article_id"], result["policy_id"],
         " -> ".join(f"{crumb['node_id']} {crumb['branch']} ({crumb['confidence']})"
                     for crumb in result["breadcrumbs"]), result["direct_access_allowed"],
         ", ".join(result["required_it_tickets"]), result["plain_english_why"]]
        for result in evaluations))
    lines.extend(["## Runbook Articles", ""])
    for article in data["knowledge_articles"]:
        lines.extend(["### " + _markdown_cell(article["article_id"] + ": " + article["title"]),
                      "", "Category: " + _markdown_cell(article["category"]), "",
                      _markdown_cell(article["summary"]), ""])
        lines.extend(f"{number}. {_markdown_cell(step)}"
                     for number, step in enumerate(article["steps"], 1))
        snippet = article["reference_snippet"]
        # A longer fence preserves even a reference containing Markdown fences.
        fence = "`" * max(3, 1 + max((len(run) for run in re.findall(r"`+", snippet)), default=0))
        lines.extend(["", "Reference YAML/CLI:", "", fence + _snippet_language(snippet),
                      snippet, fence, "", "Focused citations:", ""])
        lines.extend("- " + _markdown_cell(citation) for citation in article["focused_citations"])
        lines.append("")
    return "\n".join(lines)


def render_jev_knowledge_html(catalog=None) -> str:
    """Render an offline explorer with text-only DOM updates and safe JSON."""
    data = build_jev_knowledge_catalog(catalog=catalog)
    payload = (json.dumps(data, ensure_ascii=True, allow_nan=False)
               .replace("&", r"\u0026").replace("<", r"\u003c").replace(">", r"\u003e"))
    return _KNOWLEDGE_HTML.replace("__KB_EXPLORER_DATA__", payload)


_KNOWLEDGE_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Jev Knowledge Base &amp; Intent Resolution Explorer</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#0b1220;color:#e7eefb}
*{box-sizing:border-box}body{max-width:1440px;margin:auto;padding:24px}
nav,.chips{display:flex;flex-wrap:wrap;gap:8px}nav{margin-bottom:28px}
nav a{color:#a9ceff;text-decoration:none;padding:10px;border-radius:10px}
nav a:hover,nav a[aria-current=page]{background:#263c5b;color:#fff}
h1{font-size:clamp(1.7rem,4vw,2.8rem);margin-bottom:8px}h2{font-size:1.2rem}
p{line-height:1.6;color:#c2cfe3}main{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}
.panel,article{background:#152238;border:1px solid #30445f;border-radius:20px;padding:22px}
.wide{grid-column:1/-1}label{display:block;margin:16px 0 8px}
input,button{font:inherit;border:1px solid #5a789d;border-radius:10px;padding:12px}
input{width:100%;background:#0b1220;color:#fff}button{background:#263c5b;color:#e7eefb;cursor:pointer}
button[aria-pressed=true]{background:#a9ceff;color:#0b1220}button:hover{border-color:#a9ceff}
a:focus-visible,input:focus-visible,button:focus-visible{outline:3px solid #ffd58a;outline-offset:3px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;border-bottom:1px solid #30445f;padding:12px;vertical-align:top}
caption{text-align:left;padding:8px 0;color:#c2cfe3}th{color:#a9ceff}
#kb-breadcrumb-trail{padding-left:24px;line-height:1.8;overflow-wrap:anywhere}
#kb-article-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}
article h3{margin-top:0}article li{margin-bottom:10px;line-height:1.5}
pre{padding:16px;background:#0b1220;border-radius:12px;white-space:pre-wrap;overflow-wrap:anywhere}
.citations{font-size:.85rem;overflow-wrap:anywhere}.eyebrow{color:#8ee0c2}
@media(max-width:800px){main,#kb-article-grid{grid-template-columns:1fr}body{padding:12px}.panel,article{padding:16px}}
</style>
</head>
<body>
<nav aria-label="Primary navigation">
<a href="/">Spatial Browser</a><a href="/chat">Chat</a><a href="/incidents">Incidents</a>
<a href="/capacity">Capacity</a><a href="/network">Network</a><a href="/gitops">GitOps</a>
<a href="/executive">Executive</a><a href="/hub">Hub</a><a href="/simulator">Simulator</a>
<a href="/playbooks">Playbooks</a><a href="/models">Models</a><a href="/games">Games</a>
<a href="/kb" aria-current="page">Knowledge Base</a>
</nav>
<header><p class="eyebrow">OPSCRYER / READ-ONLY KNOWLEDGE</p>
<h1>Jev Knowledge Base &amp; Intent Resolution Explorer</h1>
<p>Explore deterministic intent routing and copy runbook references. No tickets or system actions are executed.</p>
</header>
<main>
<section class="panel wide" aria-labelledby="kb-query-heading">
<h2 id="kb-query-heading">Shorthand query resolutions</h2>
<p>Select a sample to inspect its predicate scores and decision path. Search filters the runbooks below.</p>
<div id="kb-query-buttons" class="chips" aria-label="Sample questions"></div>
<label for="kb-search-input">Search runbook articles</label>
<input id="kb-search-input" type="search" placeholder="Search database, storage, SSO, CLI commands...">
<p id="kb-search-status" role="status"></p>
</section>
<section class="panel" aria-labelledby="kb-predicate-heading">
<h2 id="kb-predicate-heading">Predicate Probability Matrix</h2>
<p id="kb-confidence-note"></p><div class="scroll">
<table id="kb-predicate-table"><caption id="kb-selected-query"></caption>
<thead><tr><th scope="col">Predicate</th><th scope="col">Value</th><th scope="col">Provider confidence</th></tr></thead>
<tbody id="kb-predicate-body"></tbody></table></div>
</section>
<section class="panel" aria-labelledby="kb-path-heading">
<h2 id="kb-path-heading">Jev decision path</h2>
<ol id="kb-breadcrumb-trail"></ol><p id="kb-resolution" role="status"></p>
</section>
<section class="panel wide" aria-labelledby="kb-tree-heading">
<h2 id="kb-tree-heading">Jev Decision Tree Nodes</h2><div class="scroll">
<table><thead><tr><th scope="col">Node</th><th scope="col">Predicate / Policy</th>
<th scope="col">Branches / Access requirements</th><th scope="col">Anchor</th></tr></thead>
<tbody id="kb-tree-body"></tbody></table></div>
</section>
<section class="wide" aria-labelledby="kb-articles-heading">
<h2 id="kb-articles-heading">Runbook Articles</h2><div id="kb-article-grid"></div>
</section>
</main>
<noscript>Enable JavaScript to explore the embedded offline knowledge catalog.</noscript>
<script id="kb-explorer-data" type="application/json">__KB_EXPLORER_DATA__</script>
<script>
'use strict';
const data = JSON.parse(document.getElementById('kb-explorer-data').textContent);
const byId = id => document.getElementById(id);
function element(tag, text) {
  const node = document.createElement(tag);
  node.textContent = String(text);
  return node;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function row(target, values) {
  const tr = document.createElement('tr');
  for (const value of values) tr.appendChild(element('td', value));
  target.appendChild(tr);
}
function selectQuery(result) {
  byId('kb-selected-query').textContent = result.query;
  clear(byId('kb-predicate-body'));
  for (const score of result.predicate_probabilities) {
    row(byId('kb-predicate-body'), [score.predicate_id, score.evaluated_value,
      score.calibrated_probability]);
  }
  const trail = byId('kb-breadcrumb-trail'); clear(trail);
  for (const crumb of result.breadcrumbs) {
    trail.appendChild(element('li', crumb.node_id + ' → ' + crumb.branch + ' (' + crumb.confidence + ')'));
  }
  trail.appendChild(element('li', 'Policy: ' + result.policy_id));
  byId('kb-resolution').textContent = result.knowledge_article.article_id + ' · ' +
    result.knowledge_article.title + '. ' + result.plain_english_why + ' Required IT tickets: ' +
    (result.required_it_tickets.join(', ') || 'None');
  for (const button of byId('kb-query-buttons').children) {
    button.setAttribute('aria-pressed', String(button.textContent === result.query));
  }
}
function renderArticles() {
  const search = byId('kb-search-input').value.trim().toLowerCase();
  const articles = data.knowledge_articles.filter(article =>
    [article.article_id, article.title, article.category, article.summary,
      ...article.steps, article.reference_snippet, ...article.focused_citations]
      .join(' ').toLowerCase().includes(search));
  const grid = byId('kb-article-grid'); clear(grid);
  byId('kb-search-status').textContent = articles.length + ' of ' + data.knowledge_articles.length + ' runbooks';
  for (const article of articles) {
    const card = document.createElement('article');
    card.appendChild(element('h3', article.article_id + ' · ' + article.title));
    card.appendChild(element('p', article.category));
    card.appendChild(element('p', article.summary));
    const steps = document.createElement('ol');
    for (const step of article.steps) steps.appendChild(element('li', step));
    card.appendChild(steps);
    card.appendChild(element('h4', 'YAML / CLI reference'));
    const pre = document.createElement('pre');
    const code = element('code', article.reference_snippet); pre.appendChild(code);
    card.appendChild(pre);
    const copy = element('button', 'Copy reference'); copy.type = 'button';
    copy.setAttribute('aria-label', 'Copy reference for ' + article.article_id);
    const status = element('p', ''); status.setAttribute('role', 'status');
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(article.reference_snippet);
        status.textContent = 'Reference copied.';
      } catch (_) {
        const selection = window.getSelection(); const range = document.createRange();
        range.selectNodeContents(code); selection.removeAllRanges(); selection.addRange(range);
        status.textContent = 'Reference selected. Use your browser copy command.';
      }
    });
    card.appendChild(copy); card.appendChild(status);
    const citations = element('p', 'Focused citations: ' + article.focused_citations.join(' · '));
    citations.className = 'citations'; card.appendChild(citations); grid.appendChild(card);
  }
  if (!articles.length) grid.appendChild(element('p', 'No matching runbooks. Try another search.'));
}
byId('kb-confidence-note').textContent = data.confidence_note;
for (const result of data.sample_queries) {
  const button = element('button', result.query); button.type = 'button';
  button.addEventListener('click', () => selectQuery(result));
  byId('kb-query-buttons').appendChild(button);
}
for (const node of Object.values(data.decision_tree.nodes)) {
  row(byId('kb-tree-body'), [node.node_id, node.predicate_id || node.policy_id,
    node.kind === 'decision' ? 'True → ' + node.true_branch + '; False → ' + node.false_branch :
      'Direct access: ' + node.direct_access_allowed + '; IT tickets: ' + node.required_it_tickets.join(', '),
    node.anchor_node_id]);
}
byId('kb-search-input').addEventListener('input', renderArticles);
selectQuery(data.sample_queries[0]); renderArticles();
</script>
</body>
</html>'''


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        super().error(_INVALID_REQUEST)


def _build_kb_explorer_handler(catalog=None):
    """Serve the offline knowledge explorer without logging request input."""
    class KnowledgeExplorerRequestHandler(BaseHTTPRequestHandler):
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
                if url.path not in {"/", "/kb", "/api/v1/kb-explorer"}:
                    self._send(404, '{"error":"Not found"}', "application/json")
                    return
                if re.search(r"%(?![0-9a-fA-F]{2})", url.query):
                    raise ValueError(_INVALID_REQUEST)
                query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True,
                                 max_num_fields=1, errors="strict")
                if set(query) - {"q"}:
                    raise ValueError(_INVALID_REQUEST)
                if url.path in {"/", "/kb"}:
                    if url.query:
                        raise ValueError(_INVALID_REQUEST)
                    body = render_jev_knowledge_html(catalog=catalog)
                    content_type = "text/html"
                else:
                    body = json.dumps(build_jev_knowledge_catalog(
                        query=query.get("q", [None])[0], catalog=catalog),
                        indent=2, allow_nan=False)
                    content_type = "application/json"
            except (ValueError, TypeError, KeyError):
                self._send(400, json.dumps({"error": _INVALID_REQUEST}), "application/json")
                return
            except Exception:
                self._send(503, '{"error":"Knowledge explorer unavailable"}',
                           "application/json")
                return
            self._send(200, body, content_type)

    return KnowledgeExplorerRequestHandler


def main(argv=None) -> int:
    """Export knowledge and routing evidence or serve it on IPv4 loopback."""
    parser = _SafeArgumentParser(prog="jev_knowledge_explorer", description=__doc__,
                                 allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--markdown", action="store_true")
    mode.add_argument("--serve", action="store_true")
    parser.add_argument("--query", metavar="TEXT")
    parser.add_argument("--catalog", type=Path, metavar="FILE")
    parser.add_argument("--port", type=int, default=8100)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error(_INVALID_REQUEST)
    try:
        catalog = _snapshot(args.catalog)
        # Validate the optional query even when serving rather than exporting.
        data = build_jev_knowledge_catalog(query=args.query, catalog=catalog)
        if args.serve:
            with ThreadingHTTPServer(("127.0.0.1", args.port),
                                     _build_kb_explorer_handler(catalog)) as server:
                print(f"Knowledge explorer: http://127.0.0.1:{args.port}/kb", flush=True)
                try:
                    server.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.markdown:
            print(render_jev_knowledge_markdown(query=args.query, catalog=catalog), end="")
        else:
            print(json.dumps(data, indent=2, allow_nan=False))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        parser.error(_INVALID_REQUEST)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
