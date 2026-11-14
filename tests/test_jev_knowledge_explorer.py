# SPDX-License-Identifier: Apache-2.0
"""Knowledge exports preserve routing evidence and contain untrusted text."""

from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
from http.client import HTTPConnection
from html.parser import HTMLParser
from io import StringIO
from ipaddress import IPv4Address
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlencode

import jev_knowledge_explorer as explorer
from tests.test_opscryer_public_smoke import opsec_findings


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = {}
        self.ids = set()
        self.duplicate_ids = set()
        self.tags = []
        self.payload = []
        self.in_data = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append(tag)
        if 'id' in attrs:
            if attrs['id'] in self.ids:
                self.duplicate_ids.add(attrs['id'])
            self.ids.add(attrs['id'])
        if tag == 'a':
            self.links[attrs['href']] = attrs.get('aria-current')
        if tag == 'script' and attrs.get('id') == 'kb-explorer-data':
            self.in_data = True
            assert attrs['type'] == 'application/json'

    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_data = False

    def handle_data(self, data):
        if self.in_data:
            self.payload.append(data)


class TestJevKnowledgeExplorer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads(explorer.DEFAULT_CATALOG_PATH.read_text(encoding='utf-8'))

    def test_catalog_samples_and_explicit_queries_have_complete_routing_evidence(self):
        with patch('jev_client.urlopen', side_effect=AssertionError('Unexpected model call')):
            data = explorer.build_jev_knowledge_catalog(catalog=self.catalog)
        self.assertEqual(data['schema_version'], '1.0')
        self.assertIs(data['read_only'], True)
        self.assertIsNone(data['query_result'])
        self.assertEqual(data['catalog_summary'], {
            'node_count': len(self.catalog['nodes']), 'edge_count': len(self.catalog['edges'])})
        self.assertEqual([row['query'] for row in data['sample_queries']], list(explorer.SAMPLE_QUERIES))
        self.assertEqual(len(data['knowledge_articles']),
                         len(explorer.ticket_chat_portal.KNOWLEDGE_BASE_ARTICLES))
        cases = (
            ('How 2 database?', 'KB-DB-001', 'playbook-golden-path-database-cnpg',
             ['node-check-database'], ['IT-PLAT-GP-01', 'IT-SEC-DB-01']),
            ('How 2 storage?', 'KB-STOR-007', 'playbook-storage-openzfs-csi',
             ['node-check-database', 'node-check-scaffolding', 'node-check-storage'],
             ['IT-STOR-CSI-01']),
            ('How does SSO work?', 'KB-IAM-008', 'playbook-identity-authentik-oidc',
             ['node-check-database', 'node-check-scaffolding', 'node-check-storage',
              'node-check-sso'], ['IT-IAM-OIDC-01']),
        )
        tree = data['decision_tree']['nodes']
        predicates = {node['predicate_id'] for node in tree.values() if node['kind'] == 'decision'}
        for query, article, policy, path, tickets in cases:
            with self.subTest(query=query):
                result = explorer.build_jev_knowledge_catalog(query, self.catalog)['query_result']
                self.assertEqual(result, next(row for row in data['sample_queries'] if row['query'] == query))
                self.assertEqual(result['knowledge_article']['article_id'], article)
                self.assertEqual(result['policy_id'], policy)
                self.assertEqual(result['required_it_tickets'], tickets)
                self.assertIs(result['direct_access_allowed'], True)
                self.assertEqual([crumb['node_id'] for crumb in result['breadcrumbs']], path)
                self.assertEqual(result['resolved_policy'],
                                 next(node for node in tree.values() if node.get('policy_id') == policy))
                scores = result['predicate_probabilities']
                self.assertEqual(len(scores), len(predicates))
                self.assertEqual({score['predicate_id'] for score in scores}, predicates)
                for score in scores:
                    self.assertIsInstance(score['evaluated_value'], bool)
                    self.assertGreaterEqual(score['calibrated_probability'], 0)
                    self.assertLessEqual(score['calibrated_probability'], 1)
                for index, crumb in enumerate(result['breadcrumbs']):
                    branch = 'true_branch' if index == len(path) - 1 else 'false_branch'
                    self.assertEqual(crumb['branch'], branch)
                self.assertTrue(result['plain_english_why'])
        json.dumps(data, allow_nan=False)

    def test_results_are_detached_from_caller_and_shared_constants(self):
        catalog = deepcopy(self.catalog)
        original = deepcopy(catalog)
        articles = deepcopy(explorer.ticket_chat_portal.KNOWLEDGE_BASE_ARTICLES)
        tree = deepcopy(explorer.ticket_chat_portal.CONCIERGE_JEV_TREE)
        data = explorer.build_jev_knowledge_catalog('How 2 database?', catalog)
        expected = deepcopy(data)
        data['knowledge_articles'][0]['steps'].append('changed')
        data['query_result']['knowledge_article']['steps'].clear()
        data['query_result']['resolved_policy']['required_it_tickets'].clear()
        data['decision_tree']['nodes'].clear()
        data['sample_queries'].clear()
        self.assertEqual(catalog, original)
        self.assertEqual(explorer.ticket_chat_portal.KNOWLEDGE_BASE_ARTICLES, articles)
        self.assertEqual(explorer.ticket_chat_portal.CONCIERGE_JEV_TREE, tree)
        self.assertEqual(explorer.build_jev_knowledge_catalog('How 2 database?', catalog), expected)

    def test_malformed_catalogs_fail_closed_before_evaluation(self):
        invalid = [[], True, 42, {}, {'nodes': []}]
        for field, value in (('schema_version', 'unknown'), ('nodes', []),
                             ('edges', {}), ('node_count', -1), ('edge_count', True)):
            invalid.append({**self.catalog, field: value})
        for mutate in (
            lambda c: c['nodes'].append(deepcopy(c['nodes'][0])),
            lambda c: c['nodes'][0].pop('label'),
            lambda c: c['nodes'][0].update(domain='unknown'),
            lambda c: c['nodes'][0].update(drilldown_children=['missing-node']),
            lambda c: c['edges'].append({'source': 'missing', 'target': 'missing', 'relation': 'test'}),
            lambda c: c.update(extra=float('nan')),
            lambda c: c.update(extra=object()),
        ):
            catalog = deepcopy(self.catalog)
            mutate(catalog)
            invalid.append(catalog)
        for index, catalog in enumerate(invalid):
            with self.subTest(case=index), patch.object(explorer, '_evaluate_query') as evaluate:
                with self.assertRaisesRegex(ValueError, '^Invalid knowledge explorer catalog$'):
                    explorer.build_jev_knowledge_catalog(catalog=catalog)
                evaluate.assert_not_called()

    def test_catalog_paths_reject_invalid_json_duplicates_and_nonfinite_values(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'catalog.json'
            path.write_text(json.dumps(self.catalog), encoding='utf-8')
            expected = explorer.build_jev_knowledge_catalog(catalog=self.catalog)
            for source in (path, str(path)):
                self.assertEqual(explorer.build_jev_knowledge_catalog(catalog=source), expected)
            valid = json.dumps(self.catalog)
            invalid = ['{', '[]', valid + '{}',
                       valid[:-1] + ', "nodes": []}',
                       *(valid[:-1] + ', "extra": ' + value + '}'
                         for value in ('NaN', 'Infinity', '-Infinity', '1e999'))]
            for index, content in enumerate(invalid):
                with self.subTest(case=index):
                    path.write_text(content, encoding='utf-8')
                    with self.assertRaisesRegex(ValueError, '^Invalid knowledge explorer catalog$'):
                        explorer.build_jev_knowledge_catalog(catalog=path)
            with self.assertRaisesRegex(ValueError, '^Invalid knowledge explorer catalog$'):
                explorer.build_jev_knowledge_catalog(catalog=Path(directory) / 'missing.json')

    def test_invalid_queries_fail_closed(self):
        for index, query in enumerate(('', '  ', 0, True, [], {}, 'bad\nquery', 'bad\x00query', '\x7f')):
            with self.subTest(case=index), patch.object(explorer, '_evaluate_query') as evaluate:
                with self.assertRaisesRegex(ValueError, '^Invalid knowledge explorer query$'):
                    explorer.build_jev_knowledge_catalog(query, self.catalog)
                evaluate.assert_not_called()

    def test_markdown_contains_complete_routing_evidence_and_runbooks(self):
        report = explorer.render_jev_knowledge_markdown('How 2 storage?')
        data = explorer.build_jev_knowledge_catalog(query='How 2 storage?')
        self.assertTrue(report.startswith('# Jev Knowledge Base & Intent Resolution Explorer\n'))
        for heading in ('Jev Decision Tree Nodes', 'Predicate Probability Matrix',
                        'Shorthand Query Resolutions', 'Runbook Articles'):
            self.assertIn('## ' + heading, report)
        for result in data['sample_queries'] + [data['query_result']]:
            self.assertIn(explorer._markdown_cell(result['query']), report)
            self.assertIn(explorer._markdown_cell(result['policy_id']), report)
        for article in data['knowledge_articles']:
            self.assertIn(article['reference_snippet'], report)
        self.assertIn('```yaml\n', report)
        self.assertIn('```bash\n', report)

    def test_html_navigation_and_embedded_catalog(self):
        page = explorer.render_jev_knowledge_html()
        self.assertTrue(page.startswith('<!DOCTYPE html>'))
        parsed = PageParser()
        parsed.feed(page)
        self.assertEqual(set(parsed.links), {'/', '/chat', '/incidents', '/capacity',
                         '/network', '/gitops', '/executive', '/hub', '/simulator',
                         '/playbooks', '/models', '/games', '/kb'})
        self.assertEqual(parsed.links['/kb'], 'page')
        self.assertTrue({'kb-query-buttons', 'kb-search-input', 'kb-predicate-table',
                         'kb-breadcrumb-trail', 'kb-article-grid'} <= parsed.ids)
        self.assertFalse(parsed.duplicate_ids)
        referenced = set(re.findall(r"(?:byId|document\.getElementById)\('([^']+)'\)", page))
        self.assertTrue(referenced <= parsed.ids)
        self.assertTrue({'kb-explorer-data', 'kb-tree-body', 'kb-predicate-body',
                         'kb-resolution', 'kb-selected-query', 'kb-search-status',
                         'kb-confidence-note'} <= parsed.ids)
        self.assertEqual(json.loads(''.join(parsed.payload)), explorer.build_jev_knowledge_catalog())
        self.assertNotRegex(page, r'innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(')
        self.assertNotRegex(page, r'<script[^>]+src=|<link[^>]+href=|\bfetch\s*\(')
        self.assertNotRegex(page, r'\bFunction\s*\(|(?:setTimeout|setInterval)\s*\(\s*[\'"]')
        self.assertNotRegex(page, r'\bon\w+\s*=|javascript\s*:|\.srcdoc\s*=')

    def test_untrusted_article_stays_text_and_snippet_fences_survive(self):
        articles = deepcopy(explorer.ticket_chat_portal.KNOWLEDGE_BASE_ARTICLES)
        title = 'Injected | cell\n</script><img src=x onerror=alert(1)> & text'
        snippet = 'kubectl get pods\n```\n<script>alert(1)</script>'
        articles[0]['title'] = title
        articles[0]['reference_snippet'] = snippet
        with patch.object(explorer.ticket_chat_portal, 'KNOWLEDGE_BASE_ARTICLES', articles):
            page = explorer.render_jev_knowledge_html()
            report = explorer.render_jev_knowledge_markdown()
        parsed = PageParser()
        parsed.feed(page)
        payload = ''.join(parsed.payload)
        self.assertEqual(parsed.tags.count('script'), 2)
        self.assertNotIn('img', parsed.tags)
        self.assertNotRegex(payload, r'[&<>]')
        for escaped in (r'\u0026', r'\u003c', r'\u003e'):
            self.assertIn(escaped, payload)
        self.assertEqual(json.loads(payload)['knowledge_articles'][0]['title'], title)
        self.assertNotIn('<img', report)
        self.assertIn('Injected \\| cell &lt;/script&gt;', report)
        self.assertIn('````bash\n' + snippet + '\n````', report)

    def test_validation_and_caller_catalog_are_preserved(self):
        catalog = json.loads(explorer.DEFAULT_CATALOG_PATH.read_text(encoding='utf-8'))
        original = deepcopy(catalog)
        explorer.render_jev_knowledge_html(catalog=catalog)
        explorer.render_jev_knowledge_markdown(catalog=catalog)
        self.assertEqual(catalog, original)
        for renderer in (explorer.render_jev_knowledge_html, explorer.render_jev_knowledge_markdown):
            with self.assertRaisesRegex(ValueError, '^Invalid knowledge explorer catalog$'):
                renderer(catalog={})
        with self.assertRaisesRegex(ValueError, '^Invalid knowledge explorer query$'):
            explorer.render_jev_knowledge_markdown(query='bad\nquery')


class TestKnowledgeExplorerCLI(unittest.TestCase):
    def run_cli(self, args):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = explorer.main(args)
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), '')
        return stdout.getvalue()

    def test_default_json_explicit_json_markdown_and_catalog_flags(self):
        self.assertIsNone(json.loads(self.run_cli([]))['query_result'])
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'catalog.json'
            path.write_bytes(explorer.DEFAULT_CATALOG_PATH.read_bytes())
            output = self.run_cli(['--json', '--query', 'How 2 storage?', '--catalog', str(path)])
            self.assertEqual(json.loads(output)['query_result']['knowledge_article']['article_id'], 'KB-STOR-007')
            report = self.run_cli(['--markdown', '--query', 'How does SSO work?', '--catalog', str(path)])
            self.assertEqual(report, explorer.render_jev_knowledge_markdown('How does SSO work?', path))

    def test_help_and_invalid_flags_are_safe(self):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            explorer.main(['--help'])
        self.assertEqual(raised.exception.code, 0)
        for flag in ('--json', '--markdown', '--serve', '--query', '--catalog', '--port'):
            self.assertIn(flag, stdout.getvalue())
        cases = [
            ['--json', '--markdown'], ['--serve', '--json'], ['--serve', '--markdown'],
            ['--unknown'], ['--mar'], ['--query'], ['--query', ''], ['--query', 'bad\nquery'],
            ['--port', '0'], ['--port', '65536'], ['--port', 'invalid'],
            ['--catalog', 'missing-catalog.json'], ['--serve', '--query', ''],
        ]
        for index, args in enumerate(cases):
            with self.subTest(case=index):
                stdout, stderr = StringIO(), StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                    explorer.main(args)
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(stdout.getvalue(), '')
                self.assertTrue(stderr.getvalue().endswith('error: Invalid knowledge explorer request\n'))

    def test_serve_binds_loopback_and_handles_keyboard_interrupt(self):
        server = MagicMock()
        server.__enter__.return_value.serve_forever.side_effect = KeyboardInterrupt
        with patch.object(explorer, 'ThreadingHTTPServer', return_value=server) as constructor:
            output = self.run_cli(['--serve', '--port', '8123'])
        self.assertEqual(constructor.call_args.args[0], ('127.0.0.1', 8123))
        self.assertIn('/kb', output)
        server.__enter__.return_value.serve_forever.assert_called_once_with()
        server.__exit__.assert_called_once()


class TestKnowledgeExplorerHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = explorer.ThreadingHTTPServer(
            ('127.0.0.1', 0), explorer._build_kb_explorer_handler())
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, path, method='GET'):
        connection = HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            connection.request(method, path)
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(int(response.getheader('Content-Length')), len(body))
            self.assertEqual(response.getheader('Cache-Control'), 'no-store')
            self.assertEqual(response.getheader('Referrer-Policy'), 'no-referrer')
            self.assertEqual(response.getheader('X-Content-Type-Options'), 'nosniff')
            self.assertEqual(opsec_findings(body), dict.fromkeys(opsec_findings(body), 0))
            return response.status, response.getheader('Content-Type'), body.decode('utf-8')
        finally:
            connection.close()

    def test_html_and_json_routes(self):
        for path in ('/', '/kb'):
            with self.subTest(path=path):
                status, content_type, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertEqual(content_type, 'text/html; charset=utf-8')
                self.assertEqual(body, explorer.render_jev_knowledge_html())
        status, content_type, body = self.request('/api/v1/kb-explorer')
        self.assertEqual(status, 200)
        self.assertEqual(content_type, 'application/json; charset=utf-8')
        self.assertEqual(json.loads(body), explorer.build_jev_knowledge_catalog())
        for query in ('How 2 database?', 'How 2 storage?', 'How does SSO work?'):
            status, _, body = self.request('/api/v1/kb-explorer?' + urlencode({'q': query}))
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)['query_result'],
                             explorer.build_jev_knowledge_catalog(query)['query_result'])

    def test_invalid_requests_unknown_routes_and_methods(self):
        for query in ('q=', 'q=+', 'q=a&q=b', 'unknown=a', 'q', 'q=%', 'q=%GG',
                      'q=%FF', 'q=%00', 'q=%0A', 'q=a&unknown=b'):
            with self.subTest(query=query):
                status, _, body = self.request('/api/v1/kb-explorer?' + query)
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(body), {'error': 'Invalid knowledge explorer request'})
        for path in ('/?q=hello', '/kb?q=hello'):
            self.assertEqual(self.request(path)[0], 400)
        status, _, body = self.request('/missing')
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {'error': 'Not found'})
        status, _, body = self.request('/api/v1/kb-explorer', method='POST')
        self.assertEqual(status, 501)
        self.assertEqual(json.loads(body), {'error': 'Invalid HTTP request'})

    def test_errors_are_generic_and_request_logging_is_silent(self):
        for error, status, message in (
            (ValueError('private detail'), 400, 'Invalid knowledge explorer request'),
            (RuntimeError('private detail'), 503, 'Knowledge explorer unavailable'),
        ):
            stderr = StringIO()
            with self.subTest(status=status), redirect_stderr(stderr), patch.object(
                    explorer, 'build_jev_knowledge_catalog', side_effect=error):
                actual, _, body = self.request('/api/v1/kb-explorer?q=private-request')
                self.assertEqual(actual, status)
                self.assertEqual(json.loads(body), {'error': message})
            self.assertEqual(stderr.getvalue(), '')


class TestKnowledgeExplorerOPSEC(unittest.TestCase):
    def test_exports_scrub_sensitive_queries_and_articles_without_mutating_sources(self):
        # Assemble synthetic sensitive fixtures at runtime; assertions show only counts.
        address = str(IPv4Address(0x08080808))
        mac = ':'.join(('AA', 'BB', 'CC', 'DD', 'EE', 'FF'))
        tokens = [prefix + 'synthetic_test_value' for prefix in
                  ('gh' + 'o_', 'gh' + 'p_', 'gl' + 'pat-', 's' + 'k-')]
        sensitive = ' '.join([address, mac, *tokens])
        allowed = '10.0.0.1 172.20.1.1 172.16.0.1 host.cluster.example.org'
        articles = deepcopy(explorer.ticket_chat_portal.KNOWLEDGE_BASE_ARTICLES)
        articles[0]['summary'] = sensitive + ' ' + allowed
        original = deepcopy(articles)
        with patch.object(explorer.ticket_chat_portal, 'KNOWLEDGE_BASE_ARTICLES', articles):
            outputs = (
                json.dumps(explorer.build_jev_knowledge_catalog(query=sensitive)),
                explorer.render_jev_knowledge_markdown(query=sensitive),
                explorer.render_jev_knowledge_html(),
            )
        self.assertTrue(articles == original, 'Caller articles changed')
        for index, output in enumerate(outputs):
            with self.subTest(format=index):
                # Scan both source and literal Markdown text so escapes cannot hide leaks.
                findings = opsec_findings(output.encode('utf-8'))
                self.assertEqual(findings, dict.fromkeys(findings, 0))
                if index == 1:
                    output = re.sub(r'\\([\\`*_{}\[\]()#+.!|~\-])', r'\1', output)
                findings = opsec_findings(output.encode('utf-8'))
                self.assertEqual(findings, dict.fromkeys(findings, 0))
                self.assertFalse(any(value in output for value in [address, mac, *tokens]),
                                 'Unsanitized fixture found')
                self.assertTrue('203.0.113.1' in output, 'Missing sanitized address')
                self.assertTrue('AA:BB:CC:XX:XX:XX' in output, 'Missing masked identifier')
                self.assertTrue(allowed in output, 'Allowed LAN references changed')
        source = Path(__file__).read_bytes()
        self.assertTrue(source.startswith(b'# SPDX-License-Identifier: Apache-2.0\n'))
        findings = opsec_findings(source)
        self.assertEqual(findings, dict.fromkeys(findings, 0))


if __name__ == '__main__':
    unittest.main()
