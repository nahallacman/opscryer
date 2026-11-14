# SPDX-License-Identifier: Apache-2.0
"""STAGE-149 game fleet, runbook, presentation and loopback boundary tests."""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from html.parser import HTMLParser
import http.client
import io
import json
from pathlib import Path
import re
import tempfile
import threading
import unittest
from unittest.mock import patch

import game_observability_loop as games
from opscryer_backend import CONTRACT_VERSION, validate_spatial_graph_contract
from tests.test_opscryer_public_smoke import opsec_findings


PROFILES = ('minecraft', 'satisfactory', 'factorio', 'palworld', 'romm')
LINKS = {
    'grafana_dashboard_url': 'https://grafana.cluster.example.org/dashboards',
    'grafana_explore_url': 'https://grafana.cluster.example.org/explore',
    'argocd_app_url': 'https://argocd.cluster.example.org/applications',
    'gitlab_pipelines_url': 'https://gitlab.cluster.example.org/platform/infra-gitops/-/pipelines',
    'runbookgate_actions_url': 'https://runbookgate.cluster.example.org',
}
STEP_IDS = ('symptom_and_triage', 'knowledge_graph_lineage',
            'cross_tool_observability', 'dual_tier_ai_what_to_do',
            'recovery_verification')
TITLE = '# Live Game Server & Cross-Tool Observability Debugging Loop\n'
MARKER = 'UNTRUSTED_GAME_INPUT'


def fixture():
    """Five observed pods, one physical host and an explicit company policy root."""
    def node(identity, label, kind, domain):
        return {'id': identity, 'label': label, 'kind': kind, 'domain': domain,
                'summary': 'Offline game server observation',
                'primary_url': 'https://ops.cluster.example.org', 'drilldown_children': []}

    root = node('root-company', 'Offline company', 'company_root', 'company_org')
    hardware = node('host-mini', 'nodebeta02 hardware', 'server', 'hardware_topology')
    host = node('node-mini', 'nodebeta02', 'kubernetes_node', 'deployments_k8s')
    root['drilldown_children'] = ['host-mini']
    hardware['drilldown_children'] = ['node-mini']
    host.update(resource_kind='Node', metrics={'cpu_percent': 20, 'ram_percent': 30},
                resource={'kind': 'Node', 'metadata': {'name': 'nodebeta02'},
                          'status': {'conditions': [{'type': 'Ready', 'status': 'False'}]}})
    nodes = [root, hardware, host]
    edges = [{'source': 'root-company', 'target': 'host-mini', 'relation': 'contains'},
             {'source': 'node-mini', 'target': 'host-mini', 'relation': 'hosted_on'}]
    for game in PROFILES:
        pod = node('pod-' + game, game + '-server', 'kubernetes_pod', 'deployments_k8s')
        pod.update(resource_kind='Pod', resource={
            'kind': 'Pod', 'metadata': {'namespace': 'game-servers', 'name': game + '-server'},
            'spec': {'nodeName': 'nodebeta02'},
            'status': {'phase': 'Failed', 'conditions': [{'type': 'Ready', 'status': 'False'}]}})
        nodes.append(pod)
        edges.append({'source': pod['id'], 'target': 'node-mini', 'relation': 'hosted_on'})
    return {'schema_version': CONTRACT_VERSION, 'root_id': root['id'],
            'nodes': nodes, 'edges': edges, 'node_count': len(nodes), 'edge_count': len(edges)}


EXPORTS = (
    games.inspect_game_server_fleet,
    *(lambda catalog, game=game: games.trace_game_debugging_loop(game, catalog)
      for game in PROFILES),
    *(lambda catalog, game=game: games.render_game_debug_markdown(game, catalog)
      for game in PROFILES),
    games.render_game_debug_html,
)


class Document(HTMLParser):
    """Parse actual elements and script boundaries without executing evidence."""

    def __init__(self, source):
        super().__init__()
        self.elements, self.scripts = [], []
        self.current_script = None
        self.feed(source)
        self.close()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.elements.append((tag, attrs))
        if tag == 'script':
            self.current_script = {'attrs': attrs, 'text': ''}
            self.scripts.append(self.current_script)

    def handle_endtag(self, tag):
        if tag == 'script':
            self.current_script = None

    def handle_data(self, data):
        if self.current_script is not None:
            self.current_script['text'] += data


@contextmanager
def serving(catalog):
    server = games.ThreadingHTTPServer(('127.0.0.1', 0), games._build_game_debug_handler(catalog))
    worker = threading.Thread(target=server.serve_forever,
                              kwargs={'poll_interval': 0.01}, daemon=True)
    worker.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise AssertionError('Loopback server failed to stop')


class GameObservabilityLoopTests(unittest.TestCase):
    def assert_clean(self, value):
        if not isinstance(value, (str, bytes)):
            value = json.dumps(value, allow_nan=False)
        if isinstance(value, str):
            value = value.encode('utf-8')
        findings = opsec_findings(value)
        self.assertEqual(findings, dict.fromkeys(findings, 0),
                         'Prohibited telemetry detected; values withheld')

    def assert_catalog_rejected(self, catalog):
        for export in EXPORTS:
            with self.subTest(export=EXPORTS.index(export)):
                with self.assertRaises(ValueError) as caught:
                    export(catalog)
                self.assertEqual(str(caught.exception), 'Invalid game observability catalog')
                self.assert_clean(str(caught.exception))

    def cli(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                code = games.main(argv)
            except SystemExit as error:
                code = error.code
        self.assert_clean(stdout.getvalue())
        self.assert_clean(stderr.getvalue())
        return code, stdout.getvalue(), stderr.getvalue()

    def request(self, address, path, method='GET'):
        connection = http.client.HTTPConnection(*address, timeout=10)
        try:
            connection.request(method, path)
            response = connection.getresponse()
            body = response.read().decode('utf-8')
            headers = dict(response.getheaders())
            self.assertEqual(int(headers['Content-Length']), len(body.encode('utf-8')))
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
            self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
            self.assert_clean(body)
            return response.status, headers['Content-Type'], body
        finally:
            connection.close()

    def test_fleet_all_five_games_and_observed_host_evidence(self):
        catalog = fixture()
        self.assertEqual(validate_spatial_graph_contract(catalog), [])
        fleet = games.inspect_game_server_fleet(catalog)
        self.assertTrue(fleet['read_only'])
        self.assertEqual(fleet['observability_links'], LINKS)
        self.assertEqual([entry['game'] for entry in fleet['games']], list(PROFILES))
        self.assertEqual(fleet['nominal_hardware_nodes'],
                         ['nodealpha01', 'nodebeta02', 'nodegamma03'])
        hardware = {entry['name']: entry for entry in fleet['hardware_nodes']}
        self.assertFalse(hardware['nodegamma03']['present_in_snapshot'])
        self.assertIsNone(hardware['nodegamma03']['ready'])
        self.assertIsNone(hardware['nodegamma03']['metrics']['cpu_percent'])
        for entry in fleet['games']:
            with self.subTest(game=entry['game']):
                self.assertTrue(entry['present_in_snapshot'])
                self.assertEqual(entry['snapshot_status'], 'present')
                self.assertEqual(entry['matched_node_ids'], ['pod-' + entry['game']])
                self.assertEqual(entry['observability_links'], LINKS)
                self.assertEqual(len(entry['observed_hosting_nodes']), 1)
                host = entry['observed_hosting_nodes'][0]
                self.assertEqual(host['name'], 'nodebeta02')
                self.assertFalse(host['ready'])
                self.assertEqual(host['metrics']['cpu_percent'], 20)
                self.assertEqual(host['metrics']['ram_percent'], 30)
                self.assertTrue(entry['incidents'])
        for field in ('cluster_capacity', 'active_incidents', 'gpu_workload_plan'):
            self.assertTrue(fleet[field])
        self.assert_clean(fleet)

    def test_all_five_debug_steps_queries_and_dual_tier_guidance(self):
        catalog = fixture()
        graph_ids = {node['id'] for node in catalog['nodes']}
        for game in PROFILES:
            with self.subTest(game=game):
                trace = games.trace_game_debugging_loop(game, catalog)
                self.assertEqual(trace['game'], game)
                self.assertTrue(trace['read_only'])
                self.assertEqual(trace['observability_links'], LINKS)
                steps = trace['debugging_steps']
                self.assertEqual([step['step'] for step in steps], [1, 2, 3, 4, 5])
                self.assertEqual(tuple(step['id'] for step in steps), STEP_IDS)
                self.assertIn(game, steps[0]['player_symptom'])
                self.assertTrue(steps[0]['triage'])
                self.assertTrue(steps[1]['hardware_lineage'])
                self.assertTrue(steps[1]['hosting_node_lineage'])
                self.assertEqual(steps[1]['missing_evidence'], [])
                self.assertLessEqual(set(steps[1]['cited_node_ids']), graph_ids)
                self.assertEqual(steps[2]['observability_links'], LINKS)
                queries = steps[2]['queries']
                self.assertEqual({query['language'] for query in queries}, {'PromQL', 'Loki'})
                expressions = '\n'.join(query['query'] for query in queries)
                for metric in ('kube_pod_container_status_restarts_total',
                               'container_cpu_cfs_throttled_periods_total',
                               'container_cpu_cfs_periods_total',
                               'container_memory_working_set_bytes', 'node_load15'):
                    self.assertIn(metric, expressions)
                self.assertIn('namespace="game-servers",pod="' + game + '-server"', expressions)
                self.assertIn('nodename="nodebeta02"', expressions)
                loki = next(query['query'] for query in queries if query['language'] == 'Loki')
                for text in ('|~', 'tick', 'lag', 'oom'):
                    self.assertIn(text, loki)
                for query in queries:
                    self.assertFalse(query['template'])
                    self.assertEqual(query['url'], LINKS['grafana_explore_url'])
                pivots = ' '.join(steps[2]['operator_pivots'])
                for tool in ('OpsCryer', 'Grafana', 'ArgoCD', 'GitLab', 'RunbookGate'):
                    self.assertIn(tool, pivots)
                comparison = steps[3]['model_comparison']
                self.assertFalse(comparison['airlock_blocked'])
                self.assertEqual(comparison['provider'], 'deterministic')
                for tier in ('low_power', 'high_power'):
                    guidance = comparison['tiers'][tier]
                    self.assertEqual(guidance['status'], 'ok')
                    for field in ('what_to_do', 'diagnostic_commands', 'required_ticket',
                                  'verification_criteria', 'escalation_policy', 'cited_node_ids'):
                        self.assertTrue(guidance[field])
                    self.assertLessEqual(set(guidance['cited_node_ids']), graph_ids)
                    for command in guidance['diagnostic_commands']:
                        self.assertRegex(command, r'^kubectl (get|describe) ')
                low, high = (comparison['tiers'][tier] for tier in ('low_power', 'high_power'))
                self.assertLess(low['context_pack_estimated_tokens'], 400)
                self.assertGreater(low['context_pack_estimated_tokens'], 0)
                self.assertGreater(high['context_pack_estimated_tokens'], low['context_pack_estimated_tokens'])
                checks = ' '.join(steps[4]['checklist'])
                for term in ('Grafana', 'Ready', 'nslookup ' + game + '.cluster.example.org', 'ticket'):
                    self.assertIn(term, checks)
                self.assert_clean(trace)

    def test_missing_workloads_are_explicit_and_queries_remain_templates(self):
        catalog = fixture()
        catalog['nodes'] = catalog['nodes'][:3]
        catalog['edges'] = catalog['edges'][:2]
        catalog.update(node_count=3, edge_count=2)
        fleet = games.inspect_game_server_fleet(catalog)
        for entry in fleet['games']:
            self.assertFalse(entry['present_in_snapshot'])
            self.assertEqual(entry['snapshot_status'], 'not_present_in_snapshot')
            self.assertEqual(entry['observed_hosting_nodes'], [])
            trace = games.trace_game_debugging_loop(entry['game'], catalog)
            self.assertTrue(trace['debugging_steps'][1]['missing_evidence'])
            self.assertTrue(all(query['template'] for query in trace['debugging_steps'][2]['queries']))
            expressions = json.dumps(trace['debugging_steps'][2]['queries'])
            for placeholder in ('NAMESPACE', 'POD', 'NODE'):
                self.assertIn(placeholder, expressions)

    def test_bundled_exports_preserve_airlock_denial(self):
        fleet = games.inspect_game_server_fleet()
        self.assertEqual([entry['game'] for entry in fleet['games']], list(PROFILES))
        self.assert_clean(fleet)
        for game in PROFILES:
            trace = games.trace_game_debugging_loop(game)
            comparison = trace['debugging_steps'][3]['model_comparison']
            self.assertTrue(comparison['airlock_blocked'])
            self.assertEqual(comparison['status'], 'blocked')
            for guidance in comparison['tiers'].values():
                self.assertEqual(guidance['status'], 'blocked')
                for field in ('what_to_do', 'diagnostic_commands', 'cited_node_ids'):
                    self.assertEqual(guidance[field], [])
            self.assert_clean(trace)
            self.assert_clean(games.render_game_debug_markdown(game))
        self.assert_clean(games.render_game_debug_html())

    def test_caller_catalog_and_return_values_are_detached(self):
        catalog = fixture()
        original = deepcopy(catalog)
        for export in EXPORTS:
            result = export(catalog)
            self.assertEqual(catalog, original)
            if isinstance(result, dict):
                result.clear()
                self.assertEqual(catalog, original)
        fleet = games.inspect_game_server_fleet(catalog)
        fleet['games'][0]['matched_nodes'][0]['resource']['metadata']['name'] = 'changed'
        fleet['games'][0]['observability_links'].clear()
        self.assertEqual(catalog, original)
        self.assertEqual(games.inspect_game_server_fleet(catalog)['observability_links'], LINKS)

    def test_unknown_games_fail_closed_without_input_echo(self):
        for game in (MARKER, '', 'Minecraft', None, [], {}, 1):
            for export in (games.trace_game_debugging_loop, games.render_game_debug_markdown):
                with self.subTest(game_type=type(game).__name__, export=export.__name__):
                    with self.assertRaises(ValueError) as caught:
                        export(game, fixture())
                    self.assertEqual(str(caught.exception), 'Unknown game server profile')

    def test_malformed_catalogs_fail_closed_without_input_echo(self):
        for catalog in ([], 7, True, {}, {'nodes': MARKER}):
            self.assert_catalog_rejected(catalog)
        for mutate in (
                lambda c: c.update(schema_version=MARKER),
                lambda c: c['nodes'].append(deepcopy(c['nodes'][0])),
                lambda c: c['nodes'][0].update(id=MARKER),
                lambda c: c['nodes'][3].update(resource=[]),
                lambda c: c['edges'][0].update(target=MARKER)):
            catalog = fixture()
            mutate(catalog)
            self.assert_catalog_rejected(catalog)
        cyclic = fixture()
        cyclic['cycle'] = cyclic
        self.assert_catalog_rejected(cyclic)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / (MARKER + '.json')
            self.assert_catalog_rejected(path)
            for contents in (MARKER, '{', '[]'):
                path.write_text(contents, encoding='utf-8')
                self.assert_catalog_rejected(path)

    def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'catalog.json'
            encoded = json.dumps(fixture())
            for duplicate in ('"source":1,"source":2',
                              '"extra":{"' + MARKER + '":1,"' + MARKER + '":2}'):
                path.write_text(encoded[:-1] + ',' + duplicate + '}', encoding='utf-8')
                self.assert_catalog_rejected(path)
            for constant in ('NaN', 'Infinity', '-Infinity', '1e999'):
                path.write_text(encoded[:-1] + ',"extra":{"' + MARKER + '":' + constant + '}}',
                                encoding='utf-8')
                self.assert_catalog_rejected(path)
        for value in (float('nan'), float('inf'), -float('inf')):
            catalog = fixture()
            catalog['extra'] = {MARKER: value}
            self.assert_catalog_rejected(catalog)

    def test_markdown_sections_clickable_links_and_all_games(self):
        for game in PROFILES:
            markdown = games.render_game_debug_markdown(game, fixture())
            self.assertTrue(markdown.startswith(TITLE))
            self.assertIn('Selected game: ' + game, markdown)
            for section in ('Fleet Status', 'External Observability Deep-Links',
                            'PromQL & Loki Queries', '5-Step Debugging Loop',
                            'Dual-Tier Low-Power vs. High-Power AI "What To Do" Guidance'):
                self.assertIn('## ' + section, markdown)
            self.assertEqual(set(re.findall(r'\[Open tool\]\(([^)]+)\)', markdown)), set(LINKS.values()))
            for name in PROFILES:
                self.assertIn('| ' + name + ' |', markdown)
            for index, identity in enumerate(STEP_IDS, 1):
                self.assertIn(str(index) + r'\. ' + identity.replace('_', r'\_'), markdown)
            self.assertIn('< 400', markdown)
            self.assertIn('kubectl', markdown)
            self.assert_clean(markdown)

    def test_html_structure_unique_ids_navigation_links_and_safe_dom(self):
        html = games.render_game_debug_html(fixture())
        self.assertTrue(html.startswith('<!DOCTYPE html>'))
        document = Document(html)
        ids = [attrs['id'] for _, attrs in document.elements if 'id' in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertLessEqual({'game-observability-links', 'game-selector-buttons', 'game-fleet-grid',
                              'game-debug-steps', 'game-ai-guidance', 'game-promql-panel'}, set(ids))
        anchors = [attrs for tag, attrs in document.elements if tag == 'a']
        hrefs = {attrs['href'] for attrs in anchors}
        self.assertLessEqual(set(LINKS.values()), hrefs)
        self.assertLessEqual({'/', '/chat', '/incidents', '/capacity', '/network', '/gitops',
                              '/executive', '/hub', '/simulator', '/playbooks', '/models', '/games'}, hrefs)
        self.assertEqual([attrs['href'] for attrs in anchors if attrs.get('aria-current') == 'page'],
                         ['/games'])
        self.assertEqual(len(document.scripts), 2)
        evidence, script = document.scripts
        self.assertEqual(evidence['attrs'], {'id': 'game-debug-data', 'type': 'application/json'})
        data = json.loads(evidence['text'])
        self.assertEqual([trace['game'] for trace in data['traces']], list(PROFILES))
        self.assertEqual(len(data['fleet']['games']), 5)
        self.assertEqual(data['fleet'], games.inspect_game_server_fleet(fixture()))
        self.assertEqual(data['traces'], [games.trace_game_debugging_loop(game, fixture())
                                          for game in PROFILES])
        self.assertIn('document.createElement(', script['text'])
        self.assertIn('.textContent', script['text'])
        self.assertIn('addEventListener("click"', script['text'])
        self.assertIn('aria-pressed', script['text'])
        self.assertNotRegex(script['text'], r'(?i)innerHTML|outerHTML|insertAdjacentHTML|document\s*\.\s*write|'
                            r'\beval\s*\(|new\s+Function|createContextualFragment|DOMParser|\bsrcdoc\b|javascript:')
        for _, attrs in document.elements:
            self.assertFalse(any(key.lower().startswith('on') for key in attrs))
            self.assertNotIn('srcdoc', attrs)
        self.assert_clean(html)

    def test_xss_and_markdown_payloads_stay_escaped_data(self):
        payload = '</script><img src=x onerror="alert(1)"> & | [click](javascript:alert(1)) ` *_\n# forged'
        catalog = fixture()
        catalog['nodes'][3]['summary'] = payload
        catalog['nodes'][3]['label'] = 'minecraft ' + payload
        markdown = games.render_game_debug_markdown('minecraft', catalog)
        self.assertNotIn('<img', markdown)
        self.assertNotIn('</script>', markdown)
        self.assertNotIn('\n# forged', markdown)
        self.assertNotIn('[click](javascript:', markdown)
        for escaped in ('&lt;', '&gt;', '&amp;', r'\|', r'\[click\]', r'\`', r'\*', r'\_'):
            self.assertIn(escaped, markdown)
        html = games.render_game_debug_html(catalog)
        document = Document(html)
        self.assertEqual(len(document.scripts), 2)
        self.assertFalse(any(tag == 'img' for tag, _ in document.elements))
        evidence = document.scripts[0]['text']
        self.assertNotIn('<', evidence)
        self.assertNotIn('>', evidence)
        self.assertNotIn('&', evidence)
        data = json.loads(evidence)
        observed = data['fleet']['games'][0]['matched_nodes'][0]
        self.assertEqual(observed['summary'], payload)
        self.assert_clean(markdown)
        self.assert_clean(html)

    def test_query_label_values_are_json_escaped(self):
        catalog = fixture()
        metadata = catalog['nodes'][3]['resource']['metadata']
        metadata.update(name='minecraft-"pod\\name', namespace='games"\\namespace')
        trace = games.trace_game_debugging_loop('minecraft', catalog)
        for query in trace['debugging_steps'][2]['queries']:
            if 'namespace=' in query['query']:
                self.assertIn('namespace=' + json.dumps(metadata['namespace']), query['query'])
                self.assertIn('pod=' + json.dumps(metadata['name']), query['query'])

    def test_cli_default_json_markdown_game_and_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'catalog.json'
            path.write_text(json.dumps(fixture()), encoding='utf-8')
            for game in PROFILES:
                for mode in ('--json', '--markdown'):
                    with self.subTest(game=game, mode=mode):
                        code, output, error = self.cli([mode, '--game', game, '--catalog', str(path)])
                        self.assertEqual(code, 0)
                        self.assertEqual(error, '')
                        if mode == '--json':
                            self.assertEqual(json.loads(output)['game'], game)
                        else:
                            self.assertTrue(output.startswith(TITLE))
                            self.assertIn('Selected game: ' + game, output)
            code, output, error = self.cli(['--catalog', str(path)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)['game'], 'minecraft')
            self.assertEqual(error, '')
        code, output, error = self.cli([])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['game'], 'minecraft')

    def test_cli_invalid_flags_and_catalogs_do_not_echo_input(self):
        cases = (["--" + MARKER], ['--game', MARKER], ['--game'],
                 ['--json', '--markdown'], ['--serve', '--json'], ['--j'],
                 ['--port', MARKER], ['--port', '0'], ['--port', '65536'],
                 ['--port', '-1'], ['--catalog'], ['--catalog', MARKER], [MARKER])
        for argv in cases:
            with self.subTest(argv_index=cases.index(argv)):
                code, output, error = self.cli(argv)
                self.assertEqual(code, 2)
                self.assertEqual(output, '')
                self.assertIn('Invalid game observability request', error)
                self.assertNotIn(MARKER, error)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / (MARKER + '.json')
            path.write_text('{"' + MARKER + '":NaN}', encoding='utf-8')
            code, output, error = self.cli(['--catalog', str(path)])
            self.assertEqual(code, 2)
            self.assertEqual(output, '')
            self.assertNotIn(MARKER, error)

    def test_cli_serve_binds_only_loopback_and_handles_interrupt(self):
        with patch.object(games, 'ThreadingHTTPServer') as server_type:
            server = server_type.return_value.__enter__.return_value
            server.serve_forever.side_effect = KeyboardInterrupt
            code, output, error = self.cli(['--serve'])
            self.assertEqual(code, 0)
            self.assertEqual(server_type.call_args.args[0], ('127.0.0.1', 8099))
            self.assertIn('http://127.0.0.1:8099/games', output)
            self.assertEqual(error, '')
            server.serve_forever.assert_called_once_with()
            server_type.return_value.__exit__.assert_called_once()
        with patch.object(games, 'ThreadingHTTPServer') as server_type:
            server_type.return_value.__enter__.return_value.serve_forever.side_effect = KeyboardInterrupt
            self.assertEqual(self.cli(['--serve', '--port', '8100'])[0], 0)
            self.assertEqual(server_type.call_args.args[0], ('127.0.0.1', 8100))

    def test_loopback_http_routes_and_game_selection(self):
        with serving(fixture()) as address:
            self.assertEqual(address[0], '127.0.0.1')
            for route in ('/', '/games'):
                status, content_type, body = self.request(address, route)
                self.assertEqual(status, 200)
                self.assertEqual(content_type, 'text/html; charset=utf-8')
                self.assertTrue(body.startswith('<!DOCTYPE html>'))
            for game in PROFILES:
                for route in ('/api/v1/game-debug-loop', '/games/debug.md'):
                    status, content_type, body = self.request(address, route + '?game=' + game)
                    self.assertEqual(status, 200)
                    if route.endswith('.md'):
                        self.assertEqual(content_type, 'text/markdown; charset=utf-8')
                        self.assertTrue(body.startswith(TITLE))
                        self.assertIn('Selected game: ' + game, body)
                    else:
                        self.assertEqual(content_type, 'application/json; charset=utf-8')
                        self.assertEqual(json.loads(body)['game'], game)
            for route in ('/api/v1/game-debug-loop', '/games/debug.md'):
                status, _, body = self.request(address, route)
                self.assertEqual(status, 200)
                self.assertIn('minecraft', body)

    def test_loopback_http_rejects_bad_routes_queries_and_methods_without_echo(self):
        with serving(fixture()) as address:
            for route in ('/' + MARKER, '/api/v1/' + MARKER):
                status, _, body = self.request(address, route)
                self.assertEqual(status, 404)
                self.assertEqual(json.loads(body), {'error': 'Not found'})
            bad_queries = ('game=' + MARKER, 'game=', 'game=minecraft&game=romm',
                           MARKER + '=minecraft', 'game=%', 'game=%ZZ', 'game=%FF', 'game')
            for query in bad_queries:
                for route in ('/api/v1/game-debug-loop', '/games/debug.md'):
                    status, _, body = self.request(address, route + '?' + query)
                    self.assertEqual(status, 400)
                    self.assertEqual(json.loads(body), {'error': 'Invalid game observability request'})
            for route in ('/?game=minecraft', '/games?game=minecraft'):
                self.assertEqual(self.request(address, route)[0], 400)
            status, _, body = self.request(address, '/' + MARKER, method='POST')
            self.assertEqual(status, 501)
            self.assertEqual(json.loads(body), {'error': 'Invalid HTTP request'})
        with serving({'nodes': MARKER}) as address:
            for route in ('/', '/games', '/api/v1/game-debug-loop', '/games/debug.md'):
                status, _, body = self.request(address, route)
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(body), {'error': 'Invalid game observability request'})

    def test_opsec_all_exports_and_test_source(self):
        catalog = fixture()
        # Synthetic probes are assembled at runtime and never emitted in failures.
        wan = '.'.join(str(part) for part in (93, 184, 216, 34))
        mac = ':'.join(('AA', 'BB', 'CC', '11', '22', '33'))
        tokens = [prefix + 'syntheticProbe1234567890' for prefix in
                  ('gh' + 'o_', 'gh' + 'p_', 'gl' + 'pat-', 's' + 'k-')]
        catalog['nodes'][3]['summary'] = ' '.join([wan, mac, *tokens,
                                                  '10.0.0.7', '172.20.1.7', '172.16.0.7',
                                                  'minecraft.cluster.example.org'])
        for export in EXPORTS:
            result = export(catalog)
            self.assert_clean(result)
            encoded = result if isinstance(result, str) else json.dumps(result)
            self.assertTrue(wan not in encoded, 'WAN probe was not redacted')
            self.assertTrue(mac not in encoded, 'MAC probe was not masked')
            self.assertTrue(all(token not in encoded for token in tokens), 'Token probe was not redacted')
        fleet = games.inspect_game_server_fleet(catalog)
        summary = fleet['games'][0]['matched_nodes'][0]['summary']
        self.assertIn('203.0.113.1', summary)
        self.assertIn('AA:BB:CC:XX:XX:XX', summary)
        for allowed in ('10.0.0.7', '172.20.1.7', '172.16.0.7', 'minecraft.cluster.example.org'):
            self.assertIn(allowed, summary)
        source = Path(__file__).read_bytes()
        self.assertTrue(source.startswith(b'# SPDX-License-Identifier: Apache-2.0\n'))
        self.assertNotIn(b'\r', source)
        self.assert_clean(source)


if __name__ == '__main__':
    unittest.main()
