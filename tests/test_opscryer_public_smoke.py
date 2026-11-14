# SPDX-License-Identifier: Apache-2.0
"""Standalone smoke tests for the OpsCryer public repository."""

import json
from ipaddress import IPv4Address
from html.parser import HTMLParser
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import opscryer_browser as browser

ROOT = Path(__file__).resolve().parents[1]


def opsec_findings(content: bytes) -> dict[str, int]:
    """Count forbidden values without retaining or displaying sensitive matches."""
    findings = {'external WAN IPv4': 0, 'unmasked MAC': 0, 'secret token': 0}
    for match in re.finditer(rb'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)', content):
        try:
            address = IPv4Address(match.group().decode('ascii'))
        except ValueError:
            continue
        if address.is_global and not address.is_multicast and str(address) != '203.0.113.1':
            findings['external WAN IPv4'] += 1
    mac = rb'(?<![\w:-])(?:[0-9a-f]{2}([:-]))(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}(?![\w:-])'
    cisco_mac = rb'(?<![\w.])(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}(?!\w|\.[0-9a-f])'
    findings['unmasked MAC'] = sum(1 for _ in re.finditer(mac, content, re.IGNORECASE))
    findings['unmasked MAC'] += sum(1 for _ in re.finditer(cisco_mac, content, re.IGNORECASE))
    # Split prefixes so the scanner does not mistake its own patterns for tokens.
    prefixes = [b'gh' + b'o_', b'gh' + b'p_', b'gl' + b'pat-', b's' + b'k-']
    token = rb'(?<![A-Za-z0-9_])(?:' + b'|'.join(prefixes) + rb')[A-Za-z0-9_-]+'
    findings['secret token'] = sum(1 for _ in re.finditer(token, content))
    return findings


def scan_public_files(root: Path) -> dict[str, int]:
    """Scan all working-tree files, including hidden, untracked and binary files.

    Git metadata and Python bytecode caches are local tooling, not release files.
    The checked-in environment template is allowed; actual environment files fail.
    """
    totals = {'external WAN IPv4': 0, 'unmasked MAC': 0, 'secret token': 0,
              'environment file': 0}
    def fail_on_walk_error(error: OSError) -> None:
        raise OSError('OPSEC scan could not read a directory; details redacted') from None

    for directory, directories, filenames in os.walk(root, onerror=fail_on_walk_error):
        directories[:] = sorted(name for name in directories if name not in {'.git', '__pycache__'})
        for filename in sorted(filenames):
            path = Path(directory) / filename
            if path == root / '.git':  # Linked worktrees use a metadata file.
                continue
            if filename == '.env' or (filename.startswith('.env.') and filename != '.env.example'):
                totals['environment file'] += 1
            content = path.relative_to(root).as_posix().encode('utf-8') + b'\n' + path.read_bytes()
            for category, count in opsec_findings(content).items():
                totals[category] += count
    return totals


class TestOpsCryerPublicSmoke(unittest.TestCase):
    def test_all_public_files_are_opsec_clean(self) -> None:
        findings = scan_public_files(ROOT)
        self.assertEqual(findings, dict.fromkeys(findings, 0),
                         'OPSEC violations found; counts only, sensitive values redacted')

    def test_opsec_scanner_detects_forbidden_values_without_disclosing_them(self) -> None:
        public_address = str(IPv4Address(0x08080808)).encode('ascii')
        mac_octets = [b'AA', b'BB', b'CC', b'DD', b'EE', b'FF']
        prefixes = [b'gh' + b'o_', b'gh' + b'p_', b'gl' + b'pat-', b's' + b'k-']
        for payload, category in (
            (public_address, 'external WAN IPv4'),
            (b'https://' + public_address + b'/ and ' + public_address + b'.', 'external WAN IPv4'),
            (b':'.join(mac_octets), 'unmasked MAC'),
            (b'-'.join(mac_octets).lower(), 'unmasked MAC'),
            (b'.'.join([b'AABB', b'CCDD', b'EEFF']), 'unmasked MAC'),
            *((prefix + b'synthetic_test_value', 'secret token') for prefix in prefixes),
        ):
            expected_count = 2 if payload.startswith(b'https://') else 1
            self.assertEqual(opsec_findings(payload)[category], expected_count, category)
            self.assertEqual(opsec_findings(payload + b'.')[category], expected_count, category)
        safe = (b'10.0.0.1 172.20.1.1 172.16.0.1 172.31.255.254 '
                b'127.0.0.1 203.0.113.1 host.cluster.example.org AA:BB:CC:XX:XX:XX')
        self.assertEqual(opsec_findings(safe), dict.fromkeys(opsec_findings(safe), 0))

    def test_opsec_scan_includes_hidden_untracked_and_binary_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.hidden').mkdir()
            (root / '.hidden' / 'payload.bin').write_bytes(
                b'\x00\xff' + b'gh' + b'p_' + b'synthetic_test_value')
            (root / '.env').write_bytes(b'')
            (root / '.env.local').write_bytes(b'')
            (root / '.env.example').write_bytes(b'')
            findings = scan_public_files(root)
        self.assertEqual(findings, {'external WAN IPv4': 0, 'unmasked MAC': 0,
                                    'secret token': 1, 'environment file': 2})

    def test_sample_graph_data_schema_contract(self) -> None:
        data = json.loads((ROOT / 'sample-graph-data.json').read_text(encoding='utf-8'))
        self.assertEqual(data['schema_version'], '1.0-separable-spatial-graph-contract')
        self.assertEqual(data['schema_version'], browser.CONTRACT_VERSION)
        self.assertEqual(data['piece_role'], 'PIECE_A_FRONTEND_SPATIAL_BROWSER_DEMO_DATASET')
        self.assertIs(data['backend_coupled'], False)
        for collection, count in (('nodes', 'node_count'), ('edges', 'edge_count')):
            self.assertIsInstance(data[collection], list)
            self.assertTrue(data[collection])
            self.assertIs(type(data[count]), int)
            self.assertEqual(data[count], len(data[collection]))
        node_ids = set()
        for node in data['nodes']:
            with self.subTest(node=node.get('id')):
                for field in ('id', 'label', 'kind', 'domain', 'section', 'summary', 'primary_url'):
                    self.assertIsInstance(node[field], str)
                    self.assertTrue(node[field])
                self.assertNotIn(node['id'], node_ids)
                node_ids.add(node['id'])
                self.assertIs(type(node['level_index']), int)
                self.assertGreaterEqual(node['level_index'], 0)
                self.assertIsInstance(node['drilldown_children'], list)
                self.assertEqual(len(node['drilldown_children']), len(set(node['drilldown_children'])))
                self.assertIn(node['kind'], data['object_archetypes'])
        self.assertIn('root-company', node_ids)
        for node in data['nodes']:
            for child in node['drilldown_children']:
                with self.subTest(parent=node['id'], child=child):
                    self.assertIsInstance(child, str)
                    self.assertIn(child, node_ids)
                    self.assertNotEqual(child, node['id'])
        for edge in data['edges']:
            with self.subTest(edge=edge):
                self.assertIn(edge['source'], node_ids)
                self.assertIn(edge['target'], node_ids)
                self.assertIsInstance(edge['relation'], str)
                self.assertTrue(edge['relation'])
        self.assertEqual(data, browser.build_standalone_demo_dataset())

    def test_seven_rts_currencies_schema_contract(self) -> None:
        data = json.loads((ROOT / 'sample-graph-data.json').read_text(encoding='utf-8'))
        expected = {
            'nodes': 'supply_cap', 'cpu_load': 'currency_rate',
            'ram_load': 'currency_rate', 'network_load': 'currency_rate',
            'build_supply': 'food_supply', 'renovate_failures': 'upkeep_alert',
            'open_mrs': 'production_queue',
        }
        currencies = data['rts_currencies']
        self.assertIsInstance(currencies, list)
        self.assertEqual(len(currencies), 7)
        self.assertEqual({currency['currency_id'] for currency in currencies}, set(expected))
        node_ids = {node['id'] for node in data['nodes']}
        for currency in currencies:
            with self.subTest(currency=currency['currency_id']):
                for field in ('currency_id', 'icon', 'label', 'display_value', 'supply_kind', 'hex_color'):
                    self.assertIsInstance(currency[field], str)
                    self.assertTrue(currency[field])
                self.assertEqual(currency['supply_kind'], expected[currency['currency_id']])
                self.assertRegex(currency['hex_color'], r'^#[0-9A-Fa-f]{6}$')
                self.assertIsInstance(currency['dropdown_items'], list)
                self.assertTrue(currency['dropdown_items'])
                for item in currency['dropdown_items']:
                    for field in ('label', 'value', 'target_id'):
                        self.assertIsInstance(item[field], str)
                        self.assertTrue(item[field])
                    self.assertIn(item['target_id'], node_ids)
        self.assertEqual(currencies, browser.build_standalone_rts_currencies())

    def test_standalone_index_html_export_contract(self) -> None:
        class PageTags(HTMLParser):
            def __init__(self):
                super().__init__()
                self.tags = []

            def handle_starttag(self, tag, attrs):
                self.tags.append((tag, dict(attrs)))

        sample = json.loads((ROOT / 'sample-graph-data.json').read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            result = browser.export_standalone_browser_bundle(output)
            self.assertEqual({path.name for path in output.iterdir()},
                             {'index.html', 'sample-graph-data.json', 'README.md'})
            self.assertEqual({Path(path) for path in result['files_written']},
                             {output / name for name in ('index.html', 'sample-graph-data.json', 'README.md')})
            self.assertEqual(result['contract_version'], browser.CONTRACT_VERSION)
            self.assertEqual(result['demo_node_count'], sample['node_count'])
            self.assertEqual(result['backend_imports_used'], 0)
            exported = json.loads((output / 'sample-graph-data.json').read_text(encoding='utf-8'))
            self.assertEqual(exported, sample)
            html = (output / 'index.html').read_text(encoding='utf-8')
        self.assertEqual(html, (ROOT / 'index.html').read_text(encoding='utf-8'))
        self.assertEqual(html, browser.render_standalone_browser_html())
        self.assertTrue(html.lower().startswith('<!doctype html>'))
        page = PageTags()
        page.feed(html)
        for tag, attrs in page.tags:
            with self.subTest(tag=tag, attrs=attrs):
                if tag == 'script':
                    self.assertNotIn('src', attrs, 'Standalone scripts must be embedded')
                if tag == 'link':
                    self.assertNotIn('stylesheet', attrs.get('rel', '').split(),
                                     'Standalone styles must be embedded')
        ids = [attrs['id'] for _, attrs in page.tags if 'id' in attrs]
        self.assertEqual(len(ids), len(set(ids)), 'HTML IDs must be unique')
        self.assertTrue({'rts-currencies-strip', 'browser-children-list', 'rts-minimap-blips',
                         'adapter-select', 'backend-api-input'}.issubset(ids))
        dataset_start = re.search(r'\bconst\s+STANDALONE_DEMO_DATASET\s*=\s*', html)
        self.assertIsNotNone(dataset_start, 'Standalone HTML must embed its demo catalog')
        embedded, _ = json.JSONDecoder().raw_decode(html[dataset_start.end():])
        self.assertEqual(embedded['schema_version'], sample['schema_version'])
        for field in ('edges', 'rts_currencies', 'object_archetypes'):
            self.assertEqual(embedded[field], sample[field])
        # The HTML embeds the fields consumed by the UI, not every sample metadata field.
        self.assertEqual(embedded['nodes'], [
            {key: node[key] for key in (
                'id', 'label', 'kind', 'domain', 'summary', 'primary_url', 'drilldown_children',
                'rts_ai_unit_telemetry') if key in node}
            for node in sample['nodes']
        ])
        self.assertRegex(html, r'\bconst\s+DEFAULT_API_BASE\s*=\s*""\s*;')
        self.assertIn("mode: 'STANDALONE_MOCK'", html)

    @staticmethod
    def readme_blocks(language: str) -> list[str]:
        text = (ROOT / 'README.md').read_text(encoding='utf-8')
        return re.findall(r'^```' + re.escape(language) + r'\n(.*?)^```',
                          text, flags=re.MULTILINE | re.DOTALL)

    def documented_predicate_route(self):
        blocks = self.readme_blocks('python')
        self.assertEqual(len(blocks), 1, 'Expected one standalone response gate example')
        namespace = {}
        exec(compile(blocks[0], 'README.md response gate', 'exec'), namespace)
        return namespace['predicate_route']

    def test_public_config_loads_offline_defaults_and_client_examples(self) -> None:
        settings = browser.load_browser_runtime_settings(ROOT / 'config.public.example.yaml')
        self.assertEqual(settings['default_mode'], 'STANDALONE_MOCK')
        self.assertIs(settings['read_only_public_mode'], True)
        self.assertEqual(settings['api_base_url'], '')
        self.assertEqual(settings['port'], 8088)
        self.assertEqual(settings['ollama_url'], 'http://localhost:11434')
        self.assertEqual(settings['jev_provider'], 'ollama')
        self.assertEqual(settings['jev_model'], 'qwen2.5-coder:7b')
        self.assertEqual(settings['codex_command'], 'codex')
        self.assertEqual(settings['openai_base_url'], '')
        # Document the flat parser's actual decimal behavior for future clients.
        self.assertEqual(settings['jev_min_confidence'], '0.80')
        self.assertEqual(float(settings['jev_min_confidence']),
                         browser.build_standalone_demo_jev_tree()['default_min_confidence'])

    def test_readme_predicate_schema_and_examples_match_demo_contract(self) -> None:
        blocks = self.readme_blocks('json')
        self.assertEqual(len(blocks), 2)
        schema, examples = map(json.loads, blocks)
        self.assertEqual(schema['type'], 'object')
        self.assertIs(schema['additionalProperties'], False)
        fields = {'predicate_id', 'evaluated_value', 'calibrated_probability'}
        self.assertEqual(set(schema['required']), fields)
        self.assertEqual(set(schema['properties']), fields)
        self.assertEqual(schema['properties']['evaluated_value'], {'type': 'boolean'})
        self.assertEqual(schema['properties']['calibrated_probability'],
                         {'type': 'number', 'minimum': 0, 'maximum': 1})
        tree = browser.build_standalone_demo_jev_tree()
        root = tree['nodes'][tree['root_node_id']]
        self.assertEqual(schema['properties']['predicate_id'],
                         {'type': 'string', 'enum': [root['predicate_id']]})
        demo = browser.evaluate_demo_jev_ticket(
            'Scaffold a new project with a deployment pipeline.')
        step = demo['traversal_steps'][0]
        self.assertEqual(examples[0], {key: step[key] for key in fields})
        self.assertEqual(step['anchor_node_id'], root['anchor_node_id'])
        route = self.documented_predicate_route()
        self.assertEqual([route(json.dumps(item)) for item in examples],
                         ['true_branch', 'false_branch', 'human_escalation'])

    def test_readme_response_gate_confidence_boundary_and_boolean_branches(self) -> None:
        route = self.documented_predicate_route()
        for probability, eligible in ((0, False), (0.79, False), (0.799999, False),
                                      (0.80, True), (0.96, True), (1, True)):
            for value in (True, False):
                with self.subTest(probability=probability, value=value):
                    response = json.dumps({
                        'predicate_id': 'is_project_scaffolding',
                        'evaluated_value': value,
                        'calibrated_probability': probability,
                    })
                    expected = ('true_branch' if value else 'false_branch')
                    self.assertEqual(route(response),
                                     expected if eligible else 'human_escalation')

    def test_readme_response_gate_rejects_invalid_provider_results(self) -> None:
        route = self.documented_predicate_route()
        valid = {'predicate_id': 'is_project_scaffolding', 'evaluated_value': True,
                 'calibrated_probability': 0.96}
        invalid = ['', 'not JSON', '```json\n{}\n```', None, '{}', '[]', 'null',
                   'true', '0.96', json.dumps({**valid, 'extra': 'unexpected'})]
        for field in valid:
            invalid.append(json.dumps({key: value for key, value in valid.items() if key != field}))
        for field, values in (
            ('predicate_id', ['is_credential_access', None, 1]),
            ('evaluated_value', ['true', 'false', 0, 1, None]),
            ('calibrated_probability', ['0.96', None, True, False, -0.01, 1.01, 10**400,
                                        float('nan'), float('inf'), -float('inf')]),
        ):
            invalid.extend(json.dumps({**valid, field: value}) for value in values)
        for response in invalid:
            with self.subTest(response=response):
                self.assertEqual(route(response), 'human_escalation')

    def test_required_public_release_files_exist(self) -> None:
        for name in ("AGENTS.md", "CODEX_OVERNIGHT_SWARM_TASKS.md", "LICENSE", "NOTICE.md"):
            self.assertTrue((ROOT / name).exists(), msg=f'Missing {name}')

    def test_presentation_runbook_documents_suite_portals(self) -> None:
        runbook = ROOT / 'PRESENTATION_RUNBOOK.md'
        self.assertTrue(runbook.is_file(), 'Missing PRESENTATION_RUNBOOK.md')
        text = runbook.read_text(encoding='utf-8')
        self.assertTrue(text.startswith('<!-- SPDX-License-Identifier: Apache-2.0 -->'))
        for route in ('/', '/chat', '/incidents', '/capacity', '/network',
                      '/gitops', '/executive', '/simulator', '/playbooks',
                      '/models', '/games', '/kb', '/storage', '/secops', '/hub'):
            with self.subTest(route=route):
                self.assertIn(f'`{route}`', text)
        for api, module in (('/api/v1/gameday-simulator', 'gameday_simulator'),
                            ('/api/v1/playbook-studio', 'playbook_studio'),
                            ('/api/v1/model-copilot', 'model_tier_copilot'),
                            ('/api/v1/game-debug-loop', 'game_observability_loop'),
                            ('/api/v1/kb-explorer', 'jev_knowledge_explorer'),
                            ('/api/v1/storage-cockpit', 'storage_zfs_cockpit'),
                            ('/api/v1/secops-cockpit', 'secops_vulnerability_cockpit')):
            with self.subTest(api=api):
                self.assertIn(f'`{api}`', text)
                self.assertIn(f'python {module}.py --json', text)

    def test_apache_license_warranty_liability_and_notice(self) -> None:
        license_text = ' '.join((ROOT / 'LICENSE').read_text(encoding='utf-8').split())
        self.assertIn('Apache License Version 2.0, January 2004', license_text)
        warranty = license_text.split('7. Disclaimer of Warranty.', 1)[1].split(
            '8. Limitation of Liability.', 1)[0]
        liability = license_text.split('8. Limitation of Liability.', 1)[1].split(
            '9. Accepting Warranty or Additional Liability.', 1)[0]
        for clause in ('Unless required by applicable law or agreed to in writing',
                       'on an "AS IS" BASIS',
                       'WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND',
                       'TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE',
                       'assume any risks associated with Your exercise of permissions under this License.'):
            self.assertIn(clause, warranty)
        for clause in ('In no event and under no legal theory',
                       'unless required by applicable law', 'or agreed to in writing',
                       'direct, indirect, special, incidental, or consequential damages',
                       'even if such Contributor has been advised of the possibility of such damages.'):
            self.assertIn(clause, liability)
        # Guard the previously truncated terms elsewhere in the license as well.
        for clause in ('as of the date such litigation is filed.',
                       'The contents of the NOTICE file are for informational purposes only',
                       'nothing herein shall supersede or modify the terms of any separate license agreement',
                       'defend, and hold each Contributor harmless',
                       'APPENDIX: How to apply the Apache License to your work.'):
            self.assertIn(clause, license_text)
        notice = (ROOT / 'NOTICE.md').read_text(encoding='utf-8')
        for clause in ('Copyright 2026 OpsCryer Authors and Contributors.',
                       'Apache License, Version 2.0', '[LICENSE](LICENSE)',
                       '"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND',
                       'Section 7', 'Limitation of Liability (Section 8)',
                       'does not modify the License'):
            self.assertIn(clause, notice)

    def test_opscryer_browser_imports_cleanly_when_present(self) -> None:
        browser_py = ROOT / 'opscryer_browser.py'
        if browser_py.exists():
            src = browser_py.read_text(encoding='utf-8', errors='replace')
            self.assertIn('SPDX-License-Identifier: Apache-2.0', src)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required to execute browser JavaScript')
    def test_progressive_zoom_l0_through_l4_and_back(self) -> None:
        html = browser.render_standalone_browser_html()
        script = html.split('<script>', 1)[1].split('</script>', 1)[0]
        # Minimal DOM: run the shipped navigation and rendering code without a browser.
        harness = r'''
const assert = require('node:assert/strict');
class Element {
  constructor() {
    this.children = [];
    this.style = {};
    this.textContent = '';
    this.listeners = {};
  }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  addEventListener(type, callback) { this.listeners[type] = callback; }
}
const elements = new Map();
global.document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  },
  createElement() { return new Element(); }
};
global.window = {location: {search: ''}};
'''
        assertions = r'''
(async () => {
  // Let the page's asynchronous initialization finish before interacting.
  await new Promise(resolve => setImmediate(resolve));
  const route = ['root-company', 'team-demo-platform', 'proj-demo-spatial-ui',
                 'deploy-demo-k8s', 'hw-demo-gpu-node'];
  const adapter = window.SpatialGraphAdapter;
  function checkLayer(level) {
    assert.equal(adapter.currentId, route[level]);
    assert.equal(adapter.selectedBoxId, route[level]);
    assert.deepEqual(adapter.historyStack, route.slice(0, level));
    assert.equal($('browser-focal-level').textContent, 'L' + level);
    assert.equal($('rts-current-layer-banner').textContent,
                 'LAYER L' + level + ': ' + adapter.getNode(route[level]).label);
    const children = adapter.getNode(route[level]).drilldown_children;
    const visible = children.length ? children : [route[level]];
    assert.deepEqual($('browser-children-list').children.map(box =>
      box.children[0].children[0].textContent),
      visible.map(id => adapter.getNode(id).label));
    assert.equal($('rts-minimap-blips').children.length, children.length);
  }
  checkLayer(0);
  for (let level = 1; level <= 4; level++) {
    const parent = adapter.getNode(route[level - 1]);
    const box = $('browser-children-list').children[
      parent.drilldown_children.indexOf(route[level])];
    // Exercise both supported box navigation gestures.
    if (level === 1) box.listeners.wheel({deltaY: 20});
    else box.listeners.click();
    checkLayer(level);
  }
  // Clicking the displayed leaf must not add a spurious L5 history entry.
  $('browser-children-list').children[0].listeners.click();
  checkLayer(4);
  await adapter.selectNode('missing-node', false);
  checkLayer(4);
  ascendBoxLayer();
  checkLayer(3);
  $('browser-ancestor-list').children[1].listeners.click();
  checkLayer(1);
  resetToRootLayer();
  checkLayer(0);
  ascendBoxLayer();
  checkLayer(0);
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
        result = subprocess.run(
            [shutil.which('node'), '-'], input=harness + script + assertions,
            text=True, encoding='utf-8', capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_demo_shortest_path_cross_domain_and_reverse(self) -> None:
        route = ['proj-demo-spatial-ui', 'deploy-demo-k8s', 'proc-demo-secret-policy']
        for ids in (route, route[::-1]):
            with self.subTest(source=ids[0], target=ids[-1]):
                result = browser.compute_demo_shortest_path(ids[0], ids[-1])
                self.assertTrue(result['path_found'])
                self.assertEqual(result['schema_version'], browser.CONTRACT_VERSION)
                self.assertEqual(result['source_id'], ids[0])
                self.assertEqual(result['target_id'], ids[-1])
                self.assertEqual(result['path_ids'], ids)
                self.assertEqual(result['hop_count'], 2)
                self.assertEqual([n['id'] for n in result['path_nodes']], ids)
                self.assertEqual(len({n['domain'] for n in result['path_nodes']}), 3)
                self.assertEqual(result['ascii_lineage'], ' -> '.join(
                    f"{n['label']} ({n['id']})" for n in result['path_nodes']))

    def test_shortest_path_prefers_fewer_hops_with_cycles_and_mixed_links(self) -> None:
        dataset = {
            'nodes': [
                {'id': 'a', 'drilldown_children': ['b', 'c', 'missing']},
                {'id': 'b', 'drilldown_children': ['d', 'a']},
                {'id': 'd', 'drilldown_children': ['e']},
                {'id': 'c', 'drilldown_children': []},
                {'id': 'e', 'drilldown_children': []},
                {'id': 'isolated', 'drilldown_children': []},
            ],
            'edges': [{'source': 'c', 'target': 'e'},
                      {'source': 'c', 'target': 'e'},
                      {'source': 'missing', 'target': 'e'}],
        }
        before = json.dumps(dataset, sort_keys=True)
        for source, target, expected in (
            ('a', 'e', ['a', 'c', 'e']),
            ('e', 'a', ['e', 'c', 'a']),
        ):
            with self.subTest(source=source, target=target):
                result = browser.compute_demo_shortest_path(source, target, dataset)
                self.assertTrue(result['path_found'])
                self.assertEqual(result['path_ids'], expected)
                self.assertEqual(result['hop_count'], 2)
        self.assertEqual(json.dumps(dataset, sort_keys=True), before)
        result = browser.compute_demo_shortest_path('a', 'isolated', dataset)
        self.assertFalse(result['path_found'])
        self.assertEqual(result['hop_count'], 0)
        self.assertEqual(result['path_ids'], [])
        self.assertEqual(result['path_nodes'], [])
        self.assertEqual(result['ascii_lineage'], '')

    def test_demo_shortest_path_same_node_and_unknown_endpoints(self) -> None:
        result = browser.compute_demo_shortest_path('root-company', 'root-company')
        self.assertTrue(result['path_found'])
        self.assertEqual(result['hop_count'], 0)
        self.assertEqual(result['path_ids'], ['root-company'])
        self.assertEqual(len(result['path_nodes']), 1)
        for source, target, dataset in (
            ('missing', 'root-company', None),
            ('root-company', 'missing', None),
            ('missing', 'missing', None),
            ('root-company', 'root-company', {}),
        ):
            with self.subTest(source=source, target=target, dataset=dataset):
                result = browser.compute_demo_shortest_path(source, target, dataset)
                self.assertEqual(result, {
                    'schema_version': browser.CONTRACT_VERSION,
                    'path_found': False, 'source_id': source, 'target_id': target,
                    'hop_count': 0, 'path_ids': [], 'path_nodes': [], 'ascii_lineage': '',
                })

    def test_demo_jev_ticket_policy_branches_and_precedence(self) -> None:
        cases = (
            ('  SCAFFOLD a new project  ', 'playbook-demo-golden-path-3tier', True,
             'IT-DEMO-GP-01', 'proc-demo-cicd', 'leaf-demo-golden-path', [True]),
            ('new project with database credentials', 'playbook-demo-golden-path-3tier', True,
             'IT-DEMO-GP-01', 'proc-demo-cicd', 'leaf-demo-golden-path', [True]),
            ('  DATABASE ACCESS please  ', 'policy-demo-zero-trust-secrets', False,
             'IT-DEMO-DB-01', 'proc-demo-secret-policy', 'leaf-demo-zero-trust-secret', [False, True]),
            ('Where are the runbooks?', 'policy-demo-standard-guidance', True,
             'IT-DEMO-OPS-01', 'deploy-demo-k8s', 'leaf-demo-standard-guidance', [False, False]),
            ('', 'policy-demo-standard-guidance', True,
             'IT-DEMO-OPS-01', 'deploy-demo-k8s', 'leaf-demo-standard-guidance', [False, False]),
            ('   ', 'policy-demo-standard-guidance', True,
             'IT-DEMO-OPS-01', 'deploy-demo-k8s', 'leaf-demo-standard-guidance', [False, False]),
        )
        tree = browser.build_standalone_demo_jev_tree()
        for title, policy, access, ticket, anchor, leaf, decisions in cases:
            with self.subTest(title=title):
                result = browser.evaluate_demo_jev_ticket(title)
                self.assertEqual(result['schema_version'], browser.CONTRACT_VERSION)
                self.assertEqual(result['policy_id'], policy)
                self.assertIs(result['direct_access_allowed'], access)
                self.assertEqual(result['required_it_tickets'], [ticket])
                self.assertEqual(result['anchor_node_id'], anchor)
                steps = result['traversal_steps']
                self.assertEqual([s['evaluated_value'] for s in steps[:-1]], decisions)
                current = tree['root_node_id']
                for step in steps[:-1]:
                    self.assertEqual(step['node_id'], current)
                    node = tree['nodes'][current]
                    self.assertEqual(step['predicate_id'], node['predicate_id'])
                    self.assertEqual(step['anchor_node_id'], node['anchor_node_id'])
                    self.assertGreaterEqual(step['calibrated_probability'], tree['default_min_confidence'])
                    self.assertLessEqual(step['calibrated_probability'], 1.0)
                    current = node['true_branch' if step['evaluated_value'] else 'false_branch']
                self.assertEqual(current, leaf)
                self.assertEqual(steps[-1], {
                    'node_id': leaf, 'kind': 'leaf', 'policy_id': policy, 'anchor_node_id': anchor,
                })


if __name__ == "__main__":
    unittest.main()
