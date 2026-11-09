# SPDX-License-Identifier: Apache-2.0
"""Verify subsystem imports, repository metadata, and public re-exports."""

from pathlib import Path
import subprocess
import sys
import textwrap
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TestPackageOrganization(unittest.TestCase):
    def test_architecture_documentation_covers_subsystems_and_cli(self):
        path = ROOT / 'ARCHITECTURE.md'
        self.assertTrue(path.is_file(), 'Missing architecture documentation')
        documentation = path.read_text(encoding='utf-8')
        self.assertEqual(documentation.splitlines()[0],
                         '<!-- SPDX-License-Identifier: Apache-2.0 -->')
        for subsystem in ('core', 'live', 'security', 'portals'):
            with self.subTest(subsystem=subsystem):
                self.assertIn(f'`opscryer.{subsystem}`', documentation)
        for command in ('doctor', 'metrics', 'routes', 'adapters', 'ask'):
            with self.subTest(command=command):
                self.assertIn(f'python opscryer_cli.py {command} ', documentation)
        for section in (
            '## 1. Package & Subsystem Organization',
            '## 2. Single-Token System-1 Jev Decision Tree & Knowledge Graph Lookup Architecture',
            '## 3. Live Telemetry & Metrics Poller vs. Sanitized Snapshot Airlock',
            '## 4. Multi-Environment Compatibility Adapters & OpenAPI 3.1 Contract',
        ):
            with self.subTest(section=section):
                self.assertIn(section, documentation)

    def test_pyproject_metadata_and_console_scripts(self):
        path = ROOT / 'pyproject.toml'
        self.assertEqual(path.read_text(encoding='utf-8').splitlines()[0],
                         '# SPDX-License-Identifier: Apache-2.0')
        with path.open('rb') as stream:
            metadata = tomllib.load(stream)
        project = metadata['project']
        self.assertEqual(project['name'], 'opscryer')
        self.assertEqual(project['version'], '1.2.0')
        self.assertEqual(project['requires-python'], '>=3.11')
        self.assertEqual(project['license'], {'text': 'Apache-2.0'})
        self.assertEqual(project['dependencies'], [])
        self.assertEqual(project['scripts'], {
            'opscryer': 'opscryer_cli:main',
            'opscryer-browser': 'opscryer_browser:main',
            'opscryer-hub': 'opscryer_suite_hub:main',
        })

    def test_fresh_imports_have_no_network_or_subprocess_side_effects(self):
        # A fresh interpreter prevents previously cached imports from hiding
        # circular imports or import-time I/O. Audit hooks also catch aliases
        # and record attempts even if application code catches the exception.
        script = textwrap.dedent("""
            import sys

            attempts = []

            def guard(event, args):
                if (event.startswith('socket.') or event in {
                    'subprocess.Popen', 'os.system', 'os.posix_spawn',
                    'os.spawn', 'os.exec', 'os.fork', 'os.forkpty',
                }):
                    attempts.append(event)
                    raise RuntimeError('Import attempted network or process I/O')

            sys.addaudithook(guard)
            if sys.argv[1] == 'reverse':
                import opscryer.portals
                import opscryer.security
                import opscryer.live
                import opscryer.core
            import opscryer
            from opscryer import core, live, security, portals

            for name, module in (
                ('core', core), ('live', live),
                ('security', security), ('portals', portals),
            ):
                assert module.__name__ == 'opscryer.' + name
                assert getattr(opscryer, name) is module
            assert not attempts, 'Import side effects: ' + ', '.join(attempts)
        """)
        for order in ('forward', 'reverse'):
            with self.subTest(order=order):
                result = subprocess.run(
                    [sys.executable, '-c', script, order], cwd=ROOT,
                    capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_architecture_map_lists_existing_repository_modules(self):
        import opscryer

        architecture = opscryer.get_package_architecture_map()
        self.assertEqual(set(architecture), {'core', 'live', 'security', 'portals'})
        for subsystem, metadata in architecture.items():
            with self.subTest(subsystem=subsystem):
                self.assertIsInstance(metadata['modules'], list)
                self.assertTrue(metadata['modules'])
            for module_name in metadata['modules']:
                with self.subTest(subsystem=subsystem, module=module_name):
                    self.assertIsInstance(module_name, str)
                    module_path = ROOT.joinpath(*module_name.split('.'))
                    self.assertTrue(
                        module_path.with_suffix('.py').is_file()
                        or (module_path / '__init__.py').is_file(),
                        f'Missing repository module: {module_name}',
                    )

    def test_subsystem_exports_match_top_level_counterparts(self):
        from opscryer import core, live, security, portals
        from opscryer_backend import KnowledgeGraphBackendEngine
        from live_metrics_poller import poll_live_cluster_metrics
        from security_airlock import evaluate_code_search_airlock
        from opscryer_browser import render_standalone_browser_html

        self.assertIs(core.KnowledgeGraphBackendEngine, KnowledgeGraphBackendEngine)
        self.assertIs(live.poll_live_cluster_metrics, poll_live_cluster_metrics)
        self.assertIs(security.evaluate_code_search_airlock, evaluate_code_search_airlock)
        self.assertIs(portals.render_standalone_browser_html, render_standalone_browser_html)


if __name__ == '__main__':
    unittest.main()
