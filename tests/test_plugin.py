"""Exercise actual plugin registration/handlers; host fixtures never execute candidates."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('judge_contract_plugin', ROOT / '__init__.py', submodule_search_locations=[str(ROOT)])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)


class Host:
    def __init__(self):
        self.tools = {}
        self.commands = {}
        self.cli = {}
        self.skills = {}
        self.dispatches = []
        self.reply = {'error': 'Approval denied', 'exit_code': -1, 'output': ''}

    def register_tool(self, **kw):
        self.tools[kw['name']] = kw

    def register_command(self, **kw):
        self.commands[kw['name']] = kw

    def register_cli_command(self, **kw):
        self.cli[kw['name']] = kw

    def register_skill(self, name, path):
        self.skills[name] = path

    def dispatch_tool(self, name, args):
        self.dispatches.append((name, args))
        return self.reply


class PluginTests(unittest.TestCase):
    def setUp(self):
        self.host = Host()
        plugin.register(self.host)
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.root / '__init__.py').write_text('def register(ctx):\n    pass\n')
        self.handler = self.host.tools['hackathon_judge']['handler']

    def call(self, **args):
        return json.loads(self.handler({'path': str(self.root), **args}))

    def test_public_registration_surfaces(self):
        self.assertIn('judge-plugin', self.host.commands)
        self.assertIn('hackathon-judge', self.host.cli)
        self.assertTrue(self.host.skills['judge-plugin'].is_file())

    def test_audit_no_terminal_or_network_dispatch(self):
        self.assertFalse(self.call()['certified'])
        self.assertEqual(self.host.dispatches, [])

    def test_validate_requires_explicit_trusted_code(self):
        self.assertIn('error', self.call(action='validate'))
        self.assertEqual(self.host.dispatches, [])

    def test_denied_approval_is_never_reported_as_pass(self):
        report = self.call(action='validate', trusted_code=True)
        self.assertEqual(report['official_validation']['status'], 'error')
        self.assertEqual(self.host.dispatches[0][0], 'terminal')
        self.assertNotIn('--install-deps', self.host.dispatches[0][1]['command'])
        self.assertNotIn('--yolo', self.host.dispatches[0][1]['command'])

    def test_complete_official_fixture_is_attributed_but_not_certified(self):
        self.host.reply = {'exit_code': 0, 'output': json.dumps({'ok': True, 'checks': [{'name': name, 'ok': True} for name in ['manifest', 'loadable', 'capability probe', 'security scan', 'no core override']], 'warnings': []})}
        report = self.call(action='validate', trusted_code=True)
        self.assertEqual(report['official_validation']['status'], 'pass')
        self.assertFalse(report['official_validation']['install_deps'])
        self.assertFalse(report['certified'])
        self.assertEqual(report['verdict'], 'needs_review')

    def test_empty_official_checks_not_a_pass(self):
        self.host.reply = {'exit_code': 0, 'output': '{"ok": true, "checks": []}'}
        report = self.call(action='validate', trusted_code=True)
        self.assertEqual(report['official_validation']['status'], 'error')

    def test_runtime_boolean_exit_code_is_not_a_success(self):
        self.host.reply = {'exit_code': False, 'output': json.dumps({'ok': True, 'checks': [{'name': name, 'ok': True} for name in ['manifest', 'loadable', 'capability probe', 'security scan', 'no core override']], 'warnings': []})}
        self.assertEqual(self.call(action='validate', trusted_code=True)['official_validation']['status'], 'error')

    def test_runtime_warnings_are_preserved_for_review(self):
        warnings = ['Fixture caution: inspect the named source before acceptance']
        self.host.reply = {'exit_code': 0, 'output': json.dumps({'ok': True, 'checks': [{'name': name, 'ok': True} for name in ['manifest', 'loadable', 'capability probe', 'security scan', 'no core override']], 'warnings': warnings})}
        self.assertEqual(self.call(action='validate', trusted_code=True)['official_validation'].get('warnings'), warnings)

    def test_runtime_malformed_warning_table_is_not_a_success(self):
        self.host.reply = {'exit_code': 0, 'output': json.dumps({'ok': True, 'checks': [{'name': name, 'ok': True} for name in ['manifest', 'loadable', 'capability probe', 'security scan', 'no core override']], 'warnings': {'invalid': 'not a list'}})}
        self.assertEqual(self.call(action='validate', trusted_code=True)['official_validation']['status'], 'error')

    def test_official_failure_blocks(self):
        self.host.reply = {'exit_code': 1, 'output': json.dumps({'ok': False, 'checks': [{'name': 'security scan', 'ok': False}], 'warnings': []})}
        self.assertEqual(self.call(action='validate', trusted_code=True)['verdict'], 'blocked')

    def test_tree_changed_during_validation_invalidates_binding(self):
        def dispatch(name, args):
            (self.root / 'changed.py').write_text('print("changed")')
            return {'exit_code': 0, 'output': json.dumps({'ok': True, 'checks': [{'name': name, 'ok': True} for name in ['manifest', 'loadable', 'capability probe', 'security scan', 'no core override']]})}
        self.host.dispatch_tool = dispatch
        report = self.call(action='validate', trusted_code=True)
        self.assertFalse(report['official_validation']['tree_unchanged'])
        self.assertEqual(report['official_validation']['status'], 'stale')
        check = next(c for c in report['checks'] if c['id'] == 'official-validator')
        self.assertEqual(check['status'], 'needs_review')

    def test_bad_path_error_does_not_leak_content(self):
        self.assertIn('error', self.call(path=str(self.root / 'missing')))

    def test_slash_safe_parse(self):
        self.assertIn('Usage:', plugin.slash(''))
        self.assertIn('Unable to audit', plugin.slash('"unterminated'))
        self.assertIn('needs_review', plugin.slash(str(self.root)))

    def test_rules_and_review_worksheet(self):
        self.assertEqual(len(self.call(action='rules')['requirements']), 45)
        self.assertIn('CAT-18', self.call(action='template')['reviews'])


if __name__ == '__main__':
    unittest.main()
