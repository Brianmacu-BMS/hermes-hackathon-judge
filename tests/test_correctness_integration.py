"""Behavioral native/CLI contracts; controlled backend, never live Hermes."""
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from hackathon_judge.cli import main

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('correctness_plugin', ROOT / '__init__.py', submodule_search_locations=[str(ROOT)])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)


class CorrectnessIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.candidate = self.base / 'candidate'
        self.candidate.mkdir()
        (self.candidate / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.candidate / '__init__.py').write_text('def register(ctx):\n    pass\n')
        self.calls = []
        self.host = SimpleNamespace(dispatch_tool=self.dispatch)
        self.reply = {'exit_code': 0, 'output': json.dumps({'ok': True, 'checks': [
            {'name': name, 'ok': True} for name in ('manifest', 'loadable', 'capability probe', 'security scan', 'no core override')], 'warnings': []})}

    def dispatch(self, name, args, **kwargs):
        self.calls.append((name, args, kwargs))
        return self.reply

    def validate(self, **kwargs):
        return json.loads(plugin.handle(self.host, {'path': str(self.candidate), 'action': 'validate', 'trusted_code': True}, **kwargs))

    def test_fresh_bound_five_name_report_is_not_runtime_success(self):
        # Exact independent reviewer minimum: no details, warnings or isolation.
        payload = {'ok': True, 'checks': [{'name': n, 'ok': True} for n in
                   ('manifest', 'loadable', 'capability probe', 'security scan', 'no core override')]}
        self.bind_payload(payload)
        self.assertEqual(self.validate()['official_validation']['status'], 'error')

    def bind_payload(self, payload):
        def dispatch(name, args, **kwargs):
            request = json.loads(shlex.split(args['command'])[-1])
            self.calls.append((name, args, kwargs))
            return {'exit_code': 0, 'output': json.dumps({
                'protocol': 'backend-snapshot-v1', 'nonce': request['nonce'],
                'tree_sha256': request['tree_sha256'], 'bound_before': True,
                'tree_unchanged': True, 'validator_exit_code': 0,
                'validator_output': json.dumps(payload)})}
        self.host.dispatch_tool = dispatch

    def complete_payload(self):
        # Independently source-derived identities: pinned native producer base + Python probe.
        return {'ok': True, 'checks': [{'name': n, 'ok': True, 'detail': 'source-derived fixture'} for n in
            ('manifest', 'manifest fields', 'requires_hermes', 'config schema', 'requires_env', 'oauth',
             'loadable', 'python dependencies', 'capability probe', 'built-in tool collisions',
             'security scan', 'no core override', 'declared tools', 'declared hooks', 'declared middleware')],
            'warnings': [], 'isolation': {'verdict': 'host', 'host_ready': True,
                                         'reasons': [], 'notes': [], 'ctx_methods': []}}

    def test_runtime_complete_shape_positive_and_all_missing_identity_controls(self):
        from copy import deepcopy
        payload = self.complete_payload()
        self.bind_payload(payload)
        self.assertEqual(self.validate()['official_validation']['status'], 'pass')
        for check in payload['checks']:
            with self.subTest(missing=check['name']):
                altered = deepcopy(payload)
                altered['checks'].remove(check)
                self.bind_payload(altered)
                self.assertEqual(self.validate()['official_validation']['status'], 'error')

    def test_runtime_requires_explicit_typed_details_warnings_and_isolation(self):
        from copy import deepcopy
        payload = self.complete_payload()
        for field, values in [('warnings', ['absent', None, {}, [False]]),
                              ('isolation', ['absent', None, {}, {'verdict': 'host'}])]:
            for value in values:
                with self.subTest(field=field, value=value):
                    altered = deepcopy(payload)
                    if value == 'absent': altered.pop(field)
                    else: altered[field] = value
                    self.bind_payload(altered)
                    self.assertEqual(self.validate()['official_validation']['status'], 'error')
        for value in (None, 1, False):
            with self.subTest(detail=value):
                altered = deepcopy(payload)
                altered['checks'][0]['detail'] = value
                self.bind_payload(altered)
                self.assertEqual(self.validate()['official_validation']['status'], 'error')

    def test_runtime_source_applicable_desktop_and_manifest_only_locale_reports(self):
        payload = self.complete_payload()
        desktop = self.candidate / 'plugin.js'
        desktop.write_text('export function activate(ctx) {}')
        self.bind_payload(payload)
        self.assertEqual(self.validate()['official_validation']['status'], 'error')
        payload['checks'].append({'name': 'desktop surface', 'ok': True, 'detail': 'fixture'})
        self.bind_payload(payload)
        self.assertEqual(self.validate()['official_validation']['status'], 'pass')
        desktop.unlink()
        (self.candidate / '__init__.py').unlink()
        manifest = self.candidate / 'plugin.yaml'
        manifest.write_text(manifest.read_text() + 'provides_locales: [pl]\n')
        (self.candidate / 'locales').mkdir()
        (self.candidate / 'locales/pl.yaml').write_text('greeting: hello\n')
        payload = self.complete_payload()
        payload['checks'] = [c for c in payload['checks'] if not c['name'].startswith('declared ')]
        self.bind_payload(payload)
        self.assertEqual(self.validate()['official_validation']['status'], 'error')
        payload['checks'].append({'name': 'locale pl', 'ok': True, 'detail': 'fixture'})
        self.bind_payload(payload)
        self.assertEqual(self.validate()['official_validation']['status'], 'pass')

    def test_unbound_remote_success_is_not_attributed_to_local_candidate(self):
        report = self.validate()
        self.assertEqual(report['official_validation']['status'], 'error')
        self.assertNotEqual(next(c for c in report['checks'] if c['id'] == 'official-validator')['status'], 'pass')

    def test_invocation_identity_reaches_public_terminal_dispatch(self):
        self.validate(task_id='task-exact', session_id='session-exact', parent_agent=object())
        self.assertEqual(self.calls[0][2].get('task_id'), 'task-exact')
        self.assertEqual(self.calls[0][2].get('session_id'), 'session-exact')
        self.assertNotIn('force', self.calls[0][1])
        self.assertNotIn('_host_local', self.calls[0][1])

    def test_literal_trusted_code_gate(self):
        for value in (1, 'true', False, None):
            result = json.loads(plugin.handle(self.host, {'path': str(self.candidate), 'action': 'validate', 'trusted_code': value}))
            self.assertIn('error', result)
        self.assertEqual(self.calls, [])

    def test_slash_preserves_windows_and_posix_path_tokens(self):
        cases = [
            (r'C:\Users\Admin\candidate --catalog C:\docs\entry.yaml --submission C:\docs\submission.json --review C:\docs\review.json',
             {'path': r'C:\Users\Admin\candidate', 'catalog': r'C:\docs\entry.yaml', 'submission': r'C:\docs\submission.json', 'review': r'C:\docs\review.json'}),
            (r'"C:\My Plugins\demo" --review "C:\My Docs\review.json"', {'path': r'C:\My Plugins\demo', 'catalog': None, 'submission': None, 'review': r'C:\My Docs\review.json'}),
            ("'/opt/my plugin' --catalog '/opt/my docs/entry.yaml'", {'path': '/opt/my plugin', 'catalog': '/opt/my docs/entry.yaml', 'submission': None, 'review': None}),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw), patch.object(plugin, '_native_paths', side_effect=lambda args: {k: args.get(k) for k in expected}), patch.object(plugin, 'audit', return_value={}) as audit, patch.object(plugin, 'markdown', return_value='ok'):
                self.assertEqual(plugin.slash(raw), 'ok')
                self.assertEqual(audit.call_args.kwargs, expected)

    def test_explicit_missing_session_does_not_use_resolver_fallback(self):
        module = ModuleType('agent.runtime_cwd')
        module.resolve_agent_cwd = lambda: self.base
        module.scoped_session_cwd = lambda: str(self.base / 'missing-session')
        module.resolve_context_cwd = lambda: None
        with patch.dict(sys.modules, {'agent.runtime_cwd': module}):
            self.assertIn('error', json.loads(plugin.handle(self.host, {'path': 'candidate'})))
            self.assertIn('Unable to audit', plugin.slash('candidate'))
            # Absolute requests keep working even if the session workspace vanished.
            self.assertEqual(json.loads(plugin.handle(self.host, {'path': str(self.candidate)}))['candidate'], str(self.candidate))

    def test_explicit_existing_session_never_uses_other_folder(self):
        module = ModuleType('agent.runtime_cwd')
        decoy = self.base / 'decoy' / 'candidate'
        decoy.mkdir(parents=True)
        (decoy / 'plugin.yaml').write_text('name: decoy\nversion: 1.0.0\ndescription: Decoy\n')
        (decoy / '__init__.py').write_text('def register(ctx):\n    pass\n')
        module.resolve_agent_cwd = lambda: self.base / 'decoy'
        module.scoped_session_cwd = lambda: str(self.base)
        module.resolve_context_cwd = lambda: self.base
        with patch.dict(sys.modules, {'agent.runtime_cwd': module}):
            self.assertEqual(json.loads(plugin.handle(self.host, {'path': 'candidate'}))['candidate'], str(self.candidate))

    def test_standalone_invalid_arguments_are_bounded_json_exit_three(self):
        for argv in (['--unknown-secret-marker'], ['--format', 'bad-secret-marker'], ['--review'], ['--gate', 'bad-secret-marker']):
            out, err = io.StringIO(), io.StringIO()
            with self.subTest(argv=argv), redirect_stdout(out), redirect_stderr(err):
                try:
                    code = main(argv)
                except SystemExit as exc:
                    code = exc.code
                self.assertEqual(code, 3)
                result = json.loads(out.getvalue())
                self.assertIn('error', result)
                self.assertLess(len(out.getvalue()), 500)
                self.assertNotIn('secret-marker', out.getvalue() + err.getvalue())

    def backend(self, *, remote=None, mutate=False, corrupt_helper=False, missing_helper=False):
        bindir = self.base / 'bin'
        bindir.mkdir()
        marker = self.base / 'executed.json'
        launcher = bindir / 'hermes'
        # This is a controlled validator stand-in, NOT live native Hermes.
        launcher.write_text('#!' + sys.executable + '\n' +
            'import hashlib,json,os,runpy,sys\nfrom pathlib import Path\n' +
            'p=Path(sys.argv[3]); raw=(p/"__init__.py").read_bytes()\n' +
            'runpy.run_path(str(p/"__init__.py"))\n' +
            'Path(os.environ["FIXTURE_MARKER"]).write_text(json.dumps({"sha256":hashlib.sha256(raw).hexdigest(),"path":str(p)}))\n' +
            ('(p/"__init__.py").write_text("changed")\n' if mutate else '') +
            'print(' + repr(json.dumps(self.complete_payload())) + ')\n')
        launcher.chmod(0o755)
        def dispatch(name, args, **kwargs):
            self.calls.append((name, args, kwargs))
            argv = shlex.split(args['command'])
            if remote is not None:
                # Simulate a selected backend's separate filesystem mapping.
                argv = [arg.replace(str(self.candidate), str(remote)) for arg in argv]
            if corrupt_helper and len(argv) > 6:
                argv[-2] = '0' * 64
            if missing_helper and len(argv) > 6:
                argv[-3] = str(self.base / 'missing-helper.py')
            env = {**os.environ, 'PATH': str(bindir) + os.pathsep + os.environ['PATH'], 'FIXTURE_MARKER': str(marker)}
            done = subprocess.run(argv, text=True, capture_output=True, env=env, timeout=30)
            return {'exit_code': done.returncode, 'output': done.stdout, 'error': done.stderr if done.returncode not in (0, 1) else None}
        self.host.dispatch_tool = dispatch
        return marker

    def test_backend_different_bytes_are_rejected_before_validator_launch(self):
        remote = self.base / 'remote-B'
        remote.mkdir()
        (remote / 'plugin.yaml').write_bytes((self.candidate / 'plugin.yaml').read_bytes())
        (remote / '__init__.py').write_text('REMOTE_B_DIFFERENT = True\n')
        marker = self.backend(remote=remote)
        report = self.validate()
        self.assertFalse(marker.exists(), 'Remote B executed despite auditing local A')
        self.assertEqual(report['official_validation']['status'], 'error')

    def test_same_backend_executes_exact_bound_bytes_positive_control(self):
        import hashlib
        executed = self.base / 'candidate-code-executed'
        (self.candidate / '__init__.py').write_text('from pathlib import Path\nPath(' + repr(str(executed)) + ').write_text("A")\n')
        marker = self.backend()
        expected = hashlib.sha256((self.candidate / '__init__.py').read_bytes()).hexdigest()
        report = self.validate()
        self.assertEqual(report['official_validation']['status'], 'pass')
        self.assertEqual(executed.read_text(), 'A')
        observed = json.loads(marker.read_text())
        self.assertEqual(observed['sha256'], expected)
        self.assertNotEqual(observed['path'], str(self.candidate))
        self.assertEqual(report['official_validation'].get('binding'), 'backend-snapshot-v1')
        self.assertFalse(report['certified'])

    def test_changed_executed_snapshot_does_not_pass(self):
        original = (self.candidate / '__init__.py').read_bytes()
        self.backend(mutate=True)
        self.assertEqual(self.validate()['official_validation']['status'], 'stale')
        self.assertEqual((self.candidate / '__init__.py').read_bytes(), original)

    def test_missing_backend_helper_refused_before_validator_launch(self):
        marker = self.backend(missing_helper=True)
        self.assertEqual(self.validate()['official_validation']['status'], 'error')
        self.assertFalse(marker.exists())

    def test_ignored_uninspected_tree_refused_before_terminal_dispatch(self):
        (self.candidate / 'node_modules').mkdir()
        (self.candidate / 'node_modules' / 'not-inspected.js').write_text('uninspected')
        self.assertEqual(self.validate()['official_validation']['status'], 'error')
        self.assertEqual(self.calls, [])

    def test_wrong_helper_digest_refused_before_validator_launch(self):
        marker = self.backend(corrupt_helper=True)
        self.assertEqual(self.validate()['official_validation']['status'], 'error')
        self.assertFalse(marker.exists())

    def test_standalone_module_process_exit_contract(self):
        routes = [(['--format', 'invalid-secret-marker'], 3), (['--review'], 3),
                  ([], 3), (['--help'], 0), (['--rules'], 0),
                  ([str(self.candidate), '--format', 'json'], 2)]
        for argv, expected in routes:
            with self.subTest(argv=argv):
                done = subprocess.run([sys.executable, '-B', '-m', 'hackathon_judge', *argv],
                                      text=True, capture_output=True, timeout=30, cwd=ROOT)
                self.assertEqual(done.returncode, expected)
                if expected == 3:
                    self.assertIn('error', json.loads(done.stdout))
                    self.assertEqual(done.stderr, '')
                    self.assertLess(len(done.stdout), 500)
                    self.assertNotIn('secret-marker', done.stdout)

    def test_standalone_help_rules_and_incomplete_positive_controls(self):
        for argv, expected in ((['--help'], 0), (['--rules'], 0), ([str(self.candidate), '--format', 'json'], 2)):
            out = io.StringIO()
            with self.subTest(argv=argv), redirect_stdout(out):
                try:
                    code = main(argv)
                except SystemExit as exc:
                    code = exc.code
                self.assertEqual(code, expected)
                self.assertTrue(out.getvalue())


if __name__ == '__main__':
    unittest.main()
