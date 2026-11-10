"""Native paths follow each calling session; standalone CLI keeps process cwd.

The public cwd boundary is a unit fixture here. CI-only installed acceptance
uses the real Hermes resolver and session context on both supported releases.
"""
from contextvars import ContextVar
from contextlib import redirect_stdout, ExitStack
import importlib.util
import io
import json
import os
from pathlib import Path, PureWindowsPath
import shlex
import stat
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hackathon_judge.cli import main
from hackathon_judge.engine import audit, review_template

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_path_plugin', ROOT / '__init__.py',
                                            submodule_search_locations=[str(ROOT)])
if spec is None or spec.loader is None:
    raise RuntimeError('Native plugin fixture could not be loaded')
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)


class NativePathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.process = self.base / 'process'
        self.session = self.base / 'session'
        self.process.mkdir()
        self.session.mkdir()
        original = Path.cwd()
        os.chdir(self.process)
        self.addCleanup(os.chdir, original)
        self.cwd = ContextVar('test_native_path_cwd', default=self.session)
        self.resolver = Mock(side_effect=self.cwd.get)
        module = ModuleType('agent.runtime_cwd')
        setattr(module, 'resolve_agent_cwd', self.resolver)
        setattr(module, 'scoped_session_cwd', lambda: '')
        self.sdk = patch.dict(sys.modules, {'agent.runtime_cwd': module})
        self.sdk.start()
        self.addCleanup(self.sdk.stop)
        self.candidate = self.make_candidate(self.session, 'session-fixture')
        self.decoy = self.make_candidate(self.process, 'process-fixture')
        self.host = SimpleNamespace(dispatch_tool=Mock(side_effect=AssertionError('No terminal calls expected')))

    def make_candidate(self, parent, name):
        path = parent / 'candidate'
        path.mkdir()
        (path / 'plugin.yaml').write_text(
            f'name: {name}\nversion: 1.0.0\ndescription: Owned static fixture\n')
        (path / '__init__.py').write_text('def register(ctx):\n    raise AssertionError("Candidate must not execute")\n')
        return path

    def call(self, surface, path, **options):
        if surface == 'tool':
            value = plugin.handle(self.host, {'path': str(path), **options}, task_id='fixture')
        else:
            flags = ' '.join('--' + key + ' ' + shlex.quote(str(value)) for key, value in options.items())
            value = plugin.slash(shlex.quote(str(path)) + ' --format json ' + flags)
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            self.fail('Native handler did not return an audit report: ' + value)

    def test_native_candidate_uses_session_not_same_named_process_tree(self):
        for surface in ('tool', 'slash'):
            with self.subTest(surface=surface):
                report = self.call(surface, 'candidate')
                self.assertEqual(report['candidate'], str(self.candidate))
                self.assertEqual(Path.cwd(), self.process)
                self.assertFalse(report['certified'])
        self.host.dispatch_tool.assert_not_called()

    def test_native_catalog_and_submission_use_session_directory(self):
        (self.session / 'entry.yaml').write_text(
            'name: session-fixture\nrepo: https://github.com/example/demo\nsha: "' + 'a' * 40 + '"\nversion: "1.0.0"\n')
        (self.session / 'submission.json').write_text(json.dumps({'event_year': 2026, 'submitted_at': 'owned-session-marker'}))
        for surface in ('tool', 'slash'):
            with self.subTest(surface=surface):
                report = self.call(surface, str(self.candidate), catalog='entry.yaml', submission='submission.json')
                self.assertEqual(report['submission_attestations']['submitted_at'], 'owned-session-marker')
                metadata = next(c for c in report['checks'] if c['id'] == 'catalog-metadata')
                self.assertEqual(metadata['status'], 'pass')

    def test_native_review_and_its_evidence_remain_relative_to_review_directory(self):
        directory = self.session / 'records'
        directory.mkdir()
        note = directory / 'note.md'
        note.write_text('Owned evidence')
        import hashlib
        value = review_template(audit(self.candidate))
        value.update(reviewer={'name': 'Fixture', 'role': 'operator'}, reviewed_at='2026-01-01T00:00:00+00:00')
        value['decisions']['CAT-03'].update(decision='pass', reason='Owned fixture checks evidence binding.',
            evidence=[{'path': 'note.md', 'sha256': hashlib.sha256(note.read_bytes()).hexdigest()}])
        (directory / 'review.json').write_text(json.dumps(value))
        for surface in ('tool', 'slash'):
            with self.subTest(surface=surface):
                report = self.call(surface, str(self.candidate), review='records/review.json')
                self.assertEqual(report['assessment']['status'], 'incomplete')
                self.assertEqual(report['assessment']['evidence_checked'][0]['path'], 'note.md')

    def test_session_context_is_resolved_once_per_invocation_not_cached(self):
        second = self.base / 'second-session'
        second.mkdir()
        other = self.make_candidate(second, 'second-fixture')
        for surface in ('tool', 'slash'):
            with self.subTest(surface=surface):
                for directory, expected in ((self.session, self.candidate), (second, other)):
                    token = self.cwd.set(directory)
                    self.resolver.reset_mock()
                    try:
                        self.assertEqual(self.call(surface, 'candidate')['candidate'], str(expected))
                        self.resolver.assert_called_once_with()
                    finally:
                        self.cwd.reset(token)

    def test_absolute_paths_do_not_require_or_consult_session_resolver(self):
        with patch.dict(sys.modules, {'agent.runtime_cwd': None}):
            for surface in ('tool', 'slash'):
                with self.subTest(surface=surface):
                    self.assertEqual(self.call(surface, self.candidate)['candidate'], str(self.candidate))
        self.resolver.assert_not_called()

    def test_relative_paths_without_host_context_fail_closed_not_process_fallback(self):
        with patch.dict(sys.modules, {'agent.runtime_cwd': None}):
            self.assertIn('error', json.loads(plugin.handle(self.host, {'path': 'candidate'})))
            self.assertIn('Unable to audit', plugin.slash('candidate'))
        self.host.dispatch_tool.assert_not_called()

    def test_relative_session_base_is_refused_not_interpreted_as_process_cwd(self):
        token = self.cwd.set(Path('relative-session'))
        try:
            self.assertIn('error', json.loads(plugin.handle(self.host, {'path': 'candidate'})))
            self.assertIn('Unable to audit', plugin.slash('candidate'))
        finally:
            self.cwd.reset(token)

    def test_rules_help_and_blank_path_do_not_need_session_context(self):
        with patch.dict(sys.modules, {'agent.runtime_cwd': None}):
            self.assertIn('requirements', json.loads(plugin.handle(self.host, {'action': 'rules'})))
            self.assertEqual(len(json.loads(plugin.slash('--rules'))), 45)
            self.assertIn('Usage:', plugin.slash(''))
            self.assertIn('Unable to audit', plugin.slash("''"))
            self.assertIn('error', json.loads(plugin.handle(self.host, {'path': ''})))
        self.resolver.assert_not_called()

    def test_relative_candidate_reparse_component_is_refused_before_content_read(self):
        original = Path.lstat
        def flagged(current, *args, **kwargs):
            info = original(current, *args, **kwargs)
            if current == self.candidate:
                values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                values['st_file_attributes'] = getattr(info, 'st_file_attributes', 0) | getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
                return SimpleNamespace(**values)
            return info
        with patch.object(Path, 'lstat', flagged), patch('os.open', side_effect=AssertionError('Read refused candidate')):
            self.assertIn('error', json.loads(plugin.handle(self.host, {'path': 'candidate'})))
            self.assertIn('Unable to audit', plugin.slash('candidate'))

    def test_nonlocal_scope_and_shared_guards_reject_before_any_metadata(self):
        # Reviewer minimum reproduction, with every native metadata escape denied.
        import ntpath
        from hackathon_judge import paths as shared
        native_shared = sys.modules[plugin.__package__ + '.hackathon_judge.paths']
        probes = []
        def forbidden(*args, **kwargs):
            probes.append(str(args[0]) if args else 'native')
            raise AssertionError('Metadata must not run on a nonlocal root')
        class InterceptWindowsPath(PureWindowsPath):
            def expanduser(self): return self
            def absolute(self): return self
            is_dir = is_file = exists = stat = lstat = resolve = forbidden
        cases = [r'\\invalid-review-host\never-contact\workspace',
                 r'\\?\UNC\invalid-review-host\never-contact\workspace',
                 r'\\?\C:\workspace', r'\\.\C:\workspace',
                 r'Z:\review-workspace', r'C:drive-relative']
        for declared in cases:
            for route in ('tool', 'slash', 'guarded_path', 'guarded_root'):
                probes.clear()
                module = ModuleType('agent.runtime_cwd')
                module.scoped_session_cwd = lambda: declared
                module.resolve_agent_cwd = Mock(side_effect=AssertionError('No fallback'))
                with self.subTest(declared=declared, route=route), ExitStack() as stack:
                    # argparse's translation lookup is unrelated local metadata;
                    # bypass only gettext, leaving every filesystem route denied.
                    stack.enter_context(patch('argparse._', side_effect=lambda text: text))
                    stack.enter_context(patch.dict(sys.modules, {'agent.runtime_cwd': module}))
                    for owner in (plugin, shared, native_shared):
                        stack.enter_context(patch.object(owner, 'Path', InterceptWindowsPath))
                    for owner in (shared, native_shared):
                        stack.enter_context(patch.object(owner, '_drive_type', return_value=4, create=True))
                    for name in ('stat', 'lstat', 'scandir', 'open'):
                        stack.enter_context(patch.object(os, name, forbidden))
                    for owner in (os.path, ntpath):
                        for name in ('isdir', 'isfile', 'exists', 'lexists', 'islink', 'realpath'):
                            stack.enter_context(patch.object(owner, name, forbidden))
                    if route == 'tool':
                        self.assertIn('error', json.loads(plugin.handle(self.host, {'path': 'candidate'})))
                    elif route == 'slash':
                        self.assertIn('Unable to audit', plugin.slash('candidate'))
                    else:
                        with self.assertRaises(ValueError):
                            shared.guarded_path(declared if route == 'guarded_path' else r'C:\local',
                                                root=declared if route == 'guarded_root' else None)
                    self.assertEqual(probes, [])
                    module.resolve_agent_cwd.assert_not_called()

    def test_projected_windows_drive_admission_and_local_path_controls(self):
        from hackathon_judge import paths as shared
        probes = []
        for kind in (0, 1, 2, 3, 4, 5, 6):
            with self.subTest(kind=kind), patch.object(shared, '_drive_type', return_value=kind, create=True), patch.object(shared, '_drive_mapping', return_value=r'\Device\HarddiskVolume1', create=True), patch('os.stat', side_effect=AssertionError('No metadata')):
                admission = getattr(shared, 'admit_local_root', lambda p: p)
                if kind in {2, 3, 5, 6}:
                    self.assertEqual(admission(r'C:\local\candidate'), r'C:\local\candidate')
                else:
                    with self.assertRaises(ValueError): admission(r'Z:\candidate')
        # Existing real POSIX local absolute/relative coverage remains above.
        self.assertEqual(shared.guarded_path(self.candidate), self.candidate)
        self.assertEqual(shared.guarded_path('candidate'), self.decoy)

    def test_local_scope_alias_rejected_before_following_directory_predicate(self):
        original = Path.lstat
        followed = []
        def flagged(current, *args, **kwargs):
            if current == self.session:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
            return original(current, *args, **kwargs)
        def following(current):
            followed.append(str(current))
            raise AssertionError('Alias was followed')
        with patch.object(Path, 'lstat', flagged), patch.object(Path, 'is_dir', following):
            self.assertIn('error', json.loads(plugin.handle(self.host, {'path': 'candidate'})))
            self.assertIn('Unable to audit', plugin.slash('candidate'))
        self.assertEqual(followed, [])

    @unittest.skipIf(os.name == 'nt', 'POSIX links; native junction case runs on Windows')
    def test_relative_link_and_link_before_dotdot_are_not_resolved_away(self):
        alias = self.session / 'alias'
        alias.symlink_to(self.candidate, target_is_directory=True)
        for path in ('alias', 'alias/../candidate'):
            with self.subTest(path=path):
                self.assertIn('error', json.loads(plugin.handle(self.host, {'path': path})))
                self.assertIn('Unable to audit', plugin.slash(shlex.quote(path)))

    @unittest.skipUnless(os.name == 'nt', 'Requires actual Windows junction')
    def test_native_windows_session_relative_junction_is_refused(self):
        alias = self.session / 'alias'
        done = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(alias), str(self.candidate)],
                              text=True, capture_output=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.addCleanup(alias.rmdir)
        self.assertTrue(getattr(alias.lstat(), 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))
        self.assertIn('error', json.loads(plugin.handle(self.host, {'path': 'alias'})))
        self.assertIn('Unable to audit', plugin.slash('alias'))

    def test_standalone_cli_keeps_process_cwd_not_native_session_context(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(['candidate', '--format', 'json'])
        self.assertIn(code, (1, 2))
        self.assertEqual(json.loads(output.getvalue())['candidate'], str(self.decoy))
        self.resolver.assert_not_called()

    def test_optional_validation_receives_same_session_bound_document_paths(self):
        (self.session / 'entry.yaml').write_text('name: session-fixture\n')
        (self.session / 'submission.json').write_text('{}')
        (self.session / 'review.json').write_text('{}')
        with patch.object(plugin, 'validate_through_host', return_value={'fixture': 'validated'}) as validate:
            result = json.loads(plugin.handle(self.host, {
                'path': 'candidate', 'catalog': 'entry.yaml', 'submission': 'submission.json',
                'review': 'review.json', 'action': 'validate', 'trusted_code': True}))
        self.assertEqual(result, {'fixture': 'validated'})
        self.assertEqual(validate.call_args.args[1]['candidate'], str(self.candidate))
        self.assertEqual(validate.call_args.kwargs, {
            'catalog': str(self.session / 'entry.yaml'), 'submission': str(self.session / 'submission.json'),
            'review': str(self.session / 'review.json')})
        self.host.dispatch_tool.assert_not_called()


if __name__ == '__main__':
    unittest.main()
