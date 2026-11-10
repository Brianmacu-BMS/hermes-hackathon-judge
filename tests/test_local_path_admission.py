"""Local-root admission before filesystem probes; no remote shares contacted."""
from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes
import stat
import importlib.util
import json
import os
from pathlib import Path, PureWindowsPath
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hackathon_judge import paths
from hackathon_judge import bound_validation

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('local_path_plugin', ROOT / '__init__.py', submodule_search_locations=[str(ROOT)])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)

REMOTE_NAMES = (r'\\server\share\candidate', r'\\?\UNC\server\share\candidate',
                '//server/share/candidate', r'\\.\C:\candidate')


def public_guard(owner, value, **kwargs):
    return owner.guarded(value) if owner is bound_validation else owner.guarded_path(value, **kwargs)


class TypedFunction:
    def __init__(self, callback):
        self.callback = callback
        self.calls = []
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        self.calls.append(args)
        return self.callback(*args)


@contextmanager
def projected(owner, *, target=r'\Device\HarddiskVolume1', kind=3, count=None, error=None):
    """Fake typed Win32 calls and metadata; no DLL, drive or device is opened."""
    state = {'metadata': [], 'events': []}
    def drive(root):
        state['events'].append(('drive', root))
        return kind
    def mapping(name, buffer, length):
        state['events'].append(('mapping', name))
        if error is not None:
            raise error
        buffer.value = target
        return len(target) + 2 if count is None else count
    drive_call = TypedFunction(drive)
    mapping_call = TypedFunction(mapping)
    library = SimpleNamespace(GetDriveTypeW=drive_call, QueryDosDeviceW=mapping_call)
    state.update(drive=drive_call, mapping=mapping_call)
    class LocalProjection(PureWindowsPath):
        def expanduser(self): return self
        def absolute(self): return self
        def resolve(self, strict=False): return self
        def lstat(self):
            state['metadata'].append(str(self))
            state['events'].append(('metadata', str(self)))
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0)
        def is_dir(self):
            state['events'].append(('is_dir', str(self)))
            return True
    local_os = SimpleNamespace(**vars(os))
    local_os.name = 'nt'
    with ExitStack() as stack:
        stack.enter_context(patch.object(owner, 'os', local_os))
        stack.enter_context(patch.object(owner, 'Path', LocalProjection))
        loader = stack.enter_context(patch.object(ctypes, 'WinDLL', return_value=library, create=True))
        state['loader'] = loader
        yield state


class LocalPathAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.candidate = self.root / 'candidate'
        self.candidate.mkdir()
        (self.candidate / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.candidate / '__init__.py').write_bytes(b'def register(ctx):\n    pass\n')
        self.host = SimpleNamespace(dispatch_tool=lambda *a, **kw: self.fail('Unexpected terminal dispatch'))

    def test_common_guard_refuses_remote_names_before_lstat(self):
        for name in REMOTE_NAMES:
            with self.subTest(name=name), patch.object(Path, 'lstat', side_effect=AssertionError('Filesystem probe')) as probe:
                with self.assertRaises(ValueError):
                    paths.guarded_path(name)
                probe.assert_not_called()

    def test_backend_guard_refuses_remote_names_before_lstat(self):
        for name in REMOTE_NAMES:
            with self.subTest(name=name), patch.object(Path, 'lstat', side_effect=AssertionError('Filesystem probe')) as probe:
                with self.assertRaises(ValueError):
                    bound_validation.guarded(name)
                probe.assert_not_called()

    def test_explicit_scoped_remote_cwd_never_reaches_metadata(self):
        for name in REMOTE_NAMES:
            module = ModuleType('agent.runtime_cwd')
            module.scoped_session_cwd = lambda: name
            module.resolve_agent_cwd = lambda: self.fail('Explicit workspace replaced by fallback')
            with self.subTest(name=name), patch.dict(sys.modules, {'agent.runtime_cwd': module}), patch.object(Path, 'is_dir', side_effect=AssertionError('Directory probe')) as probe:
                self.assertIn('error', json.loads(plugin.handle(self.host, {'path': 'candidate'})))
                self.assertIn('Unable to audit', plugin.slash('candidate'))
                probe.assert_not_called()

    def test_absolute_remote_input_rejected_before_workspace_resolver(self):
        module = ModuleType('agent.runtime_cwd')
        module.scoped_session_cwd = Mock(side_effect=AssertionError('Remote input consulted workspace'))
        module.resolve_agent_cwd = Mock(side_effect=AssertionError('Remote input consulted fallback'))
        for name in REMOTE_NAMES:
            with self.subTest(name=name), patch.dict(sys.modules, {'agent.runtime_cwd': module}), patch.object(Path, 'lstat', side_effect=AssertionError('Filesystem probe')) as probe:
                self.assertIn('error', json.loads(plugin.handle(self.host, {'path': name})))
                probe.assert_not_called()
                module.scoped_session_cwd.assert_not_called()
                module.resolve_agent_cwd.assert_not_called()

    def test_windows_device_mapping_classifier_is_fail_closed(self):
        # Keep the attachment identity, but reproduce through existing public
        # guards rather than fail on an as-yet unimplemented private helper.
        for owner in (paths, bound_validation):
            for target in (r'\Device\HarddiskVolume1', r'\Device\CdRom0', r'\Device\Floppy0', r'\Device\Ramdisk0'):
                with self.subTest(owner=owner.__name__, local=target), projected(owner, target=target) as state:
                    self.assertEqual(str(public_guard(owner, r'C:\candidate')), r'C:\candidate')
                    self.assertTrue(state['metadata'])
            for target in (r'\Device\Mup\server\share', r'\Device\LanmanRedirector\;Z:123\server\share',
                           r'\Device\WebDavRedirector\server', r'\??\C:\substituted', '',
                           r'\Device\HarddiskVolume1\extra', r'\Device\Unknown0'):
                with self.subTest(owner=owner.__name__, refused=target), projected(owner, target=target) as state:
                    with self.assertRaises(ValueError):
                        public_guard(owner, r'C:\candidate')
                    self.assertEqual(state['metadata'], [])

    def test_ambiguous_windows_paths_never_consult_workspace(self):
        module = ModuleType('agent.runtime_cwd')
        module.scoped_session_cwd = Mock(side_effect=AssertionError('Ambiguous path consulted workspace'))
        module.resolve_agent_cwd = module.scoped_session_cwd
        for name in ('C:candidate', 'C:', r'\candidate'):
            with self.subTest(name=name), patch.dict(sys.modules, {'agent.runtime_cwd': module}):
                self.assertIn('error', json.loads(plugin.handle(self.host, {'path': name})))
                module.scoped_session_cwd.assert_not_called()

    def test_scoped_symlink_is_rejected_before_directory_probe(self):
        alias = self.root / 'alias'
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except OSError as exc:
            self.skipTest(str(exc))
        module = ModuleType('agent.runtime_cwd')
        module.scoped_session_cwd = lambda: str(alias)
        module.resolve_agent_cwd = lambda: self.fail('Explicit alias replaced by fallback')
        with patch.dict(sys.modules, {'agent.runtime_cwd': module}), patch.object(Path, 'is_dir', side_effect=AssertionError('Following directory probe')) as probe:
            self.assertIn('error', json.loads(plugin.handle(self.host, {'path': 'candidate'})))
            probe.assert_not_called()

    def test_existing_local_scoped_directory_positive_control(self):
        module = ModuleType('agent.runtime_cwd')
        module.scoped_session_cwd = lambda: str(self.root)
        module.resolve_agent_cwd = lambda: self.fail('Scoped directory replaced by fallback')
        with patch.dict(sys.modules, {'agent.runtime_cwd': module}):
            report = json.loads(plugin.handle(self.host, {'path': 'candidate'}))
        self.assertEqual(report['candidate'], str(self.candidate))
        self.assertFalse(report['certified'])

    def test_absolute_local_candidate_does_not_consult_missing_scope(self):
        module = ModuleType('agent.runtime_cwd')
        module.scoped_session_cwd = lambda: self.fail('Absolute request consulted workspace')
        module.resolve_agent_cwd = module.scoped_session_cwd
        with patch.dict(sys.modules, {'agent.runtime_cwd': module}):
            self.assertEqual(json.loads(plugin.handle(self.host, {'path': str(self.candidate)}))['candidate'], str(self.candidate))

    def test_typed_windows_calls_and_direct_local_positive(self):
        for owner in (paths, bound_validation):
            with self.subTest(owner=owner.__name__), projected(owner) as state:
                self.assertEqual(str(public_guard(owner, r'C:\candidate')), r'C:\candidate')
                self.assertTrue(state['metadata'])
                self.assertTrue(state['drive'].calls)
                self.assertTrue(state['mapping'].calls)
                self.assertEqual(state['drive'].argtypes, [ctypes.c_wchar_p])
                self.assertIs(state['drive'].restype, ctypes.c_uint)
                self.assertEqual(state['mapping'].argtypes, (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD))
                self.assertIs(state['mapping'].restype, wintypes.DWORD)
                self.assertTrue(all(args == ('C:\\',) for args in state['drive'].calls))
                for name, buffer, size in state['mapping'].calls:
                    self.assertEqual(name, 'C:')
                    self.assertEqual(size, len(buffer))
                    self.assertEqual(size, 32768)
                for call in state['loader'].call_args_list:
                    self.assertEqual(call.args, ('kernel32',))
                    self.assertEqual(call.kwargs, {'use_last_error': True})
                first_metadata = next(i for i, event in enumerate(state['events']) if event[0] == 'metadata')
                self.assertTrue(any(event[0] == 'mapping' for event in state['events'][:first_metadata]))

    def test_drive_type_rejection_precedes_mapping_and_metadata(self):
        for owner in (paths, bound_validation):
            for kind in (0, 1, 4, 7):
                with self.subTest(owner=owner.__name__, kind=kind), projected(owner, kind=kind) as state:
                    with self.assertRaises(ValueError):
                        public_guard(owner, r'C:\candidate')
                    self.assertEqual(state['mapping'].calls, [])
                    self.assertEqual(state['metadata'], [])

    def test_mapping_errors_fail_closed_before_metadata(self):
        for owner in (paths, bound_validation):
            for options in ({'count': 0}, {'count': 32769}, {'error': OSError('unavailable')},
                            {'error': AttributeError('missing symbol')}):
                with self.subTest(owner=owner.__name__, options=options), projected(owner, **options) as state:
                    with self.assertRaises(ValueError):
                        public_guard(owner, r'C:\candidate')
                    self.assertEqual(state['metadata'], [])

    def test_root_relative_and_drive_relative_rejected_before_guard_metadata(self):
        for owner in (paths, bound_validation):
            for name in (r'\candidate', r'C:candidate', 'C:', r'\??\C:\candidate'):
                with self.subTest(owner=owner.__name__, name=name), projected(owner) as state:
                    with self.assertRaises(ValueError):
                        public_guard(owner, name)
                    self.assertEqual(state['metadata'], [])
                    self.assertEqual(state['drive'].calls, [])
                    self.assertEqual(state['mapping'].calls, [])

    def test_bound_collect_rejects_subst_before_walk_or_following_probe(self):
        with projected(bound_validation, target=r'\??\C:\substituted') as state, patch.object(bound_validation.os, 'walk', return_value=[]) as walk:
            with self.assertRaises(ValueError):
                bound_validation.collect(r'C:\candidate')
            self.assertEqual(state['metadata'], [])
            self.assertFalse(any(event[0] == 'is_dir' for event in state['events']))
            walk.assert_not_called()

    def test_bound_collect_ordinary_local_positive_and_reparse_denial(self):
        files, data = bound_validation.collect(self.candidate)
        self.assertEqual({item['path'] for item in files}, {'plugin.yaml', '__init__.py'})
        self.assertEqual(data['__init__.py'][0], b'def register(ctx):\n    pass\n')
        original = Path.lstat
        def flagged(current, *args, **kwargs):
            if current == self.candidate:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
            return original(current, *args, **kwargs)
        with patch.object(Path, 'lstat', flagged), patch.object(Path, 'is_dir', side_effect=AssertionError('Followed alias')) as following:
            with self.assertRaises(ValueError):
                bound_validation.collect(self.candidate)
            following.assert_not_called()

    def test_explicit_missing_scope_is_not_replaced_by_fallback(self):
        module = ModuleType('agent.runtime_cwd')
        module.scoped_session_cwd = lambda: str(self.root / 'missing')
        module.resolve_agent_cwd = Mock(return_value=str(self.root))
        with patch.dict(sys.modules, {'agent.runtime_cwd': module}):
            self.assertIn('error', json.loads(plugin.handle(self.host, {'path': 'candidate'})))
            self.assertIn('Unable to audit', plugin.slash('candidate'))
        module.resolve_agent_cwd.assert_not_called()

    def test_root_relative_optional_documents_never_consult_scope(self):
        module = ModuleType('agent.runtime_cwd')
        module.scoped_session_cwd = Mock(side_effect=AssertionError('Ambiguous document consulted workspace'))
        module.resolve_agent_cwd = module.scoped_session_cwd
        for option in ('catalog', 'submission', 'review'):
            with self.subTest(option=option), patch.dict(sys.modules, {'agent.runtime_cwd': module}):
                self.assertIn('error', json.loads(plugin.handle(self.host, {'path': str(self.candidate), option: r'\document'})))
                module.scoped_session_cwd.assert_not_called()


if __name__ == '__main__':
    unittest.main()
