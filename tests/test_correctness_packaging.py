"""Behavioral regressions for release boundaries; disposable fixtures only."""
import hashlib
from contextlib import redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
# Independent expectations, not imported from the production deny lists.
SECRET_DIRECTORY_NAMES = (
    '.env', '.env.local', '.env.production', 'auth.json', 'credentials.json',
    'secrets.json', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_ed448', 'id_dsa',
    '.npmrc', '.pypirc', '.netrc', '.dockercfg', '.git-credentials',
    'private.pem', 'private.key', 'private.p12', 'private.pfx', 'private.kdbx',
    'private.kdb', 'private.ovpn', 'private.age', 'private.gpg',
)


class PackagingFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.serial = 0
        spec = importlib.util.spec_from_file_location(
            'correctness_packaging_builder', ROOT / 'scripts/build-source-archive.py')
        self.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.builder)

    def fixture(self):
        self.serial += 1
        base = self.work / str(self.serial)
        source = base / 'source'
        source.mkdir(parents=True)
        self.put(source, 'README.md', b'# Legitimate root readme\r\n')
        self.put(source, 'hackathon_judge/__init__.py', b'# Package source\n')
        return source, base / 'output'

    def put(self, source, relative, raw):
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def assert_members(self, result, expected):
        self.assertTrue(result['ok'], result)
        manifest = json.loads(Path(result['manifest']).read_text(encoding='utf-8'))
        self.assertEqual({item['path'] for item in manifest['files']}, set(expected))
        self.assertEqual(manifest['files_included'], len(expected))
        with zipfile.ZipFile(result['archive']) as archive:
            self.assertEqual(set(archive.namelist()), set(expected))
            self.assertEqual(len(archive.namelist()), len(expected))
            self.assertIsNone(archive.testzip())
            for item in manifest['files']:
                raw = expected[item['path']]
                self.assertEqual(archive.read(item['path']), raw)
                self.assertEqual(item['bytes'], len(raw))
                self.assertEqual(item['sha256'], hashlib.sha256(raw).hexdigest())


class SecretDescendantDirectoryTests(PackagingFixture):
    def test_secret_named_directories_rejected_before_traversal_or_content_reads(self):
        for name in SECRET_DIRECTORY_NAMES:
            for spelling in dict.fromkeys((name, name.upper(), name.title())):
                for parent in ('hackathon_judge', 'unknown/deep', 'docs'):
                    with self.subTest(name=spelling, parent=parent):
                        source, output = self.fixture()
                        relative = parent + '/' + spelling
                        target = source / relative
                        self.put(target, 'payload.py', b'PRIVATE_DIRECTORY_MARKER\n')
                        traversed, reads = [], []
                        scandir = os.scandir
                        read_regular = self.builder.read_regular

                        def observed_scandir(path):
                            if Path(path) == target or Path(path).is_relative_to(target):
                                traversed.append(str(path))
                            return scandir(path)

                        def observed_read(path, **kwargs):
                            if Path(path).is_relative_to(target):
                                reads.append(str(path))
                            return read_regular(path, **kwargs)

                        with patch('os.scandir', observed_scandir), patch.object(
                                self.builder, 'read_regular', observed_read):
                            result = self.builder.build_archive(source, output)
                        self.assertFalse(result['ok'], result)
                        self.assertIn('REJECTED: ' + relative, result['error'])
                        self.assertIn('secret', result['error'])
                        self.assertEqual(traversed, [], 'Traversed credential-shaped directory')
                        self.assertEqual(reads, [], 'Read credential-shaped descendant')
                        self.assertFalse(output.exists(), 'Rejected build created output')

    def test_empty_secret_named_descendant_is_rejected(self):
        source, output = self.fixture()
        (source / 'docs' / 'Auth.Json').mkdir(parents=True)
        result = self.builder.build_archive(source, output)
        self.assertFalse(result['ok'], result)
        self.assertIn('REJECTED: docs/Auth.Json', result['error'])
        self.assertFalse(output.exists())

    def test_ordinary_nested_package_and_root_docs_are_preserved(self):
        source, output = self.fixture()
        expected = {
            'README.md': (source / 'README.md').read_bytes(),
            'hackathon_judge/__init__.py': (source / 'hackathon_judge/__init__.py').read_bytes(),
            'hackathon_judge/ordinary/worker.py': b'# Nested package source\r\n',
            'docs/MiXeD.md': b'Legitimate root documentation\r\n',
        }
        for relative, raw in expected.items():
            self.put(source, relative, raw)
        self.assert_members(self.builder.build_archive(source, output), expected)


class RootRelativeIncludeTests(PackagingFixture):
    def release_files(self, source):
        expected = {
            'README.md': (source / 'README.md').read_bytes(),
            'hackathon_judge/__init__.py': (source / 'hackathon_judge/__init__.py').read_bytes(),
        }
        # A real build/manifest assertion for every family in the release allowlist.
        for relative in (
                'plugin.yaml', '__init__.py', 'requirements-test.txt', 'LICENSE',
                '.gitignore', '.gitattributes', 'PLAN.md', 'hackathon_judge/data.json',
                'hackathon_judge/one/worker.py', 'sources/note.md', 'sources/data.json',
                'skills/judge-plugin/SKILL.md', 'tests/test_release_fixture.py',
                'scripts/tool.py', 'scripts/tool.sh', 'docs/guide.md',
                '.github/workflows/check.yml', 'submission/form.md'):
            expected[relative] = ('Valid release member: ' + relative + '\r\n').encode()
        for relative, raw in expected.items():
            self.put(source, relative, raw)
        return expected

    def test_nested_lookalike_release_roots_are_not_packaged(self):
        source, output = self.fixture()
        expected = self.release_files(source)
        for relative in tuple(expected):
            self.put(source, 'shadow/' + relative, b'UNRELATED_LOOKALIKE\n')
            self.put(source, 'deeper/shadow/' + relative, b'UNRELATED_LOOKALIKE\n')
        for relative in ('docs/nested/docs/decoy.md',
                         'hackathon_judge/resources/docs/decoy.md',
                         'hackathon_judge/resources/scripts/decoy.sh',
                         'docs/nested/not-direct.md', 'sources/nested/not-direct.md'):
            self.put(source, relative, b'NOT_IN_ROOT_ALLOWLIST\n')
        self.assert_members(self.builder.build_archive(source, output), expected)

    def test_recursive_package_sources_at_multiple_depths_are_kept(self):
        source, output = self.fixture()
        expected = self.release_files(source)
        for relative in ('hackathon_judge/first/second/worker.py',
                         'hackathon_judge/first/second/third/fourth/__init__.py',
                         'hackathon_judge/.environment/worker.py',
                         'hackathon_judge/auth.json.example/worker.py',
                         'hackathon_judge/private.pem.txt/worker.py'):
            expected[relative] = b'# Valid nested Python source\r\n'
            self.put(source, relative, expected[relative])
        self.assert_members(self.builder.build_archive(source, output), expected)

    def test_unincluded_unsafe_lookalike_file_still_rejects_build(self):
        for relative, raw, reason in (
                ('shadow/docs/AUTH.JSON', b'sensitive fixture\n', 'secret filename'),
                ('shadow/scripts/payload.pyc', b'not real bytecode', 'bytecode'),
                ('shadow/docs/payload.bin', b'MZfixture', 'binary magic'),
                ('shadow/docs/payload.zip', b'PK\x03\x04fixture', 'archive magic')):
            with self.subTest(relative=relative):
                source, output = self.fixture()
                self.put(source, relative, raw)
                result = self.builder.build_archive(source, output)
                self.assertFalse(result['ok'], result)
                self.assertTrue(any(relative in error and reason in error
                                    for error in result['rejected']), result)
                self.assertFalse(output.exists())


def assert_during_build_change_rejected(case, builder, source, output, mode):
    """Mutate real source after a real ZIP write, not between separate builds."""
    relative = 'hackathon_judge/added.py' if mode == 'add' else 'README.md'
    target = source / relative
    original_readme = (source / 'README.md').read_bytes()
    writes = []
    writestr = zipfile.ZipFile.writestr

    def write_then_mutate(archive, info, raw, *args, **kwargs):
        result = writestr(archive, info, raw, *args, **kwargs)
        writes.append(info.filename)
        if len(writes) == 1:
            if mode == 'remove':
                target.unlink()
            else:
                target.write_bytes(b'# Changed after inventory, during archive write\n')
        return result

    stderr = io.StringIO()
    with patch.object(zipfile.ZipFile, 'writestr', write_then_mutate), redirect_stderr(stderr):
        result = builder.build_archive(source, output)
    case.assertTrue(writes, 'Mutation hook did not run inside the actual ZIP writer')
    case.assertFalse(result['ok'], result)
    # Every changed source must appear exactly once, including newly added files.
    case.assertEqual(result.get('changed_during_build'), [relative], result)
    case.assertEqual(result['rejected'], [])
    case.assertIn('SOURCE_CHANGED: ' + relative, stderr.getvalue())
    case.assertIn('ERROR: 1 source file(s) changed during packaging.', stderr.getvalue())
    case.assertFalse((output / 'hackathon-judge-manifest.json').exists(),
                     'A failed build must not create a qualifying manifest')
    archive_path = output / 'hackathon-judge-source.zip'
    case.assertTrue(archive_path.is_file(), 'Failed ZIP is retained, not qualified')
    with zipfile.ZipFile(archive_path) as archive:
        case.assertIsNone(archive.testzip())
        case.assertEqual(archive.read('README.md'), original_readme)
        if mode == 'add':
            case.assertNotIn(relative, archive.namelist())
    archive_bytes = archive_path.read_bytes()
    retry = builder.build_archive(source, output)
    case.assertFalse(retry['ok'], retry)
    case.assertIn('Refusing to overwrite', retry['error'])
    case.assertEqual(archive_path.read_bytes(), archive_bytes)
    case.assertFalse((output / 'hackathon-judge-manifest.json').exists())


class DuringBuildChangeTests(PackagingFixture):
    def test_modified_source_rejected_by_actual_builder(self):
        source, output = self.fixture()
        assert_during_build_change_rejected(self, self.builder, source, output, 'modify')

    def test_added_source_rejected_and_reported_once_by_actual_builder(self):
        source, output = self.fixture()
        assert_during_build_change_rejected(self, self.builder, source, output, 'add')

    def test_removed_source_rejected_by_actual_builder(self):
        source, output = self.fixture()
        assert_during_build_change_rejected(self, self.builder, source, output, 'remove')


if __name__ == '__main__':
    unittest.main()
