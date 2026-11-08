"""Credential-name comparisons are caseless; paths and payload bytes are not."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from hackathon_judge.engine import audit, review_template
from hackathon_judge.inventory import inventory, read_document
from hackathon_judge.review import assess_review

ROOT = Path(__file__).resolve().parents[1]
# Deliberately independent of production constants; builder-only names stay separate.
SCANNER_NAMES = ('.env', 'auth.json', 'credentials.json', 'secrets.json', 'id_rsa',
                 'id_ed25519', 'id_ecdsa', 'id_dsa', '.npmrc', '.pypirc', '.netrc',
                 '.git-credentials', '.dockercfg', '.env.local', '.env.production',
                 'private.pem', 'private.key', 'private.p12', 'private.pfx', 'private.kdbx')
BUILDER_ONLY = ('id_ed448', 'private.kdb', 'private.ovpn', 'private.age', 'private.gpg')
STORE_NAMES = ('.ssh', '.aws', '.gnupg', '.codex', '.kube')
MARKER = b'OWNED_CASE_REGRESSION_MARKER\r\n'


def spellings(names):
    for name in names:
        # Separate fixtures for every spelling, including on Windows.
        for spelling in (name, name.upper(), name.title()):
            yield spelling


class SensitiveFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.serial = 0

    def fixture(self):
        self.serial += 1
        base = self.base / str(self.serial)
        candidate = base / 'candidate'
        candidate.mkdir(parents=True)
        (candidate / 'plugin.yaml').write_bytes(b'name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (candidate / '__init__.py').write_bytes(b'def register(ctx):\n    pass\n')
        return base, candidate

    def put(self, root, name, raw=MARKER):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def observe_reads(self, target, seen):
        original = os.open
        def opened(path, *args, **kwargs):
            current = Path(path)
            if current == target or current.is_relative_to(target):
                seen.append(str(current))
            return original(path, *args, **kwargs)
        return patch('os.open', opened)

    def builder(self):
        spec = importlib.util.spec_from_file_location('sensitive_names_builder', ROOT / 'scripts/build-source-archive.py')
        if spec is None or spec.loader is None:
            raise RuntimeError('Could not load source archive builder')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def review(self, base, candidate, name):
        report = audit(candidate)
        root = base / 'evidence'
        root.mkdir()
        note = self.put(root, name)
        value = review_template(report)
        value.update(reviewer={'name': 'Fixture Reviewer', 'role': 'operator'},
                     reviewed_at='2026-01-01T00:00:00+00:00')
        value['decisions']['CAT-03'].update(
            decision='pass', reason='Owned fixture checks credential-name rejection.',
            evidence=[{'path': name, 'sha256': hashlib.sha256(MARKER).hexdigest()}])
        document = self.put(root, 'review.json', json.dumps(value).encode('utf-8'))
        return report, document, note


class InventorySensitiveNameTests(SensitiveFixture):
    def test_filename_prefix_suffix_excluded_before_content_read(self):
        for name in spellings(SCANNER_NAMES):
            with self.subTest(name=name):
                _, candidate = self.fixture()
                target = self.put(candidate, name)
                seen = []
                with self.observe_reads(target, seen):
                    _, info, data = inventory(candidate)
                self.assertEqual(seen, [], 'Credential-shaped file was opened')
                self.assertFalse(info['complete'])
                self.assertIn(name, info['excluded_sensitive'])
                self.assertNotIn(name, data)
                self.assertNotIn(name, [item['path'] for item in info['files']])

    def test_sensitive_directories_pruned_before_descendant_content_read(self):
        for name in spellings(STORE_NAMES + ('.env.local', 'private.pem', 'auth.json')):
            with self.subTest(name=name):
                _, candidate = self.fixture()
                target = candidate / name
                self.put(target, 'note.md')
                seen = []
                with self.observe_reads(target, seen):
                    _, info, data = inventory(candidate)
                self.assertEqual(seen, [])
                self.assertFalse(info['complete'])
                self.assertIn(name + '/', info['excluded_sensitive'])
                self.assertNotIn(name + '/note.md', data)

    def test_sensitive_root_and_ancestor_rejected(self):
        for name in spellings(STORE_NAMES + ('.env', 'auth.json', '.env.local', 'private.pem')):
            for nested in (False, True):
                with self.subTest(name=name, nested=nested):
                    base, _ = self.fixture()
                    root = base / name
                    if nested:
                        root /= 'candidate'
                    root.mkdir(parents=True)
                    self.put(root, 'README.md')
                    with patch('os.open', side_effect=AssertionError('Opened credential-store candidate')):
                        with self.assertRaisesRegex(ValueError, 'Secret-store candidate'):
                            inventory(root)

    def test_ordinary_names_and_builder_only_names_keep_original_paths_and_bytes(self):
        _, candidate = self.fixture()
        names = ('Docs/MiXeD.md', '.environment', 'auth.json.example', 'private.pem.txt',
                 'SSH/note.md', *BUILDER_ONLY)
        for name in names:
            self.put(candidate, name)
        _, info, data = inventory(candidate)
        self.assertTrue(info['complete'])
        for name in names:
            self.assertEqual(data[name], MARKER)
            item = next(item for item in info['files'] if item['path'] == name)
            self.assertEqual(item['sha256'], hashlib.sha256(MARKER).hexdigest())


class DocumentSensitiveNameTests(SensitiveFixture):
    def test_filename_prefix_suffix_rejected_before_content_read(self):
        for name in spellings(SCANNER_NAMES):
            with self.subTest(name=name):
                _, candidate = self.fixture()
                target = self.put(candidate, name)
                with patch('os.open', side_effect=AssertionError('Opened credential document')):
                    with self.assertRaisesRegex(ValueError, 'Secret document'):
                        read_document(target, root=candidate)

    def test_sensitive_directory_ancestors_rejected_with_or_without_root(self):
        for name in spellings(STORE_NAMES + ('.env', 'auth.json', '.env.local', 'private.pem')):
            for scoped in (False, True):
                with self.subTest(name=name, scoped=scoped):
                    _, candidate = self.fixture()
                    target = self.put(candidate, name + '/note.md')
                    with patch('os.open', side_effect=AssertionError('Opened store descendant')):
                        with self.assertRaisesRegex(ValueError, 'Secret document'):
                            read_document(target, root=candidate if scoped else None)

    def test_ordinary_document_preserves_original_case_and_crlf(self):
        _, candidate = self.fixture()
        target = self.put(candidate, 'Docs/MiXeD.md')
        self.assertEqual(read_document(target, root=candidate), MARKER.decode('utf-8'))


class EvidenceSensitiveNameTests(SensitiveFixture):
    def test_referenced_sensitive_files_are_invalid_before_content_read(self):
        for name in spellings(('.env', 'auth.json', '.env.local', 'private.pem')):
            with self.subTest(name=name):
                base, candidate = self.fixture()
                report, document, target = self.review(base, candidate, name)
                seen = []
                with self.observe_reads(target, seen):
                    result = assess_review(report, document)
                self.assertEqual(seen, [], 'Evidence caller opened credential-shaped file')
                self.assertEqual(result['status'], 'invalid')
                self.assertFalse(any(item['ready'] for item in result['readiness'].values()))
                self.assertNotIn(name, [item['path'] for item in result['evidence_checked']])
                self.assertNotIn(MARKER.decode().strip(), json.dumps(result))

    def test_referenced_sensitive_store_descendants_are_invalid_before_content_read(self):
        for name in spellings(STORE_NAMES):
            with self.subTest(name=name):
                base, candidate = self.fixture()
                report, document, target = self.review(base, candidate, name + '/note.md')
                seen = []
                with self.observe_reads(target, seen):
                    result = assess_review(report, document)
                self.assertEqual(seen, [])
                self.assertEqual(result['status'], 'invalid')
                self.assertFalse(any(item['ready'] for item in result['readiness'].values()))

    def test_ordinary_evidence_is_read_and_hash_checked(self):
        base, candidate = self.fixture()
        report, document, target = self.review(base, candidate, 'Docs/MiXeD.md')
        seen = []
        with self.observe_reads(target, seen):
            result = assess_review(report, document)
        self.assertTrue(seen)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['evidence_checked'], [{'path': 'Docs/MiXeD.md',
                         'sha256': hashlib.sha256(MARKER).hexdigest(), 'kind': 'document'}])


class ArchiveSensitiveNameTests(SensitiveFixture):
    def test_included_docs_sensitive_files_rejected_before_read_without_archive(self):
        builder = self.builder()
        for name in spellings(SCANNER_NAMES + BUILDER_ONLY):
            with self.subTest(name=name):
                base, candidate = self.fixture()
                relative = 'docs/' + name
                self.assertTrue(builder._included(relative), 'Fixture must hit actual archive include rules')
                target = self.put(candidate, relative)
                seen = []
                with self.observe_reads(target, seen):
                    result = builder.build_archive(candidate, base / 'output')
                self.assertEqual(seen, [], 'Builder opened credential-shaped included file')
                self.assertFalse(result['ok'])
                self.assertTrue(any(relative in reason for reason in result['rejected']), result)
                self.assertFalse((base / 'output' / 'hackathon-judge-source.zip').exists())
                self.assertFalse((base / 'output' / 'hackathon-judge-manifest.json').exists())

    def test_excluded_root_sensitive_file_still_rejected_before_read(self):
        builder = self.builder()
        for name in ('auth.json', 'AUTH.JSON', 'Auth.Json', '.env', '.ENV'):
            with self.subTest(name=name):
                base, candidate = self.fixture()
                self.assertFalse(builder._included(name))
                target = self.put(candidate, name)
                seen = []
                with self.observe_reads(target, seen):
                    result = builder.build_archive(candidate, base / 'output')
                self.assertEqual(seen, [])
                self.assertFalse(result['ok'])
                self.assertFalse((base / 'output').exists())

    def test_sensitive_directories_rejected_without_descendant_reads_or_archive(self):
        builder = self.builder()
        for name in spellings(STORE_NAMES):
            with self.subTest(name=name):
                base, candidate = self.fixture()
                target = candidate / name
                self.put(target, 'note.md')
                with patch('os.open', side_effect=AssertionError('Read store descendant')):
                    result = builder.build_archive(candidate, base / 'output')
                self.assertFalse(result['ok'])
                self.assertIn('credential-store directory', result['error'])
                self.assertFalse((base / 'output').exists())

    def test_sensitive_root_and_ancestor_rejected_without_archive(self):
        builder = self.builder()
        for name in spellings(STORE_NAMES + ('.env', 'auth.json', '.env.local', 'private.pem')):
            for nested in (False, True):
                with self.subTest(name=name, nested=nested):
                    base, _ = self.fixture()
                    root = base / name
                    if nested:
                        root /= 'candidate'
                    root.mkdir(parents=True)
                    self.put(root, 'README.md')
                    with patch('os.open', side_effect=AssertionError('Read credential-store root')):
                        result = builder.build_archive(root, base / 'output')
                    self.assertFalse(result['ok'])
                    self.assertIn('REJECTED', result['error'])
                    self.assertFalse((base / 'output').exists())

    def test_ordinary_archive_keeps_original_member_names_and_payload_bytes(self):
        base, candidate = self.fixture()
        raw = b'Original MiXeD bytes\r\n'
        names = ('docs/MiXeD.md', 'docs/.environment', 'docs/auth.json.example', 'docs/private.pem.txt')
        for name in names:
            self.put(candidate, name, raw)
        result = self.builder().build_archive(candidate, base / 'output')
        self.assertTrue(result['ok'], result)
        with zipfile.ZipFile(result['archive']) as archive:
            for name in names:
                self.assertEqual(archive.read(name), raw)
        manifest = json.loads(Path(result['manifest']).read_text(encoding='utf-8'))
        for name in names:
            item = next(item for item in manifest['files'] if item['path'] == name)
            self.assertEqual(item['sha256'], hashlib.sha256(raw).hexdigest())


@unittest.skipUnless(os.name == 'nt', 'Requires native Windows alternate-case samefile lookup')
class NativeWindowsSensitiveAliasTests(SensitiveFixture):
    def test_uppercase_disk_and_lowercase_alias_are_samefile_and_both_refused(self):
        for disk_name, alias_name in (('.ENV', '.env'), ('AUTH.JSON', 'auth.json'),
                                      ('.EnV.Local', '.env.local'), ('Private.PeM', 'private.pem'),
                                      ('.AWS/note.md', '.aws/note.md')):
            with self.subTest(disk=disk_name, alias=alias_name):
                _, candidate = self.fixture()
                target = self.put(candidate, disk_name)
                alias = candidate / alias_name
                self.assertTrue(os.path.samefile(target, alias))
                with patch('os.open', side_effect=AssertionError('Read native credential alias')):
                    for path in (target, alias):
                        with self.subTest(path=str(path)):
                            with self.assertRaisesRegex(ValueError, 'Secret document'):
                                read_document(path, root=candidate)
                _, info, data = inventory(candidate)
                self.assertFalse(info['complete'])
                self.assertNotIn(disk_name, data)


if __name__ == '__main__':
    unittest.main()
