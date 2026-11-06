"""Stable path-boundary regressions; native junction proof runs only on Windows."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hackathon_judge.engine import audit, review_template, source_integrity
from hackathon_judge.inventory import inventory, read_document
from hackathon_judge.review import assess_review

ROOT = Path(__file__).resolve().parents[1]
REPARSE_POINT = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)


class PathFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.candidate = self.base / 'candidate'
        self.candidate.mkdir()
        (self.candidate / 'plugin.yaml').write_bytes(b'name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.candidate / '__init__.py').write_bytes(b'def register(ctx):\n    pass\n')
        self.outside = self.base / 'outside'
        self.outside.mkdir()
        (self.outside / 'sentinel.md').write_bytes(b'OWNED_OUTSIDE_BOUNDARY_SENTINEL')

    def flagged(self, path):
        """Model lstat's public reparse attribute, without faking the platform."""
        original = Path.lstat
        def lstat(current, *args, **kwargs):
            info = original(current, *args, **kwargs)
            if current == path:
                fields = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                fields['st_file_attributes'] = getattr(info, 'st_file_attributes', 0) | REPARSE_POINT
                return SimpleNamespace(**fields)
            return info
        return patch.object(Path, 'lstat', lstat)

    def builder(self):
        spec = importlib.util.spec_from_file_location('path_boundary_builder', ROOT / 'scripts/build-source-archive.py')
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


class PortablePathTests(PathFixture):
    def test_regular_candidate_and_crlf_document_remain_readable(self):
        document = self.candidate / 'note.md'
        document.write_bytes(b'first\r\nsecond\r\n')
        _, info, data = inventory(self.candidate)
        self.assertTrue(info['complete'])
        self.assertEqual(data['note.md'], b'first\r\nsecond\r\n')
        self.assertEqual(read_document(document, root=self.candidate), 'first\r\nsecond\r\n')

    def test_document_containment_uses_path_components_not_string_prefix(self):
        sibling = self.base / 'candidate-other'
        sibling.mkdir()
        note = sibling / 'note.md'
        note.write_bytes(b'OWNED_SIBLING')
        with self.assertRaises(ValueError):
            read_document(note, root=self.candidate)

    def test_reparse_candidate_root_is_refused(self):
        with self.flagged(self.candidate), self.assertRaises(ValueError):
            inventory(self.candidate)

    def test_reparse_candidate_ancestor_is_refused(self):
        with self.flagged(self.base), self.assertRaises(ValueError):
            inventory(self.candidate)

    def test_reparse_subtree_is_pruned_without_reading_its_payload(self):
        flagged = self.candidate / 'blocked'
        flagged.mkdir()
        (flagged / 'sentinel.md').write_bytes(b'OWNED_REPARSE_SENTINEL')
        original = os.open
        def no_payload(path, *args, **kwargs):
            self.assertFalse(Path(path).is_relative_to(flagged), 'Read a reparse subtree payload')
            return original(path, *args, **kwargs)
        with self.flagged(flagged), patch('os.open', no_payload):
            _, info, data = inventory(self.candidate)
        self.assertFalse(info['complete'])
        self.assertNotIn('blocked/sentinel.md', data)

    def test_reparse_leaf_is_not_opened_by_inventory_or_document_reader(self):
        document = self.candidate / 'blocked.md'
        document.write_bytes(b'OWNED_REPARSE_SENTINEL')
        original = os.open
        def no_payload(path, *args, **kwargs):
            self.assertNotEqual(Path(path), document, 'Opened a reparse file')
            return original(path, *args, **kwargs)
        with self.flagged(document), patch('os.open', no_payload):
            _, info, data = inventory(self.candidate)
            self.assertFalse(info['complete'])
            self.assertNotIn(document.name, data)
            with self.assertRaises(ValueError):
                read_document(document)

    def test_reparse_document_ancestor_is_refused_with_or_without_scope(self):
        directory = self.candidate / 'documents'
        directory.mkdir()
        document = directory / 'note.md'
        document.write_bytes(b'OWNED_REPARSE_SENTINEL')
        for scope in (None, self.candidate):
            with self.subTest(scope=scope), self.flagged(directory), self.assertRaises(ValueError):
                read_document(document, root=scope)

    def test_reparse_root_argument_cannot_be_resolved_away(self):
        with self.flagged(self.candidate), self.assertRaises(ValueError):
            read_document(self.candidate / 'plugin.yaml', root=self.candidate)

    def test_referenced_reparse_evidence_invalidates_all_readiness(self):
        document = self.base / 'review.json'
        note = self.base / 'evidence.md'
        note.write_bytes(b'Owned regression evidence, not a real submission.')
        report = audit(self.candidate)
        value = review_template(report)
        value.update(reviewer={'name': 'Fixture Reviewer', 'role': 'operator'}, reviewed_at='2026-01-01T00:00:00+00:00')
        value['decisions']['CAT-03'].update(decision='pass', reason='Fixture evidence deliberately tests path refusal.',
                                          evidence=[{'path': note.name, 'sha256': hashlib.sha256(note.read_bytes()).hexdigest()}])
        document.write_bytes(json.dumps(value).encode('utf-8'))
        with self.flagged(note):
            result = assess_review(report, document)
        self.assertEqual(result['status'], 'invalid')
        self.assertFalse(any(gate['ready'] for gate in result['readiness'].values()))
        self.assertNotIn('Owned regression evidence', json.dumps(result))

    def test_reparse_source_root_is_rejected_by_archive_builder(self):
        with self.flagged(self.candidate):
            result = self.builder().build_archive(self.candidate, self.base / 'archive')
        self.assertFalse(result['ok'])

    def test_reparse_source_subtree_is_rejected_before_archive_reads(self):
        blocked = self.candidate / 'blocked'
        blocked.mkdir()
        (blocked / 'note.md').write_bytes(b'OWNED_REPARSE_SENTINEL')
        with self.flagged(blocked):
            result = self.builder().build_archive(self.candidate, self.base / 'archive')
        self.assertFalse(result['ok'])

    def test_archive_includes_checkout_byte_policy_unchanged(self):
        attributes = self.candidate / '.gitattributes'
        raw = b'* text=auto eol=lf\nsources/** -text\n'
        attributes.write_bytes(raw)
        result = self.builder().build_archive(self.candidate, self.base / 'archive')
        self.assertTrue(result['ok'], result)
        import zipfile
        with zipfile.ZipFile(result['archive']) as archive:
            self.assertEqual(archive.read('.gitattributes'), raw)

    def test_archive_credential_store_root_is_refused(self):
        source = self.base / '.aws' / 'plugin'
        source.mkdir(parents=True)
        (source / 'README.md').write_bytes(b'OWNED_STORE_ROOT_SENTINEL')
        result = self.builder().build_archive(source, self.base / 'archive')
        self.assertFalse(result['ok'])


@unittest.skipIf(os.name == 'nt', 'POSIX symlink fixtures; Windows junction fixtures run separately')
class PosixSymlinkTests(PathFixture):
    def test_symlink_candidate_root_is_refused_before_open(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.candidate, target_is_directory=True)
        with patch('os.open', side_effect=AssertionError('Opened through root alias')), self.assertRaises(ValueError):
            inventory(alias)

    def test_symlink_candidate_ancestor_is_refused_before_open(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.base, target_is_directory=True)
        with patch('os.open', side_effect=AssertionError('Opened through ancestor alias')), self.assertRaises(ValueError):
            inventory(alias / 'candidate')

    def test_link_before_dotdot_is_not_normalized_away(self):
        alias = self.candidate / 'alias'
        alias.symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            inventory(alias / '..' / 'candidate')

    def test_linked_descendants_leave_inventory_incomplete(self):
        (self.candidate / 'directory-alias').symlink_to(self.outside, target_is_directory=True)
        (self.candidate / 'file-alias.md').symlink_to(self.outside / 'sentinel.md')
        _, info, data = inventory(self.candidate)
        self.assertFalse(info['complete'])
        self.assertEqual(set(info['symlinks']), {'directory-alias', 'file-alias.md'})
        self.assertFalse(any('alias' in name for name in data))

    def test_broken_link_is_incomplete_without_hanging(self):
        (self.candidate / 'broken').symlink_to(self.outside / 'absent')
        _, info, data = inventory(self.candidate)
        self.assertFalse(info['complete'])
        self.assertNotIn('broken', data)

    def test_symlinked_policy_capture_is_refused_even_within_sources(self):
        sources = self.base / 'sources'
        sources.mkdir()
        raw = b'OWNED_CAPTURE'
        (sources / 'actual.md').write_bytes(raw)
        (sources / 'alias.md').symlink_to(sources / 'actual.md')
        (sources / 'manifest.json').write_bytes(json.dumps([{'file': 'sources/alias.md', 'sha256': hashlib.sha256(raw).hexdigest()}]).encode())
        with patch('hackathon_judge.engine.BASE', self.base), self.assertRaises(ValueError):
            source_integrity()

    def test_symlinked_archive_root_is_refused(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.candidate, target_is_directory=True)
        self.assertFalse(self.builder().build_archive(alias, self.base / 'archive')['ok'])

    def test_cli_rejects_root_alias_without_a_report(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.candidate, target_is_directory=True)
        done = subprocess.run([sys.executable, '-m', 'hackathon_judge', str(alias), '--format', 'json'],
                              cwd=ROOT, text=True, capture_output=True, timeout=30)
        self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
        self.assertIn('error', json.loads(done.stdout))
        self.assertNotIn('inventory', json.loads(done.stdout))

    def test_archive_cli_does_not_resolve_root_alias_before_guard(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.candidate, target_is_directory=True)
        done = subprocess.run([sys.executable, str(ROOT / 'scripts/build-source-archive.py'), str(alias),
                               '--output', str(self.base / 'archive')],
                              cwd=ROOT, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse((self.base / 'archive' / 'hackathon-judge-source.zip').exists())


@unittest.skipUnless(os.name == 'nt', 'Requires a real Windows filesystem; not modelled as native proof')
class NativeWindowsJunctionTests(PathFixture):
    def junction(self, path, target):
        done = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(path), str(target)],
                              text=True, capture_output=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.addCleanup(path.rmdir)
        self.assertFalse(path.is_symlink())
        self.assertTrue(path.lstat().st_file_attributes & REPARSE_POINT)
        return path

    def test_native_external_junction_subtree_is_not_inventoried(self):
        self.junction(self.candidate / 'alias', self.outside)
        original = os.open
        def no_outside_read(path, *args, **kwargs):
            self.assertFalse(Path(path).resolve().is_relative_to(self.outside), 'Opened outside candidate through a native junction')
            return original(path, *args, **kwargs)
        with patch('os.open', no_outside_read):
            _, info, data = inventory(self.candidate)
        self.assertFalse(info['complete'])
        self.assertNotIn('alias/sentinel.md', data)
        self.assertNotIn('OWNED_OUTSIDE_BOUNDARY_SENTINEL', repr(data))

    def test_native_junction_candidate_root_is_refused(self):
        alias = self.junction(self.base / 'alias', self.candidate)
        with self.assertRaises(ValueError):
            inventory(alias)

    def test_native_junction_candidate_ancestor_is_refused(self):
        alias = self.junction(self.base / 'alias', self.base)
        with self.assertRaises(ValueError):
            inventory(alias / 'candidate')

    def test_native_external_junction_document_without_scope_is_refused(self):
        alias = self.junction(self.candidate / 'alias', self.outside)
        with self.assertRaises(ValueError):
            read_document(alias / 'sentinel.md')

    def test_native_in_scope_junction_document_is_still_refused(self):
        actual = self.candidate / 'actual'
        actual.mkdir()
        (actual / 'note.md').write_bytes(b'OWNED_IN_SCOPE_JUNCTION')
        alias = self.junction(self.candidate / 'alias', actual)
        with self.assertRaises(ValueError):
            read_document(alias / 'note.md', root=self.candidate)

    def test_native_junction_source_is_not_archived(self):
        self.junction(self.candidate / 'alias', self.outside)
        result = self.builder().build_archive(self.candidate, self.base / 'archive')
        self.assertFalse(result['ok'])


if __name__ == '__main__':
    unittest.main()
