"""End-to-end review gates and real packaging refusal behavior."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_evidence_review as fixtures
from hackathon_judge.engine import audit
from hackathon_judge.review import ADMISSION_RULES, ENTRY_RULES, SUBMISSION_RULES

ROOT = Path(__file__).resolve().parents[1]


class ReviewIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ReviewEvidenceTests('test_missing_review_stays_unreviewed')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def cli(self, gate):
        f = self.fixture
        path = f.evidence / 'review.json'
        path.write_text(json.dumps(f.doc))
        run = subprocess.run([sys.executable, '-m', 'hackathon_judge', str(f.candidate), '--review', str(path), '--gate', gate, '--format', 'json'], cwd=ROOT,
                             env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, text=True, capture_output=True, timeout=20)
        return run.returncode, json.loads(run.stdout)

    def test_real_cli_returns_zero_for_completed_code_gate(self):
        for rid in SUBMISSION_RULES | ENTRY_RULES | ADMISSION_RULES:
            self.fixture.doc['decisions'][rid]['decision'] = 'pending'
        code, report = self.cli('code_ready')
        self.assertEqual(code, 0)
        self.assertEqual(report['verdict'], 'reviewed_code_ready')
        self.assertFalse(report['certified'])

    def test_real_cli_does_not_confuse_code_with_submission(self):
        self.fixture.doc['decisions']['HACK-02']['decision'] = 'pending'
        code, report = self.cli('ready_to_submit')
        self.assertEqual(code, 2)
        self.assertTrue(report['assessment']['readiness']['code_ready']['ready'])

    def test_changed_evidence_removes_cli_success(self):
        (self.fixture.evidence / 'review.md').write_text('changed after review')
        code, report = self.cli('code_ready')
        self.assertEqual(code, 2)
        self.assertEqual(report['assessment']['status'], 'invalid')

    def test_warning_receipt_needs_exact_acknowledgement(self):
        f = self.fixture
        f.validator['report']['warnings'] = ['fixture caution: operator must inspect actual source']
        f.attach_validator()
        self.assertFalse(f.evaluate()['readiness']['code_ready']['ready'])
        f.doc['decisions']['PRE-03']['warnings_reviewed_sha256'] = hashlib.sha256(json.dumps(f.validator['report']['warnings'], sort_keys=True).encode()).hexdigest()
        self.assertTrue(f.evaluate()['readiness']['code_ready']['ready'])

    def test_evidence_hashes_preserve_crlf_bytes(self):
        f = self.fixture
        path = f.evidence / 'windows-note.md'
        path.write_bytes(b'Fixture evidence\r\nSecond line\r\n')
        f.doc['decisions']['CAT-03']['evidence'] = [{'path': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}]
        self.assertTrue(f.evaluate()['readiness']['code_ready']['ready'])

    def test_boolean_is_not_a_schema_version(self):
        self.fixture.doc['schema_version'] = True
        self.assertEqual(self.fixture.evaluate()['status'], 'invalid')

    def test_boolean_validator_schema_cannot_qualify_code(self):
        self.fixture.validator['schema_version'] = True
        self.fixture.attach_validator()
        self.assertFalse(self.fixture.evaluate()['readiness']['code_ready']['ready'])

    def test_expired_event_cannot_be_ready_to_submit_now(self):
        from datetime import datetime, timezone
        year = datetime.now(timezone.utc).year - 1
        self.fixture.doc['event_year'] = year
        self.fixture.doc['reviewed_at'] = f'{year}-11-10T00:00:00+00:00'
        result = self.fixture.evaluate()
        self.assertTrue(result['readiness']['code_ready']['ready'])
        self.assertFalse(result['readiness']['ready_to_submit']['ready'])

    def test_aggregate_evidence_bytes_are_bounded(self):
        f = self.fixture
        refs = []
        raw = b'x' * 1_000_000
        digest = hashlib.sha256(raw).hexdigest()
        for index in range(17):
            path = f.evidence / f'oversized-set-{index}.md'
            path.write_bytes(raw)
            refs.append({'path': path.name, 'sha256': digest})
        f.doc['decisions']['CAT-03']['evidence'] = refs
        self.assertEqual(f.evaluate()['status'], 'invalid')

    def test_refreshing_any_policy_source_invalidates_old_digest(self):
        import shutil
        import hackathon_judge.review as review
        target = self.fixture.base / 'policy-copy'
        (target / 'hackathon_judge').mkdir(parents=True)
        shutil.copy2(ROOT / 'hackathon_judge/requirements.json', target / 'hackathon_judge/requirements.json')
        shutil.copytree(ROOT / 'sources', target / 'sources')
        with patch.object(review, '__file__', str(target / 'hackathon_judge/review.py')):
            before = review.policy_digest()
            path = target / 'sources/developer-guide.md'
            path.write_text(path.read_text() + '\nFixture authorized source refresh\n')
            manifest = target / 'sources/manifest.json'
            index = json.loads(manifest.read_text())
            for entry in index:
                if entry['id'] == 'developer-guide':
                    entry['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(index))
            self.assertNotEqual(review.policy_digest(), before)

    def test_netrc_is_never_inventoried_as_source(self):
        f = self.fixture
        (f.candidate / '.netrc').write_text('PRIVATE_MARKER_NEVER_READ')
        report = audit(f.candidate)
        self.assertIn('.netrc', report['inventory']['excluded_sensitive'])
        self.assertFalse(report['inventory']['complete'])
        self.assertFalse(any(item['path'] == '.netrc' for item in report['inventory']['files']))


class PackagingBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'source'
        self.root.mkdir()
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: demo\n')
        (self.root / '__init__.py').write_text('def register(ctx):\n    pass\n')
        self.output = self.root.parent / 'release'
        spec = importlib.util.spec_from_file_location('judge_release_builder_contract', ROOT / 'scripts/build-source-archive.py')
        self.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.builder)

    def test_root_entrypoint_and_workflow_reach_archive(self):
        path = self.root / '.github/workflows/tests.yml'
        path.parent.mkdir(parents=True)
        path.write_text('name: tests\n')
        result = self.builder.build_archive(self.root, self.output)
        self.assertTrue(result['ok'])
        import zipfile
        with zipfile.ZipFile(result['archive']) as archive:
            self.assertIn('__init__.py', archive.namelist())
            self.assertIn('.github/workflows/tests.yml', archive.namelist())

    def test_concurrent_source_mutation_is_really_rejected(self):
        import zipfile
        original = zipfile.ZipFile.writestr
        changed = False
        def mutate(archive, *args, **kwargs):
            nonlocal changed
            result = original(archive, *args, **kwargs)
            if not changed:
                (self.root / '__init__.py').write_text('changed while packaging')
                changed = True
            return result
        with patch.object(zipfile.ZipFile, 'writestr', mutate):
            result = self.builder.build_archive(self.root, self.output)
        self.assertFalse(result['ok'])
        self.assertIn('__init__.py', result['changed_during_build'])

    def test_existing_release_is_never_overwritten(self):
        first = self.builder.build_archive(self.root, self.output)
        archive = Path(first['archive'])
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertFalse(self.builder.build_archive(self.root, self.output)['ok'])
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), digest)

    def test_unknown_symlink_cannot_be_hidden_by_include_filter(self):
        target = self.root.parent / 'outside.txt'
        target.write_text('outside')
        (self.root / 'unknown-link.txt').symlink_to(target)
        self.assertFalse(self.builder.build_archive(self.root, self.output)['ok'])

    def test_secret_suffix_refused_without_echoing_value(self):
        (self.root / '.env.testing').write_text('PRIVATE_VALUE_MARKER')
        result = self.builder.build_archive(self.root, self.output)
        self.assertFalse(result['ok'])
        self.assertNotIn('PRIVATE_VALUE_MARKER', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
