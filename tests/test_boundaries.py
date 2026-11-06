"""Regressions for filesystem limits and metadata precision."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hackathon_judge.engine import audit
from hackathon_judge.inventory import read_document


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.root / '__init__.py').write_text('def register(ctx):\n    pass\n')

    def check(self, report, key):
        return next(c for c in report['checks'] if c['id'] == key)

    def test_empty_directory_budget(self):
        for i in range(4):
            (self.root / str(i)).mkdir()
        report = audit(self.root, max_directories=2)
        self.assertFalse(report['inventory']['complete'])

    def test_walk_permission_errors_make_coverage_partial(self):
        def walk(root, *, followlinks, onerror):
            onerror(PermissionError(13, 'denied', str(root / 'private')))
            yield str(root), [], ['plugin.yaml', '__init__.py']
        with patch('hackathon_judge.inventory.os.walk', walk):
            self.assertFalse(audit(self.root)['inventory']['complete'])

    def test_secret_store_directory_is_not_traversed(self):
        vault = self.root / '.ssh'
        vault.mkdir()
        (vault / 'config').write_text('PRIVATE_SECRET_MARKER')
        report = audit(self.root)
        self.assertIn('.ssh/', report['inventory']['excluded_sensitive'])
        self.assertFalse(any(f['path'].startswith('.ssh/') for f in report['inventory']['files']))

    def test_explicit_document_in_secret_store_is_refused(self):
        vault = self.root / '.aws'
        vault.mkdir()
        file = vault / 'config'
        file.write_text('PRIVATE_SECRET_MARKER')
        with self.assertRaises(ValueError):
            read_document(file)

    def test_unquoted_semver_catalog_version_is_not_quoted(self):
        entry = self.root / 'entry.yaml'
        entry.write_text('name: demo\nrepo: https://github.com/example/demo\nsha: "' + 'a' * 40 + '"\nversion: 1.0.0\n')
        self.assertEqual(self.check(audit(self.root, catalog=entry), 'catalog-metadata')['status'], 'fail')

    def test_quoted_semver_catalog_version_is_accepted_locally(self):
        entry = self.root / 'entry.yaml'
        entry.write_text('name: demo\nrepo: https://github.com/example/demo\nsha: "' + 'a' * 40 + '"\nversion: "1.0.0"\n')
        self.assertEqual(self.check(audit(self.root, catalog=entry), 'catalog-metadata')['status'], 'pass')

    def test_stale_submission_digest_is_not_silently_accepted(self):
        evidence = self.root / 'submission.json'
        evidence.write_text(json.dumps({'tree_sha256': 'outdated'}))
        report = audit(self.root, submission=evidence)
        self.assertEqual(self.check(report, 'submission-binding')['status'], 'needs_review')


if __name__ == '__main__':
    unittest.main()
