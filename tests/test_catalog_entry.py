"""Catalog generation uses explicit source identifiers, never guessed pins."""
import importlib.util
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class CatalogEntryTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('catalog_entry_contract', ROOT / 'scripts/catalog-entry.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_exact_identifiers_and_manifest_version_preserved(self):
        sha = 'A' * 40
        repo = 'https://github.com/example/fixture'
        text = self.module.render(repo, sha, 'Fixture Maintainer', ROOT)
        result = yaml.safe_load(text)
        self.assertEqual(result['repo'], repo)
        self.assertEqual(result['sha'], sha)
        self.assertEqual(result['version'], '0.2.0')
        self.assertEqual(result['tier'], 'community')
        self.assertEqual(result['capabilities']['provides_tools'], ['hackathon_judge'])

    def test_short_sha_refused(self):
        with self.assertRaises(ValueError):
            self.module.render('https://github.com/example/fixture', 'abc123', 'Fixture Maintainer', ROOT)

    def test_credentialed_or_offsite_url_refused(self):
        for repo in ['https://user:password@github.com/example/fixture', 'http://github.com/example/fixture', 'https://example.net/a/b']:
            with self.subTest(repo=repo), self.assertRaises(ValueError):
                self.module.render(repo, 'a' * 40, 'Fixture Maintainer', ROOT)

    def test_bare_url_and_no_maintainer_refused(self):
        with self.assertRaises(ValueError):
            self.module.render('https://github.com', 'a' * 40, 'Fixture Maintainer', ROOT)
        with self.assertRaises(ValueError):
            self.module.render('https://github.com/example/fixture', 'a' * 40, '', ROOT)


if __name__ == '__main__':
    unittest.main()
