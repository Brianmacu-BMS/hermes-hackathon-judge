"""Concrete regressions derived from independent review."""
from collections import Counter
import os
from pathlib import Path
import tempfile
import unittest

from hackathon_judge.engine import audit, requirements


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.root / '__init__.py').write_text('def register(ctx):\n    pass\n')

    def test_dynamic_builtins_aliases_are_flagged(self):
        snippets = [
            'from builtins import eval\neval("1+1")',
            'from builtins import eval as evaluate\nevaluate("1+1")',
            'import builtins as b\nb.exec("x=1")',
            'from builtins import compile as c\nc("1", "x", "eval")',
            'from builtins import __import__ as load\nload("run_agent")',
        ]
        for code in snippets:
            with self.subTest(code=code):
                (self.root / 'bad.py').write_text(code)
                self.assertTrue(any(f['rule'] == 'CAT-07' for f in audit(self.root)['findings']))

    def test_aliased_builtin_setattr_core_override_is_flagged(self):
        (self.root / 'bad.py').write_text('from builtins import setattr as change\nfrom run_agent import AIAgent as Agent\nchange(Agent, "run", None)\n')
        self.assertTrue(any(f['rule'] == 'CAT-09' for f in audit(self.root)['findings']))

    def test_every_requirement_has_explicit_automated_or_manual_check(self):
        report = audit(self.root)
        for rule in report['requirements']:
            with self.subTest(rule=rule['id']):
                self.assertTrue(rule['checks'])
                self.assertIn(rule['review_mode'], {'manual_only', 'automated_preflight_plus_manual'})
        quality = next(r for r in report['requirements'] if r['id'] == 'QUALITY-01')
        self.assertEqual(quality['review_mode'], 'manual_only')

    def test_requirement_groups_have_expected_coverage(self):
        self.assertEqual(dict(Counter(r['id'].split('-')[0] for r in requirements())), {'DEV': 12, 'CAT': 18, 'PRE': 5, 'HACK': 5, 'QUALITY': 5})

    def test_readme_without_disclosure_section_is_identified(self):
        (self.root / 'README.md').write_text('# Plugin\nA tool that does things.')
        check = next(c for c in audit(self.root)['checks'] if c['id'] == 'readme-disclosures')
        self.assertIn('lacks', check['detail'])

    def test_readme_disclosures_still_need_completeness_review(self):
        (self.root / 'README.md').write_text('# Plugin\n## Disclosures\nNo network or telemetry.')
        check = next(c for c in audit(self.root)['checks'] if c['id'] == 'readme-disclosures')
        self.assertEqual(check['status'], 'needs_review')
        self.assertIn('section', check['detail'])


if __name__ == '__main__':
    unittest.main()
