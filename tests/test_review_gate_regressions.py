"""Attachment E01-E04 controls against the later independent gates.

Synthetic/source-derived complete producer fixtures; no real validator, SDK
or Windows execution. Already-passing controls are not new RED evidence.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from hackathon_judge.engine import audit, finalise
from hackathon_judge.review import assess_review, template as review_template
from hackathon_judge.checks import local_checks
from hackathon_judge.inventory import inventory


_PAST_YEAR = 2023


class GateRegressionEvidence:
    """Complete source-derived 0.23.0 native producer shape.

    See docs/review-contract.md: ValidationReport.to_dict, native mandatory
    identities, Python probe declared checks and Desktop applicability.
    This helper intentionally does not depend on runtime-worker fixtures.
    """

    @staticmethod
    def write_evidence_dir(base, report):
        ev = base / 'evidence'
        ev.mkdir()
        note = ev / 'note.md'
        note.write_text('Synthetic fixture only; not a real operator review or validator execution.')
        ref = {'path': note.name, 'sha256': hashlib.sha256(note.read_bytes()).hexdigest()}
        doc = review_template(report)
        doc.update(reviewer={'name': 'Fixture Reviewer', 'role': 'operator'},
                   reviewed_at='2024-01-01T00:00:00+00:00',
                   event_year=_PAST_YEAR)
        for rid in doc['decisions']:
            doc['decisions'][rid].update(decision='pass', reason='Fixture synthetic evidence.',
                                         evidence=[ref.copy()])
        doc['submitted_at'] = f'{_PAST_YEAR}-11-01T12:00:00+00:00'
        names = ['manifest', 'manifest fields', 'requires_hermes', 'config schema',
                 'requires_env', 'oauth', 'loadable', 'python dependencies',
                 'capability probe', 'built-in tool collisions', 'security scan', 'no core override']
        files = {item['path'] for item in report['inventory']['files']}
        if '__init__.py' in files:
            names += ['declared tools', 'declared hooks', 'declared middleware']
        if 'plugin.js' in files or 'desktop/plugin.js' in files:
            names.append('desktop surface')
        receipt = {'schema_version': 1, 'kind': 'hermes-validation',
                   'candidate_sha256': report['inventory']['tree_sha256'],
                   'candidate_after_sha256': report['inventory']['tree_sha256'],
                   'install_deps': True, 'hermes_version': '0.23.0',
                   'hermes_commit': '2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19',
                   'policy_sha256': doc['policy_sha256'], 'exit_code': 0,
                   'command': ['hermes', 'plugins', 'validate', report['candidate'], '--install-deps', '--json'],
                   'report': {'ok': True, 'checks': [{'name': n, 'ok': True, 'detail': 'Synthetic fixture'} for n in names],
                              'warnings': [], 'isolation': {'verdict': 'host', 'host_ready': True,
                                                          'reasons': [], 'notes': [], 'ctx_methods': []}}}
        native = ev / 'native-receipt.json'
        native.write_text(json.dumps(receipt))
        doc['decisions']['PRE-03']['evidence'] = [{'path': native.name,
            'sha256': hashlib.sha256(native.read_bytes()).hexdigest(), 'kind': 'validation_receipt'}]
        return ev, doc

    @staticmethod
    def evaluate(report, doc, path):
        path.write_text(json.dumps(doc))
        return assess_review(report, path)


# ---------------------------------------------------------------------------
# E01 — catalog_accepted must NOT require catalog_submitted_at (PR timestamp)
# ---------------------------------------------------------------------------

class E01_CatalogAdmissionNoPrTimestampRequired(unittest.TestCase):
    """catalog_accepted should NOT add a timeline blocker when
    catalog_submitted_at (the PR-opening timestamp) is absent.  The individual
    contest requirements still independently govern form submission."""

    PAST_YEAR = _PAST_YEAR

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.candidate = self.base / 'candidate'
        self.candidate.mkdir()
        (self.candidate / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.candidate / '__init__.py').write_text('def register(ctx):\n    pass\n')
        self.report = audit(self.candidate)
        ev, self.doc = GateRegressionEvidence.write_evidence_dir(self.base, self.report)
        # Use a past year so timestamps are never "future"
        self.doc['event_year'] = self.PAST_YEAR
        # Both submitted_at and catalog_submitted_at are on time
        self.doc['submitted_at'] = f'{self.PAST_YEAR}-11-01T12:00:00+00:00'
        self.doc['catalog_submitted_at'] = f'{self.PAST_YEAR}-11-01T12:00:00+00:00'
        self.path = ev / 'review.json'

    def test_catalog_accepted_ready_with_both_timestamps(self):
        """E01: baseline — both timestamps present and timely."""
        result = GateRegressionEvidence.evaluate(self.report, self.doc, self.path)
        self.assertTrue(result['readiness']['catalog_accepted']['ready'])

    def test_catalog_accepted_no_blocker_when_catalog_submitted_at_missing(self):
        """E01: catalog_accepted must NOT have a 'timely_submission_evidence_required'
        blocker when only catalog_submitted_at is absent AND submitted_at is timely.
        The individual HACK-05 check still requires at least one timely timestamp."""
        self.doc.pop('catalog_submitted_at', None)
        result = GateRegressionEvidence.evaluate(self.report, self.doc, self.path)
        blockers = result['readiness']['catalog_accepted'].get('blockers', [])
        self.assertNotIn(
            'timely_submission_evidence_required', blockers,
            f"E01: catalog_accepted must not get a timeline blocker from missing "
            f"catalog_submitted_at; blockers={blockers}"
        )
        # Catalog admission is independent of contest-only evidence.
        self.assertTrue(
            result['readiness']['catalog_accepted']['ready'],
            f"catalog_accepted should be ready (submitted_at timely); "
            f"pending={result['readiness']['catalog_accepted'].get('pending')}, "
            f"blockers={blockers}"
        )
        # Stronger later-baseline behavior: no contest history or HACK rows needed.
        self.doc.update(event_year=None, submitted_at=None, catalog_submitted_at=None)
        for rid in ('HACK-01', 'HACK-02', 'HACK-03', 'HACK-04', 'HACK-05'):
            self.doc['decisions'][rid]['decision'] = 'fail'
        result = GateRegressionEvidence.evaluate(self.report, self.doc, self.path)
        self.assertTrue(result['readiness']['catalog_accepted']['ready'])
        self.assertFalse(result['readiness']['entry_submitted']['ready'])

    def test_entry_submitted_still_requires_submitted_at(self):
        """E01: entry_submitted still needs timely submitted_at."""
        result = GateRegressionEvidence.evaluate(self.report, self.doc, self.path)
        self.assertTrue(result['readiness']['entry_submitted']['ready'])

    def test_entry_submitted_blocks_when_submitted_at_missing(self):
        """E01: entry_submitted blocks when submitted_at is absent."""
        self.doc['submitted_at'] = None
        result = GateRegressionEvidence.evaluate(self.report, self.doc, self.path)
        self.assertFalse(result['readiness']['entry_submitted']['ready'])

    def test_entry_submitted_blocks_on_late_submission(self):
        """E01: entry_submitted blocks on late form (Nov 12 vs Nov 11 deadline)."""
        self.doc['submitted_at'] = f'{self.PAST_YEAR}-11-12T00:00:00+00:00'
        result = GateRegressionEvidence.evaluate(self.report, self.doc, self.path)
        self.assertFalse(result['readiness']['entry_submitted']['ready'])

    def test_catalog_accepted_no_timeliness_blocker_with_late_form(self):
        """E01: catalog_accepted gets no 'timely_submission_evidence_required'
        blocker even with late form — only entry_submitted checks that.
        Contest-only rows must not veto independent catalog admission."""
        self.doc.pop('catalog_submitted_at', None)
        self.doc['submitted_at'] = f'{self.PAST_YEAR}-11-12T00:00:00+00:00'
        result = GateRegressionEvidence.evaluate(self.report, self.doc, self.path)
        blockers = result['readiness']['catalog_accepted'].get('blockers', [])
        self.assertNotIn(
            'timely_submission_evidence_required', blockers,
            f"E01: catalog_accepted must not get a timeline blocker from late "
            f"form; blockers={blockers}"
        )
        self.assertTrue(result['readiness']['catalog_accepted']['ready'])
        self.assertFalse(result['readiness']['entry_submitted']['ready'])


# ---------------------------------------------------------------------------
# E02 — locale-only packs must pass entrypoint check
# ---------------------------------------------------------------------------

class E02_LocaleOnlyPackAccepted(unittest.TestCase):
    """A native plugin.yaml with provides_locales and locales/*.yaml but no
    Python/Desktop/portable/dashboard entrypoint must pass entrypoint check."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.candidate = self.base / 'candidate'
        self.candidate.mkdir()
        (self.candidate / 'plugin.yaml').write_text(
            'name: lang-pack\nversion: 1.0.0\ndescription: Language pack\n'
            'provides_locales:\n  - id: es\n  - id: fr\n'
        )
        (self.candidate / 'locales').mkdir()
        (self.candidate / 'locales/es.yaml').write_bytes('title: Español'.encode('utf-8'))
        (self.candidate / 'locales/fr.yaml').write_bytes('title: Français'.encode('utf-8'))

    def test_locale_only_pack_passes_entrypoint(self):
        """E02: locale-only pack must pass entrypoint check."""
        root, info, data = inventory(self.candidate)
        registrations = {'tools': set(), 'hooks': set(), 'dynamic': False}
        checks = []
        def add(key, rules, status, detail):
            checks.append({'id': key, 'rules': rules, 'status': status, 'detail': detail})
        local_checks(data, registrations, add)
        entry = next((c for c in checks if c['id'] == 'entrypoint'), None)
        self.assertIsNotNone(entry, "entrypoint check must exist")
        self.assertEqual(
            entry['status'], 'pass',
            f"E02: locale-only pack entrypoint should be 'pass', got '{entry['status']}': {entry['detail']}"
        )

    def test_locale_only_pack_produces_no_local_failure(self):
        """E02: locale-only pack must allow code_ready through audit."""
        report = audit(self.candidate)
        local_fails = [c for c in report['checks'] if c['status'] == 'fail']
        self.assertFalse(
            local_fails,
            f"E02: locale-only pack should have no local failures; got {local_fails}"
        )
        for name in ('es.yaml', 'fr.yaml'):
            with self.subTest(missing_declared_asset=name):
                asset = self.candidate / 'locales' / name
                original = asset.read_bytes()
                asset.unlink()
                try:
                    report = audit(self.candidate)
                    self.assertEqual(next(c for c in report['checks']
                                          if c['id'] == 'entrypoint')['status'], 'fail')
                finally:
                    asset.write_bytes(original)

    def test_undeclared_locale_files_are_not_an_entrypoint(self):
        (self.candidate / 'plugin.yaml').write_text(
            'name: lang-pack\nversion: 1.0.0\ndescription: Language pack\nprovides_locales: []\n')
        report = audit(self.candidate)
        self.assertEqual(next(c for c in report['checks'] if c['id'] == 'entrypoint')['status'], 'fail')


# ---------------------------------------------------------------------------
# E03 — root plugin.js must also require CAT-08 just like desktop/plugin.js
# ---------------------------------------------------------------------------

class E03_RootPluginJsRequiresCat08(unittest.TestCase):
    """A candidate with root plugin.js but CAT-08 set to not_applicable must
    have CAT-08 marked incomplete."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.candidate = self.base / 'candidate'
        self.candidate.mkdir()
        (self.candidate / 'plugin.yaml').write_text(
            'name: demo\nversion: 1.0.0\ndescription: Demo\n'
        )
        (self.candidate / '__init__.py').write_text('def register(ctx):\n    pass\n')
        (self.candidate / 'plugin.js').write_text('// root desktop plugin')
        self.report = audit(self.candidate)
        ev, self.doc = GateRegressionEvidence.write_evidence_dir(self.base, self.report)
        # Set CAT-08 to not_applicable
        self.doc['decisions']['CAT-08']['decision'] = 'not_applicable'
        self.path = ev / 'review.json'

    def test_root_plugin_js_cat08_not_applicable_blocked(self):
        """E03: root plugin.js must prevent CAT-08 from being not_applicable."""
        result = GateRegressionEvidence.evaluate(self.report, self.doc, self.path)
        cat08 = result['decisions'].get('CAT-08', {})
        self.assertFalse(
            cat08.get('complete', False),
            "E03: CAT-08 should be incomplete when candidate has plugin.js"
        )

    def test_root_plugin_js_code_ready_blocked(self):
        """E03: root plugin.js + CAT-08 not_applicable must block code_ready."""
        result = GateRegressionEvidence.evaluate(self.report, self.doc, self.path)
        self.assertFalse(
            result['readiness']['code_ready']['ready'],
            "E03: code_ready blocked when CAT-08 not_applicable but root plugin.js present"
        )

    def test_root_plugin_js_positive_review_control(self):
        self.doc['decisions']['CAT-08']['decision'] = 'pass'
        result = GateRegressionEvidence.evaluate(self.report, self.doc, self.path)
        self.assertTrue(result['readiness']['code_ready']['ready'], result['readiness']['code_ready'])


# ---------------------------------------------------------------------------
# E04 — year-boundary timezone conversion overflow must fail boundedly
# ---------------------------------------------------------------------------

class E04_YearBoundaryOverflowBounded(unittest.TestCase):
    """Extreme year timestamps that cause OverflowError during timezone
    conversion must be caught and result in invalid review, not an uncaught
    exception."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.candidate = self.base / 'candidate'
        self.candidate.mkdir()
        (self.candidate / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.candidate / '__init__.py').write_text('def register(ctx):\n    pass\n')
        self.report = audit(self.candidate)
        ev, self.doc = GateRegressionEvidence.write_evidence_dir(self.base, self.report)
        self.path = ev / 'review.json'

    def test_year_1_timestamp_returns_invalid_not_raises(self):
        """E04: submitted_at in year 0001 with UTC+14 must produce 'invalid'
        review status, not an uncaught OverflowError."""
        original = deepcopy(self.doc)
        for field in ('submitted_at', 'catalog_submitted_at', 'reviewed_at'):
            with self.subTest(field=field):
                self.doc = deepcopy(original)
                self.doc.update(event_year=1, submitted_at=None, catalog_submitted_at=None)
                self.doc[field] = '0001-01-01T00:00:00+14:00'
                result = GateRegressionEvidence.evaluate(self.report, self.doc, self.path)
                self.assertEqual(result['status'], 'invalid')
                self.assertTrue(all(not value['ready'] for value in result['readiness'].values()))
                report = finalise(deepcopy(self.report), self.path)
                self.assertEqual(report['assessment']['status'], 'invalid')
                self.assertFalse(report['certified'])

    def test_normal_year_timestamp_still_works(self):
        """E04: Normal year timestamp still works."""
        result = GateRegressionEvidence.evaluate(self.report, self.doc, self.path)
        self.assertEqual(result['status'], 'complete')


if __name__ == '__main__':
    unittest.main()
