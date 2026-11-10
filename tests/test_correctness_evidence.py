"""Behavioral receipt/timing regressions. Synthetic claims, never native execution."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import unittest
from unittest.mock import patch

import test_evidence_review as fixtures
from hackathon_judge.engine import audit


class Clock(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 11, 12, 12, tzinfo=timezone.utc).astimezone(tz)


class EvidenceCorrectnessTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ReviewEvidenceTests('test_missing_review_stays_unreviewed')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def code_ready(self):
        self.f.attach_validator()
        return self.f.evaluate()['readiness']['code_ready']['ready']

    def test_catalog_admission_without_pr_time_is_independent_of_contest_rows(self):
        # Reviewer minimum, then stronger generic catalog admission control.
        result = self.timed_review(catalog=None)
        self.assertTrue(result['readiness']['entry_submitted']['ready'])
        self.assertTrue(result['readiness']['catalog_accepted']['ready'])
        for rid in ('HACK-01', 'HACK-02', 'HACK-03', 'HACK-04', 'HACK-05'):
            self.f.doc['decisions'][rid]['decision'] = 'pending'
        self.f.doc.update(event_year=None, submitted_at=None, catalog_submitted_at=None,
                          reviewed_at='2026-01-01T00:00:00+00:00')
        result = self.f.evaluate()
        self.assertTrue(result['readiness']['catalog_accepted']['ready'])
        self.assertFalse(result['readiness']['entry_submitted']['ready'])
        for rid in ('CAT-01', 'PRE-05', 'CAT-02', 'CAT-05', 'PRE-01', 'PRE-04'):
            with self.subTest(required=rid):
                self.f.doc['decisions'][rid]['decision'] = 'pending'
                self.assertFalse(self.f.evaluate()['readiness']['catalog_accepted']['ready'])
                self.f.doc['decisions'][rid]['decision'] = 'pass'

    def test_catalog_admission_is_not_vetoed_by_failed_contest_only_rows(self):
        from hackathon_judge.engine import finalise
        self.f.doc.update(event_year=None, submitted_at=None, catalog_submitted_at=None)
        for rid in ('HACK-01', 'HACK-02', 'HACK-03', 'HACK-04', 'HACK-05'):
            self.f.doc['decisions'][rid]['decision'] = 'fail'
        self.f.report['checks'].append({'id': 'demo-duration', 'rules': ['HACK-03'],
                                       'status': 'fail', 'detail': 'Contest-only duration failure'})
        result = self.f.evaluate()
        self.assertTrue(result['readiness']['catalog_accepted']['ready'])
        self.assertFalse(result['readiness']['entry_submitted']['ready'])
        report = finalise(deepcopy(self.f.report), self.f.evidence / 'review.json')
        self.assertEqual(report['verdict'], 'reviewed_catalog_accepted')
        self.assertEqual(report['preflight_verdict'], 'blocked')

    def test_manifest_only_locale_pack_can_reach_ready_with_complete_locale_receipt(self):
        (self.f.candidate / '__init__.py').unlink()
        manifest = self.f.candidate / 'plugin.yaml'
        manifest.write_text(manifest.read_text() + 'provides_locales: [pl]\n')
        (self.f.candidate / 'locales').mkdir()
        (self.f.candidate / 'locales/pl.yaml').write_text('greeting: hello\n')
        self.rebind_candidate()
        checks = self.f.validator['report']['checks']
        self.f.validator['report']['checks'] = [c for c in checks if not c['name'].startswith('declared ')]
        self.f.validator['report']['checks'].append({'name': 'locale pl', 'ok': True, 'detail': 'fixture'})
        self.assertTrue(self.code_ready())
        self.f.validator['report']['checks'].pop()
        self.assertFalse(self.code_ready())

    def test_manifest_only_missing_or_malformed_locale_entry_still_fails(self):
        (self.f.candidate / '__init__.py').unlink()
        manifest = self.f.candidate / 'plugin.yaml'
        original = manifest.read_text()
        for declaration in ('', 'provides_locales: []\n', 'provides_locales: [42]\n',
                            'provides_locales: [invalid!]\n', 'provides_locales: [pl]\n'):
            with self.subTest(declaration=declaration):
                manifest.write_text(original + declaration)
                self.rebind_candidate()
                self.assertEqual(next(c for c in self.f.report['checks'] if c['id'] == 'entrypoint')['status'], 'fail')
                self.assertFalse(self.code_ready())

    def test_root_desktop_cannot_waive_cat08(self):
        (self.f.candidate / 'plugin.js').write_text('export function activate(ctx) {}')
        self.rebind_candidate()
        self.f.validator['report']['checks'].append({'name': 'desktop surface', 'ok': True, 'detail': 'fixture'})
        self.f.doc['decisions']['CAT-08']['decision'] = 'not_applicable'
        self.assertFalse(self.code_ready())
        self.f.doc['decisions']['CAT-08']['decision'] = 'pass'
        self.assertTrue(self.code_ready())

    def test_timezone_boundary_timestamps_are_bounded_invalid_through_finalise(self):
        from hackathon_judge.engine import finalise
        for field in ('submitted_at', 'catalog_submitted_at', 'reviewed_at'):
            with self.subTest(field=field):
                self.f.doc.update(event_year=1, reviewed_at='2026-01-01T00:00:00+00:00',
                                  submitted_at=None, catalog_submitted_at=None)
                self.f.doc[field] = '0001-01-01T00:00:00+14:00'
                result = self.f.evaluate()
                self.assertEqual(result['status'], 'invalid')
                self.assertTrue(all(not g['ready'] for g in result['readiness'].values()))
                report = finalise(deepcopy(self.f.report), self.f.evidence / 'review.json')
                self.assertEqual(report['assessment']['status'], 'invalid')
                self.assertFalse(report['certified'])

    def test_both_qualified_native_pins_accept_complete_report(self):
        for version, commit in [('0.22.5', 'bf0203a794a07aac3ff764972ab9087baa4e4f4e'),
                                ('0.23.0', '2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19')]:
            with self.subTest(version=version):
                self.f.validator.update(hermes_version=version, hermes_commit=commit)
                self.assertTrue(self.code_ready())

    def test_five_name_fabrication_is_not_complete_native_report(self):
        common = {'manifest', 'loadable', 'capability probe', 'security scan', 'no core override'}
        self.f.validator['report']['checks'] = [c for c in self.f.validator['report']['checks'] if c['name'] in common]
        self.assertFalse(self.code_ready())

    def test_every_native_obligatory_identity_is_required(self):
        original = deepcopy(self.f.validator['report']['checks'])
        for check in original:
            with self.subTest(missing=check['name']):
                self.f.validator['report']['checks'] = [c for c in original if c['name'] != check['name']]
                self.assertFalse(self.code_ready())

    def test_warnings_must_be_explicit_and_well_formed(self):
        for value in ['absent', None, {}, 'none', [False], [1]]:
            with self.subTest(value=value):
                if value == 'absent':
                    self.f.validator['report'].pop('warnings', None)
                else:
                    self.f.validator['report']['warnings'] = value
                self.assertFalse(self.code_ready())

    def test_unqualified_or_missing_producer_identity_fails_closed(self):
        original = deepcopy(self.f.validator)
        for key, value in [('hermes_version', None), ('hermes_commit', None), ('hermes_version', '0.24.0'),
                           ('hermes_commit', '0' * 40), ('hermes_version', True)]:
            with self.subTest(key=key, value=value):
                self.f.validator = deepcopy(original)
                self.f.validator[key] = value
                self.assertFalse(self.code_ready())

    def test_receipt_policy_binding_is_required(self):
        for value in [None, '0' * 64]:
            with self.subTest(value=value):
                self.f.validator['policy_sha256'] = value
                self.assertFalse(self.code_ready())

    def test_native_report_cannot_masquerade_as_portable(self):
        self.f.validator['report']['checks'] = [{'name': n, 'ok': True, 'detail': 'fixture'} for n in
                                               ['portable manifest', 'manifest fields', 'config schema', 'security scan']]
        self.assertFalse(self.code_ready())

    def test_exact_report_types_and_details(self):
        original = deepcopy(self.f.validator)
        for field, value in [('ok', 1), ('detail', None), ('name', 1)]:
            with self.subTest(field=field):
                self.f.validator = deepcopy(original)
                self.f.validator['report']['checks'][0][field] = value
                self.assertFalse(self.code_ready())

    def test_isolation_is_retained_complete_official_output(self):
        self.f.validator['report'].pop('isolation')
        self.assertFalse(self.code_ready())

    def test_duplicate_and_unknown_checks_cannot_replace_real_identity(self):
        self.f.validator['report']['checks'].append(deepcopy(self.f.validator['report']['checks'][0]))
        self.assertFalse(self.code_ready())

    def test_reviewed_warnings_digest_still_exact(self):
        warnings = ['synthetic caution']
        self.f.validator['report']['warnings'] = warnings
        self.assertFalse(self.code_ready())
        self.f.doc['decisions']['PRE-03']['warnings_reviewed_sha256'] = hashlib.sha256(json.dumps(warnings, sort_keys=True).encode()).hexdigest()
        self.assertTrue(self.code_ready())
        self.f.validator['report']['warnings'].append('another caution')
        self.assertFalse(self.code_ready())

    def rebind_candidate(self):
        self.f.report = audit(self.f.candidate)
        digest = self.f.report['inventory']['tree_sha256']
        self.f.doc['candidate_sha256'] = digest
        self.f.validator.update(candidate_sha256=digest, candidate_after_sha256=digest)

    def test_desktop_branch_requires_desktop_surface_check(self):
        (self.f.candidate / 'desktop').mkdir()
        (self.f.candidate / 'desktop/plugin.js').write_text('export function activate(ctx) {}')
        self.rebind_candidate()
        self.assertFalse(self.code_ready())
        self.f.validator['report']['checks'].append({'name': 'desktop surface', 'ok': True, 'detail': 'fixture'})
        self.assertTrue(self.code_ready())

    def test_manifest_only_probe_does_not_require_unproduced_declared_checks(self):
        (self.f.candidate / '__init__.py').unlink()
        (self.f.candidate / 'plugin.json').write_text('{"name":"demo"}')
        self.rebind_candidate()
        self.f.validator['report']['checks'] = [c for c in self.f.validator['report']['checks'] if not c['name'].startswith('declared ')]
        self.f.validator['report']['warnings'] = ['no __init__.py — capability probe skipped (manifest-only plugin)']
        self.f.doc['decisions']['PRE-03']['warnings_reviewed_sha256'] = hashlib.sha256(json.dumps(self.f.validator['report']['warnings'], sort_keys=True).encode()).hexdigest()
        self.assertTrue(self.code_ready())

    def test_declared_locale_surfaces_cannot_be_silently_omitted(self):
        manifest = self.f.candidate / 'plugin.yaml'
        manifest.write_text(manifest.read_text() + 'provides_locales: [pl]\n')
        (self.f.candidate / 'locales').mkdir()
        for name in ['pl.yaml', 'pl.tui.yaml']:
            (self.f.candidate / 'locales' / name).write_text('greeting: hello\n')
        self.rebind_candidate()
        self.assertFalse(self.code_ready())
        for name in ['locale pl', 'locale pl.tui']:
            self.f.validator['report']['checks'].append({'name': name, 'ok': True, 'detail': 'fixture'})
        self.assertTrue(self.code_ready())

    def timed_review(self, submitted='2026-11-11T22:00:00+00:00', catalog='2026-11-11T22:00:00+00:00'):
        self.f.doc.update(event_year=2026, reviewed_at='2026-11-12T10:00:00+00:00',
                          submitted_at=submitted, catalog_submitted_at=catalog)
        with patch('hackathon_judge.review.datetime', Clock):
            return self.f.evaluate()

    def test_honest_post_deadline_review_can_assess_on_time_submission(self):
        result = self.timed_review()
        self.assertTrue(result['readiness']['entry_submitted']['ready'])
        self.assertTrue(result['readiness']['catalog_accepted']['ready'])
        self.assertFalse(result['readiness']['ready_to_submit']['ready'])
        self.assertEqual(result['reviewer']['reviewed_at'], '2026-11-12T10:00:00+00:00')

    def test_late_actual_form_submission_fails_even_with_old_review(self):
        self.f.doc.update(event_year=2026, reviewed_at='2026-11-11T21:00:00+00:00',
                          submitted_at='2026-11-11T22:00:01+00:00', catalog_submitted_at=None)
        with patch('hackathon_judge.review.datetime', Clock):
            result = self.f.evaluate()
        self.assertFalse(result['readiness']['entry_submitted']['ready'])

    def test_catalog_history_is_independent_of_form_but_needs_timely_pr(self):
        self.f.doc['decisions']['HACK-04']['decision'] = 'pending'
        result = self.timed_review(submitted=None)
        self.assertTrue(result['readiness']['catalog_accepted']['ready'])
        self.assertFalse(result['readiness']['entry_submitted']['ready'])
        result = self.timed_review(submitted=None, catalog='2026-11-11T22:00:01+00:00')
        self.assertTrue(result['readiness']['catalog_accepted']['ready'])

    def test_legacy_early_review_does_not_invent_actual_submission_time(self):
        self.f.doc.update(event_year=2026, reviewed_at='2026-11-10T00:00:00+00:00')
        self.f.doc.pop('submitted_at', None)
        self.f.doc.pop('catalog_submitted_at', None)
        with patch('hackathon_judge.review.datetime', Clock):
            result = self.f.evaluate()
        self.assertTrue(result['readiness']['code_ready']['ready'])
        self.assertTrue(result['readiness']['catalog_accepted']['ready'])
        for gate in ['ready_to_submit', 'entry_submitted']:
            self.assertFalse(result['readiness'][gate]['ready'])

    def test_historical_timestamps_need_timezone_and_precede_review(self):
        for timestamp in ['2026-11-11T21:00:00', '2026-11-13T00:00:00+00:00', True, 1, 'invalid']:
            with self.subTest(timestamp=timestamp):
                result = self.timed_review(submitted=timestamp, catalog=None)
                self.assertFalse(result['readiness']['entry_submitted']['ready'])

    def test_exact_fixed_est_cutoff_and_timezone_equivalence(self):
        for timestamp, ready in [('2026-11-11T17:00:00-05:00', True),
                                 ('2026-11-11T23:00:00+01:00', True),
                                 ('2026-11-11T22:00:00.000001+00:00', False)]:
            with self.subTest(timestamp=timestamp):
                self.assertEqual(self.timed_review(submitted=timestamp)['readiness']['entry_submitted']['ready'], ready)

    def test_actual_event_does_not_inherit_review_clock_skew_allowance(self):
        self.f.doc.update(event_year=2026, reviewed_at='2026-11-12T12:03:00+00:00',
                          submitted_at='2026-11-12T12:01:00+00:00',
                          catalog_submitted_at='2026-11-11T22:00:00+00:00')
        with patch('hackathon_judge.review.datetime', Clock):
            result = self.f.evaluate()
        self.assertEqual(result['status'], 'invalid')
        self.assertFalse(result['readiness']['code_ready']['ready'])

    def test_timestamp_claim_without_associated_evidence_cannot_qualify_history(self):
        self.f.doc['decisions']['HACK-04']['evidence'] = []
        self.f.doc['decisions']['PRE-04']['evidence'] = []
        result = self.timed_review()
        self.assertFalse(result['readiness']['entry_submitted']['ready'])
        self.assertFalse(result['readiness']['catalog_accepted']['ready'])
