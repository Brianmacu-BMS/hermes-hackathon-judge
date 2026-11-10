"""Shared report-policy controls; synthetic receipts, never real native execution."""
from copy import deepcopy
import hashlib
import json
import unittest

import test_evidence_review as evidence_fixtures
import test_plugin as runtime_fixtures
from native_report_fixture import native_report


class ReconciledReportContractTests(unittest.TestCase):
    def setUp(self):
        # Import the fixture module, not its TestCase, to avoid duplicate discovery.
        self.f = evidence_fixtures.ReviewEvidenceTests('test_missing_review_stays_unreviewed')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.host = runtime_fixtures.Host()
        runtime_fixtures.plugin.register(self.host)

    def runtime(self, payload, exit_code=0):
        self.host.reply = {'exit_code': exit_code, 'output': json.dumps(payload)}
        handler = self.host.tools['hackathon_judge']['handler']
        return json.loads(handler({'path': str(self.f.candidate), 'action': 'validate', 'trusted_code': True}))

    def full_receipt(self, payload, exit_code=0):
        self.f.validator.update(report=deepcopy(payload), exit_code=exit_code)
        self.f.attach_validator()
        return self.f.evaluate()

    def assert_unqualified(self, result):
        self.assertFalse(result['decisions']['PRE-03']['complete'])
        self.assertFalse(result['readiness']['code_ready']['ready'])
        self.assertIn('PRE-03', result['readiness']['code_ready']['pending'])

    def test_full_pre03_rejects_error_bearing_success(self):
        # Establish complete positive evidence through the actual receipt consumer.
        positive = self.full_receipt(native_report())
        self.assertTrue(positive['decisions']['PRE-03']['complete'])
        self.assertTrue(positive['readiness']['code_ready']['ready'])
        for error in ('failed despite ok', True, 1, ['failure'], {'reason': 'failure'}):
            with self.subTest(error=error):
                self.assert_unqualified(self.full_receipt(native_report(error=error)))

    def test_public_runtime_rejects_error_bearing_success(self):
        self.assertEqual(self.runtime(native_report())['official_validation']['status'], 'pass')
        for error in ('failed despite ok', True, 1, ['failure'], {'reason': 'failure'}):
            with self.subTest(error=error):
                result = self.runtime(native_report(error=error))
                self.assertEqual(result['official_validation']['status'], 'error')
                check = next(c for c in result['checks'] if c['id'] == 'official-validator')
                self.assertEqual(check['status'], 'needs_review')
                self.assertFalse(result['certified'])

    def test_empty_error_fields_do_not_invent_failure(self):
        for error in (None, '', False, 0, [], {}):
            with self.subTest(error=error):
                payload = native_report(error=error)
                self.assertEqual(self.runtime(payload)['official_validation']['status'], 'pass')
                self.assertTrue(self.full_receipt(payload)['readiness']['code_ready']['ready'])

    def early_failure(self):
        # Source-derived early-exit shape: report need not reach isolation probing.
        return {'ok': False, 'checks': [{'name': 'manifest', 'ok': False,
                                        'detail': 'Synthetic early manifest failure'}],
                'warnings': ['Synthetic retained failure warning'], 'isolation': None}

    def test_honest_partial_failure_with_no_isolation_remains_fail(self):
        for exit_code in (0, 1):
            for error in (None, 'Synthetic producer failure'):
                with self.subTest(exit_code=exit_code, error=error):
                    payload = self.early_failure()
                    payload['error'] = error
                    result = self.runtime(payload, exit_code)
                    self.assertEqual(result['official_validation']['status'], 'fail')
                    self.assertEqual(result['official_validation']['warnings'], payload['warnings'])
                    self.assertEqual(result['verdict'], 'blocked')
                    self.assert_unqualified(self.full_receipt(payload, exit_code))

    def test_partial_failure_cannot_be_promoted_by_success_boolean(self):
        payload = self.early_failure()
        payload['ok'] = True
        payload['checks'][0]['ok'] = True
        self.assertEqual(self.runtime(payload)['official_validation']['status'], 'error')
        self.assert_unqualified(self.full_receipt(payload))

    def test_partial_failure_still_requires_typed_checks_and_warnings(self):
        for field, value in (('detail', None), ('ok', 0), ('name', ''), ('name', None)):
            with self.subTest(field=field, value=value):
                payload = self.early_failure()
                payload['checks'][0][field] = value
                self.assertEqual(self.runtime(payload, 1)['official_validation']['status'], 'error')
        for warnings in (None, {}, 'failure', [False]):
            with self.subTest(warnings=warnings):
                payload = self.early_failure()
                payload['warnings'] = warnings
                self.assertEqual(self.runtime(payload, 1)['official_validation']['status'], 'error')

    def test_full_pre03_qualification_is_separate_from_runtime_shape(self):
        payload = native_report()
        original = deepcopy(self.f.validator)
        # A complete runtime-shaped success cannot replace full receipt provenance,
        # candidate/policy binding, --install-deps, strict exit status or command.
        changes = [('install_deps', False), ('hermes_version', None), ('hermes_commit', '0' * 40),
                   ('policy_sha256', '0' * 64), ('candidate_sha256', '0' * 64),
                   ('candidate_after_sha256', '0' * 64), ('schema_version', True),
                   ('kind', 'runtime-only'), ('command', ['hermes', 'plugins', 'validate', '--json'])]
        for field, value in changes:
            with self.subTest(field=field):
                self.f.validator = deepcopy(original)
                self.f.validator[field] = value
                self.assertEqual(self.runtime(payload)['official_validation']['status'], 'pass')
                self.assert_unqualified(self.full_receipt(payload))
        self.f.validator = deepcopy(original)
        for exit_code in (False, 1):
            with self.subTest(exit_code=exit_code):
                self.assert_unqualified(self.full_receipt(payload, exit_code))

    def test_warning_acknowledgement_is_only_a_full_receipt_requirement(self):
        warnings = ['Synthetic caution retained by both consumers']
        payload = native_report(warnings=warnings)
        result = self.runtime(payload)
        self.assertEqual(result['official_validation']['status'], 'pass')
        self.assertEqual(result['official_validation']['warnings'], warnings)
        self.assert_unqualified(self.full_receipt(payload))
        item = self.f.doc['decisions']['PRE-03']
        item['warnings_reviewed_sha256'] = hashlib.sha256(json.dumps(warnings, sort_keys=True).encode()).hexdigest()
        self.assertTrue(self.full_receipt(payload)['readiness']['code_ready']['ready'])
        payload['warnings'].append('Another synthetic caution')
        self.assert_unqualified(self.full_receipt(payload))


if __name__ == '__main__':
    unittest.main()
