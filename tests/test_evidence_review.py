"""Evidence-completion contracts; fixture claims are not real submissions."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from hackathon_judge.engine import audit, requirements, review_template
from hackathon_judge.review import assess_review, CODE_RULES, SUBMISSION_RULES, ENTRY_RULES, ADMISSION_RULES


class ReviewEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.candidate = self.base / 'candidate'
        self.candidate.mkdir()
        (self.candidate / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.candidate / '__init__.py').write_text('def register(ctx):\n    pass\n')
        self.report = audit(self.candidate)
        self.evidence = self.base / 'evidence'
        self.evidence.mkdir()
        note = self.evidence / 'review.md'
        note.write_text('Fixture operator reviewed actual source and recorded findings. Not an actual hackathon entry.')
        self.ref = {'path': note.name, 'sha256': hashlib.sha256(note.read_bytes()).hexdigest()}
        self.doc = review_template(self.report)
        self.doc.update(reviewer={'name': 'Fixture Reviewer', 'role': 'operator'}, reviewed_at=datetime.now(timezone.utc).isoformat(), event_year=datetime.now(timezone.utc).year + 1)
        for rid in self.doc['decisions']:
            self.doc['decisions'][rid].update(decision='pass', reason='Fixture source inspected against the named requirement.', evidence=[self.ref.copy()])
        self.validator = {'schema_version': 1, 'kind': 'hermes-validation', 'candidate_sha256': self.report['inventory']['tree_sha256'],
                          'candidate_after_sha256': self.report['inventory']['tree_sha256'], 'install_deps': True,
                          'hermes_version': '0.23.0', 'hermes_commit': '2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19',
                          'policy_sha256': self.doc['policy_sha256'],
                          'exit_code': 0, 'command': ['hermes', 'plugins', 'validate', str(self.candidate), '--install-deps', '--json'],
                          'report': {'ok': True, 'checks': [{'name': n, 'ok': True, 'detail': 'fixture'} for n in [
                              'manifest', 'manifest fields', 'requires_hermes', 'config schema', 'requires_env', 'oauth',
                              'loadable', 'python dependencies', 'capability probe', 'declared tools', 'declared hooks',
                              'declared middleware', 'built-in tool collisions', 'security scan', 'no core override']],
                              'warnings': [], 'isolation': {'verdict': 'host', 'host_ready': True, 'reasons': [], 'notes': [], 'ctx_methods': []}}}
        self.attach_validator()

    def attach_validator(self):
        p = self.evidence / 'validator.json'
        p.write_text(json.dumps(self.validator))
        self.doc['decisions']['PRE-03']['evidence'] = [{'path': p.name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'kind': 'validation_receipt'}]

    def evaluate(self):
        path = self.evidence / 'review.json'
        path.write_text(json.dumps(self.doc))
        return assess_review(self.report, path)

    def test_all_requirements_assigned_to_real_phase(self):
        self.assertEqual(CODE_RULES | SUBMISSION_RULES | ENTRY_RULES | ADMISSION_RULES, {r['id'] for r in requirements()})
        self.assertFalse(CODE_RULES & ADMISSION_RULES)

    def test_complete_review_is_accountable_not_official_certification(self):
        result = self.evaluate()
        self.assertTrue(result['readiness']['code_ready']['ready'])
        self.assertTrue(result['readiness']['ready_to_submit']['ready'])
        self.assertFalse(result['certified'])
        self.assertIn('reviewer', result['notice'].lower())

    def test_catalog_merge_and_form_receipt_not_required_to_prepare_submission(self):
        for rid in ADMISSION_RULES | ENTRY_RULES:
            self.doc['decisions'][rid]['decision'] = 'pending'
        result = self.evaluate()
        self.assertTrue(result['readiness']['ready_to_submit']['ready'])
        self.assertFalse(result['readiness']['entry_submitted']['ready'])
        self.assertFalse(result['readiness']['catalog_accepted']['ready'])

    def test_missing_public_demo_prevents_submission_but_not_code_readiness(self):
        self.doc['decisions']['HACK-02']['decision'] = 'pending'
        result = self.evaluate()
        self.assertTrue(result['readiness']['code_ready']['ready'])
        self.assertFalse(result['readiness']['ready_to_submit']['ready'])

    def test_hash_mismatch_blocks_all_ready_claims(self):
        self.doc['candidate_sha256'] = '0' * 64
        result = self.evaluate()
        self.assertEqual(result['status'], 'stale')
        self.assertFalse(result['readiness']['code_ready']['ready'])

    def test_policy_mismatch_invalidates_review(self):
        self.doc['policy_sha256'] = '0' * 64
        self.assertEqual(self.evaluate()['status'], 'stale')

    def test_evidence_content_change_invalidates_review(self):
        (self.evidence / 'review.md').write_text('changed')
        self.assertEqual(self.evaluate()['status'], 'invalid')

    def test_evidence_symlink_is_refused(self):
        (self.evidence / 'alias.md').symlink_to(self.evidence / 'review.md')
        self.doc['decisions']['CAT-03']['evidence'] = [{**self.ref, 'path': 'alias.md'}]
        self.assertEqual(self.evaluate()['status'], 'invalid')

    def test_evidence_escape_is_refused(self):
        self.doc['decisions']['CAT-03']['evidence'] = [{**self.ref, 'path': '../outside.md'}]
        self.assertEqual(self.evaluate()['status'], 'invalid')

    def test_sensitive_evidence_is_refused_without_content_leak(self):
        (self.evidence / '.env').write_text('NEVER_EMIT_PRIVATE_MARKER')
        self.doc['decisions']['CAT-03']['evidence'] = [{'path': '.env', 'sha256': '0' * 64}]
        result = self.evaluate()
        self.assertEqual(result['status'], 'invalid')
        self.assertNotIn('NEVER_EMIT_PRIVATE_MARKER', json.dumps(result))

    def test_pass_without_evidence_remains_pending(self):
        self.doc['decisions']['CAT-03']['evidence'] = []
        self.assertFalse(self.evaluate()['readiness']['code_ready']['ready'])

    def test_unknown_requirement_is_rejected(self):
        self.doc['decisions']['MADEUP-01'] = self.doc['decisions']['CAT-03']
        self.assertEqual(self.evaluate()['status'], 'invalid')

    def test_non_applicable_hackathon_rule_cannot_be_waived(self):
        self.doc['decisions']['HACK-02']['decision'] = 'not_applicable'
        self.assertFalse(self.evaluate()['readiness']['ready_to_submit']['ready'])

    def test_no_desktop_can_be_recorded_as_not_applicable_with_evidence(self):
        self.doc['decisions']['CAT-08']['decision'] = 'not_applicable'
        self.assertTrue(self.evaluate()['readiness']['code_ready']['ready'])

    def test_partial_inventory_cannot_be_waived(self):
        self.report['inventory']['complete'] = False
        self.assertFalse(self.evaluate()['readiness']['code_ready']['ready'])

    def test_local_failure_cannot_be_waived(self):
        self.report['checks'].append({'id': 'broken', 'rules': ['PRE-02'], 'status': 'fail', 'detail': 'broken'})
        self.assertFalse(self.evaluate()['readiness']['code_ready']['ready'])

    def test_unknown_finding_disposition_cannot_be_silently_accepted(self):
        self.doc['finding_dispositions']['made-up'] = {'decision': 'acceptable', 'reason': 'not a real finding', 'evidence': [self.ref]}
        self.assertEqual(self.evaluate()['status'], 'invalid')

    def test_validator_without_install_deps_is_not_full_ci_evidence(self):
        self.validator['install_deps'] = False
        self.attach_validator()
        self.assertFalse(self.evaluate()['readiness']['code_ready']['ready'])

    def test_incomplete_validator_checks_are_not_full_ci_evidence(self):
        self.validator['report']['checks'] = [{'name': 'manifest', 'ok': True}]
        self.attach_validator()
        self.assertFalse(self.evaluate()['readiness']['code_ready']['ready'])

    def test_failed_validator_receipt_cannot_be_overridden_by_review(self):
        self.validator['exit_code'] = 1
        self.attach_validator()
        self.assertFalse(self.evaluate()['readiness']['code_ready']['ready'])

    def test_validator_receipt_must_bind_before_and_after_tree(self):
        self.validator['candidate_after_sha256'] = '0' * 64
        self.attach_validator()
        self.assertFalse(self.evaluate()['readiness']['code_ready']['ready'])

    def test_future_review_is_invalid(self):
        self.doc['reviewed_at'] = '2999-01-01T00:00:00+00:00'
        self.assertEqual(self.evaluate()['status'], 'invalid')

    def test_duplicate_review_json_keys_are_rejected(self):
        p = self.evidence / 'review.json'
        p.write_text('{"schema_version":1,"schema_version":2}')
        self.assertEqual(assess_review(self.report, p)['status'], 'invalid')

    def test_missing_review_stays_unreviewed(self):
        result = assess_review(self.report, None)
        self.assertEqual(result['status'], 'not_supplied')
        self.assertFalse(result['readiness']['code_ready']['ready'])


if __name__ == '__main__':
    unittest.main()
