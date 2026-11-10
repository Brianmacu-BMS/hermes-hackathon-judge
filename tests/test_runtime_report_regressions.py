"""Runtime report completeness through the actual handler, with an inert host."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest

from native_report_fixture import native_report
from test_plugin import Host, plugin


class RuntimeReportRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.root / '__init__.py').write_text('def register(ctx):\n    pass\n')
        self.host = Host()
        plugin.register(self.host)

    def result(self, payload, exit_code=0):
        self.host.reply = {'exit_code': exit_code, 'output': json.dumps(payload)}
        return json.loads(plugin.handle(self.host, {'path': str(self.root), 'action': 'validate', 'trusted_code': True}))

    def assert_invalid(self, payload):
        report = self.result(payload)
        self.assertEqual(report['official_validation']['status'], 'error')
        self.assertNotEqual(next(c for c in report['checks'] if c['id'] == 'official-validator')['status'], 'pass')

    def test_complete_report_positive_control(self):
        report = self.result(native_report())
        self.assertEqual(report['official_validation']['status'], 'pass')
        self.assertFalse(report['official_validation']['install_deps'])
        self.assertFalse(report['certified'])

    def test_five_common_names_are_not_complete(self):
        payload = native_report()
        names = {'manifest', 'loadable', 'capability probe', 'security scan', 'no core override'}
        payload['checks'] = [c for c in payload['checks'] if c['name'] in names]
        self.assert_invalid(payload)

    def test_explicit_warnings_and_isolation_are_required(self):
        for field in ('warnings', 'isolation'):
            with self.subTest(field=field):
                payload = native_report()
                del payload[field]
                self.assert_invalid(payload)

    def test_details_and_strict_boolean_check_results_are_required(self):
        for field, value in (('detail', None), ('ok', 1), ('name', ''), ('name', None)):
            with self.subTest(field=field, value=value):
                payload = native_report()
                payload['checks'][0][field] = value
                self.assert_invalid(payload)

    def test_isolation_structure_and_consistency_are_required(self):
        cases = [None, {}, {'verdict': 'unknown', 'host_ready': True},
                 {'verdict': 'host', 'host_ready': 1, 'reasons': [], 'notes': [], 'ctx_methods': []},
                 {'verdict': 'host', 'host_ready': False, 'reasons': [], 'notes': [], 'ctx_methods': []},
                 {'verdict': 'in_process', 'host_ready': True, 'reasons': [], 'notes': [], 'ctx_methods': []}]
        for isolation in cases:
            with self.subTest(isolation=isolation):
                self.assert_invalid(native_report(isolation=isolation))

    def test_in_process_is_informational_not_automatic_failure(self):
        payload = native_report(isolation={'verdict': 'in_process', 'host_ready': False,
                                          'reasons': [], 'notes': [], 'ctx_methods': []})
        self.assertEqual(self.result(payload)['official_validation']['status'], 'pass')

    def test_duplicate_or_unknown_success_check_names_are_invalid(self):
        for name in ('manifest', 'invented-check'):
            with self.subTest(name=name):
                payload = native_report()
                payload['checks'].append({'name': name, 'ok': True, 'detail': 'Synthetic extra'})
                self.assert_invalid(payload)

    def test_each_required_identity_is_required(self):
        positive = native_report()
        for removed in positive['checks']:
            with self.subTest(name=removed['name']):
                payload = deepcopy(positive)
                payload['checks'] = [c for c in payload['checks'] if c['name'] != removed['name']]
                self.assert_invalid(payload)

    def test_warnings_are_retained_not_suppressed(self):
        warnings = ['Synthetic caution to inspect']
        result = self.result(native_report(warnings=warnings))
        self.assertEqual(result['official_validation']['warnings'], warnings)
        self.assertEqual(result['official_validation']['status'], 'pass')

    def test_malformed_warning_and_error_shaped_success_are_invalid(self):
        for payload in (native_report(warnings={}), native_report(error='failed despite ok'),
                        native_report(ok=1)):
            with self.subTest(payload=payload):
                self.assert_invalid(payload)

    def test_genuine_failure_shaped_report_remains_failure(self):
        payload = native_report(ok=False)
        payload['checks'][0]['ok'] = False
        report = self.result(payload, exit_code=1)
        self.assertEqual(report['official_validation']['status'], 'fail')
        self.assertEqual(report['verdict'], 'blocked')


if __name__ == '__main__':
    unittest.main()
