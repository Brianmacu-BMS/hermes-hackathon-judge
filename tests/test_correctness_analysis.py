"""Static correctness regressions; synthetic candidates are never imported."""
import os
from pathlib import Path
import tempfile
import unittest

from hackathon_judge.engine import audit
from hackathon_judge.scan import scan


class RegistrationReachabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.put('plugin.yaml', 'name: demo\nversion: "1.0.0"\ndescription: Demo\nprovides_tools: [demo]\n')
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name="demo", schema={}, handler=lambda args: "{}")\n')

    def put(self, file, source):
        path = self.root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding='utf-8')

    def status(self):
        return next(c['status'] for c in audit(self.root)['checks'] if c['id'] == 'declared-registrations')

    def test_unimported_example_cannot_add_declaration_blocker(self):
        self.put('examples/not_loaded.py', 'def register(ctx):\n    ctx.register_tool(name="example_only")\n')
        self.assertEqual(self.status(), 'pass')

    def test_uncalled_local_example_cannot_add_declaration_blocker(self):
        self.put('__init__.py', 'def example(ctx):\n    ctx.register_tool(name="example_only")\ndef register(ctx):\n    ctx.register_tool(name="demo")\n')
        self.assertEqual(self.status(), 'pass')

    def test_unrelated_receiver_is_not_a_proven_plugin_registration(self):
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name="demo")\n    other.register_tool(name="unrelated")\n')
        self.assertEqual(self.status(), 'needs_review')

    def test_literal_false_branch_cannot_add_declaration_blocker(self):
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name="demo")\n    if False:\n        ctx.register_tool(name="unreachable")\n')
        self.assertEqual(self.status(), 'pass')

    def test_after_return_cannot_add_declaration_blocker(self):
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name="demo")\n    return\n    ctx.register_tool(name="unreachable")\n')
        self.assertEqual(self.status(), 'pass')

    def test_actual_reachable_literal_mismatch_still_fails(self):
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name="wrong")\n')
        self.assertEqual(self.status(), 'fail')

    def test_reexport_and_context_helper_still_detect_literal_mismatch(self):
        self.put('__init__.py', 'from .wiring import register\n')
        self.put('wiring.py', 'def helper(context):\n    context.register_tool(name="wrong")\ndef register(ctx):\n    helper(ctx)\n')
        self.assertEqual(self.status(), 'fail')

    def test_unresolved_context_helper_requires_review(self):
        self.put('__init__.py', 'from external import wire\ndef register(ctx):\n    wire(ctx)\n')
        self.assertEqual(self.status(), 'needs_review')

    def test_factory_registration_requires_review_even_with_no_declarations(self):
        self.put('plugin.yaml', 'name: demo\nversion: "1.0.0"\ndescription: Demo\n')
        self.put('__init__.py', 'register = make_register()\n')
        self.assertEqual(self.status(), 'needs_review')

    def test_conditional_wiring_is_review_not_a_literal_blocker(self):
        self.put('__init__.py', 'def helper(ctx):\n    ctx.register_tool(name="maybe")\ndef register(ctx):\n    ctx.register_tool(name="demo")\n    if enabled:\n        helper(ctx)\n')
        self.assertEqual(self.status(), 'needs_review')

    def test_unknown_if_return_does_not_hide_else_literal_mismatch(self):
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name="demo")\n    if enabled:\n        return\n    else:\n        ctx.register_tool(name="wrong")\n')
        self.assertEqual(self.status(), 'needs_review')

    def test_unknown_if_return_does_not_hide_else_unresolved_helper(self):
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name="demo")\n    if enabled:\n        return\n    else:\n        unresolved_wire(ctx)\n')
        self.assertEqual(self.status(), 'needs_review')

    def test_dynamic_name_is_never_invented_pass(self):
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name=tool_name())\n')
        self.assertEqual(self.status(), 'needs_review')

    def test_known_bad_literal_is_not_hidden_by_dynamic_wiring(self):
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name="wrong")\n    ctx.register_tool(name=tool_name())\n')
        self.assertEqual(self.status(), 'fail')

    def test_unreachable_example_environment_read_is_still_scanned(self):
        self.put('examples/not_loaded.py', 'import os\ndef example():\n    return os.environ["SYNTHETIC_TOKEN"]\n')
        report = audit(self.root)
        self.assertTrue(any(f['rule'] == 'CAT-11' and f['file'] == 'examples/not_loaded.py' for f in report['findings']))


class DecoratedRegistrationTests(unittest.TestCase):
    def status(self, source):
        from hackathon_judge.guide import analyze
        data = {'__init__.py': source.encode('utf-8')}
        _, registrations = scan(data)
        checks = {}
        analyze(data, {}, registrations, lambda key, rules, status, detail: checks.update({key: status}))
        return checks['guide-registration']

    def test_decorated_zero_arg_register_is_review_not_signature_failure(self):
        source = 'def adapt(fn):\n    return lambda ctx: fn()\n@adapt\ndef register():\n    pass\n'
        self.assertEqual(self.status(source), 'needs_review')

    def test_decorated_extra_required_args_are_review_not_signature_failure(self):
        self.assertEqual(self.status('@wrap\ndef register(ctx, required):\n    pass\n'), 'needs_review')

    def test_decorated_required_keyword_is_review_not_signature_failure(self):
        self.assertEqual(self.status('@wrap\ndef register(*, required):\n    pass\n'), 'needs_review')

    def test_undecorated_zero_args_remain_hard_failure(self):
        self.assertEqual(self.status('def register():\n    pass\n'), 'fail')

    def test_undecorated_extra_required_arg_remains_hard_failure(self):
        self.assertEqual(self.status('def register(ctx, required):\n    pass\n'), 'fail')

    def test_undecorated_required_keyword_remains_hard_failure(self):
        self.assertEqual(self.status('def register(ctx, *, required):\n    pass\n'), 'fail')

    def test_noncallable_remains_hard_failure(self):
        self.assertEqual(self.status('register = 7\n'), 'fail')

    def test_valid_undecorated_register_remains_static_pass(self):
        self.assertEqual(self.status('def register(ctx):\n    pass\n'), 'pass')


class LexicalImportTests(unittest.TestCase):
    def findings(self, source):
        return scan({'module.py': source.encode('utf-8')})[0]

    def assert_rule_at(self, source, rule, line):
        self.assertTrue(any(f['rule'] == rule and f['line'] == line for f in self.findings(source)),
                        f'{rule} missing at line {line}')

    def test_function_import_cannot_hide_module_environment_call(self):
        self.assert_rule_at('import os\nvalue = os.getenv("SYNTHETIC")\ndef unrelated():\n    import harmless as os\n', 'CAT-11', 2)

    def test_function_from_import_cannot_hide_module_environment_subscript(self):
        self.assert_rule_at('from os import environ as env\nvalue = env["SYNTHETIC"]\ndef unrelated():\n    from harmless import mapping as env\n', 'CAT-11', 2)

    def test_function_import_cannot_hide_module_network(self):
        self.assert_rule_at('import requests as client\nclient.get("https://example.invalid")\ndef unrelated():\n    import harmless as client\n', 'CAT-13', 2)

    def test_function_import_cannot_hide_module_subprocess(self):
        source = 'import subprocess as proc\nproc.run(["synthetic", "--yolo"])\ndef unrelated():\n    import harmless as proc\n'
        self.assert_rule_at(source, 'CAT-12', 2)
        self.assert_rule_at(source, 'CAT-13', 2)
        self.assertTrue(any('approval-bypass' in f['message'] for f in self.findings(source)))

    def test_sibling_function_import_cannot_hide_real_local_env(self):
        self.assert_rule_at('def actual():\n    import os as settings\n    return settings.getenv("SYNTHETIC")\ndef unrelated():\n    import harmless as settings\n', 'CAT-11', 3)

    def test_nested_import_cannot_hide_enclosing_function_env(self):
        self.assert_rule_at('def actual():\n    import os as settings\n    value = settings.environ["SYNTHETIC"]\n    def unrelated():\n        import harmless as settings\n', 'CAT-11', 3)

    def test_module_alias_is_visible_in_function_without_local_import(self):
        self.assert_rule_at('import os as settings\ndef actual():\n    return settings.getenv("SYNTHETIC")\n', 'CAT-11', 3)

    def test_local_harmless_import_does_not_invent_environment_read(self):
        source = 'import os as settings\ndef unrelated():\n    import harmless as settings\n    return settings.getenv("not_environment")\n'
        self.assertFalse(any(f['rule'] == 'CAT-11' for f in self.findings(source)))

    def test_method_does_not_inherit_class_import_alias(self):
        self.assert_rule_at('import os\nclass Example:\n    import harmless as os\n    def actual(self):\n        return os.getenv("SYNTHETIC")\n', 'CAT-11', 5)

    def test_default_expression_uses_enclosing_not_function_import(self):
        self.assert_rule_at('import os\ndef example(value=os.getenv("SYNTHETIC")):\n    import harmless as os\n', 'CAT-11', 2)

    def test_function_import_cannot_hide_core_assignment(self):
        self.assert_rule_at('import run_agent as core\ncore.AIAgent.run = None\ndef unrelated():\n    import harmless as core\n', 'CAT-09', 2)

    def test_environment_read_remains_detected_without_any_shadow(self):
        self.assert_rule_at('import os\nos.getenv("SYNTHETIC")\n', 'CAT-11', 2)


if __name__ == '__main__':
    unittest.main()
