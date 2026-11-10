"""Attachment branch controls reconciled with the later fixed scanner.

Synthetic static-source fixtures only. These controls may already pass;
this reconciliation claims no new RED and changes no production behavior.
"""
import os
from pathlib import Path
import tempfile
import unittest

from hackathon_judge.engine import audit


class UnknownConditionalBranchTerminatorRegressionTests(unittest.TestCase):
    """Unknown mutually exclusive branches must be scanned independently."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.put('plugin.yaml',
                 'name: demo\nversion: "1.0.0"\ndescription: Demo\n'
                 'provides_tools: [demo]\n')

    def put(self, file, source):
        path = self.root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source.encode('utf-8'))

    def registration_status(self):
        return next(
            c['status'] for c in audit(self.root)['checks']
            if c['id'] == 'declared-registrations'
        )

    # --- Unknown sibling-branch controls ---

    def test_unknown_if_return_hides_else_literal(self):
        """Unknown true-arm return hides else literal registration.

        if unknown: return; else: ctx.register_tool(name="wrong")
        Bug: body+orelse=[Return(), Call(...)] -> Return breaks before
        visiting the else call -> tools={demo}, dynamic=False -> pass.
        Fix: visit branches separately -> else call yields definite=False
        -> dynamic=True -> needs_review.
        """
        self.put('__init__.py',
                 'def register(ctx):\n'
                 '    ctx.register_tool(name="demo")\n'
                 '    if unknown:\n'
                 '        return\n'
                 '    else:\n'
                 '        ctx.register_tool(name="wrong")\n'
                 )
        self.assertEqual(self.registration_status(), 'needs_review')

    def test_unknown_if_return_hides_else_unresolved_wire(self):
        """Unknown true-arm return hides else unresolved wire(ctx).

        if unknown: return; else: wire(ctx)  (wire imported from external)
        Bug: wire is never visited -> tools={demo}, dynamic=False -> pass.
        Fix: wire visited with definite=False, fails resolve -> dynamic=True
        -> needs_review.
        """
        self.put('__init__.py',
                 'from external import wire\n'
                 'def register(ctx):\n'
                 '    ctx.register_tool(name="demo")\n'
                 '    if enabled:\n'
                 '        return\n'
                 '    else:\n'
                 '        wire(ctx)\n'
                 )
        self.assertEqual(self.registration_status(), 'needs_review')

    def test_unknown_if_return_hides_else_unresolved_toolset_or_continue(
        self):
        """Raise/break/continue in unknown if should also not suppress sibling."""
        for terminator in ('return', 'raise RuntimeError("x")', 'break', 'continue'):
            with self.subTest(terminator=terminator):
                self.put('__init__.py',
                         'def register(ctx):\n'
                         '    ctx.register_tool(name="demo")\n'
                         '    for item in items:\n'
                         '        if unknown:\n'
                         f'            {terminator}\n'
                         '        else:\n'
                         '            ctx.register_tool(name="wrong")\n')
                self.assertEqual(self.registration_status(), 'needs_review')

    # --- False-arm termination does NOT suppress true arm ---

    def test_unknown_if_else_return_does_not_suppress_true_body(self):
        """False-arm return must not suppress true-arm registrations."""
        self.put('__init__.py',
                 'def register(ctx):\n'
                 '    ctx.register_tool(name="demo")\n'
                 '    if unknown:\n'
                 '        ctx.register_tool(name="helper")\n'
                 '    else:\n'
                 '        return\n'
                 )
        # The helper is in body (visited first), with definite=False
        # so it sets dynamic=True. No literal mismatch.
        self.assertEqual(self.registration_status(), 'needs_review')

    # --- Known-conditional behavior preserved ---

    def test_known_true_conditional_registration_still_pass(self):
        """if True: ctx.register_tool(name="demo") -> pass."""
        self.put('__init__.py',
                 'def register(ctx):\n'
                 '    if True:\n'
                 '        ctx.register_tool(name="demo")\n'
                 )
        self.assertEqual(self.registration_status(), 'pass')

    def test_known_false_conditional_still_does_not_invent(self):
        """if False: ctx.register_tool(name="unreachable"); demo -> pass."""
        self.put('__init__.py',
                 'def register(ctx):\n'
                 '    if False:\n'
                 '        ctx.register_tool(name="unreachable")\n'
                 '    ctx.register_tool(name="demo")\n'
                 )
        self.assertEqual(self.registration_status(), 'pass')

    def test_known_false_else_branch_still_not_added(self):
        """if True: pass; else: ctx.register_tool(name="unreachable") -> pass."""
        self.put('__init__.py',
                 'def register(ctx):\n'
                 '    if True:\n'
                 '        pass\n'
                 '    else:\n'
                 '        ctx.register_tool(name="unreachable")\n'
                 '    ctx.register_tool(name="demo")\n'
                 )
        self.assertEqual(self.registration_status(), 'pass')

    # --- Unconditional/after-return behavior unchanged ---

    def test_unreachable_after_return_still_not_invented(self):
        """return; ctx.register_tool(name="unreachable") -> pass."""
        self.put('__init__.py',
                 'def register(ctx):\n'
                 '    ctx.register_tool(name="demo")\n'
                 '    return\n'
                 '    ctx.register_tool(name="unreachable")\n'
                 )
        self.assertEqual(self.registration_status(), 'pass')

    def test_known_bad_literal_still_fails(self):
        """Literal mismatch without dynamic wiring -> fail."""
        self.put('__init__.py',
                 'def register(ctx):\n'
                 '    ctx.register_tool(name="wrong")\n'
                 )
        self.assertEqual(self.registration_status(), 'fail')

    def test_unresolved_context_helper_still_needs_review(self):
        """wire(ctx) from external import -> needs_review."""
        self.put('__init__.py',
                 'from external import wire\n'
                 'def register(ctx):\n'
                 '    wire(ctx)\n'
                 )
        self.assertEqual(self.registration_status(), 'needs_review')

    def test_unknown_if_with_terminator_does_not_skip_non_if_sibling(self):
        """Unknown-if with terminator: sibling after if is still visited.

        A Return inside an unknown if's body (not the else) should not
        suppress the next statement after the if. The extra call here
        is certain=True, so if the sibling were skipped and only 'demo'
        seen, dynamic=False -> pass. The certain extra registration must still be visited and
        fail its literal declaration mismatch.
        """
        self.put('__init__.py',
                 'def register(ctx):\n'
                 '    ctx.register_tool(name="demo")\n'
                 '    if unknown:\n'
                 '        return\n'
                 '    ctx.register_tool(name="extra")\n'
                 )
        # "extra" is certain but not declared -> literal mismatch -> fail.
        # If the sibling after if were skipped, only {demo} seen -> pass.
        self.assertEqual(self.registration_status(), 'fail')


if __name__ == '__main__':
    unittest.main()

