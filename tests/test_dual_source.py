"""Both source families are reviewed without executing candidate code."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from hackathon_judge.engine import audit, markdown, requirements, review_template

SCHEMA = {'name': 'demo', 'description': 'Inspect a synthetic value and return a report.',
          'parameters': {'type': 'object', 'properties': {'value': {'type': 'string'}}, 'required': ['value']}}


class DualSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'candidate'; self.root.mkdir()
        self.put('plugin.yaml', 'name: demo\nversion: "1.0.0"\ndescription: Demo\nprovides_tools: [demo]\n')
        self.put('__init__.py', 'import json\nSCHEMA = ' + repr(SCHEMA) + '\ndef handle(args, **kwargs):\n    return json.dumps({"ok": True})\ndef register(ctx):\n    ctx.register_tool(name="demo", toolset="demo", schema=SCHEMA, handler=handle)\n')

    def put(self, name, text):
        path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)

    def check(self, key):
        return next(c for c in audit(self.root)['checks'] if c['id'] == key)

    def test_both_source_families_have_explicit_tracks(self):
        report = audit(self.root)
        self.assertEqual(set(report['tracks']), {'build_guide', 'competition'})
        self.assertEqual(set(report['tracks']['build_guide']['requirement_ids']), {r['id'] for r in requirements() if r['source'] == 'developer-guide'})
        self.assertIn('HACK-05', report['tracks']['competition']['requirement_ids'])
        self.assertEqual(report['tracks']['build_guide']['status'], 'needs_review')
        self.assertFalse(report['certified'])

    def test_guide_rules_are_source_quoted_not_just_a_captured_url(self):
        rows = [r for r in requirements() if r['source'] == 'developer-guide']
        self.assertEqual({r['id'] for r in rows}, {f'DEV-{n:02}' for n in range(1, 13)})
        guide = (Path(__file__).resolve().parents[1] / 'sources/developer-guide.md').read_text().splitlines()
        for row in rows:
            start, end = row['source_lines']
            self.assertIn(row['source_quote'], '\n'.join(guide[start - 1:end]))
            self.assertIn('/plugins#', row['url'])
            self.assertTrue(row['requirement'])
        self.assertEqual(self.check('guide-source-map')['status'], 'pass')

    def test_missing_register_is_not_a_loadable_python_entrypoint(self):
        self.put('__init__.py', 'VALUE = 1\n')
        self.assertEqual(self.check('guide-registration')['status'], 'fail')
        self.assertEqual(audit(self.root)['tracks']['build_guide']['status'], 'blocked')

    def test_noncallable_register_is_rejected_without_importing(self):
        self.put('__init__.py', 'register = 7\n')
        self.assertEqual(self.check('guide-registration')['status'], 'fail')

    def test_wrong_register_signature_is_rejected(self):
        self.put('__init__.py', 'def register():\n    pass\n')
        self.assertEqual(self.check('guide-registration')['status'], 'fail')

    def test_alternative_module_layout_and_reexport_are_valid(self):
        self.put('__init__.py', 'from .implementation.wiring import register\n')
        self.put('implementation/__init__.py', '')
        self.put('implementation/contracts.py', 'TOOL = ' + repr(SCHEMA))
        self.put('implementation/wiring.py', 'from .contracts import TOOL\nfrom .operations import handle\ndef register(ctx):\n    ctx.register_tool(name="demo", toolset="demo", schema=TOOL, handler=handle)\n')
        self.put('implementation/operations.py', 'import json\ndef handle(args, **kwargs):\n    return json.dumps({"ok": True})\n')
        report = audit(self.root)
        for key in ('guide-registration', 'guide-schemas'):
            self.assertEqual(next(c for c in report['checks'] if c['id'] == key)['status'], 'pass')
        self.assertFalse((self.root / 'tools.py').exists())
        self.assertFalse((self.root / 'schemas.py').exists())
        self.assertIn('implementation/contracts.py', report['guide_analysis']['components']['schemas'])
        self.assertIn('implementation/operations.py', report['guide_analysis']['components']['handlers'])

    def test_inline_schema_and_handler_do_not_need_example_filenames(self):
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name="demo", schema=' + repr(SCHEMA) + ', handler=lambda args, **kwargs: "{}")\n')
        self.assertEqual(self.check('guide-schemas')['status'], 'pass')
        self.assertNotEqual(self.check('guide-handlers')['status'], 'fail')

    def test_unreachable_example_registration_does_not_invent_a_guide_failure(self):
        self.put('examples/not_loaded.py', 'def register(ctx):\n    ctx.register_tool(name="demo", schema=[], handler=lambda args: {"ok": True})\n')
        self.assertNotEqual(self.check('guide-schemas')['status'], 'fail')
        self.assertNotEqual(self.check('guide-handlers')['status'], 'fail')

    def test_local_registration_helper_is_inspected(self):
        self.put('__init__.py', 'def wire(context):\n    context.register_tool(name="demo", schema=[], handler=lambda args: "{}")\ndef register(ctx):\n    wire(ctx)\n')
        self.assertEqual(self.check('guide-schemas')['status'], 'fail')

    def test_dynamic_register_is_reviewable_not_guessed_missing(self):
        self.put('__init__.py', 'def factory():\n    return lambda ctx: None\nregister = factory()\n')
        self.assertEqual(self.check('guide-registration')['status'], 'needs_review')

    def test_specialized_entrypoint_is_not_forced_into_general_register(self):
        self.put('plugin.yaml', 'name: demo\nversion: "1.0.0"\ndescription: Demo\nkind: platform\n')
        self.put('__init__.py', 'def create_adapter():\n    return None\n')
        self.assertEqual(self.check('guide-registration')['status'], 'needs_review')

    def test_no_optional_surfaces_are_required(self):
        self.put('plugin.yaml', 'name: demo\nversion: "1.0.0"\ndescription: Demo\n')
        self.put('__init__.py', 'def register(ctx):\n    pass\n')
        self.assertFalse(any(c['status'] == 'fail' for c in audit(self.root)['checks']))
        self.assertNotEqual(self.check('guide-resources')['status'], 'fail')

    def test_schema_literal_wrong_type_is_a_blocker(self):
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name="demo", schema=[], handler=lambda args: "{}")\n')
        self.assertEqual(self.check('guide-schemas')['status'], 'fail')
        diagnostics = audit(self.root)['guide_analysis']['diagnostics']
        self.assertTrue(any(d['rule'] == 'DEV-03' and d['file'] == '__init__.py' and d['line'] == 2 and d['fix'] for d in diagnostics))

    def test_dynamic_schema_is_never_promoted_to_pass(self):
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name="demo", schema=make_schema(), handler=lambda args: "{}")\n')
        self.assertEqual(self.check('guide-schemas')['status'], 'needs_review')

    def test_undefined_schema_is_reviewable_without_code_execution(self):
        self.put('__init__.py', 'def register(ctx):\n    ctx.register_tool(name="demo", schema=UNKNOWN, handler=lambda args: "{}")\n')
        self.assertEqual(self.check('guide-schemas')['status'], 'needs_review')

    def test_plain_dict_handler_return_is_not_a_json_string(self):
        self.put('__init__.py', 'SCHEMA = ' + repr(SCHEMA) + '\ndef handle(args, **kwargs):\n    return {"private_payload": "SYNTHETIC-NOT-FOR-OUTPUT"}\ndef register(ctx):\n    ctx.register_tool(name="demo", schema=SCHEMA, handler=handle)\n')
        self.assertEqual(self.check('guide-handlers')['status'], 'fail')
        self.assertNotIn('SYNTHETIC-NOT-FOR-OUTPUT', json.dumps(audit(self.root)))

    def test_handler_without_kwargs_is_not_a_universal_ban(self):
        self.put('__init__.py', 'SCHEMA = ' + repr(SCHEMA) + '\ndef handle(args):\n    return "{}"\ndef register(ctx):\n    ctx.register_tool(name="demo", schema=SCHEMA, handler=handle)\n')
        self.assertNotEqual(self.check('guide-handlers')['status'], 'fail')

    def test_decorator_can_transform_a_handler_result(self):
        self.put('__init__.py', 'import json\nSCHEMA = ' + repr(SCHEMA) + '\ndef encode(fn):\n    return lambda args, **kw: json.dumps(fn(args, **kw))\n@encode\ndef handle(args, **kw):\n    return {"ok": True}\ndef register(ctx):\n    ctx.register_tool(name="demo", schema=SCHEMA, handler=handle)\n')
        self.assertEqual(self.check('guide-handlers')['status'], 'needs_review')

    def test_registration_local_schema_shadow_is_not_a_false_failure(self):
        self.put('__init__.py', 'SCHEMA = []\ndef register(ctx):\n    SCHEMA = ' + repr(SCHEMA) + '\n    ctx.register_tool(name="demo", schema=SCHEMA, handler=lambda args: "{}")\n')
        self.assertEqual(self.check('guide-schemas')['status'], 'needs_review')

    def test_no_candidate_import_or_out_of_tree_asset_reads(self):
        marker = self.root.parent / 'EXECUTED'
        self.put('__init__.py', 'from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\ndef register(ctx):\n    ctx.register_skill("x", "../PRIVATE-SYNTHETIC-ASSET")\n')
        report = audit(self.root)
        self.assertFalse(marker.exists())
        self.assertNotIn('PRIVATE-SYNTHETIC-ASSET', json.dumps(report['guide_analysis']['diagnostics']))
        self.assertNotEqual(self.check('guide-resources')['status'], 'pass')

    def test_markdown_explains_both_tracks_and_guide_findings(self):
        text = markdown(audit(self.root))
        self.assertIn('Build-guide conformance', text)
        self.assertIn('Competition and catalog readiness', text)
        self.assertIn('DEV-01', text)
        self.assertIn('schemas', text.lower())

    def test_real_demo_distinguishes_catalog_fix_from_guide_fix(self):
        import subprocess
        import sys
        output = Path(self.tmp.name) / 'recordings'
        script = Path(__file__).resolve().parents[1] / 'scripts/demo.py'
        process = subprocess.run([sys.executable, '-B', str(script), '--output', str(output)],
                                 capture_output=True, text=True, timeout=30,
                                 env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(process.returncode, 0, process.stderr)
        receipts = list(output.glob('run-*/receipt.json'))
        self.assertEqual(len(receipts), 1)
        receipt = json.loads(receipts[0].read_text())
        self.assertEqual([event['exit_code'] for event in receipt['events']], [1, 1, 2, 2])
        template = json.loads((receipts[0].parent / 'review-template.json').read_text())
        self.assertEqual(set(template['decisions']), {row['id'] for row in requirements()})
        self.assertFalse(receipt['published_on_x'])
        self.assertFalse(receipt['video_recorded'])

    def test_template_requires_guide_decisions(self):
        doc = review_template(audit(self.root))
        self.assertIn('DEV-12', doc['decisions'])


class DualSourceEvidenceTests(unittest.TestCase):
    def test_competition_only_decisions_cannot_skip_build_guide(self):
        import test_evidence_review as old
        case = old.ReviewEvidenceTests('test_complete_review_is_accountable_not_official_certification')
        case.setUp(); self.addCleanup(case.doCleanups)
        case.doc['decisions'] = {key: value for key, value in case.doc['decisions'].items() if not key.startswith('DEV-')}
        result = case.evaluate()
        self.assertFalse(result['readiness']['code_ready']['ready'])
        self.assertIn('DEV-01', result['readiness']['code_ready']['pending'])

    def test_complete_evidence_can_review_both_tracks(self):
        import test_evidence_review as old
        case = old.ReviewEvidenceTests('test_complete_review_is_accountable_not_official_certification')
        case.setUp(); self.addCleanup(case.doCleanups)
        case.evaluate()
        report = audit(case.candidate, review=case.evidence / 'review.json')
        self.assertEqual({track['status'] for track in report['tracks'].values()}, {'reviewed'})
        self.assertTrue(report['assessment']['readiness']['code_ready']['ready'])
        self.assertFalse(report['certified'])

    def test_invalid_evidence_cannot_leave_a_reviewed_track(self):
        import test_evidence_review as old
        case = old.ReviewEvidenceTests('test_complete_review_is_accountable_not_official_certification')
        case.setUp(); self.addCleanup(case.doCleanups)
        case.evaluate()
        (case.evidence / 'review.md').write_text('Changed fixture evidence')
        report = audit(case.candidate, review=case.evidence / 'review.json')
        self.assertEqual(report['assessment']['status'], 'invalid')
        self.assertFalse(any(track['status'] == 'reviewed' for track in report['tracks'].values()))

    def test_mandatory_guide_layout_cannot_be_marked_not_applicable(self):
        import test_evidence_review as old
        case = old.ReviewEvidenceTests('test_complete_review_is_accountable_not_official_certification')
        case.setUp(); self.addCleanup(case.doCleanups)
        case.doc['decisions']['DEV-01']['decision'] = 'not_applicable'
        self.assertIn('DEV-01', case.evaluate()['readiness']['code_ready']['pending'])

    def test_actual_guide_blocker_cannot_be_waived_by_complete_review(self):
        import test_evidence_review as old
        case = old.ReviewEvidenceTests('test_complete_review_is_accountable_not_official_certification')
        case.setUp(); self.addCleanup(case.doCleanups)
        case.report['checks'].append({'id': 'broken-guide', 'rules': ['DEV-02'], 'status': 'fail', 'detail': 'Registration missing'})
        self.assertFalse(case.evaluate()['readiness']['code_ready']['ready'])


if __name__ == '__main__':
    unittest.main()
