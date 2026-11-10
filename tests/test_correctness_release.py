"""The repaired source is a distinct, internally consistent patch release."""
from pathlib import Path
import importlib.util
import unittest
import yaml
from hackathon_judge import __version__
ROOT=Path(__file__).resolve().parents[1]
class CorrectnessReleaseTests(unittest.TestCase):
    def test_repaired_package_has_new_patch_version(self):
        self.assertEqual(__version__,'0.3.1')
    def test_manifest_and_generated_catalog_identify_repaired_release(self):
        manifest=yaml.safe_load((ROOT/'plugin.yaml').read_text())
        self.assertEqual(str(manifest['version']),'0.3.1')
        spec=importlib.util.spec_from_file_location('correctness_catalog_generator',ROOT/'scripts/catalog-entry.py')
        if spec is None or spec.loader is None:
            raise RuntimeError('Cannot load the source catalog generator')
        loader=spec.loader
        mod=importlib.util.module_from_spec(spec);loader.exec_module(mod)
        entry=yaml.safe_load(mod.render('https://github.com/example/fixture','a'*40,'Fixture Maintainer',ROOT))
        self.assertEqual(entry['version'],manifest['version'])
    def test_release_docs_and_submission_template_do_not_mislabel_patch(self):
        self.assertIn('Version 0.3.1',(ROOT/'README.md').read_text())
        self.assertIn('version 0.3.1',(ROOT/'submission/pr-body.md').read_text())
        import json
        self.assertEqual(json.loads((ROOT/'submission/form-handoff.json').read_text())['plugin']['version'],'0.3.1')
if __name__=='__main__':unittest.main()
