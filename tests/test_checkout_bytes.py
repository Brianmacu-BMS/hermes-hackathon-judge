"""Checkout-byte stability regressions for the repo's canonical byte policy.

``core.autocrlf=true`` (the Windows default) rewrites LF to CRLF on checkout,
and ``git archive`` applies the same text/eol conversion in modern Git. That
corrupts three byte-sensitive surfaces unless ``.gitattributes`` pins them:

- ``sources/**`` raw source captures: hashed byte-for-byte by
  ``engine.source_integrity()`` against ``sources/manifest.json`` SHA-256s.
- ``hackathon_judge/requirements.json`` compiled policy: its bytes feed the
  policy digest and review receipts (``review.policy_digest``).
- Bash scripts (``scripts/demo-recording.sh``): CRLF breaks the shebang.

The repo root ``.gitattributes`` is copied into the fixture so the fixture
exercises exactly the file that ships. The fixture is a throwaway Git repo in
the test temp dir (its own index and object store, plumbing-only: index +
``write-tree`` + ``checkout-index``/``git archive``, no commits), so this
suite never touches the source repository's index or refs.
"""

import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTRIBUTES = REPO_ROOT / '.gitattributes'

# Author bytes exactly as authored (LF or no trailing newline), mirroring the
# repo's byte-sensitive layout: raw captures, compiled policy, Bash, text.
FILES = {
    Path('scripts') / 'demo-recording.sh': (
        b'#!/usr/bin/env bash\nset -euo pipefail\necho "recording"\n'
    ),
    Path('sources') / 'catalog-readme.md': b'# Catalog\n\nAdmission rules.\n',
    Path('sources') / 'raw-crlf.md': b'# Raw capture\r\nPreserve the captured bytes.\r\n',
    Path('sources') / 'manifest.json': b'{"captures": [{"file": "catalog-readme.md"}]}',
    Path('sources') / 'announcement-oembed.json': b'{"raw": "no newline at all"}',
    Path('hackathon_judge') / 'requirements.json': (
        b'[\n  {"id": "CAT-01", "requirement": "PR gated"}\n]\n'
    ),
    Path('hackathon_judge') / 'checks.py': b'def check():\n    return True\n',
    Path('__init__.py'): b'def register(ctx):\n    pass\n',
    Path('plugin.yaml'): b'name: demo\nversion: 1.0.0\ndescription: Demo\n',
    Path('README.md'): b'# Demo\n',
}


def _repo_attributes():
    """Bytes of the repo-root .gitattributes; hard-fail if it is missing."""
    try:
        return ATTRIBUTES.read_bytes()
    except FileNotFoundError:
        raise FileNotFoundError(
            f'Byte-stability regression requires {ATTRIBUTES}; '
            'without it autocrlf=true checkouts and archives corrupt '
            'sources/**, the policy JSON and Bash shebangs'
        ) from None


def _git(repo, *args, timeout=60, binary=False):
    """Run git in a fixture repo with host/global config fully isolated."""
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env['GIT_CONFIG_GLOBAL'] = os.devnull
    env['GIT_CONFIG_SYSTEM'] = os.devnull
    env['GIT_ATTR_NOSYSTEM'] = '1'
    env['GIT_TERMINAL_PROMPT'] = '0'
    proc = subprocess.run(
        ['git', *args], cwd=str(repo), env=env,
        capture_output=True, text=not binary, timeout=timeout,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f'git {" ".join(args)} failed (rc={proc.returncode}): '
            f'{proc.stderr.strip() or proc.stdout.strip()}'
        )
    return proc.stdout


class CheckoutByteStabilityTests(unittest.TestCase):
    def setUp(self):
        if shutil.which('git') is None:
            self.skipTest('git binary not available')
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / 'fixture'
        self.repo.mkdir()

    def _write_fixture(self, include_attributes=True):
        """Author canonical byte fixtures and init an isolated repo."""
        for rel, raw in FILES.items():
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        if include_attributes:
            (self.repo / '.gitattributes').write_bytes(_repo_attributes())
        _git(self.repo, 'init', '-q')
        _git(self.repo, 'config', 'core.autocrlf', 'true')

    def _stage_and_commitless_tree(self, has_attributes=True):
        """Fill the fixture index, verify stored blobs, return the tree id.

        When *has_attributes* is False the vacuity-guard test skips the
        .gitattributes blob assertion (no such file exists in that fixture).
        """
        expected = {}
        for rel in FILES:
            expected[rel] = _git(self.repo, 'hash-object', str(self.repo / rel)).strip()
        if has_attributes:
            expected[Path('.gitattributes')] = _git(
                self.repo, 'hash-object', str(self.repo / '.gitattributes')).strip()
        _git(self.repo, 'add', '-A')
        staged = {}
        for line in _git(self.repo, 'ls-files', '-s').splitlines():
            _, blob, _, path = line.split(None, 3)
            staged[Path(path)] = blob
        self.assertEqual(staged, expected,
                         'staging under the shipped .gitattributes must store '
                         'canonical blob bytes (no rehashing of sources/** or '
                         'the policy JSON)')
        tree = _git(self.repo, 'write-tree').strip()
        self.assertTrue(tree)
        return tree

    def _materialize(self):
        """Drop authored files and materialize the index via checkout-index."""
        for rel in FILES:
            (self.repo / rel).unlink()
        _git(self.repo, 'checkout-index', '--all')

    def _assert_canonical(self, root):
        for rel, raw in FILES.items():
            self.assertEqual((root / rel).read_bytes(), raw,
                             f'{rel} lost its canonical bytes')
        if (root / '.gitattributes').exists():
            self.assertEqual((root / '.gitattributes').read_bytes(), _repo_attributes())
        self.assertNotIn(b'\r', (root / 'scripts/demo-recording.sh').read_bytes())

    def test_autocrlf_true_checkout_preserves_canonical_bytes(self):
        self._write_fixture()
        self._stage_and_commitless_tree()
        self._materialize()
        self._assert_canonical(self.repo)

    def test_git_archive_reproduces_canonical_bytes(self):
        self._write_fixture()
        tree = self._stage_and_commitless_tree()
        archive = _git(self.repo, 'archive', '--format=tar', tree, binary=True)
        extracted = self.repo / 'archived'
        extracted.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tar:
            self.assertIn(Path('.gitattributes'),
                          {Path(m.name) for m in tar.getmembers()},
                          'archive must carry .gitattributes for later '
                          'byte-clean exports')
            tar.extractall(extracted)
        self._assert_canonical(extracted)

    def test_without_attributes_checkout_introduces_crlf(self):
        """Vacuity guard: the harness genuinely exercises conversion, so the
        byte assertions above are meaningful (this is the vulnerability that
        .gitattributes closes)."""
        self._write_fixture(include_attributes=False)
        self._stage_and_commitless_tree(has_attributes=False)
        self._materialize()
        shebang = (self.repo / 'scripts' / 'demo-recording.sh').read_bytes()
        self.assertIn(b'\r\n', shebang,
                      'fixture must visibly corrupt LF without attributes; '
                      'if Git stops converting, rework this harness')


if __name__ == '__main__':
    unittest.main()