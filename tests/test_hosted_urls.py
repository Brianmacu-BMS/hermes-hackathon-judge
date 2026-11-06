"""Table-driven tests for _hosted_url helper and catalog image/screenshot validation.

Tests exercise the operator-precedence bypass fix and align admission
with the captured official catalog policy (sources/catalog-readme.md):
- Scheme must be https for every admitted host branch
- exact hosts: raw.githubusercontent.com, github.com
- suffix host: *.githubusercontent.com
- www.github.com is NOT an admitted host (upstream loader
  hermes_cli/plugin_catalog.py IMAGE_HOSTS omits it; captured policy
  prose lists only "github.com")
- Userinfo, ports, and uppercase are handled transparently by urlparse
- Malformed/non-string inputs are refused via try/except ValueError/TypeError
"""
import unittest
import os

from hackathon_judge.checks import _hosted_url


class HostedUrlAllowedTests(unittest.TestCase):
    """Cases that MUST be accepted by _hosted_url."""

    _allowed_urls: list[tuple[str, str]] = [
        # --- exact host: raw.githubusercontent.com ---
        (
            "https://raw.githubusercontent.com/owner/repo/sha/path/img.png",
            "canonical raw.githubusercontent.com URL",
        ),
        (
            "https://raw.githubusercontent.com:443/path.png",
            "port 443 on raw.githubusercontent.com (stripped by urlparse)",
        ),
        (
            "https://user@raw.githubusercontent.com/path.png",
            "userinfo on raw.githubusercontent.com (ignored by urlparse)",
        ),
        (
            "https://user:pass@raw.githubusercontent.com/path.png",
            "credentials on raw.githubusercontent.com (ignored by urlparse)",
        ),
        # --- exact host: github.com ---
        (
            "https://github.com/owner/repo/blob/sha/icon.png",
            "github.com path, exact host match",
        ),
        (
            "https://github.com",
            "bare github.com host with no path",
        ),
        # --- suffix *.githubusercontent.com ---
        (
            "https://gist.githubusercontent.com/user/raw/id/file.png",
            "gist.githubusercontent.com (matches *.githubusercontent.com)",
        ),
        (
            "https://avatars.githubusercontent.com/u/123?v=4",
            "avatars.githubusercontent.com (matches *.githubusercontent.com)",
        ),
        (
            "https://camo.githubusercontent.com/abc/def/ghi.png",
            "camo.githubusercontent.com (matches *.githubusercontent.com)",
        ),
        (
            "https://objects.githubusercontent.com/raw/file.png",
            "objects.githubusercontent.com (matches *.githubusercontent.com)",
        ),
        # --- case insensitivity ---
        (
            "HTTPS://RAW.GITHUBUSERCONTENT.COM/O/R/S.PNG",
            "uppercase scheme and hostname",
        ),
        (
            "https://Gist.GitHubUserContent.COM/something.png",
            "mixed-case *.githubusercontent.com host",
        ),
        # --- other GitHub *.githubusercontent.com services ---
        (
            "https://media.githubusercontent.com/file.png",
            "media.githubusercontent.com (GitHub LFS/media, matches *.githubusercontent.com)",
        ),
    ]

    def test_all_allowed(self):
        for url, desc in self._allowed_urls:
            with self.subTest(url=url, desc=desc):
                self.assertTrue(
                    _hosted_url(url),
                    f"Expected ALLOW but got DENY: {desc}\n  url={url!r}",
                )


class HostedUrlDeniedTests(unittest.TestCase):
    """Cases that MUST be rejected by _hosted_url."""

    _denied_urls: list[tuple[object, str]] = [
        # --- operator-precedence bypass: wrong scheme on exact hosts ---
        (
            "http://raw.githubusercontent.com/path.png",
            "http on raw.githubusercontent.com (bypasses exact-host branch)",
        ),
        (
            "ftp://raw.githubusercontent.com/path.png",
            "ftp on raw.githubusercontent.com (bypasses exact-host branch)",
        ),
        (
            "http://github.com/path.png",
            "http on github.com (bypasses exact-host branch)",
        ),
        (
            "//raw.githubusercontent.com/path.png",
            "scheme-relative on raw.githubusercontent.com (scheme='')",
        ),
        # --- operator-precedence bypass: wrong scheme on *.githubusercontent.com ---
        (
            "http://evil.githubusercontent.com/path.png",
            "http on *.githubusercontent.com host (bypasses suffix branch)",
        ),
        (
            "ftp://evil.githubusercontent.com/path.png",
            "ftp on *.githubusercontent.com host (bypasses suffix branch)",
        ),
        (
            "//evil.githubusercontent.com/path.png",
            "scheme-relative on *.githubusercontent.com (scheme='')",
        ),
        (
            "http://gist.githubusercontent.com/path.png",
            "http on gist.githubusercontent.com",
        ),
        (
            "http://avatars.githubusercontent.com/path.png",
            "http on avatars.githubusercontent.com",
        ),
        # --- www.github.com not admitted ---
        (
            "https://www.github.com/path.png",
            "www.github.com not in exact-host set or suffix",
        ),
        (
            "http://www.github.com/path.png",
            "www.github.com http (rejected on both branches)",
        ),
        # --- foreign hosts, any scheme ---
        (
            "https://example.com/banner.png",
            "foreign host https (not a GitHub host)",
        ),
        (
            "http://example.com/banner.png",
            "foreign host http",
        ),
        # --- suffix-boundary denial: no leading dot ---
        (
            "https://xgithubusercontent.com/file.png",
            "bare xprefix does not create *.githubusercontent.com match",
        ),
        # --- bare githubusercontent.com (no subdomain) ---
        (
            "https://githubusercontent.com/path.png",
            "bare githubusercontent.com does not end with .githubusercontent.com",
        ),
        # --- trailing dot hostname ---
        (
            "https://raw.githubusercontent.com./path.png",
            "trailing dot — hostname='raw.githubusercontent.com.'",
        ),
        # --- malformed / edge cases ---
        (
            "",
            "empty string",
        ),
        (
            "https://",
            "scheme with empty netloc",
        ),
        (
            "not-a-url",
            "no scheme, no netloc",
        ),
        (
            None,
            "None input",
        ),
        (
            42,
            "integer input",
        ),
        (
            ["https://raw.githubusercontent.com/x.png"],
            "list input (wrong type)",
        ),
    ]

    def test_all_denied(self):
        for url, desc in self._denied_urls:
            with self.subTest(url=url, desc=desc):
                self.assertFalse(
                    _hosted_url(url),
                    f"Expected DENY but got ALLOW: {desc}\n  url={url!r}",
                )


class HostedUrlIntegrationViaCatalogChecks(unittest.TestCase):
    """Integration tests: catalog_checks with image/screenshot fields.

    These exercise the full path from catalog entry loading through
    _hosted_url via the public catalog_checks API, ensuring the error
    messages reference the right field(s).
    """
    maxDiff = None

    def setUp(self):
        from pathlib import Path
        import tempfile
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "plugin.yaml").write_text(
            "name: test-plugin\nversion: 1.0.0\ndescription: A test\n"
            "requires_hermes: \">=0.22.5\"\n"
        )
        (self.root / "__init__.py").write_text("def register(ctx):\n    pass\n")


    def _make_entry(self, entry_data: dict) -> str:
        """Write entry.yaml and run catalog_checks, returning detail text.

        Entries are serialized with every scalar double-quoted so the
        version node satisfies the judge's quoted-string requirement;
        only the field under test varies.
        """
        import yaml
        from hackathon_judge.engine import audit

        base = {
            "name": "test-plugin",
            "repo": "https://github.com/o/r",
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "version": "1.0.0",
            "requires_hermes": ">=0.22.5",
        }
        base.update(entry_data)
        entry = self.root / "entry.yaml"
        entry.write_text(yaml.safe_dump(base, default_style='"'))
        meta = next(c for c in audit(self.root, catalog=entry)['checks'] if c['id'] == 'catalog-metadata')
        return f"{meta['status']}: {meta['detail']}"

    def test_http_image_on_raw_githubusercontent_com_fails(self):
        """http://raw.githubusercontent.com/... image — the exact-host bypass."""
        detail = self._make_entry({
            "name": "test-plugin",
            "repo": "https://github.com/o/r",
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "version": "1.0.0",
            "image": "http://raw.githubusercontent.com/o/r/s/p.png",
        })
        self.assertIn("fail", detail, f"Expected fail but got: {detail}")
        self.assertIn("image", detail.lower())

    def test_http_image_on_evil_githubusercontent_com_fails(self):
        """http on *.githubusercontent.com — the suffix-branch bypass."""
        detail = self._make_entry({
            "name": "test-plugin",
            "repo": "https://github.com/o/r",
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "version": "1.0.0",
            "image": "http://evil.githubusercontent.com/path.png",
        })
        self.assertIn("fail", detail, f"Expected fail but got: {detail}")
        self.assertIn("image", detail.lower())

    def test_scheme_relative_image_on_githubusercontent_fails(self):
        """//evil.githubusercontent.com/... — scheme-relative bypass."""
        detail = self._make_entry({
            "name": "test-plugin",
            "repo": "https://github.com/o/r",
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "version": "1.0.0",
            "image": "//evil.githubusercontent.com/path.png",
        })
        self.assertIn("fail", detail, f"Expected fail but got: {detail}")
        self.assertIn("image", detail.lower())

    def test_ftp_image_on_raw_githubusercontent_com_fails(self):
        """ftp://raw.githubusercontent.com/... — wrong scheme on exact host."""
        detail = self._make_entry({
            "name": "test-plugin",
            "repo": "https://github.com/o/r",
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "version": "1.0.0",
            "image": "ftp://raw.githubusercontent.com/o/r/s/p.png",
        })
        self.assertIn("fail", detail, f"Expected fail but got: {detail}")
        self.assertIn("image", detail.lower())

    def test_www_github_com_image_fails(self):
        """https://www.github.com/... — www.github.com not admitted."""
        detail = self._make_entry({
            "name": "test-plugin",
            "repo": "https://github.com/o/r",
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "version": "1.0.0",
            "image": "https://www.github.com/o/r/s/p.png",
        })
        self.assertIn("fail", detail, f"Expected fail but got: {detail}")

    def test_valid_https_images_pass(self):
        """Representative valid URLs pass integration."""
        detail = self._make_entry({
            "name": "test-plugin",
            "repo": "https://github.com/o/r",
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "version": "1.0.0",
            "image": "https://raw.githubusercontent.com/o/r/s/p.png",
            "screenshots": [
                "https://raw.githubusercontent.com/o/r/s/s1.png",
                "https://gist.githubusercontent.com/u/s/s2.png",
            ],
        })
        self.assertIn("pass", detail, f"Expected pass but got: {detail}")

    def test_denied_screenshots_are_flagged(self):
        """Non-HTTPS screenshots in the list produce a fail."""
        detail = self._make_entry({
            "name": "test-plugin",
            "repo": "https://github.com/o/r",
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "version": "1.0.0",
            "screenshots": [
                "http://raw.githubusercontent.com/o/r/s.png",
                "https://raw.githubusercontent.com/o/r/s2.png",
            ],
        })
        self.assertIn("fail", detail, f"Expected fail but got: {detail}")
        self.assertIn("screenshot", detail.lower())

    def test_foreign_host_screenshot_fails(self):
        """HTTPS on non-GitHub host is denied for screenshots too."""
        detail = self._make_entry({
            "name": "test-plugin",
            "repo": "https://github.com/o/r",
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "version": "1.0.0",
            "screenshots": ["https://example.com/s.png"],
        })
        self.assertIn("fail", detail, f"Expected fail but got: {detail}")
        self.assertIn("screenshot", detail.lower())


    def test_public_audit_all_admitted_host_branches(self):
        for url, description in HostedUrlAllowedTests._allowed_urls:
            with self.subTest(url=url, description=description):
                detail = self._make_entry({'image': url, 'screenshots': [url]})
                self.assertTrue(detail.startswith('pass:'), detail)

    def test_public_audit_wrong_scheme_on_every_host_branch(self):
        for host in ['github.com', 'raw.githubusercontent.com', 'gist.githubusercontent.com',
                     'avatars.githubusercontent.com', 'objects.githubusercontent.com']:
            for scheme in ['http:', 'ftp:', '']:
                url = scheme + '//' + host + '/owned.png'
                for field, value in [('image', url), ('screenshots', [url])]:
                    with self.subTest(url=url, field=field):
                        detail = self._make_entry({field: value})
                        self.assertTrue(detail.startswith('fail:'), detail)
                        self.assertIn(field.rstrip('s'), detail)


class HostedUrlEdgeCases(unittest.TestCase):
    """Malformed / non-string / boundary cases for _hosted_url."""

    def test_urlparse_raises_valueerror(self):
        """A URL that makes urlparse raise should return False, not crash."""
        # The try/except (ValueError, TypeError) wrapper must refuse these
        bad_inputs = [
            None,
            42,
            {"key": "value"},
        ]
        for inp in bad_inputs:
            with self.subTest(input=inp):
                self.assertFalse(_hosted_url(inp))

    def test_very_long_url(self):
        """Extremely long URL should not crash the validator."""
        long = "https://raw.githubusercontent.com/" + "x" * 50000 + "/img.png"
        self.assertTrue(_hosted_url(long))

    def test_url_with_fragment(self):
        """Fragment in URL is stripped by urlparse; hostname unaffected."""
        self.assertTrue(
            _hosted_url("https://raw.githubusercontent.com/o/r/s/p.png#section")
        )
        self.assertFalse(
            _hosted_url("http://raw.githubusercontent.com/o/r/s/p.png#section")
        )

    def test_url_with_query(self):
        """Query string in URL is stripped by urlparse; hostname unaffected."""
        self.assertTrue(
            _hosted_url("https://raw.githubusercontent.com/o/r/s/p.png?w=600&h=300")
        )
        self.assertFalse(
            _hosted_url("http://raw.githubusercontent.com/o/r/s/p.png?w=600")
        )


if __name__ == "__main__":
    unittest.main()