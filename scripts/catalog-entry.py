#!/usr/bin/env python3
"""Prepare one catalog entry from explicit real repo/SHA inputs; never publish it."""
import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlparse

import yaml


def render(repo, sha, maintainer, root):
    url = urlparse(repo)
    if url.scheme != 'https' or url.hostname not in {'github.com', 'gitlab.com'} or url.username or url.password or url.query or url.fragment or url.port not in {None, 443}:
        raise ValueError('A credential-free public HTTPS GitHub/GitLab repository URL is required')
    if len(url.path.strip('/').split('/')) < 2 or not re.fullmatch('[0-9a-fA-F]{40}', sha):
        raise ValueError('Repository path and literal full 40-hex source commit required; branches and archive hashes are not accepted')
    if not maintainer.strip():
        raise ValueError('Actual maintainer required')
    manifest = yaml.safe_load((root / 'plugin.yaml').read_text())
    fields = {'name': manifest['name'], 'repo': repo, 'sha': sha,
              'description': manifest['description'], 'maintainer': maintainer,
              'tier': 'community', 'category': 'tools', 'requires_hermes': manifest['requires_hermes'],
              'version': str(manifest['version']), 'platforms': ['linux']}
    lines = [key + ': ' + (json.dumps(value) if not isinstance(value, list) else json.dumps(value)) for key, value in fields.items()]
    lines += ['capabilities:']
    for key in ('provides_tools', 'provides_hooks', 'provides_middleware', 'requires_env'):
        value = manifest.get(key, [])
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            raise ValueError('Catalog generator supports literal string capability lists only')
        lines.append('  ' + key + ': ' + json.dumps(value))
    return '\n'.join(lines) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--maintainer', required=True)
    args = parser.parse_args(argv)
    try:
        print(render(args.repo, args.sha, args.maintainer, Path(__file__).resolve().parents[1]), end='')
    except (ValueError, KeyError, TypeError, OSError):
        parser.error('Invalid explicit repository, pin, maintainer or source manifest')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
