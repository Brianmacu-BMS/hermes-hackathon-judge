"""Local metadata checks, intentionally narrower than official validation."""
from datetime import datetime, timedelta, timezone
import json
import re
import tomllib
from urllib.parse import urlparse

import yaml
from packaging.requirements import InvalidRequirement, Requirement

from .inventory import read_document


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node):
    result = {}
    for key, value in node.value:
        k = loader.construct_object(key)
        if k in result:
            raise ValueError('Duplicate YAML mapping key')
        result[k] = loader.construct_object(value)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def mapping(text):
    value = yaml.load(text, Loader=UniqueLoader)
    if not isinstance(value, dict):
        raise ValueError('Expected a mapping')
    return value


def local_checks(data, registrations, add):
    manifest = {}
    try:
        manifest = mapping(data.get('plugin.yaml', b'').decode('utf-8'))
        valid = all(isinstance(manifest.get(k), str) and manifest[k].strip() for k in ('name', 'version', 'description'))
        add('manifest', ['PRE-02'], 'pass' if valid else 'fail', 'Required manifest string fields ' + ('present' if valid else 'missing or invalid'))
    except (ValueError, yaml.YAMLError, UnicodeError, TypeError):
        add('manifest', ['PRE-02'], 'fail', 'plugin.yaml missing or malformed (including duplicate keys)')
    entries = [p for p in ('__init__.py', 'desktop/plugin.js', 'plugin.json', 'dashboard/manifest.json') if p in data]
    add('entrypoint', ['PRE-02'], 'pass' if entries else 'fail', 'Entrypoint files: ' + (', '.join(entries) or 'none'))
    floor = manifest.get('requires_hermes', '')
    if floor and (not isinstance(floor, str) or not re.fullmatch(r'>=\s*\d{1,3}\.\d+(?:\.\d+)?', floor)):
        add('hermes-floor', ['CAT-14'], 'fail', 'Expected a SemVer floor such as >=0.22.5; dates and malformed values refused')
    else:
        add('hermes-floor', ['CAT-14'], 'needs_review', 'Floor syntax plausible; compare against published release and APIs actually used' if floor else 'No floor declared; assess whether recent APIs require one')
    readme = next((v for k, v in data.items() if k.lower() in {'readme.md', 'readme.rst', 'readme.txt'}), b'').decode('utf-8', errors='replace')
    has_section = bool(re.search(r'(?im)^\s*#+\s+.*(?:disclosure|risk|privacy|security)', readme))
    detail = 'README disclosure section found; verify completeness against actual network, file, shell, process, credential and opt-in telemetry behavior AND the PR'
    if not has_section:
        detail = 'README lacks an obvious disclosure section; add explicit risks/disclosures and compare with actual code and PR' if readme else 'README absent; add functionality, installation, risks and disclosures'
    add('readme-disclosures', ['CAT-13', 'PRE-04'], 'needs_review', detail)
    _registrations(manifest, registrations, add)
    _dependencies(manifest, data, add)
    _payloads(data, add)
    return manifest


def _registrations(manifest, actual, add):
    mismatches = []
    for kind in ('tools', 'hooks'):
        value = manifest.get('provides_' + kind, [])
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            mismatches.append('Invalid provides_' + kind)
        elif set(value) != actual[kind]:
            mismatches.append(kind + ' declarations differ from literal registrations')
    if actual['dynamic']:
        status, detail = 'needs_review', 'Dynamic registration or unparseable source; official runtime probe required'
    elif mismatches:
        status, detail = 'fail', '; '.join(mismatches)
    else:
        status, detail = 'pass', 'Static literal tool/hook declarations match; does not prove runtime capabilities, middleware or env parity'
    add('declared-registrations', ['CAT-06'], status, detail)


def _dependencies(manifest, data, add):
    deps = manifest.get('python_dependencies', [])
    if not isinstance(deps, list):
        add('dependency-bounds', ['CAT-10', 'CAT-14'], 'fail', 'python_dependencies must be a list')
        return
    deps = list(deps)
    if 'pyproject.toml' in data:
        try:
            project = tomllib.loads(data['pyproject.toml'].decode())
            deps.extend(project.get('project', {}).get('dependencies', []))
        except (ValueError, TypeError, AttributeError, UnicodeError):
            add('dependency-bounds', ['CAT-10'], 'fail', 'pyproject.toml could not be parsed')
            return
    if len(deps) > 1000:
        add('dependency-bounds', ['CAT-10'], 'fail', 'Dependency table exceeds inspection budget')
        return
    issues = 0
    for value in deps:
        try:
            dep = Requirement(value)
            bounded = any(s.operator in {'<', '<=', '==', '~='} for s in dep.specifier)
            if dep.url or not bounded:
                issues += 1
        except (InvalidRequirement, TypeError):
            issues += 1
    add('dependency-bounds', ['CAT-10', 'CAT-14'], 'needs_review' if issues else 'pass', f'{issues} invalid, unbounded or direct-URL dependencies need policy review' if issues else 'Local dependency declarations bounded; install resolution, quarantine and core constraints NOT tested')


def _payloads(data, add):
    magic = (b'\x7fELF', b'MZ', b'\x00asm', b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca')
    archive = (b'PK\x03\x04', b'\x1f\x8b', b'BZh', b'\xfd7zXZ\x00', b'7z\xbc\xaf\x27\x1c', b'Rar!')
    suspicious = [p for p, raw in data.items() if raw.startswith(magic + archive) or raw[257:262] == b'ustar' or p.endswith(('.pyc', '.pyo', '.zip', '.tar', '.tgz', '.gz', '.7z'))]
    add('reviewable-payloads', ['CAT-17'], 'needs_review' if suspicious else 'pass', 'Potential executable/bytecode/archive payloads require source or pinned build-attestation review: ' + ', '.join(suspicious[:40]) if suspicious else 'No recognized binary/bytecode/archive signatures in inspected files; not a proof of reviewability')


def _valid_catalog_name(name):
    """Check name is a plausible catalog key."""
    return bool(re.fullmatch(r'[a-z0-9_-]{1,64}', name)) if isinstance(name, str) else False


def _hosted_url(url):
    """Check url is https on raw.githubusercontent.com, github.com or *.githubusercontent.com.

    Matches the captured official catalog policy ("Images must live on
    raw.githubusercontent.com, github.com or *.githubusercontent.com",
    sources/catalog-readme.md) and the upstream loader's IMAGE_HOSTS /
    IMAGE_HOST_SUFFIX admission. www.github.com is not an admitted host.
    urlparse normalizes scheme/hostname; hostname matching ignores userinfo
    and ports, as the upstream metadata filter does. No URL is fetched here.
    """
    try:
        parts = urlparse(url)
        host = parts.hostname or ''
        return parts.scheme == 'https' and (
            host in {'raw.githubusercontent.com', 'github.com'}
            or host.endswith('.githubusercontent.com')
        )
    except (AttributeError, TypeError, ValueError):
        return False


def catalog_checks(path, manifest, add):
    if path is None:
        for key, rules in [('catalog-pin', ['CAT-02']), ('catalog-metadata', ['PRE-01', 'PRE-04', 'CAT-14'])]:
            add(key, rules, 'needs_review', 'No catalog entry supplied')
        return
    try:
        text = read_document(path)
        entry = mapping(text)
    except (ValueError, yaml.YAMLError, UnicodeError, TypeError, OSError):
        add('catalog-pin', ['CAT-02'], 'fail', 'Entry file could not be read or parsed')
        add('catalog-metadata', ['PRE-01', 'PRE-04', 'CAT-14'], 'fail', 'Entry file missing, unreadable, malformed YAML, or duplicate keys')
        return
    if not isinstance(entry, dict):
        add('catalog-pin', ['CAT-02'], 'fail', 'Entry is not a mapping')
        add('catalog-metadata', ['PRE-01', 'PRE-04', 'CAT-14'], 'fail', 'Catalog entry must be a YAML mapping')
        return
    sha = entry.get('sha')
    add('catalog-pin', ['CAT-02'], 'pass' if isinstance(sha, str) and re.fullmatch('[0-9a-fA-F]{40}', sha) else 'fail', 'Pin syntax only; verify exact commit, clean tree and monorepo subdir against the source repository')
    issues = []
    entry_name = entry.get('name')
    if entry_name is None:
        issues.append('missing name field in catalog entry')
    elif not _valid_catalog_name(entry_name):
        issues.append('name must be [a-z0-9_-] up to 64 chars')
    elif entry_name != manifest.get('name'):
        issues.append('entry name differs from plugin.yaml')
    repo = urlparse(entry.get('repo', '') if isinstance(entry.get('repo', ''), str) else '')
    if repo.scheme != 'https' or repo.hostname not in {'github.com', 'gitlab.com'} or repo.username or repo.password or repo.query or repo.fragment or len(repo.path.strip('/').split('/')) < 2:
        issues.append('repo must be a public HTTPS GitHub/GitLab repository URL without credentials')
    node = yaml.compose(text, Loader=UniqueLoader)
    version_node = next((value for key, value in node.value if key.value == 'version'), None)
    if not isinstance(entry.get('version'), str) or version_node is None or version_node.style not in {'"', "'"}:
        issues.append('version must be a quoted string')
    if entry.get('version') != manifest.get('version'):
        issues.append('entry version differs from plugin.yaml')
    if entry.get('requires_hermes') != manifest.get('requires_hermes'):
        issues.append('requires_hermes differs between entry and manifest')
    subdir = entry.get('subdir', '')
    if not isinstance(subdir, str) or (subdir and (not re.fullmatch(r'[A-Za-z0-9._/-]+', subdir) or any(p in {'', '.', '..'} for p in subdir.split('/')))):
        issues.append('invalid subdir')
    # Image and screenshot URL validation
    image = entry.get('image')
    if image is not None and not (isinstance(image, str) and _hosted_url(image)):
        issues.append('image must be https on github.com or *.githubusercontent.com')
    screenshots = entry.get('screenshots', [])
    if not isinstance(screenshots, list):
        issues.append('screenshots must be a list')
    elif len(screenshots) > 6:
        issues.append('max 6 screenshots')
    else:
        bad = [s for s in screenshots if not (isinstance(s, str) and _hosted_url(s))]
        if bad:
            issues.append(f'screenshots must be https URLs on GitHub hosts: {len(bad)} invalid')
    add('catalog-metadata', ['PRE-01', 'PRE-04', 'CAT-14'], 'fail' if issues else 'pass', '; '.join(issues) if issues else 'Local entry name/version/floor/repo/subdir/image/screenshots shape valid; public access, schema and pin/tree equivalence remain unverified')


def submission_checks(path, add):
    supplied = json.loads(read_document(path)) if path else {}
    if not isinstance(supplied, dict):
        raise ValueError('Submission evidence must be a JSON object')
    for key, rule, prefix in [('catalog_pr_url', 'HACK-01', 'https://github.com/NousResearch/hermes-agent/pull/'), ('demo_url', 'HACK-02', 'https://x.com/')]:
        value = supplied.get(key)
        valid = isinstance(value, str) and value.startswith(prefix) and len(value) > len(prefix)
        add(key, [rule], 'attested' if valid else 'needs_review', 'URL supplied by author; existence, ownership, contents and tags NOT fetched or verified' if valid else 'Missing or unexpected submission URL')
    seconds = supplied.get('demo_seconds')
    valid = isinstance(seconds, (int, float)) and not isinstance(seconds, bool)
    status = ('attested' if 0 < seconds < 90 else 'fail') if valid else 'needs_review'
    add('demo-duration', ['HACK-03'], status, 'Author-supplied duration; video media and working behavior need independent review' if status == 'attested' else 'Demo must be strictly between 0 and 90 seconds; missing duration is unknown')
    for key, rule in [('demo_tags_nous', 'HACK-02'), ('demo_shows_working_plugin', 'HACK-03'), ('form_submitted', 'HACK-04')]:
        add(key, [rule], 'attested' if supplied.get(key) is True else 'needs_review', 'Author attestation only; independently inspect media/form confirmation')
    _deadline(supplied, add)
    return supplied


def _deadline(supplied, add):
    year = supplied.get('event_year')
    stamp = supplied.get('submitted_at')
    status = 'needs_review'
    detail = 'Confirm event year and timezone-aware submission timestamp; source body gives Nov 11, 5PM EST but no explicit year'
    if year is not None or stamp is not None:
        try:
            if not isinstance(year, int) or isinstance(year, bool) or not isinstance(stamp, str):
                raise ValueError('Invalid timestamp/year')
            submitted = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            if submitted.tzinfo is None:
                raise ValueError('Timestamp must include timezone')
            deadline = datetime(year, 11, 11, 17, tzinfo=timezone(timedelta(hours=-5)))
            status = 'attested' if submitted <= deadline else 'fail'
            detail = 'Author-supplied timestamp compared with ' + deadline.isoformat() + '; event year and actual form receipt still need independent confirmation'
        except (ValueError, TypeError, OverflowError):
            detail = 'Invalid evidence: event_year integer and timezone-aware submitted_at required'
    add('deadline', ['HACK-05'], status, detail)
