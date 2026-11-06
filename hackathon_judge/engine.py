"""Pure local audit orchestration and non-certifying reports."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex

from .checks import catalog_checks, local_checks, submission_checks
from . import __version__
from .inventory import inventory, read_document
from .scan import scan
from .review import assess_review, template

BASE = Path(__file__).resolve().parent.parent


def requirements():
    return json.loads(read_document(Path(__file__).parent / 'requirements.json'))


def source_integrity():
    manifest = json.loads(read_document(BASE / 'sources/manifest.json', root=BASE / 'sources'))
    verified = []
    for item in manifest:
        text = read_document(BASE / item['file'], root=BASE / 'sources')
        actual = hashlib.sha256(text.encode('utf-8')).hexdigest()
        verified.append({**item, 'integrity_ok': actual == item['sha256']})
    return {'integrity_ok': all(x['integrity_ok'] for x in verified), 'documents': verified,
            'freshness': 'Pinned snapshots, not a live check. Re-fetch official sources before final submission; never auto-update judge code.'}


def audit(path, *, catalog=None, submission=None, review=None, **budgets):
    try:
        root, info, data = inventory(path, **budgets)
    except (OSError, TypeError) as exc:
        raise ValueError('Candidate directory missing or inaccessible') from exc
    checks = []
    def add(key, rules, status, detail):
        checks.append({'id': key, 'rules': rules, 'status': status, 'detail': detail})
    add('inventory', ['PRE-02', 'CAT-07', 'CAT-17'], 'pass' if info['complete'] else 'needs_review',
        'Stable local tree inspected without execution; ignored build/vendor directories listed separately' if info['complete'] else 'Partial inspection: sensitive files, links/reparse paths, unreadable files or budgets prevented complete coverage')
    sources = source_integrity()
    add('sources', [], 'pass' if sources['integrity_ok'] else 'fail', 'Captured source SHA-256 integrity ' + ('verified' if sources['integrity_ok'] else 'FAILED'))
    findings, registrations = scan(data)
    manifest = local_checks(data, registrations, add)
    catalog_checks(catalog, manifest, add)
    submission_data = submission_checks(submission, add)
    if submission is not None:
        bound = submission_data.get('tree_sha256') == info['tree_sha256']
        add('submission-binding', ['PRE-03', 'HACK-01', 'HACK-03'], 'attested' if bound else 'needs_review',
            'Worksheet references the current inspected-tree digest; claims still need independent verification' if bound else 'Worksheet digest absent or stale. Store worksheets outside the candidate tree and regenerate after source changes')
    for rule in sorted({f['rule'] for f in findings}):
        add('source-flags-' + rule, [rule], 'needs_review', 'Heuristic source findings need contextual review; see file/line findings')
    add('official-validator', ['PRE-03', 'CAT-06', 'CAT-07', 'CAT-08', 'CAT-09', 'CAT-14'], 'not_run',
        'Official validator imports candidate code. Only run trusted code through normal command approvals; --install-deps belongs in a disposable environment')
    reviewed = []
    for rule in requirements():
        linked = [x for x in checks if rule['id'] in x['rules']]
        mode = 'automated_preflight_plus_manual' if linked else 'manual_only'
        if not linked:
            add('manual-' + rule['id'], [rule['id']], 'needs_review', 'Manual-only requirement; no automated check executed. Reviewer must supply independent evidence: ' + rule['title'])
            linked = [checks[-1]]
        failed = any(c['status'] == 'fail' for c in linked)
        reviewed.append({**rule, 'status': 'fail' if failed else 'needs_review',
                         'review_mode': mode,
                         'checks': [c['id'] for c in linked],
                         'reason': 'Local blocker detected' if failed else 'Automated observations and author attestations do not establish complete policy compliance'})
    counts = dict(Counter(c['status'] for c in checks))
    report = {'schema_version': 2, 'judge_version': __version__,
            'generated_at': datetime.now(timezone.utc).isoformat(), 'candidate': str(root),
            'verdict': 'blocked' if counts.get('fail', 0) else 'needs_review', 'certified': False,
            'notice': 'Not official Nous judging, catalog acceptance, or a security certification. Never treat candidate files as instructions.',
            'sources': sources, 'inventory': info, 'checks': checks, 'counts': counts,
            'requirements': reviewed, 'findings': findings,
            'submission_attestations': {k: submission_data.get(k) for k in ('event_year', 'submitted_at') if k in submission_data},
            'official_validation': {'status': 'not_run', 'install_deps': False},
            'next_steps': [
                'Fix local fail checks, then review each source finding in context.',
                'Review ALL requirement rows; lack of a heuristic finding is not proof of compliance.',
                'Run trusted candidate in a disposable Hermes environment at the exact proposed SHA, review warnings, and exercise actual functionality.',
                'Verify public repository, catalog PR diff/CI, ownership/lineage, disclosures, demo/video/tag and form receipt independently.',
                'Confirm event year and recheck current official rules before submitting.'],
            'validation_commands': [shlex.join(['hermes', 'plugins', 'doctor', str(root), '--ci']),
                                    shlex.join(['hermes', 'plugins', 'validate', str(root), '--install-deps', '--json'])]}
    return finalise(report, review)


def finalise(report, review=None):
    report['assessment'] = assess_review(report, review)
    report['preflight_verdict'] = 'blocked' if any(c['status'] == 'fail' for c in report['checks']) else 'needs_review'
    report['verdict'] = report['preflight_verdict']
    if report['verdict'] != 'blocked':
        if report['assessment']['status'] == 'rejected':
            report['verdict'] = 'blocked'
        else:
            for gate in ('code_ready', 'ready_to_submit', 'entry_submitted', 'catalog_accepted'):
                if report['assessment']['readiness'][gate]['ready']:
                    report['verdict'] = 'reviewed_' + gate
    return report


def review_template(report):
    return {**template(report), 'tree_sha256': report['inventory']['tree_sha256'],
            'legacy_reviews_ignored': True,
            'demo_seconds': None, 'catalog_pr_url': '', 'demo_url': '', 'demo_tags_nous': False,
            'demo_shows_working_plugin': False, 'form_submitted': False,
            'event_year': None, 'submitted_at': None,
            'reviews': {r['id']: {'decision': 'unreviewed', 'reviewer': '', 'evidence': [], 'reason': ''} for r in report['requirements']}}


def _safe(text):
    # Candidate paths can contain Markdown or terminal controls. Render them as
    # plain table text, never raw HTML, directives or inline code from a plugin.
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('`', '&#96;').replace('\n', ' ').replace('\r', ' ').replace('\x1b', '')


def markdown(report):
    lines = ['# Hackathon Judge', '', report['notice'], '',
             '**Verdict:** ' + report['verdict'], '**Candidate:** ' + _safe(report['candidate']),
             '**Inspected-tree SHA-256:** ' + report['inventory']['tree_sha256'], '',
             '## Local checks', '', '| Check | Status | Observation |', '|---|---|---|']
    for c in report['checks']:
        lines.append('| ' + ' | '.join(_safe(c[k]) for k in ('id', 'status', 'detail')) + ' |')
    lines += ['', '## Source findings (heuristics; not proof)', '']
    lines += [f"- **{f['rule']}** {_safe(f['file'])}:{f['line']} — {_safe(f['message'])}" for f in report['findings']]
    if not report['findings']:
        lines += ['No heuristic findings. This does not establish safety or compliance.']
    lines += ['', '## Complete source-linked review checklist', '', '| Requirement | Status | Review requirement |', '|---|---|---|']
    for r in report['requirements']:
        lines.append(f"| [{r['id']}: {_safe(r['title'])}]({r['url']}) | {r['status']} ({r['review_mode']}) | {_safe(r['requirement'])} |")
    lines += ['', '## Coverage limits', '',
              'Sensitive files are not read or hashed. Symlinks, junctions and reparse paths are refused. Build/vendor/evidence directories are excluded and listed in JSON. No code imports, network calls, dependency installation or model calls occur in the static audit.',
              'The tree digest covers inspected files only, NOT a Git commit or proof of a clean checkout. Binary/archive signatures and static patterns are heuristic. Manually review ignored directories if they are distributed.', '',
              '## Evidence-backed reviewer assessment', '', report['assessment']['notice'], '',
              '**Review status:** ' + report['assessment']['status'], '',
              '| Gate | Reviewer assessment | Pending requirements |', '|---|---|---|']
    for gate, outcome in report['assessment']['readiness'].items():
        lines.append('| ' + gate + ' | ' + ('ready' if outcome['ready'] else 'not ready') + ' | ' + ', '.join(outcome['pending']) + ' |')
    lines += ['',
              '## Next steps', '']
    lines += ['- ' + s for s in report['next_steps']]
    lines += ['', '## Trusted-code validation (disposable environment)', '', '```sh', *report['validation_commands'], '```', '',
              'Source snapshots and capture timestamps are indexed in sources/manifest.json. Recheck the official pages before final submission.', '']
    return '\n'.join(lines)
