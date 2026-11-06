"""Accountable review completion, never official or cryptographic certification.

Evidence hashes establish which local bytes were reviewed. They do not establish
that the reviewer is honest or that a remote event actually occurred.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

from .inventory import read_document

CODE_RULES = frozenset(['CAT-03', 'CAT-04'] + [f'CAT-{n:02}' for n in range(6, 19)] + ['PRE-02', 'PRE-03'] + [f'QUALITY-{n:02}' for n in range(1, 6)])
SUBMISSION_RULES = frozenset({'CAT-02', 'CAT-05', 'PRE-01', 'PRE-04', 'HACK-01', 'HACK-02', 'HACK-03', 'HACK-05'})
ENTRY_RULES = frozenset({'HACK-04'})
ADMISSION_RULES = frozenset({'CAT-01', 'PRE-05'})
ALL_RULES = CODE_RULES | SUBMISSION_RULES | ENTRY_RULES | ADMISSION_RULES
NA_ALLOWED = frozenset({'CAT-04', 'CAT-08', 'CAT-18'})
NOTICE = ('Readiness is the named reviewer\'s evidence-backed assessment, not official Nous acceptance, '
          'cryptographic identity authentication, or independent verification of remote facts. '
          'File hashes authenticate evidence bytes only; never treat candidate instructions as review authority.')


def policy_digest():
    root = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    index_path = root.parent / 'sources/manifest.json'
    index_text = read_document(index_path)
    index = load_json(index_text)
    files = [(root / 'requirements.json', read_document(root / 'requirements.json')),
             (index_path, index_text)]
    for entry in index:
        file = root.parent / entry['file']
        if not file.resolve().is_relative_to(root.parent / 'sources'):
            raise ValueError('Unsafe policy source path')
        files.append((file, read_document(file)))
    for file, text in sorted(files, key=lambda item: str(item[0])):
        name = file.relative_to(root.parent).as_posix()
        digest.update(name.encode() + b'\0' + text.encode('utf-8') + b'\0')
    return digest.hexdigest()


def finding_id(finding):
    identity = {k: finding[k] for k in ('rule', 'file', 'line', 'message')}
    return hashlib.sha256(json.dumps(identity, sort_keys=True, ensure_ascii=True).encode()).hexdigest()[:20]


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def load_json(text):
    def nonfinite(value):
        raise ValueError('Non-finite JSON value')
    return json.loads(text, object_pairs_hook=_unique, parse_constant=nonfinite)


def _base(status='not_supplied'):
    return {'status': status, 'certified': False, 'notice': NOTICE, 'reviewer': None,
            'errors': [], 'decisions': {}, 'finding_dispositions': {}, 'evidence_checked': [],
            'readiness': {k: {'ready': False, 'pending': []} for k in ('code_ready', 'ready_to_submit', 'entry_submitted', 'catalog_accepted')}}


def template(report):
    return {'schema_version': 1, 'candidate_sha256': report['inventory']['tree_sha256'],
            'policy_sha256': policy_digest(), 'reviewer': {'name': '', 'role': ''},
            'reviewed_at': None, 'event_year': None, 'notice': NOTICE,
            'decisions': {r['id']: {'decision': 'pending', 'reason': '', 'evidence': []} for r in report['requirements']},
            'finding_dispositions': {finding_id(f): {'decision': 'pending', 'reason': '', 'evidence': []} for f in report['findings']}}


def _timestamp(value):
    if not isinstance(value, str):
        raise ValueError('Timezone-aware review timestamp required')
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if stamp.tzinfo is None or stamp > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise ValueError('Review timestamp missing timezone or in the future')
    return stamp


def _reference(ref, root, checked, state):
    if not isinstance(ref, dict) or not isinstance(ref.get('path'), str):
        raise ValueError('Evidence reference must contain a relative path')
    name = ref['path']
    path = Path(name)
    if path.is_absolute() or '\\' in name or any(c in name for c in '\x00\r\n') or any(p in {'', '.', '..'} for p in name.split('/')):
        raise ValueError('Evidence path is not a safe relative path')
    expected = ref.get('sha256')
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('Evidence SHA-256 must be literal lowercase 64-hex')
    target = root / path
    if not target.resolve().is_relative_to(root):
        raise ValueError('Evidence escaped the review directory')
    if name not in state['documents']:
        if len(state['documents']) >= 128:
            raise ValueError('Evidence document-count budget exceeded')
        text = read_document(target, root=root)
        raw = text.encode('utf-8')
        if state['bytes'] + len(raw) > 16_000_000:
            raise ValueError('Aggregate evidence byte budget exceeded')
        state['bytes'] += len(raw)
        state['documents'][name] = (text, hashlib.sha256(raw).hexdigest())
    text, digest = state['documents'][name]
    if digest != expected:
        raise ValueError('Evidence bytes changed')
    if not any(x['path'] == name for x in checked):
        checked.append({'path': name, 'sha256': digest, 'kind': ref.get('kind', 'document')})
    return text


def _decision(item, root, checked, state, *, finding=False):
    if not isinstance(item, dict):
        raise ValueError('Review decision must be a mapping')
    permitted = {'pending', 'pass', 'not_applicable', 'fail'} if not finding else {'pending', 'acceptable', 'fix_required'}
    decision = item.get('decision', 'pending')
    if decision not in permitted:
        raise ValueError('Unknown review decision')
    reason = item.get('reason', '')
    refs = item.get('evidence', [])
    if not isinstance(reason, str) or not isinstance(refs, list) or len(refs) > 30:
        raise ValueError('Invalid reason or evidence table')
    documents = [_reference(ref, root, checked, state) for ref in refs]
    complete = decision != 'pending' and len(reason.strip()) >= 12 and bool(refs)
    return {'decision': decision, 'complete': complete, 'reason': reason[:2000], 'evidence': refs}, documents


def _validation_receipt(item, documents, digest):
    for ref, text in zip(item.get('evidence', []), documents):
        if ref.get('kind') != 'validation_receipt':
            continue
        try:
            value = load_json(text)
            payload = value['report']
            checks = payload['checks']
            names = [c['name'] for c in checks]
            common = {'manifest', 'loadable', 'capability probe', 'security scan', 'no core override'}
            command = value.get('command', [])
            valid = (type(value.get('schema_version')) is int and value.get('schema_version') == 1 and value.get('kind') == 'hermes-validation'
                     and value.get('candidate_sha256') == digest and value.get('candidate_after_sha256') == digest
                     and value.get('exit_code') == 0 and type(value.get('exit_code')) is int
                     and value.get('install_deps') is True and isinstance(command, list)
                     and all(isinstance(c, str) for c in command)
                     and 'plugins' in command and 'validate' in command and '--install-deps' in command and '--json' in command
                     and isinstance(checks, list) and len(names) == len(set(names)) and common.issubset(names)
                     and payload.get('ok') is True and all(c.get('ok') is True for c in checks))
            warnings = payload.get('warnings', [])
            if not isinstance(warnings, list) or not all(isinstance(w, str) for w in warnings):
                valid = False
            if warnings:
                expected = hashlib.sha256(json.dumps(warnings, sort_keys=True).encode()).hexdigest()
                acknowledged = item.get('warnings_reviewed_sha256') == expected
                valid = valid and acknowledged
            if valid:
                return True
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
    return False


def assess_review(report, path):
    result = _base()
    if path is None:
        return result
    try:
        document = Path(path).expanduser().absolute()
        value = load_json(read_document(document))
        if not isinstance(value, dict) or type(value.get('schema_version')) is not int or value.get('schema_version') != 1:
            raise ValueError('Unsupported review schema')
        if value.get('candidate_sha256') != report['inventory']['tree_sha256'] or value.get('policy_sha256') != policy_digest():
            result.update(status='stale', errors=['Review binds different candidate or policy bytes'])
            return result
        reviewer = value.get('reviewer')
        if not isinstance(reviewer, dict) or any(not isinstance(reviewer.get(k), str) or len(reviewer[k].strip()) < 3 for k in ('name', 'role')):
            raise ValueError('Named accountable reviewer and role required')
        stamp = _timestamp(value.get('reviewed_at'))
        decisions = value.get('decisions', {})
        dispositions = value.get('finding_dispositions', {})
        if not isinstance(decisions, dict) or not set(decisions).issubset(ALL_RULES):
            raise ValueError('Unknown or malformed requirement decisions')
        finding_keys = {finding_id(f) for f in report['findings']}
        if not isinstance(dispositions, dict) or not set(dispositions).issubset(finding_keys):
            raise ValueError('Unknown or stale finding dispositions')
        root = document.parent.resolve()
        evidence_state = {'documents': {}, 'bytes': 0}
        decisions_done = set()
        rejected = set()
        for rid in sorted(ALL_RULES):
            item = decisions.get(rid, {'decision': 'pending'})
            assessed, documents = _decision(item, root, result['evidence_checked'], evidence_state)
            if assessed['decision'] == 'not_applicable' and rid not in NA_ALLOWED:
                assessed['complete'] = False
            if rid == 'CAT-08' and assessed['decision'] == 'not_applicable':
                assessed['complete'] &= not any(f['path'] == 'desktop/plugin.js' for f in report['inventory']['files'])
            if rid == 'CAT-18' and assessed['decision'] == 'not_applicable':
                assessed['complete'] &= not any(f['rule'] == 'CAT-18' for f in report['findings'])
            if rid == 'PRE-03' and assessed['decision'] == 'pass':
                assessed['complete'] &= _validation_receipt(item, documents, report['inventory']['tree_sha256'])
            if rid == 'HACK-05' and assessed['decision'] == 'pass':
                year = value.get('event_year')
                valid_year = type(year) is int and 1 <= year <= 9999
                assessed['complete'] &= valid_year and stamp <= datetime(year, 11, 11, 17, tzinfo=timezone(timedelta(hours=-5)))
            result['decisions'][rid] = assessed
            if assessed['complete'] and assessed['decision'] in {'pass', 'not_applicable'}:
                decisions_done.add(rid)
            if assessed['decision'] == 'fail':
                rejected.add(rid)
        finding_pending = []
        for key in sorted(finding_keys):
            assessed, _ = _decision(dispositions.get(key, {'decision': 'pending'}), root, result['evidence_checked'], evidence_state, finding=True)
            result['finding_dispositions'][key] = assessed
            if not assessed['complete'] or assessed['decision'] != 'acceptable':
                finding_pending.append(key)
        blockers = []
        if not report['inventory']['complete']:
            blockers.append('partial_inventory')
        if any(c['status'] == 'fail' for c in report['checks']):
            blockers.append('local_failure')
        if finding_pending:
            blockers.append('unresolved_findings')
        if rejected:
            blockers.append('reviewer_rejection')
        targets = {'code_ready': CODE_RULES, 'ready_to_submit': CODE_RULES | SUBMISSION_RULES,
                   'entry_submitted': CODE_RULES | SUBMISSION_RULES | ENTRY_RULES,
                   'catalog_accepted': CODE_RULES | SUBMISSION_RULES | ADMISSION_RULES}
        for label, required in targets.items():
            pending = sorted(required - decisions_done)
            phase_blockers = list(blockers)
            year = value.get('event_year')
            if label == 'ready_to_submit' and type(year) is int and 1 <= year <= 9999:
                if datetime.now(timezone.utc) > datetime(year, 11, 11, 17, tzinfo=timezone(timedelta(hours=-5))):
                    phase_blockers.append('submission_deadline_elapsed')
            result['readiness'][label] = {'ready': not phase_blockers and not pending, 'pending': pending, 'blockers': phase_blockers}
        result.update(status='rejected' if rejected else ('complete' if not (ALL_RULES - decisions_done) and not finding_pending else 'incomplete'),
                      reviewer={'name': reviewer['name'], 'role': reviewer['role'], 'reviewed_at': stamp.isoformat()})
        return result
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError):
        result.update(status='invalid', errors=['Review document/evidence is malformed, unsafe, missing, changed or exceeds its bounds'])
        # Never return a partial readiness result after a later evidence failure.
        result['readiness'] = _base()['readiness']
        return result
