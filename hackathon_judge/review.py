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
from .guide import GUIDE_RULES, CONDITIONAL_GUIDE_RULES

CODE_RULES = GUIDE_RULES | frozenset(['CAT-03', 'CAT-04'] + [f'CAT-{n:02}' for n in range(6, 19)] + ['PRE-02', 'PRE-03'] + [f'QUALITY-{n:02}' for n in range(1, 6)])
SUBMISSION_RULES = frozenset({'CAT-02', 'CAT-05', 'PRE-01', 'PRE-04', 'HACK-01', 'HACK-02', 'HACK-03', 'HACK-05'})
ENTRY_RULES = frozenset({'HACK-04'})
ADMISSION_RULES = frozenset({'CAT-01', 'PRE-05'})
CATALOG_RULES = CODE_RULES | ADMISSION_RULES | frozenset({'CAT-02', 'CAT-05', 'PRE-01', 'PRE-04'})
ALL_RULES = CODE_RULES | SUBMISSION_RULES | ENTRY_RULES | ADMISSION_RULES
NA_ALLOWED = CONDITIONAL_GUIDE_RULES | frozenset({'CAT-04', 'CAT-08', 'CAT-18'})
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
    if stamp.tzinfo is not None:
        stamp.astimezone(timezone.utc)  # Reject timezone conversions outside datetime's range.
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


# Qualified producer contracts, traced at these exact public source pins.
# Portable Agent Plugins have a different report and are not qualified here.
_NATIVE_PRODUCERS = {
    '0.22.5': 'bf0203a794a07aac3ff764972ab9087baa4e4f4e',
    '0.23.0': '2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19',
}
_NATIVE_CHECKS = frozenset({
    'manifest', 'manifest fields', 'requires_hermes', 'config schema', 'requires_env', 'oauth',
    'loadable', 'python dependencies', 'capability probe', 'built-in tool collisions',
    'security scan', 'no core override',
})


def _native_checks(report):
    """Derive applicability from bound source, never from receipt-declared exemptions."""
    from .inventory import inventory
    from .checks import mapping
    import yaml
    root, info, data = inventory(report['candidate'])
    if not info['complete'] or info['tree_sha256'] != report['inventory']['tree_sha256']:
        raise ValueError('Candidate changed before receipt assessment')
    manifest_name = next((n for n in ('plugin.yaml', 'plugin.yml') if n in data), None)
    if manifest_name is None:
        raise ValueError('Portable-only validator reports are not qualified')
    try:
        manifest = mapping(data[manifest_name].decode('utf-8-sig'))
    except yaml.YAMLError as exc:
        raise ValueError('Malformed native manifest') from exc
    required = set(_NATIVE_CHECKS)
    if '__init__.py' in data:
        required.update({'declared tools', 'declared hooks', 'declared middleware'})
    if (root / 'desktop').is_dir() or 'plugin.js' in data:
        required.add('desktop surface')
    raw = manifest.get('provides_locales')
    if raw is not None:
        entries = [raw] if isinstance(raw, (str, dict)) else raw
        declared = set()
        for entry in entries if isinstance(entries, list) else []:
            lang = entry.get('id', '') if isinstance(entry, dict) else entry
            if isinstance(lang, str):
                lang = lang.strip().lower().replace('_', '-')
                if re.fullmatch(r'[a-z]{2,3}(-[a-z0-9]{2,8})*', lang):
                    declared.add(lang)
        if not declared:
            required.add('locales')  # Producer emits a failure, never a passing exemption.
        for lang in declared:
            required.add('locale ' + lang)
            for name in data:
                match = re.fullmatch(r'locales/([a-z]{2,3}(?:-[a-z0-9]{2,8})*)(?:\.([a-z]+))?\.ya?ml', name)
                if match and match[1] == lang and match[2] in {'tui', 'desktop'}:
                    required.add('locale ' + lang + '.' + match[2])
    return required


def native_report_shape(payload, required):
    """Shared native output contract; authenticity still belongs to the trusted producer.

    Failed producers can stop early (including isolation=None). Only a complete
    successful applicable report may be called a pass by either consumer.
    """
    if not isinstance(payload, dict) or type(payload.get('ok')) is not bool:
        return False
    checks, warnings = payload.get('checks'), payload.get('warnings')
    if (not isinstance(checks, list) or not checks
            or not isinstance(warnings, list) or any(not isinstance(w, str) for w in warnings)
            or any(not isinstance(c, dict) or not isinstance(c.get('name'), str) or not c['name']
                   or type(c.get('ok')) is not bool or not isinstance(c.get('detail'), str) for c in checks)):
        return False
    names = [c['name'] for c in checks]
    if len(names) != len(set(names)):
        return False
    if not payload['ok']:
        return True
    isolation = payload.get('isolation')
    return (not payload.get('error') and required.issubset(names)
            and set(names).issubset(required | {'trusted inbound'})
            and all(c['ok'] for c in checks) and isinstance(isolation, dict)
            and isolation.get('verdict') in {'host', 'in_process', 'portable'}
            and type(isolation.get('host_ready')) is bool
            and isolation['host_ready'] == (isolation['verdict'] in {'host', 'portable'})
            and all(isinstance(isolation.get(k), list) and all(isinstance(s, str) for s in isolation[k])
                    for k in ('reasons', 'notes', 'ctx_methods')))


def _validation_receipt(item, documents, report, policy):
    digest = report['inventory']['tree_sha256']
    try:
        required = _native_checks(report)
    except (ValueError, TypeError, KeyError, OSError, UnicodeError):
        return False
    for ref, text in zip(item.get('evidence', []), documents):
        if ref.get('kind') != 'validation_receipt':
            continue
        try:
            value = load_json(text)
            payload = value['report']
            command = value.get('command', [])
            valid = (type(value.get('schema_version')) is int and value.get('schema_version') == 1 and value.get('kind') == 'hermes-validation'
                     and isinstance(value.get('hermes_version'), str)
                     and _NATIVE_PRODUCERS.get(value.get('hermes_version')) == value.get('hermes_commit')
                     and value.get('hermes_version') in _NATIVE_PRODUCERS
                     and value.get('policy_sha256') == policy
                     and value.get('candidate_sha256') == digest and value.get('candidate_after_sha256') == digest
                     and value.get('exit_code') == 0 and type(value.get('exit_code')) is int
                     and value.get('install_deps') is True and isinstance(command, list)
                     and all(isinstance(c, str) for c in command)
                     and any(command[i:i+2] == ['plugins', 'validate'] for i in range(len(command) - 1))
                     and '--install-deps' in command and '--json' in command
                     and payload.get('ok') is True and native_report_shape(payload, required))
            warnings = payload.get('warnings')
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
        year = value.get('event_year')
        deadline = (datetime(year, 11, 11, 17, tzinfo=timezone(timedelta(hours=-5)))
                    if type(year) is int and 1 <= year <= 9999 else None)
        event_times = {}
        for field in ('submitted_at', 'catalog_submitted_at'):
            raw = value.get(field)
            event_times[field] = None if raw is None else _timestamp(raw)
            if event_times[field] is not None and (event_times[field] > stamp
                                                   or event_times[field] > datetime.now(timezone.utc)):
                raise ValueError('An actual submission cannot be future or follow its review timestamp')
        timely = {field: deadline is not None and timestamp is not None
                  and timestamp.astimezone(deadline.tzinfo).year == year and timestamp <= deadline
                  for field, timestamp in event_times.items()}
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
                assessed['complete'] &= not any(f['path'] in {'desktop/plugin.js', 'plugin.js'} for f in report['inventory']['files'])
            if rid == 'CAT-18' and assessed['decision'] == 'not_applicable':
                assessed['complete'] &= not any(f['rule'] == 'CAT-18' for f in report['findings'])
            if rid == 'PRE-03' and assessed['decision'] == 'pass':
                assessed['complete'] &= _validation_receipt(item, documents, report, value['policy_sha256'])
            if rid == 'HACK-05' and assessed['decision'] == 'pass':
                assessed['complete'] &= deadline is not None and (stamp <= deadline or any(timely.values()))
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
                   'catalog_accepted': CATALOG_RULES}
        for label, required in targets.items():
            pending = sorted(required - decisions_done)
            phase_blockers = list(blockers)
            if label == 'catalog_accepted':
                # Contest-only failures cannot revoke independently evidenced admission.
                if not any(c['status'] == 'fail' and (not c['rules'] or CATALOG_RULES.intersection(c['rules']))
                           for c in report['checks']):
                    phase_blockers = [b for b in phase_blockers if b != 'local_failure']
                if not (rejected & CATALOG_RULES):
                    phase_blockers = [b for b in phase_blockers if b != 'reviewer_rejection']
            if label == 'ready_to_submit' and deadline is not None and datetime.now(timezone.utc) > deadline:
                phase_blockers.append('submission_deadline_elapsed')
            if label == 'entry_submitted':
                if not timely['submitted_at']:
                    phase_blockers.append('timely_submission_evidence_required')
            result['readiness'][label] = {'ready': not phase_blockers and not pending, 'pending': pending, 'blockers': phase_blockers}
        result.update(status='rejected' if rejected else ('complete' if not (ALL_RULES - decisions_done) and not finding_pending else 'incomplete'),
                      reviewer={'name': reviewer['name'], 'role': reviewer['role'], 'reviewed_at': stamp.isoformat()})
        return result
    except (ValueError, TypeError, KeyError, AttributeError, OSError, RecursionError, OverflowError):
        result.update(status='invalid', errors=['Review document/evidence is malformed, unsafe, missing, changed or exceeds its bounds'])
        # Never return a partial readiness result after a later evidence failure.
        result['readiness'] = _base()['readiness']
        return result
