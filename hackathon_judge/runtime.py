"""Optional validation: one byte-bound transaction in normal terminal dispatch."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import secrets
import shlex

from .engine import audit, finalise
from .paths import read_regular
from .review import load_json, native_report_shape, _native_checks

# Runs on the SELECTED terminal backend. Verify the shipped helper bytes before
# it may read a candidate or launch Hermes. Missing/old helpers fail closed.
_BOOTSTRAP = '''import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]); raw=p.read_bytes()
if len(raw)>100000 or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:
    raise SystemExit(3)
ns={"__name__":"judge_terminal_transaction","__file__":str(p)}
exec(compile(raw,str(p),"exec"),ns)
raise SystemExit(ns["main"](json.loads(sys.argv[3])))
'''


def _command(before):
    info = before['inventory']
    if info.get('complete') is not True or any(info.get(key) for key in
            ('excluded_sensitive', 'symlinks', 'omitted', 'ignored_directories')):
        raise ValueError('Validation requires a fully inspected tree without ignored directories')
    helper = Path(__file__).with_name('bound_validation.py')
    helper_hash = hashlib.sha256(read_regular(helper, max_bytes=100000)).hexdigest()
    nonce = secrets.token_hex(24)
    request = {'candidate': before['candidate'], 'files': sorted(info['files'], key=lambda item: item['path']),
               'tree_sha256': info['tree_sha256'], 'nonce': nonce}
    command = shlex.join(['python3', '-I', '-B', '-c', _BOOTSTRAP, str(helper), helper_hash,
                          json.dumps(request, separators=(',', ':'))])
    if len(command) > 24000:
        raise ValueError('Bound transaction command budget exceeded')
    return command, nonce


def validate_through_host(ctx, before, *, catalog=None, submission=None, review=None, **kwargs):
    path = before['candidate']
    command, nonce, result = None, None, None
    try:
        command, nonce = _command(before)
        # Public API only: preserve native invocation identity and normal host
        # approvals/budgets/backend selection. No private terminal calls.
        result = ctx.dispatch_tool('terminal', {'command': command, 'timeout': 120},
                                   **{key: kwargs[key] for key in ('task_id', 'session_id') if key in kwargs})
        if isinstance(result, str):
            result = load_json(result)
    except Exception:
        result = None
    after = audit(path, catalog=catalog, submission=submission)
    item = next(c for c in after['checks'] if c['id'] == 'official-validator')
    same = before['inventory']['tree_sha256'] == after['inventory']['tree_sha256']
    receipt = {'status': 'error', 'install_deps': False, 'command': command,
               'tree_unchanged': same, 'notice': 'Runtime validation uses a byte-bound temporary snapshot on the selected terminal backend, not the original location. Not a sandbox or --install-deps CI parity; ambient dependencies and approval of the helper command remain operator responsibilities.'}
    item.update(status='needs_review', detail='Backend byte binding or normal terminal dispatch failed; validator not verified')
    try:
        if not isinstance(result, dict) or type(result.get('exit_code')) is not int or result['exit_code'] not in {0, 1} or result.get('error'):
            raise ValueError('Terminal result unavailable')
        bound = load_json(result.get('output', ''))
        if not isinstance(bound, dict) or bound.get('protocol') != 'backend-snapshot-v1' or bound.get('nonce') != nonce or nonce is None or bound.get('error'):
            raise ValueError('Missing fresh backend transaction')
        if bound.get('tree_sha256') != before['inventory']['tree_sha256'] or bound.get('bound_before') is not True or type(bound.get('tree_unchanged')) is not bool:
            raise ValueError('Invalid backend byte binding')
        if type(bound.get('validator_exit_code')) is not int or bound['validator_exit_code'] not in {0, 1} or result['exit_code'] != bound['validator_exit_code']:
            raise ValueError('Invalid validator exit status')
        payload = load_json(bound.get('validator_output', ''))
        if not native_report_shape(payload, _native_checks(after)):
            raise ValueError('Incomplete or malformed official report')
        checks = payload['checks']
        passed = payload['ok'] is True and bound['validator_exit_code'] == 0
        warnings = payload['warnings']
        same = same and bound['tree_unchanged']
        receipt.update(status=('pass' if passed else 'fail') if same else 'stale',
                       binding=bound['protocol'], tree_unchanged=same,
                       checks=[{'name': c['name'], 'ok': c['ok']} for c in checks],
                       warning_count=len(warnings), warnings=warnings)
        item.update(status=('pass' if passed else 'fail') if same else 'needs_review',
                    detail='Official runtime check ' + ('passed' if passed else 'failed') + ' on byte-bound backend snapshot; --install-deps parity remains separate.' if same else 'Source or executed snapshot changed; result is stale')
    except (ValueError, TypeError, AttributeError, KeyError, OSError):
        pass
    after['official_validation'] = receipt
    after['counts'] = dict(Counter(c['status'] for c in after['checks']))
    for rule in after['requirements']:
        if rule['id'] in item['rules'] and item['status'] == 'fail':
            rule.update(status='fail', reason='Official runtime validator reported a failure')
    return finalise(after, review)
