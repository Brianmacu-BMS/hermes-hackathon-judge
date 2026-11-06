"""Optional trusted-code validation stays in Hermes's normal approval pipeline."""
from collections import Counter
import shlex

from .engine import audit, finalise
from .review import load_json


def validate_through_host(ctx, before, *, catalog=None, submission=None, review=None):
    path = before['candidate']
    command = shlex.join(['hermes', 'plugins', 'validate', path, '--json'])
    # Public ctx dispatch preserves parent agent context, approvals and budgets.
    # No raw subprocess, YOLO, background job or dependency installation.
    result = ctx.dispatch_tool('terminal', {'command': command, 'timeout': 120})
    if isinstance(result, str):
        result = load_json(result)
    after = audit(path, catalog=catalog, submission=submission)
    item = next(c for c in after['checks'] if c['id'] == 'official-validator')
    same = before['inventory']['tree_sha256'] == after['inventory']['tree_sha256']
    receipt = {'status': 'error', 'install_deps': False, 'command': command,
               'tree_unchanged': same, 'notice': 'Runtime validation is NOT --install-deps catalog CI parity; no dependency resolution or maintainer approval implied.'}
    if not isinstance(result, dict) or type(result.get('exit_code')) is not int or result.get('exit_code') not in {0, 1} or result.get('error'):
        item.update(status='needs_review', detail='Host terminal denied, timed out, or failed; validator not verified')
    else:
        try:
            payload = load_json(result.get('output', ''))
            checks = payload.get('checks')
            if not isinstance(checks, list) or not checks or any(not isinstance(c, dict) or type(c.get('ok')) is not bool for c in checks):
                raise ValueError('Invalid official report')
            passed = payload.get('ok') is True and all(c['ok'] for c in checks) and result['exit_code'] == 0
            names = [c.get('name') for c in checks]
            if any(not isinstance(name, str) for name in names) or len(names) != len(set(names)):
                raise ValueError('Invalid official check identities')
            if passed and not {'manifest', 'loadable', 'capability probe', 'security scan', 'no core override'}.issubset(names):
                raise ValueError('Incomplete official success report')
            warnings = payload.get('warnings', [])
            if not isinstance(warnings, list) or any(not isinstance(warning, str) for warning in warnings):
                raise ValueError('Malformed official warnings')
            receipt.update(status=('pass' if passed else 'fail') if same else 'stale', checks=[{'name': c.get('name', 'unnamed'), 'ok': c['ok']} for c in checks], warning_count=len(warnings), warnings=warnings)
            item.update(status=('pass' if passed else 'fail') if same else 'needs_review', detail='Official runtime check ' + ('passed' if passed else 'failed') + '; review raw warnings. --install-deps and exact-pin verification remain separate.' if same else 'Tree changed during validation; result cannot be bound to current inspected tree')
        except (ValueError, TypeError, AttributeError):
            item.update(status='needs_review', detail='Host output was not a complete official validation JSON report')
    after['official_validation'] = receipt
    after['counts'] = dict(Counter(c['status'] for c in after['checks']))
    for rule in after['requirements']:
        if rule['id'] in item['rules'] and item['status'] == 'fail':
            rule.update(status='fail', reason='Official runtime validator reported a failure')
    return finalise(after, review)
