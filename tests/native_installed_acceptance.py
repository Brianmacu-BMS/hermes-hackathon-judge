#!/usr/bin/env python3
"""CI-only native acceptance. Refuse outside disposable GitHub-hosted runners.

Never imported by plugin registration or ordinary test discovery. This is not
an isolation sandbox: the runner, not a profile or an environment flag, is the
machine boundary. Only the explicitly trusted fixture is executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def runner_guard():
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted',
            'Refusing installed acceptance outside a disposable GitHub-hosted runner')
    temporary = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    for name in ('HOME', 'HERMES_HOME', 'HERMES_RUNTIME_DIR', 'TMPDIR'):
        path = Path(os.environ[name]).resolve(strict=True)
        require(path.is_relative_to(temporary) and path != temporary,
                'Acceptance state must be below RUNNER_TEMP: ' + name)
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    core = Path(os.environ['HERMES_CORE_ROOT']).resolve(strict=True)
    source = Path(os.environ['JUDGE_SOURCE']).resolve(strict=True)
    require(core.is_relative_to(workspace) and source.is_relative_to(workspace)
            and core != source, 'Separate runner-owned source checkouts required')
    for name in ('OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'OPENROUTER_API_KEY',
                 'NOUS_API_KEY', 'GOOGLE_API_KEY', 'GEMINI_API_KEY', 'LITELLM_API_KEY',
                 'HERMES_YOLO'):
        require(not os.environ.get(name), 'Provider credentials or YOLO are not allowed')
    return core, source


def decode(value):
    return json.loads(value) if isinstance(value, str) else value


def native_host(core):
    sys.path.insert(0, str(core))
    from hermes_cli.plugins import discover_plugins, get_plugin_manager
    from model_tools import discover_builtin_tools, handle_function_call
    from tools.registry import registry, session_tool_scope
    discover_builtin_tools()
    discover_plugins()
    manager = get_plugin_manager()
    rows = [row for row in manager.list_plugins() if row['name'] == 'hackathon-judge']
    require(len(rows) == 1 and rows[0]['enabled'] is True and not rows[0]['error'],
            'Installed plugin was not discovered and enabled')
    require(registry.get_entry('hackathon_judge', scope=manager.scope_key) is not None,
            'Native registered tool missing')
    require('judge-plugin' in manager.list_plugin_skills('hackathon-judge'),
            'Namespaced skill missing')

    def dispatch(args):
        with session_tool_scope(manager.scope_key):
            return decode(handle_function_call('hackathon_judge', args,
                                               enabled_tools=['hackathon_judge', 'terminal']))
    return manager, registry, dispatch, rows[0]


def probe(core, source, mode, candidate):
    from unittest.mock import patch
    manager, registry, dispatch, discovered = native_host(core)
    marker = Path(os.environ['HERMES_HOME']) / 'candidate-executed'
    terminal = registry.get_entry('terminal', scope=manager.scope_key)
    if terminal is None:
        raise RuntimeError('Native terminal registration missing')
    original = terminal.handler
    observed = []

    def observing_handler(args, **kwargs):
        # Observe, do not replace, the real terminal and its policy/backend.
        result = original(args, **kwargs)
        observed.append({'args': args, 'result': decode(result)})
        return result

    with patch.object(terminal, 'handler', observing_handler):
        report = dispatch({'action': 'validate', 'path': str(candidate), 'trusted_code': True})
    require(len(observed) == 1, 'Expected exactly one native terminal dispatch')
    require(shlex.split(observed[0]['args']['command']) ==
            ['hermes', 'plugins', 'validate', str(candidate), '--json'],
            'Validator dispatch changed or requested extra privileges/dependencies')
    receipt = report.get('official_validation', {})
    require(report.get('certified') is False, 'Runtime result must never imply certification')
    if mode == 'denied':
        require(receipt.get('status') == 'error' and not marker.exists(),
                'Denied native terminal executed candidate or reported a pass')
        require('deny' in json.dumps(observed[0]['result']).lower(),
                'Did not observe the real host deny policy response')
    else:
        require(receipt.get('status') == 'pass' and marker.is_file()
                and receipt.get('tree_unchanged') is True
                and receipt.get('install_deps') is False,
                'Real trusted validation did not pass on unchanged candidate bytes')
        require(observed[0]['result'].get('exit_code') == 0,
                'Real validator process did not exit successfully')
    return {'probe': mode, 'discovered': discovered, 'report': report,
            'terminal_dispatches': observed, 'candidate_executed': marker.exists()}


def session_paths(home, dispatch):
    """Use real host context with a process cwd outside both calling sessions."""
    from agent.runtime_cwd import set_session_cwd, reset_session_cwd, resolve_agent_cwd
    from hermes_cli.plugins import get_plugin_command_handler
    process = Path.cwd()
    session = home / 'session workspace'
    candidate = session / 'fixture'
    candidate.mkdir(parents=True)
    (candidate / 'plugin.yaml').write_text('name: session-fixture\nversion: 1.0.0\ndescription: Owned CI fixture\n')
    (candidate / '__init__.py').write_text('def register(ctx):\n    raise AssertionError("Static candidate executed")\n')
    (session / 'entry.yaml').write_text('name: session-fixture\nrepo: https://github.com/example/fixture\nsha: "' + 'a' * 40 + '"\nversion: "1.0.0"\n')
    (session / 'submission.json').write_text(json.dumps({'submitted_at': 'owned-session-marker'}))
    records = session / 'records'
    records.mkdir()
    note = records / 'note.md'
    note.write_text('Owned session-path evidence.')
    document = dispatch({'action': 'template', 'path': str(candidate)})
    document.update(reviewer={'name': 'CI Fixture', 'role': 'operator'}, reviewed_at='2026-01-01T00:00:00+00:00')
    document['decisions']['CAT-03'].update(decision='pass', reason='Owned session-path fixture only.',
        evidence=[{'path': note.name, 'sha256': hashlib.sha256(note.read_bytes()).hexdigest()}])
    (records / 'review.json').write_text(json.dumps(document))
    slash = get_plugin_command_handler('judge-plugin')
    if not callable(slash):
        raise RuntimeError('Session path probe requires the real discovered slash handler')
    token = set_session_cwd(str(session))
    try:
        require(resolve_agent_cwd() == session and process != session, 'Real differing session cwd not bound')
        args = {'path': 'fixture', 'catalog': 'entry.yaml', 'submission': 'submission.json', 'review': 'records/review.json'}
        reports = [dispatch(args), json.loads(slash('fixture --catalog entry.yaml --submission submission.json --review records/review.json --format json'))]
        for report in reports:
            require(report.get('candidate') == str(candidate), 'Native relative path selected process cwd')
            require(report['submission_attestations'].get('submitted_at') == 'owned-session-marker', 'Native submission path not session-bound')
            require(report['assessment']['status'] == 'incomplete' and len(report['assessment']['evidence_checked']) == 1,
                    'Native review/evidence paths did not bind to the intended records')
            metadata = next(c for c in report['checks'] if c['id'] == 'catalog-metadata')
            require(metadata['status'] == 'pass', 'Native catalog path not session-bound')
        alias = session / 'alias'
        alias.symlink_to(candidate, target_is_directory=True)
        require('error' in dispatch({'path': 'alias/../fixture'}), 'Native tool erased lexical alias')
        require('Unable to audit' in slash('alias/../fixture'), 'Native slash erased lexical alias')
    finally:
        reset_session_cwd(token)
    second = home / 'second session'
    other = second / 'fixture'
    other.mkdir(parents=True)
    (other / 'plugin.yaml').write_text('name: other-fixture\nversion: 1.0.0\ndescription: Owned CI fixture\n')
    (other / '__init__.py').write_text('def register(ctx):\n    raise AssertionError("Static candidate executed")\n')
    token = set_session_cwd(str(second))
    try:
        require(dispatch({'path': 'fixture'}).get('candidate') == str(other), 'Tool cached another session cwd')
        require(json.loads(slash('fixture --format json')).get('candidate') == str(other), 'Slash cached another session cwd')
    finally:
        reset_session_cwd(token)
    require(Path.cwd() == process, 'Native handlers changed process cwd')
    return {'ok': True, 'process_cwd': str(process), 'session_cwd': str(session),
            'candidate': str(candidate), 'second_session_candidate': str(other),
            'tool_and_slash_documents_verified': True, 'lexical_alias_refused': True,
            'process_cwd_unchanged': True, 'context_switch_verified': True}


def main(core, source):
    home = Path(os.environ['HERMES_HOME'])
    bindir = home / 'acceptance-bin'
    bindir.mkdir()
    launcher = bindir / 'hermes'
    launcher.write_text('#!/bin/sh\nexec ' + shlex.join([sys.executable, str(core / 'hermes')]) + ' "$@"\n')
    launcher.chmod(0o755)
    os.environ['PATH'] = str(bindir) + os.pathsep + os.environ['PATH']
    installed = home / 'plugins' / 'hackathon-judge'
    files = subprocess.check_output(['git', '-C', str(source), 'ls-files', '-z']).decode().split('\0')
    hashes = {}
    for relative in filter(None, files):
        expected = (source / relative).read_bytes()
        require((installed / relative).read_bytes() == expected,
                'Installed file differs from the exact source pin: ' + relative)
        hashes[relative] = hashlib.sha256(expected).hexdigest()
    marker = home / 'candidate-executed'
    require(not marker.exists(), 'Fresh candidate execution marker required')
    candidate = home / 'fixture'
    candidate.mkdir()
    (candidate / 'plugin.yaml').write_text('name: acceptance-fixture\nversion: 1.0.0\ndescription: Trusted CI fixture\n')
    (candidate / '__init__.py').write_text(
        'from pathlib import Path\n'
        + 'def register(ctx):\n    Path(' + repr(str(marker)) + ').write_text("executed")\n')
    blocked = home / 'missing-manifest-fixture'
    blocked.mkdir()
    manager, registry, dispatch, discovered = native_host(core)
    from hermes_cli.plugins import get_plugin_command_handler
    report = dispatch({'action': 'audit', 'path': str(candidate)})
    require(report.get('certified') is False and not marker.exists(),
            'Registered static audit executed candidate code')
    require(len(dispatch({'action': 'rules'})['requirements']) == 33, 'Native rules incomplete')
    require('CAT-18' in dispatch({'action': 'template', 'path': str(candidate)})['reviews'],
            'Native review template incomplete')
    require('error' in dispatch({'action': 'validate', 'path': str(candidate)})
            and not marker.exists(), 'Trusted-code refusal failed')
    alias = home / 'candidate-alias'
    alias.symlink_to(candidate, target_is_directory=True)
    require('error' in dispatch({'action': 'audit', 'path': str(alias)}),
            'Registered tool accepted a candidate symlink alias')
    slash = get_plugin_command_handler('judge-plugin')
    if not callable(slash):
        raise RuntimeError('Native slash discovery failed')
    slash_report = json.loads(slash(shlex.quote(str(candidate)) + ' --format json'))
    require(slash_report.get('certified') is False and not marker.exists(),
            'Discovered slash audit executed candidate code')
    require('Unable to audit' in slash('"unterminated'), 'Malformed slash arguments escaped')
    require('Unable to audit' in slash(shlex.quote(str(alias))), 'Slash erased a candidate alias')
    path_receipt = session_paths(home, dispatch)
    require(not marker.exists(), 'Session-relative audit unexpectedly executed candidate code')
    runs = []

    def run(label, args, expected=0, cwd=core):
        done = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=300)
        runs.append({'label': label, 'args': args, 'exit_code': done.returncode,
                     'stdout': done.stdout, 'stderr': done.stderr})
        require(done.returncode == expected, label + ' failed: ' + done.stderr[-2000:])
        return done.stdout

    cli = [sys.executable, str(core / 'hermes')]
    require(len(json.loads(run('cli-rules', cli + ['hackathon-judge', '--rules']))) == 33,
            'Native CLI rules missing')
    run('cli-missing-path', cli + ['hackathon-judge'], 3)
    run('cli-nonexistent-path', cli + ['hackathon-judge', str(home / 'absent')], 3)
    run('cli-blocker', cli + ['hackathon-judge', str(blocked), '--format', 'json'], 1)
    expected = 1 if report['verdict'] == 'blocked' else 2
    cli_report = json.loads(run('cli-incomplete-review',
                                cli + ['hackathon-judge', str(candidate), '--format', 'json'], expected))
    require(cli_report.get('certified') is False and not marker.exists(),
            'Native CLI executed the candidate or invented readiness')
    run('cli-alias-refusal', cli + ['hackathon-judge', str(alias)], 3)
    relative_cli = json.loads(run('cli-relative-path', cli + ['hackathon-judge', 'fixture', '--format', 'json'],
                                  2, cwd=Path(path_receipt['session_cwd'])))
    require(relative_cli.get('candidate') == path_receipt['candidate'], 'Native terminal CLI lost process cwd semantics')
    run('policy-deny', cli + ['config', 'set', 'approvals.deny', '["hermes plugins validate *"]'])
    denied = run('native-denial', [sys.executable, __file__, '--probe', 'denied', str(candidate)])
    run('policy-remove-test-deny', cli + ['config', 'set', 'approvals.deny', '[]'])
    allowed = run('native-validation', [sys.executable, __file__, '--probe', 'allowed', str(candidate)])
    probes = [json.loads(next(line.split('PROBE_RESULT=', 1)[1] for line in text.splitlines()
                              if line.startswith('PROBE_RESULT='))) for text in (denied, allowed)]
    run('doctor-qualified-source', cli + ['plugins', 'doctor', str(source), '--ci'])
    qualification = json.loads(run('validate-qualified-source', cli +
                                   ['plugins', 'validate', str(source), '--install-deps', '--json']))
    require(qualification.get('ok') is True and qualification.get('checks')
            and all(check.get('ok') is True for check in qualification['checks']),
            'Full official source qualification failed')
    for relative, digest in hashes.items():
        require(hashlib.sha256((installed / relative).read_bytes()).hexdigest() == digest,
                'Installed source changed during acceptance')
        require(hashlib.sha256((source / relative).read_bytes()).hexdigest() == digest,
                'Tracked source changed during qualification')
    from pm import paths
    from pm.environments import selected_venv
    require(Path(paths.store_root()).resolve() == Path(os.environ['HERMES_RUNTIME_DIR']).resolve(),
            'PM escaped the runner-owned tool store')
    selected = Path(selected_venv(core)).resolve()
    require(selected.is_relative_to(Path(os.environ['RUNNER_TEMP']).resolve()),
            'PM selected environment escaped the runner boundary')
    receipt = {'ok': True, 'source_commit': subprocess.check_output(
        ['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip(),
        'hermes_commit': subprocess.check_output(['git', '-C', str(core), 'rev-parse', 'HEAD'], text=True).strip(),
        'runner': os.environ['RUNNER_ENVIRONMENT'], 'home': str(home),
        'python': sys.executable, 'selected_venv': str(selected), 'installed': str(installed),
        'installed_files': hashes, 'discovered': discovered, 'runs': runs, 'probes': probes,
        'session_paths': path_receipt,
        'source_qualification': qualification, 'source_qualification_install_deps': True,
        'static_candidate_nonexecution': True, 'activation': 'disposable GitHub runner only',
        'approval_scope': 'real approvals.deny policy refusal, not interactive UI acceptance',
        'models_called': False, 'certified': False}
    print('ACCEPTANCE_RECEIPT=' + json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    try:
        core, source = runner_guard()
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--guard-only', action='store_true')
        parser.add_argument('--probe', choices=['denied', 'allowed'])
        parser.add_argument('candidate', nargs='?')
        args = parser.parse_args()
        if args.guard_only:
            print(json.dumps({'runner_guard': 'passed', 'activation_performed': False}))
        elif args.probe:
            require(args.candidate is not None, 'Probe candidate required')
            print('PROBE_RESULT=' + json.dumps(probe(core, source, args.probe, Path(args.candidate))))
        else:
            main(core, source)
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}), file=sys.stderr)
        raise SystemExit(2)
