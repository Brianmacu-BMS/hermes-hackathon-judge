"""Native Hermes public API registration. No candidate code runs on import."""
import json
from pathlib import Path
import shlex

from .hackathon_judge.cli import parser_setup, run
from .hackathon_judge.engine import audit, markdown, requirements, review_template
from .hackathon_judge.runtime import validate_through_host
from .hackathon_judge.paths import admit_local_root, guarded_path

SCHEMA = {
    'name': 'hackathon_judge',
    'description': 'Audit a local Hermes plugin against the captured hackathon and catalog rules. Default static audit never executes candidate code. Returns source-linked blockers, heuristic file/line findings and complete human review checklist; never official certification. validate action executes TRUSTED candidate code through normal terminal approvals (no dependency installs).',
    'parameters': {
        'type': 'object',
        'properties': {
            'action': {'type': 'string', 'enum': ['audit', 'rules', 'template', 'validate'], 'default': 'audit'},
            'path': {'type': 'string', 'description': 'Explicit local candidate plugin directory'},
            'catalog': {'type': 'string', 'description': 'Optional explicit local catalog YAML'},
            'submission': {'type': 'string', 'description': 'Optional explicit author-attestation JSON; not verified evidence'},
            'review': {'type': 'string', 'description': 'Optional accountable reviewer record; candidate, policy and evidence hashes must match. Not official certification.'},
            'trusted_code': {'type': 'boolean', 'default': False, 'description': 'Required for validate: user has authorized executing this candidate; does NOT replace Hermes command approval'},
        },
        'additionalProperties': False,
    },
}


def _native_paths(args):
    """Bind native inputs once to this session without erasing lexical aliases."""
    if not isinstance(args.get('path'), str) or not args['path'].strip():
        raise ValueError('Explicit candidate path required')
    for name in ('path', 'catalog', 'submission', 'review'):
        if args.get(name) is not None:
            admit_local_root(args[name])
    paths = {name: Path(args[name]).expanduser() if args.get(name) is not None else None
             for name in ('path', 'catalog', 'submission', 'review')}
    if any(path is not None and not path.is_absolute() for path in paths.values()):
        # This documented host seam is invocation-scoped. Keep the standalone
        # CLI independent of Hermes, and fail closed if native context is absent.
        from agent.runtime_cwd import resolve_agent_cwd, scoped_session_cwd
        declared = scoped_session_cwd()
        # The host resolver deliberately falls back for missing session folders.
        # That is unsafe for explicit scoped native inputs: honor or refuse it.
        base = declared if declared else resolve_agent_cwd()
        admit_local_root(base)
        cwd = Path(base).expanduser()
        if not cwd.is_absolute():
            raise ValueError('Session working directory must be absolute')
        # Non-following ancestor/reparse inspection must precede is_dir().
        cwd = guarded_path(cwd)
        if not cwd.is_dir():
            raise ValueError('Session working directory must exist and be absolute')
        paths = {name: cwd / path if path is not None and not path.is_absolute() else path
                 for name, path in paths.items()}
    # Do not resolve() or chdir(): the existing guards must still see every
    # link/reparse component, and other sessions share this process.
    return {name: str(path) if path is not None else None for name, path in paths.items()}


def handle(ctx, args, **kwargs):
    try:
        action = args.get('action', 'audit')
        if action == 'rules':
            return json.dumps({'requirements': requirements()})
        if action not in {'audit', 'template', 'validate'}:
            raise ValueError('Unknown action')
        paths = _native_paths(args)
        report = audit(**paths)
        if action == 'validate':
            if args.get('trusted_code') is not True:
                return json.dumps({'error': 'validate imports and executes candidate code. Obtain user authorization for this exact candidate and set trusted_code; Hermes terminal approvals still apply.'})
            report = validate_through_host(ctx, report, catalog=paths['catalog'], submission=paths['submission'], review=paths['review'],
                                           **{key: kwargs[key] for key in ('task_id', 'session_id') if key in kwargs})
        return json.dumps(review_template(report) if action == 'template' else report)
    except Exception as exc:
        return json.dumps({'error': 'Audit failed; verify candidate path and document format', 'kind': type(exc).__name__})


def slash(raw):
    try:
        # These are path arguments, not a shell program. Keep backslashes literal
        # on every host while retaining POSIX single/double quotes and spaces.
        lexer = shlex.shlex(raw, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ''
        lexer.escape = ''
        tokens = list(lexer)
        if not tokens:
            return 'Usage: /judge-plugin <local-path> [--catalog FILE] [--submission FILE]. Static only; runtime validation requires explicit trusted-code action.'
        # argparse is shared with standalone CLI, with errors returned rather than
        # terminating a gateway worker. No candidate command is executed here.
        import argparse
        parser = parser_setup(argparse.ArgumentParser(add_help=False, exit_on_error=False))
        if any(t in {'-h', '--help'} for t in tokens):
            return parser.format_help()
        args, unknown = parser.parse_known_args(tokens)
        if unknown:
            raise ValueError('Unexpected arguments')
        if args.rules:
            return json.dumps(requirements())
        report = audit(**_native_paths(vars(args)))
        return json.dumps(report) if args.format == 'json' else (json.dumps(review_template(report)) if args.format == 'template' else markdown(report))
    except (Exception, SystemExit):
        return 'Unable to audit: check path and arguments. Usage: /judge-plugin <local-path> [--catalog FILE] [--submission FILE]'


def cli_handler(args):
    raise SystemExit(run(args))


def register(ctx):
    ctx.register_tool(name='hackathon_judge', toolset='hackathon_judge', schema=SCHEMA,
                      handler=lambda args, **kwargs: handle(ctx, args, **kwargs))
    ctx.register_command(name='judge-plugin', handler=slash,
                         description='Static hackathon/catalog plugin preflight; never imports candidate code',
                         args_hint='<path> [--catalog FILE] [--submission FILE]')
    ctx.register_cli_command(name='hackathon-judge', help='Audit a local plugin against hackathon/catalog rules',
                             setup_fn=parser_setup, handler_fn=cli_handler)
    ctx.register_skill('judge-plugin', Path(__file__).parent / 'skills/judge-plugin/SKILL.md')
