"""Standalone CLI. Output is stdout-only unless the caller redirects it."""
import argparse
import json

from .engine import audit, markdown, requirements, review_template


def parser_setup(parser):
    parser.add_argument('path', nargs='?', help='Local trusted-stable plugin directory (static audit never imports it)')
    parser.add_argument('--catalog', help='Explicit local catalog YAML entry')
    parser.add_argument('--submission', help='Explicit local JSON attestations; never treated as verified evidence')
    parser.add_argument('--review', help='Accountable review record with candidate/policy/evidence hashes; not official acceptance')
    parser.add_argument('--gate', choices=['code_ready', 'ready_to_submit', 'entry_submitted', 'catalog_accepted'], default='code_ready', help='Explicit reviewer readiness gate required for exit 0')
    parser.add_argument('--format', choices=['markdown', 'json', 'template'], default='markdown')
    parser.add_argument('--rules', action='store_true', help='Print complete source-linked requirement set')
    return parser


def run(args):
    if args.rules:
        print(json.dumps(requirements(), indent=2))
        return 0
    if not args.path:
        print(json.dumps({'error': 'A local plugin directory is required unless --rules is set'}))
        return 3
    try:
        report = audit(args.path, catalog=args.catalog, submission=args.submission, review=getattr(args, 'review', None))
    except Exception as exc:
        # Do not echo candidate source, YAML snippets, credentials or parser errors.
        print(json.dumps({'error': 'Audit failed; check paths and input document format', 'kind': type(exc).__name__}))
        return 3
    if args.format == 'json':
        print(json.dumps(report, indent=2))
    elif args.format == 'template':
        print(json.dumps(review_template(report), indent=2))
    else:
        print(markdown(report))
    if report['verdict'] == 'blocked':
        return 1
    return 0 if report['assessment']['readiness'][getattr(args, 'gate', 'code_ready')]['ready'] else 2


def main(argv=None):
    return run(parser_setup(argparse.ArgumentParser(description='Hermes Hackathon Judge: non-executing preflight, never official certification')).parse_args(argv))
