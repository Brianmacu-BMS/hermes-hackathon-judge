#!/usr/bin/env python3
"""Record real CLI outcomes without installation, activation, or network access."""
import argparse
from datetime import datetime, timezone
import html
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT.parent / 'hackathon-judge-demo-output')
    parser.add_argument('--script', action='store_true', help='Record a real CLI transcript (also the default)')
    parser.add_argument('--dry-run', action='store_true', help='Describe commands without executing or writing anything')
    parser.add_argument('--replay', action='store_true', help='Print the latest recorded transcript without rerunning code')
    args = parser.parse_args(argv)
    if args.dry_run:
        print('DRY RUN: create a disposable mismatched plugin; audit both sources; repair catalog declarations; show the remaining guide blocker; fix schema/handler; generate the evidence template. No activation or network.')
        return 0
    if args.replay:
        files = list(args.output.glob('run-*/transcript.txt'))
        if not files:
            parser.error('No recording found')
        print(max(files, key=lambda p: p.stat().st_mtime).read_text())
        return 0
    scratch = os.environ.get('TMPDIR')
    if not scratch:
        parser.error('Set TMPDIR to an approved scratch directory before recording')
    args.output.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='run-', dir=args.output))
    fixture = Path(tempfile.mkdtemp(prefix='judge-demo-fixture-', dir=scratch))
    (fixture / 'plugin.yaml').write_text('name: demo-plugin\nversion: 1.0.0\ndescription: Minimal demonstration fixture\nprovides_tools: [demo]\npython_dependencies: ["requests>=2.0"]\n')
    (fixture / '__init__.py').write_text('def register(ctx):\n    ctx.register_tool(name="surprise", toolset="demo", schema=[], handler=None)\n')
    (fixture / 'README.md').write_text('# Demonstration fixture\n## Disclosures\nNo network, credentials, subprocesses or telemetry.\n')
    start = time.monotonic()
    events = []
    env = {'PATH': os.defpath, 'TMPDIR': scratch, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(ROOT)}
    def audit_step(name, expected):
        command = [sys.executable, '-m', 'hackathon_judge', str(fixture), '--format', 'json']
        run = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
        if run.returncode != expected:
            raise RuntimeError(f'{name} returned {run.returncode}; expected {expected}')
        report = json.loads(run.stdout)
        (output / (name + '.json')).write_text(run.stdout)
        rows = [f"$ python -m hackathon_judge <fixture> --format json", f"exit={run.returncode}; verdict={report['verdict']}"]
        rows += [f"{track['title']}: {track['status']}" for track in report['tracks'].values()]
        rows += [f"{c['id']}: {c['status']} — {c['detail']}" for c in report['checks'] if c['id'] in {'manifest', 'declared-registrations', 'dependency-bounds', 'guide-schemas', 'guide-handlers'}]
        events.append({'step': name, 'exit_code': run.returncode, 'verdict': report['verdict'], 'display': '\n'.join(rows)})
        return report
    audit_step('01-find-problems', 1)
    (fixture / '__init__.py').write_text('def register(ctx):\n    ctx.register_tool(name="demo", toolset="demo", schema=[], handler=None)\n')
    (fixture / 'plugin.yaml').write_text('name: demo-plugin\nversion: 1.0.0\ndescription: Minimal demonstration fixture\nprovides_tools: [demo]\npython_dependencies: ["requests>=2.0,<3"]\n')
    audit_step('02-catalog-fixed-guide-still-broken', 1)
    schema = {'name': 'demo', 'description': 'Report successful synthetic fixture execution.',
              'parameters': {'type': 'object', 'properties': {}}}
    (fixture / '__init__.py').write_text('import json\nSCHEMA = ' + repr(schema) + '\ndef handle(args, **kwargs):\n    return json.dumps({"ok": True})\ndef register(ctx):\n    ctx.register_tool(name="demo", toolset="demo", schema=SCHEMA, handler=handle)\n')
    fixed = audit_step('03-guide-fixed-evidence-pending', 2)
    command = [sys.executable, '-m', 'hackathon_judge', str(fixture), '--format', 'template']
    run = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=20)
    if run.returncode != 2:
        raise RuntimeError('Template command failed')
    template = json.loads(run.stdout)
    (output / 'review-template.json').write_text(run.stdout)
    events.append({'step': '04-honest-review-gate', 'exit_code': run.returncode,
                   'display': f"$ python -m hackathon_judge <fixture> --format template\n{len(template['decisions'])} source-linked decisions, bound to candidate {template['candidate_sha256'][:16]}…\nLocal fixes are not official compliance. Missing review/submission evidence remains incomplete."})
    duration = time.monotonic() - start
    if duration >= 90:
        raise RuntimeError('Demonstration exceeded the strict 90-second limit')
    transcript = '\n\n'.join(e['display'] for e in events)
    (output / 'transcript.txt').write_text(transcript + '\n')
    sections = ''.join('<section><h2>' + html.escape(e['step']) + '</h2><pre>' + html.escape(e['display']) + '</pre></section>' for e in events)
    page = '<!doctype html><meta charset="utf-8"><title>Hackathon Judge — recorded CLI results</title><style>body{background:#10151c;color:#e2e8f0;font:20px system-ui;padding:32px}pre{white-space:pre-wrap;font:18px monospace;line-height:1.5}section{border-top:1px solid #334155;padding:16px 0}</style><h1>Hackathon Judge — real CLI results</h1><p>Both sources → fix catalog declarations → fix build-guide contracts → honest evidence gate. No activation or network.</p>' + sections
    (output / 'transcript.html').write_text(page)
    receipt = {'schema_version': 1, 'kind': 'local-cli-demo', 'recorded_at': datetime.now(timezone.utc).isoformat(),
               'execution_seconds': duration, 'strictly_under_90_seconds': True, 'published_on_x': False,
               'video_recorded': False, 'fixture': str(fixture), 'output': str(output), 'events': events,
               'final_candidate_sha256': fixed['inventory']['tree_sha256']}
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2))
    print(transcript)
    print(json.dumps({'output': str(output), 'execution_seconds': duration, 'activation': 'none', 'publication': 'none'}, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print('Demo failed: ' + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
