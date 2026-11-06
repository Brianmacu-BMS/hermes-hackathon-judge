"""Heuristic review flags, not a replacement for Hermes's admission scanner."""
import ast
from pathlib import PurePosixPath
import re

from .inventory import SOURCE_SUFFIXES

JS_RULES = [
    ('CAT-08', r'\beval\s*\(|\bnew\s+Function\s*\(', 'Dynamic JavaScript execution'),
    ('CAT-08', r'\bimport\s*\(\s*[\"\'](?!@hermes/plugin-sdk[\"\']|react(?:/jsx-runtime)?[\"\'])', 'Non-SDK dynamic import'),
    ('CAT-08', r'\.prototype\s*(?:\.[\w$]+|\[[^\]]+\])\s*=|defineProperty\s*\([^\n]*prototype', 'Prototype mutation; verify whether host or plugin-owned class'),
    ('CAT-08', r'createElement\s*\(\s*[\"\']script[\"\']', 'Script injection'),
    ('CAT-08', r'document\.(?:querySelector|querySelectorAll|getElementById)|document\.body|window\.hermesDesktop|data-(?:slot|tour|sidebar|testid|tree-)', 'Host DOM or raw Desktop bridge access'),
    ('CAT-03', r'(?:self[._]?updat|auto[._]?updat|check[._]?[fF]or[._]?[uU]pdat|download[._]?[uU]pdat)', 'Possible self-updater; distinguish host-managed updates'),
    ('CAT-11', r'(?:localStorage|sessionStorage).*(?:token|secret)|(?:readFile|fetch).*auth\.json', 'Potential direct credential store access'),
    ('CAT-12', r'\b(?:yolo|autoApprove|skipApproval|disableGuard)\b', 'Potential approval bypass'),
    ('CAT-13', r'\b(?:fetch|WebSocket|XMLHttpRequest)\s*\(', 'Network behavior needs README and PR disclosure'),
]


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return dotted(node.value) + '.' + node.attr
    if isinstance(node, ast.Subscript):
        return dotted(node.value)
    return ''


def _self_update_patterns():
    """Return compiled patterns for self-update indicators."""
    return re.compile(r'(?:self[._]?updat|auto[._]?updat|check[._]?[fF]or[._]?[uU]pdat|download[._]?[uU]pdat)', re.I)


def _is_dangerous_call(name):
    """Return True if the call name is a subprocess/shell execution."""
    return name.startswith(('subprocess.', 'os.system', 'os.popen'))


def scan(data):
    findings = []
    registrations = {'tools': set(), 'hooks': set(), 'dynamic': False}
    def add(rule, file, line, message):
        findings.append({'rule': rule, 'file': file, 'line': line, 'severity': 'review', 'message': message})
    self_upd = _self_update_patterns()
    for file, raw in sorted(data.items()):
        path = PurePosixPath(file)
        if path.suffix not in SOURCE_SUFFIXES or any(p in {'tests', 'fixtures', 'sources', '__pycache__'} for p in path.parts):
            continue
        try:
            text = raw.decode('utf-8')
        except UnicodeError:
            add('CAT-17', file, 1, 'Source file is not UTF-8; manual inspection required')
            continue
        if path.suffix != '.py':
            for rule, pattern, message in JS_RULES:
                for match in re.finditer(pattern, text, re.I):
                    add(rule, file, text.count('\n', 0, match.start()) + 1, message)
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            add('PRE-02', file, 1, 'Python syntax could not be parsed')
            registrations['dynamic'] = True
            continue
        aliases = {}
        core = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    # import os.path brings os into scope as os, not os.path.
                    # Only map the root name to itself when no asname is given.
                    root_name = alias.name.split('.')[0]
                    if alias.asname:
                        aliases[alias.asname] = alias.name
                    else:
                        aliases[root_name] = root_name
                    if root_name in {'run_agent', 'hermes_cli', 'model_tools', 'tools', 'gateway', 'agent', 'hermes_state'}:
                        core.add(alias.asname or root_name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    aliases[alias.asname or alias.name] = (node.module or '') + '.' + alias.name
                    if (node.module or '').split('.')[0] in {'run_agent', 'hermes_cli', 'model_tools', 'tools', 'gateway', 'agent', 'hermes_state'}:
                        core.add(alias.asname or alias.name)
        def resolved(node):
            name = dotted(node)
            head, dot, tail = name.partition('.')
            return aliases.get(head, head) + (dot + tail if dot else '')
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    name = dotted(target)
                    if isinstance(target, (ast.Attribute, ast.Subscript)) and (name.split('.')[0] in core or resolved(target).startswith('sys.modules')):
                        add('CAT-09', file, node.lineno, 'Assignment into a core object or module table')
            if not isinstance(node, ast.Call):
                continue
            name = resolved(node.func)
            if name.endswith(('.register_tool', '.register_hook')):
                keyword = next((k.value for k in node.keywords if k.arg == 'name'), None)
                value = keyword or (node.args[0] if node.args else None)
                kind = 'tools' if name.endswith('.register_tool') else 'hooks'
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    registrations[kind].add(value.value)
                else:
                    registrations['dynamic'] = True
            if name.endswith('.register_login_backend'):
                add('CAT-18', file, node.lineno, 'Login backend requires vendor-owned verified or Nous official provenance')
            if name.startswith(('os.getenv', 'os.environ')):
                add('CAT-11', file, node.lineno, 'Environment read: verify profile-scoped get_secret for credentials')
            if name.removeprefix('builtins.') in {'eval', 'exec', 'compile', '__import__'}:
                add('CAT-07', file, node.lineno, 'Dynamic execution requires security review')
            if name.removeprefix('builtins.') == 'setattr' and node.args and dotted(node.args[0]).split('.')[0] in core:
                add('CAT-09', file, node.lineno, 'setattr on a core object')
            if name.startswith(('subprocess.', 'os.system', 'os.popen')):
                add('CAT-12', file, node.lineno, 'Child command: inspect approval/unattended behavior')
                add('CAT-13', file, node.lineno, 'Shell/subprocess behavior needs README and PR disclosure')
            if name.startswith(('requests.', 'httpx.', 'urllib.request.', 'socket.')):
                add('CAT-13', file, node.lineno, 'Network behavior needs README and PR disclosure')
            # Self-update detection for Python (function name or method call)
            if self_upd.search(name.split('.')[-1]):
                add('CAT-03', file, node.lineno, 'Self-update indicator; catalog rules forbid self-updating code')
            # String analysis: only scan strings in dangerous contexts
            if _is_dangerous_call(name):
                strings = [x.value for x in ast.walk(node) if isinstance(x, ast.Constant) and isinstance(x.value, str)]
                if any(re.search(r'--yolo|skip.approval|auto.approv', s, re.I) for s in strings):
                    add('CAT-12', file, node.lineno, 'Possible approval-bypass argument')
            # Credential path scanning: only in file-read calls or open()
            func_root = name.split('.')[0]
            if func_root == 'open' or name.startswith(('builtins.open',)):
                strings = [x.value for x in ast.walk(node) if isinstance(x, ast.Constant) and isinstance(x.value, str)]
                if any(re.search(r'(?:^|[/\\\\])(?:auth\.json|\.env|credentials\.json)(?:$|[/\\\\])', s) for s in strings):
                    add('CAT-11', file, node.lineno, 'Possible direct credential file reference; inspect read/write behavior')
        # Subscript environment reads are not calls.
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript) and resolved(node.value) == 'os.environ':
                add('CAT-11', file, node.lineno, 'Direct environment lookup; verify secret scoping')
        # Walk function/method definitions for self-update names
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and self_upd.search(node.name):
                add('CAT-03', file, node.lineno, 'Self-update function definition; catalog rules forbid self-updating code')
    unique = {(f['rule'], f['file'], f['line'], f['message']): f for f in findings}
    return list(unique.values()), registrations