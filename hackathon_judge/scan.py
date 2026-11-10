"""Heuristic review flags, not a replacement for Hermes's admission scanner."""
import ast
from pathlib import PurePosixPath
import re

from .inventory import SOURCE_SUFFIXES
from .guide import LocalIndex, _argument, _local_names


def _registration_nodes(nodes, certain=True):
    """Bounded reachability, not general execution: unknown control flow is review."""
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.If):
            yield from _registration_nodes([node.test], certain)
            if isinstance(node.test, ast.Constant):
                branch = node.body if node.test.value else node.orelse
                yield from _registration_nodes(branch, certain)
            else:
                yield from _registration_nodes(node.body, False)
                yield from _registration_nodes(node.orelse, False)
        else:
            conditional = isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.Try,
                                            ast.With, ast.AsyncWith, ast.Match,
                                            ast.IfExp, ast.BoolOp))
            if isinstance(node, ast.Call):
                yield node, certain
            yield from _registration_nodes(list(ast.iter_child_nodes(node)), certain and not conditional)
        if isinstance(node, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            break


def _registration_observations(data):
    """Only entrypoint/context-connected literals can establish a mismatch."""
    actual = {'tools': set(), 'hooks': set(), 'dynamic': False}
    index = LocalIndex(data)
    entry = index.resolve('__init__.py', ast.Name(id='register'))
    pending = [(entry, True)] if entry else []
    actual['dynamic'] = bool(index.incomplete) or entry is None
    seen = set()
    while pending:
        resolved, certain = pending.pop()
        file, function = resolved
        key = (file, id(function), certain)
        if key in seen:
            continue
        seen.add(key)
        if len(seen) > 128:
            actual['dynamic'] = True
            break
        if (not isinstance(function, (ast.FunctionDef, ast.Lambda))
                or getattr(function, 'decorator_list', [])):
            actual['dynamic'] = True
            continue
        positional = function.args.posonlyargs + function.args.args
        if not positional:
            actual['dynamic'] = True
            continue
        context = positional[0].arg
        shadows = _local_names(function)
        body = function.body if isinstance(function.body, list) else [function.body]
        calls = list(_registration_nodes(body, certain))
        # A local rebinding/alias can change the receiver. Do not claim literals.
        if any(isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id == context
               for n in ast.walk(function)):
            actual['dynamic'] = True
            continue
        for call, definite in calls:
            if isinstance(call.func, ast.Attribute) and call.func.attr in {'register_tool', 'register_hook'}:
                if not (definite and isinstance(call.func.value, ast.Name) and call.func.value.id == context):
                    actual['dynamic'] = True
                    continue
                value = _argument(call, 'name', 0)
                kind = 'tools' if call.func.attr == 'register_tool' else 'hooks'
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    actual[kind].add(value.value)
                else:
                    actual['dynamic'] = True
                continue
            context_args = any(isinstance(arg, ast.Name) and arg.id == context
                               for arg in call.args + [kw.value for kw in call.keywords])
            if not context_args:
                continue
            child = None if any(isinstance(n, ast.Name) and n.id in shadows for n in ast.walk(call.func)) else index.resolve(file, call.func)
            if child and isinstance(child[1], (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                parameters = child[1].args.posonlyargs + child[1].args.args
                argument = _argument(call, parameters[0].arg, 0) if parameters else None
                if isinstance(argument, ast.Name) and argument.id == context:
                    pending.append((child, definite))
                    if not definite:
                        actual['dynamic'] = True
                    continue
            actual['dynamic'] = True
    return actual

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


class _ImportScopes(ast.NodeVisitor):
    """Index imports per lexical scope; never merge sibling/local imports."""
    def __init__(self, tree):
        self.scope = ({}, None, 'module')
        self.scopes = {}
        self.visit(tree)

    def visit(self, node):
        self.scopes[id(node)] = self.scope
        return super().visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            root = alias.name.split('.')[0]
            self.scope[0][alias.asname or root] = alias.name if alias.asname else root

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.scope[0][alias.asname or alias.name] = (node.module or '') + '.' + alias.name

    def _body_scope(self, node, kind):
        outer = self.scope
        parent = outer
        # Class namespaces are not lexical closures for nested bodies/methods.
        while parent[2] == 'class':
            parent = parent[1]
        self.scope = ({}, parent, kind)
        body = node.body if isinstance(node.body, list) else [node.body]
        for statement in body:
            self.visit(statement)
        self.scope = outer

    def visit_FunctionDef(self, node):
        # Decorators, defaults and annotations are evaluated outside the body.
        for decorator in node.decorator_list:
            self.visit(decorator)
        self.visit(node.args)
        if node.returns:
            self.visit(node.returns)
        self._body_scope(node, 'function')

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        self.visit(node.args)
        self._body_scope(node, 'function')

    def visit_ClassDef(self, node):
        for expression in node.decorator_list + node.bases + node.keywords:
            self.visit(expression)
        self._body_scope(node, 'class')

    def resolved(self, node):
        name = dotted(node)
        head, dot, tail = name.partition('.')
        scope = self.scopes.get(id(node))
        while scope is not None:
            if head in scope[0]:
                head = scope[0][head]
                break
            scope = scope[1]
        return head + (dot + tail if dot else '')


CORE_MODULES = {'run_agent', 'hermes_cli', 'model_tools', 'tools', 'gateway', 'agent', 'hermes_state'}


def scan(data):
    findings = []
    registrations = _registration_observations(data)
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
        resolved = _ImportScopes(tree).resolved
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    name = dotted(target)
                    if isinstance(target, (ast.Attribute, ast.Subscript)) and (resolved(target).split('.')[0] in CORE_MODULES or resolved(target).startswith('sys.modules')):
                        add('CAT-09', file, node.lineno, 'Assignment into a core object or module table')
            if not isinstance(node, ast.Call):
                continue
            name = resolved(node.func)
            if name.endswith('.register_login_backend'):
                add('CAT-18', file, node.lineno, 'Login backend requires vendor-owned verified or Nous official provenance')
            if name.startswith(('os.getenv', 'os.environ')):
                add('CAT-11', file, node.lineno, 'Environment read: verify profile-scoped get_secret for credentials')
            if name.removeprefix('builtins.') in {'eval', 'exec', 'compile', '__import__'}:
                add('CAT-07', file, node.lineno, 'Dynamic execution requires security review')
            if name.removeprefix('builtins.') == 'setattr' and node.args and resolved(node.args[0]).split('.')[0] in CORE_MODULES:
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