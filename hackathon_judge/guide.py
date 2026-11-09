"""Bounded static guide checks. Never import candidates or resolve filesystem assets."""
import ast
from itertools import islice
import json
from pathlib import PurePosixPath

from .inventory import read_document

GUIDE_RULES = frozenset(f'DEV-{n:02}' for n in range(1, 13))
CONDITIONAL_GUIDE_RULES = GUIDE_RULES - {'DEV-01', 'DEV-06', 'DEV-12'}
UNKNOWN = object()
SKIP_PARTS = {'tests', 'fixtures', 'sources', 'docs', 'scripts', '__pycache__'}


def source_map_valid(base, rows):
    """A real quote/line binding, independent of the capture hash check."""
    lines = read_document(base / 'sources/developer-guide.md').splitlines()
    guide = [row for row in rows if row.get('source') == 'developer-guide']
    if {row['id'] for row in guide} != GUIDE_RULES:
        return False
    for row in guide:
        span, quote = row.get('source_lines'), row.get('source_quote')
        if not isinstance(span, list) or len(span) != 2 or any(type(n) is not int for n in span):
            return False
        start, end = span
        if not 1 <= start <= end <= len(lines) or not isinstance(quote, str) or not quote.strip():
            return False
        if quote not in '\n'.join(lines[start - 1:end]):
            return False
    return True


class LocalIndex:
    """Resolve only local module bindings; calls, descriptors and imports never run."""
    def __init__(self, data):
        self.modules, self.records, self.incomplete = {}, {}, []
        for file, raw in sorted(data.items()):
            path = PurePosixPath(file)
            if path.suffix != '.py' or set(path.parts) & SKIP_PARTS:
                continue
            try:
                tree = ast.parse(raw.decode('utf-8'))
                if len(list(islice(ast.walk(tree), 50001))) > 50000:
                    self.incomplete.append(file); continue
            except (SyntaxError, UnicodeError, ValueError, RecursionError):
                self.incomplete.append(file); continue
            parts = list(path.with_suffix('').parts)
            if parts[-1] == '__init__':parts.pop()
            module = '.'.join(parts)
            # module.py and module/__init__.py cannot be guessed interchangeable.
            if module in self.modules:
                self.incomplete.extend([file, self.modules[module]])
                self.modules[module] = None
            else:self.modules[module] = file
            self.records[file] = {'tree': tree, 'module': module, 'bindings': {}}
        for file, record in self.records.items():
            self._bindings(file, record)

    def _bindings(self, file, record):
        symbols = record['bindings']
        for node in record['tree'].body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbols[node.name] = (file, node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):symbols[target.id] = (file, node.value)
            elif isinstance(node, ast.ImportFrom):
                module = self._import_base(file, node)
                if module is None:continue
                for alias in node.names:
                    if alias.name == '*':continue
                    child = '.'.join(p for p in (module, alias.name) if p)
                    target = self.modules.get(child)
                    if target:symbols[alias.asname or alias.name] = (target, self.records[target]['tree'])
                    else:
                        target = self.modules.get(module)
                        if target:symbols[alias.asname or alias.name] = (target, ast.Name(id=alias.name))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name if alias.asname else alias.name.split('.')[0]
                    target = self.modules.get(module)
                    if target:symbols[alias.asname or module] = (target, self.records[target]['tree'])

    def _import_base(self, file, node):
        if not node.level:return node.module or ''
        record = self.records[file]
        package = record['module'].split('.') if record['module'] else []
        if PurePosixPath(file).name != '__init__.py' and package:package.pop()
        if node.level > len(package) + 1:return None
        keep = len(package) - node.level + 1
        return '.'.join(package[:keep] + ([node.module] if node.module else []))

    def resolve(self, file, node, seen=()):
        if node is None or file not in self.records or len(seen) >= 12:return None
        if isinstance(node, ast.Name):
            key = (file, node.id)
            if key in seen:return None
            bound = self.records[file]['bindings'].get(node.id)
            return self.resolve(*bound, seen=seen + (key,)) if bound else None
        if isinstance(node, ast.Attribute):
            owner = self.resolve(file, node.value, seen)
            if owner and isinstance(owner[1], ast.Module):
                return self.resolve(owner[0], ast.Name(id=node.attr), seen)
            return None
        return file, node

    def literal(self, file, node):
        result = self.resolve(file, node)
        if result is None:return UNKNOWN
        try:return ast.literal_eval(result[1])
        except (ValueError, TypeError, SyntaxError, RecursionError):return UNKNOWN

    def registration_functions(self):
        entry = self.resolve('__init__.py', ast.Name(id='register'))
        pending = [entry] if entry else []
        seen, functions = set(), []
        while pending:
            file, function = pending.pop()
            if id(function) in seen:continue
            seen.add(id(function))
            if len(seen) > 128:
                self.incomplete.append(file); break
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):continue
            positional = function.args.posonlyargs + function.args.args
            if not positional:continue
            context = positional[0].arg
            if getattr(function, 'decorator_list', []) or isinstance(function, ast.AsyncFunctionDef):
                self.incomplete.append(file); continue
            nodes = list(_body_nodes(function))
            if any(isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id == context for n in nodes):
                self.incomplete.append(file); continue
            functions.append((file, function, context, nodes))
            shadows = _local_names(function)
            for node in nodes:
                if not isinstance(node, ast.Call):continue
                if any(isinstance(ref, ast.Name) and ref.id in shadows for ref in ast.walk(node.func)):continue
                child = self.resolve(file, node.func)
                if child is None or not isinstance(child[1], (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):continue
                parameters = child[1].args.posonlyargs + child[1].args.args
                if not parameters:continue
                argument = _argument(node, parameters[0].arg, 0)
                if isinstance(argument, ast.Name) and argument.id == context:pending.append(child)
        return functions

    def calls(self, method):
        for file, function, context, nodes in self.registration_functions():
            shadows = _local_names(function)
            for node in nodes:
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == context and node.func.attr == method:
                        yield file, node, shadows


def _body_nodes(function):
    stack = list(function.body) if isinstance(function.body, list) else [function.body]
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _local_names(function):
    names = {arg.arg for arg in function.args.posonlyargs + function.args.args + function.args.kwonlyargs}
    for node in ast.walk(function):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):names.add(node.id)
        elif node is not function and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
    return names


def _argument(call, name, position=None):
    for keyword in call.keywords:
        if keyword.arg == name:return keyword.value
    return call.args[position] if position is not None and len(call.args) > position else None


def _registration(index, data, manifest):
    if '__init__.py' not in data or manifest.get('kind') not in (None, '', 'plugin'):
        return 'needs_review', 'Use the actual surface-specific loader contract; general Python register(ctx) is not assumed for this layout'
    record = index.records.get('__init__.py')
    if record is None:return 'needs_review', 'Python entrypoint could not be analyzed completely; inspect syntax and the real loader'
    binding = record['bindings'].get('register')
    if binding is None:
        if any(isinstance(n, (ast.ImportFrom, ast.If, ast.Try)) for n in record['tree'].body):
            return 'needs_review', 'Conditional/imported registration may exist; official loader evidence required'
        return 'fail', 'General native Python entrypoint has no register binding; expose register(ctx) or a valid re-export'
    resolved = index.resolve(*binding)
    if resolved is None:return 'needs_review', 'Imported or dynamic registration cannot be resolved statically; inspect the real loader'
    function = resolved[1]
    if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        args = function.args
        positional = len(args.posonlyargs) + len(args.args)
        required = positional - len(args.defaults)
        required_keywords = any(default is None for default in args.kw_defaults)
        if (not positional and args.vararg is None) or required > 1 or required_keywords:
            return 'fail', 'register must accept the host context without additional required arguments'
        if getattr(function, 'decorator_list', []) or isinstance(function, ast.AsyncFunctionDef):
            return 'needs_review', 'Decorated/asynchronous registration requires actual supported-loader evidence'
        return 'pass', 'Static callable register(ctx) wiring found; loading and side effects are not executed'
    if isinstance(function, (ast.Constant, ast.Dict, ast.List, ast.Tuple, ast.Set)):
        return 'fail', 'register is a statically noncallable value; expose the supported callable entrypoint'
    return 'needs_review', 'Registration factory/expression is dynamic; actual supported-loader evidence required'


def _schema(value):
    if value is UNKNOWN:return 'needs_review', 'Schema expression is dynamic or unresolved; inspect the real registered schema'
    if not isinstance(value, dict):return 'fail', 'Tool schema is not a mapping'
    parameters = value.get('parameters', UNKNOWN)
    if parameters is UNKNOWN:return 'needs_review', 'Schema has no explicit parameter contract; inspect the host-normalized schema'
    if not isinstance(parameters, dict):return 'fail', 'Tool parameters must be an object schema mapping'
    if isinstance(parameters.get('type'), str) and parameters['type'] != 'object':
        return 'fail', 'Tool parameters declare a non-object argument type'
    properties = parameters.get('properties', {})
    required = parameters.get('required', [])
    if not isinstance(properties, dict) or not isinstance(required, list) or any(not isinstance(n, str) for n in required):
        return 'fail', 'Parameter properties/required have invalid schema shapes'
    if any(name not in properties for name in required):
        return 'needs_review', 'Required parameters are not locally described; inspect references/composed schemas'
    if not isinstance(value.get('description'), str) or not value['description'].strip() or parameters.get('type') != 'object':
        return 'needs_review', 'Provide a meaningful tool description and inspect the object parameter contract'
    return 'pass', 'Static schema mapping/description/parameter shape found; runtime agreement still needs tests'


def _own_returns(node):
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):continue
        if isinstance(child, ast.Return):yield child.value
        else:yield from _own_returns(child)


def _handler(index, file, node):
    resolved = index.resolve(file, node)
    if resolved is None:return 'needs_review', 'Handler is unresolved/dynamic; inspect callable signature and actual results'
    function = resolved[1]
    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        if isinstance(function, (ast.Constant, ast.Dict, ast.List, ast.Tuple, ast.Set)):
            return 'fail', 'Tool handler is a statically noncallable value'
        return 'needs_review', 'Handler factory/wrapper requires actual behavior evidence'
    if getattr(function, 'decorator_list', []):
        return 'needs_review', 'A decorator may transform the callable/result; inspect the real registered handler'
    args = function.args
    if not args.posonlyargs and not args.args and args.vararg is None:
        return 'fail', 'Tool handler cannot accept the positional argument mapping'
    returns = [function.body] if isinstance(function, ast.Lambda) else _own_returns(function)
    for result in returns:
        if result is None or isinstance(result, (ast.Dict, ast.List, ast.Set, ast.Tuple)):
            return 'fail', 'Tool handler explicitly returns a non-JSON-string literal'
        if isinstance(result, ast.Constant):
            if not isinstance(result.value, str):return 'fail', 'Tool handler explicitly returns a non-string value'
            try:json.loads(result.value)
            except (ValueError, RecursionError):return 'fail', 'Tool handler returns a string literal that is not valid JSON'
    return 'needs_review', 'Inspect success/error JSON strings and exception handling; **kwargs is recommended, not universally required'


def analyze(data, manifest, registrations, add):
    index = LocalIndex(data)
    components = {'manifest': ['plugin.yaml'] if 'plugin.yaml' in data else [],
                  'registration': [], 'schemas': [], 'handlers': [],
                  'skills': sorted(p for p in data if p.startswith('skills/') and p.endswith('/SKILL.md'))}
    diagnostics = []
    status, detail = _registration(index, data, manifest)
    add('guide-registration', ['DEV-02'], status, detail)
    if status != 'pass' and '__init__.py' in data:
        diagnostics.append({'rule': 'DEV-02', 'file': '__init__.py', 'line': 1,
                            'status': status, 'detail': detail,
                            'fix': 'Expose the supported registration entrypoint or provide surface-specific loader evidence'})
    for file, record in index.records.items():
        if 'register' in record['bindings']:components['registration'].append(file)
    calls = list(index.calls('register_tool'))
    checks = {'schemas': [], 'handlers': []}
    for file, call, shadows in calls:
        for component, keyword, rid, inspect in (
                ('schemas', 'schema', 'DEV-03', lambda f, n: _schema(index.literal(f, n))),
                ('handlers', 'handler', 'DEV-04', lambda f, n: _handler(index, f, n))):
            node = _argument(call, keyword)
            if node is not None and any(isinstance(ref, ast.Name) and ref.id in shadows for ref in ast.walk(node)):
                node = None
            status, detail = inspect(file, node)
            checks[component].append(status)
            resolved = index.resolve(file, node)
            if resolved:components[component].append(resolved[0])
            diagnostics.append({'rule': rid, 'file': file, 'line': call.lineno,
                                'status': status, 'detail': detail,
                                'fix': 'Inspect the actual callable/interface and add source-bound success/error tests' if component == 'handlers' else 'Provide a descriptive schema matching the argument mapping; inspect dynamic references manually'})
    for component, rid in (('schemas', 'DEV-03'), ('handlers', 'DEV-04')):
        states = checks[component]
        expected = registrations['tools'] or manifest.get('provides_tools') or registrations['dynamic']
        status = 'fail' if 'fail' in states else 'needs_review' if not states and expected or 'needs_review' in states else 'pass'
        if index.incomplete or registrations['dynamic'] or len(calls) < len(registrations['tools']):
            if status != 'fail':status = 'needs_review'
        detail = f'{len(states)} statically located tool {component}; no candidate code executed. '
        detail += 'No declared/literal tools; this role is conditional.' if not expected and not states else 'Alternate filenames and inline definitions are allowed; review unresolved wiring and actual behavior.'
        add('guide-' + component, [rid], status, detail)
    resources = bool(components['skills'] or list(index.calls('register_skill')) or
                     any(PurePosixPath(file).parts[0] in {'data', 'assets', 'resources'} for file in data))
    add('guide-resources', ['DEV-08'], 'needs_review' if resources else 'pass',
        'Bundled skills/data references require package-relative path, metadata and registration review; no asset path was opened' if resources else 'No bundled skill registration observed; optional resources are not required. Inspect any shipped data references manually')
    add('guide-declarations', ['DEV-05', 'CAT-06'], 'needs_review', 'Compare manifest to literal observations AND runtime registrations/capability consent; static matching alone is not proof')
    add('guide-public-apis', ['DEV-06', 'CAT-09', 'CAT-08'], 'needs_review', 'Review only documented APIs/SDKs for the selected surface; no core or host-markup overrides')
    add('guide-profile-state', ['DEV-07', 'CAT-11'], 'needs_review', 'If settings/state are used, inspect plugin/profile ownership, durable storage outside source and stable conversation identity; no writes executed')
    add('guide-dependencies', ['DEV-09', 'CAT-10', 'CAT-11'], 'needs_review', 'Review declared dependencies/environment inputs, profile-scoped secrets and required-versus-optional behavior; no credentials or dependencies read/installed')
    add('guide-hooks', ['DEV-10'], 'needs_review', 'Hooks and availability are optional; inspect documented names/payloads and failure behavior when present')
    add('guide-session-paths', ['DEV-11'], 'needs_review', 'For path-taking native commands, verify per-invocation session cwd/context or explicit relative-path refusal; never infer gateway cwd is the session cwd')
    add('guide-runtime-tests', ['DEV-12', 'PRE-03'], 'not_run', 'Real discovery/Doctor/validator and success/failure behavior require trusted-code authorization and source-bound receipts; no automatic activation')
    if index.incomplete:
        add('guide-analysis-coverage', ['DEV-01', 'DEV-02', 'DEV-03', 'DEV-04'], 'needs_review', 'Unparseable, oversized or ambiguous local modules prevent complete static role resolution')
    return {'scope': 'Core build-guide contract with conditional surface review; not all specialized SDK behavior is statically verifiable',
            'components': {key: sorted(set(value)) for key, value in components.items()},
            'diagnostics': diagnostics, 'unresolved_modules': sorted(set(index.incomplete)),
            'notice': 'The calculator filenames, hooks, skills and data are examples/optional features, not universal requirements. Static shapes never prove real execution.'}
