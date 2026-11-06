"""Bounded inspection. Refuse stable links/reparse points and secret stores."""
import hashlib
import os
from pathlib import Path
from .paths import UnsafePath, guarded_path, read_regular

SKIP_DIRS = {'.git', '.venv', 'venv', 'node_modules', '.pytest_cache', '.ruff_cache', 'evidence'}
SENSITIVE = {'auth.json', 'credentials.json', 'secrets.json', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', '.npmrc', '.pypirc', '.netrc', '.git-credentials', '.dockercfg'}
SENSITIVE_DIRS = {'.ssh', '.aws', '.gnupg', '.codex', '.kube'}
SOURCE_SUFFIXES = {'.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'}


def sensitive(name):
    return name == '.env' or name.startswith('.env.') or name in SENSITIVE or name.endswith(('.pem', '.key', '.p12', '.pfx', '.kdbx'))


def inventory(root, *, max_files=10000, max_directories=10000, max_file_bytes=2_000_000, max_total_bytes=32_000_000):
    root = Path(root).expanduser().absolute()
    if any(p.name in SENSITIVE_DIRS or sensitive(p.name) for p in (root, *root.parents)):
        raise ValueError('Secret-store candidate paths are refused')
    root = guarded_path(root)
    if not root.is_dir():
        raise ValueError('Candidate path must be a directory')
    if min(max_files, max_directories, max_file_bytes, max_total_bytes) <= 0:
        raise ValueError('Inspection budgets must be positive')
    result = {'complete': True, 'files': [], 'excluded_sensitive': [], 'symlinks': [], 'omitted': [], 'ignored_directories': [], 'bytes_read': 0}
    data = {}
    seen = 0
    directory_entries = 1
    def walk_error(error):
        result['complete'] = False
        result['omitted'].append('Directory traversal failed; inaccessible subtree not inspected')
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        directory_entries += len(dirs)
        if directory_entries > max_directories:
            result['complete'] = False
            result['omitted'].append('Directory-count budget exceeded; remaining tree not inspected')
            break
        dirs.sort()
        files.sort()
        kept = []
        for name in dirs:
            p = Path(directory) / name
            rel = p.relative_to(root).as_posix()
            if name in SENSITIVE_DIRS or sensitive(name):
                result['excluded_sensitive'].append(rel + '/')
                result['complete'] = False
            else:
                try:
                    guarded_path(p, root=root)
                except UnsafePath:
                    result['symlinks'].append(rel)
                    result['complete'] = False
                except (OSError, ValueError):
                    result['omitted'].append(rel + '/')
                    result['complete'] = False
                else:
                    if name in SKIP_DIRS:
                        result['ignored_directories'].append(rel)
                    else:
                        kept.append(name)
        dirs[:] = kept
        for name in files:
            seen += 1
            if seen > max_files:
                result['omitted'].append('File-count budget exceeded; remaining tree not inspected')
                result['complete'] = False
                result['tree_sha256'] = fingerprint(result['files'])
                return root, result, data
            p = Path(directory) / name
            rel = p.relative_to(root).as_posix()
            if sensitive(name):
                result['excluded_sensitive'].append(rel)
                result['complete'] = False
                continue
            try:
                raw = read_regular(p, root=root, max_bytes=max_file_bytes,
                                   remaining_bytes=max_total_bytes - result['bytes_read'])
                result['bytes_read'] += len(raw)
                digest = hashlib.sha256(raw).hexdigest()
                result['files'].append({'path': rel, 'bytes': len(raw), 'sha256': digest})
                data[rel] = raw
            except UnsafePath:
                result['symlinks'].append(rel)
                result['complete'] = False
            except (OSError, ValueError):
                result['omitted'].append(rel)
                result['complete'] = False
    result['tree_sha256'] = fingerprint(result['files'])
    return root, result, data


def fingerprint(files):
    digest = hashlib.sha256()
    for item in sorted(files, key=lambda f: f['path']):
        digest.update(item['path'].encode() + b'\0' + item['sha256'].encode() + b'\n')
    return digest.hexdigest()


def read_document(path, root=None):
    """Read an explicitly supplied non-secret regular document, bounded to 1 MiB."""
    p = Path(path).expanduser().absolute()
    if any(x.name in SENSITIVE_DIRS or sensitive(x.name) for x in (p, *p.parents)):
        raise ValueError('Secret document paths are refused')
    raw = read_regular(p, root=root, max_bytes=1_000_000)
    return raw.decode('utf-8')
