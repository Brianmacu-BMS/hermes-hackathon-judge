"""Terminal-owned bound validator transaction; never imported by candidate code.

The caller verifies this file's exact hash before exec on the selected backend.
Only a complete, non-ignored regular-file tree can be snapshotted. This is byte
binding, not a sandbox against hostile same-user writers or ambient dependencies.
"""
import hashlib
import json
import os
import ntpath
import re
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

PROTOCOL = 'backend-snapshot-v1'


def digest(files):
    value = hashlib.sha256()
    for item in sorted(files, key=lambda item: item['path']):
        value.update(item['path'].encode() + b'\0' + item['sha256'].encode() + b'\n')
    return value.hexdigest()


def _drive_type(root):
    """Query only the drive root's Windows classification, never its target metadata."""
    if os.name != 'nt':
        return 0
    import ctypes
    query = ctypes.WinDLL('kernel32', use_last_error=True).GetDriveTypeW
    query.argtypes = [ctypes.c_wchar_p]
    query.restype = ctypes.c_uint
    return query(root)


def _drive_mapping(drive):
    """Read the DOS-device table only; never follow a mapped filesystem target."""
    if os.name != 'nt':
        return ''
    import ctypes
    from ctypes import wintypes
    query = ctypes.WinDLL('kernel32', use_last_error=True).QueryDosDeviceW
    query.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
    query.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    count = query(drive, buffer, len(buffer))
    if not 0 < count <= len(buffer):
        raise OSError('DOS-device mapping is unavailable')
    return buffer.value


def _local_drive_mapping(target):
    # Deliberately conservative: SUBST, redirectors and unknown device targets
    # are not proof of direct-local storage, even when GetDriveTypeW is local.
    return re.fullmatch(r'\\Device\\(?:HarddiskVolume|CdRom|Floppy|Ramdisk)[0-9]+', target, re.IGNORECASE) is not None


def admit_local_root(path):
    """Lexical admission before expand/absolute/stat, plus conservative drive admission."""
    text = os.fspath(path)
    if not isinstance(text, str) or not text or '\x00' in text:
        raise ValueError('A local text path is required')
    windows = text.replace('\\', '/')
    # Includes UNC, extended-length, NT/device namespace and POSIX double-root paths.
    if windows.startswith('//') or windows.startswith('/??/'):
        raise ValueError('Nonlocal and device roots are refused')
    if text.startswith('\\'):
        raise ValueError('Root-relative Windows paths are refused')
    drive, tail = ntpath.splitdrive(text)
    if drive:
        if not re.fullmatch('[A-Za-z]:', drive) or not tail.startswith(('\\', '/')):
            raise ValueError('Ambiguous or nonlocal Windows root is refused')
        try:
            local = (_drive_type(drive + '\\') in {2, 3, 5, 6}
                     and _local_drive_mapping(_drive_mapping(drive)))
        except (OSError, AttributeError):
            local = False
        if not local:
            raise ValueError('Remote, missing, aliased or unclassified drives are refused')
    return path


def guarded(path):
    admit_local_root(path)
    path = Path(path).absolute()
    admit_local_root(path)
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Alias refused')
    return path


def collect(root):
    root = guarded(root)
    if not root.is_dir():
        raise ValueError('Missing backend candidate')
    files, data, total, directories = [], {}, 0, 1
    def failed(error):
        raise ValueError('Unreadable backend tree')
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=failed):
        directories += len(dirs)
        if directories > 10000:
            raise ValueError('Directory budget exceeded')
        for name in dirs:
            guarded(Path(directory) / name)
        for name in sorted(names):
            if len(files) >= 10000:
                raise ValueError('File budget exceeded')
            path = guarded(Path(directory) / name)
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_size > 2_000_000:
                raise ValueError('Nonregular or oversized backend file')
            flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(path, flags)
            with os.fdopen(fd, 'rb') as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ValueError('File identity changed')
                raw = stream.read(min(2_000_001, 32_000_001 - total))
                closed = os.fstat(stream.fileno())
            guarded(path)
            if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (closed.st_size, closed.st_mtime_ns, closed.st_ctime_ns) or len(raw) != opened.st_size:
                raise ValueError('File changed during read')
            total += len(raw)
            if total > 32_000_000 or len(raw) > 2_000_000:
                raise ValueError('Byte budget exceeded')
            relative = path.relative_to(root).as_posix()
            files.append({'path': relative, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
            data[relative] = (raw, stat.S_IMODE(opened.st_mode))
    return sorted(files, key=lambda item: item['path']), data


def transaction(request):
    expected = request['files']
    if not isinstance(expected, list) or not expected or len(expected) > 10000:
        raise ValueError('Missing complete candidate manifest')
    # Never use request paths for writes; only validated traversal names are copied.
    files, data = collect(request['candidate'])
    if files != expected or digest(files) != request['tree_sha256']:
        raise ValueError('Backend candidate bytes differ from the audited candidate')
    with tempfile.TemporaryDirectory(prefix='judge-bound-') as directory:
        snapshot = Path(directory) / 'candidate'
        snapshot.mkdir()
        for relative, (raw, mode) in data.items():
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(mode)
        copied, _ = collect(snapshot)
        if copied != expected:
            raise ValueError('Snapshot byte binding failed')
        # Candidate execution is wholly inside this normal, approval-visible
        # terminal dispatch; no install, bypass flag, local-backend override or SDK internals.
        command = ['hermes', 'plugins', 'validate', str(snapshot), '--json']
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            done = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                  env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, timeout=100)
            stdout.seek(0)
            output = stdout.read(1_000_001)
            if len(output) > 1_000_000:
                raise ValueError('Validator report too large')
        changed = False
        try:
            source_after, _ = collect(request['candidate'])
            snapshot_after, _ = collect(snapshot)
            changed = source_after != expected or snapshot_after != expected
        except (OSError, ValueError):
            changed = True
        return {'protocol': PROTOCOL, 'nonce': request['nonce'],
                'tree_sha256': request['tree_sha256'], 'bound_before': True,
                'tree_unchanged': not changed, 'validator_exit_code': done.returncode,
                'validator_output': output.decode('utf-8'), 'validator_command': command}


def main(request):
    try:
        result = transaction(request)
        print(json.dumps(result))
        return 0 if result['validator_exit_code'] == 0 else 1
    except Exception:
        # No candidate output, paths or parser fragments on error.
        print(json.dumps({'protocol': PROTOCOL, 'nonce': request.get('nonce'),
                          'error': 'Backend binding or validation failed; no result attributed'}))
        return 3
