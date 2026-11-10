"""Stable local path guards, not a sandbox against concurrent ancestor swaps."""
import os
import ntpath
import re
from pathlib import Path
import stat


class UnsafePath(ValueError):
    """A lexical path component is a link or Windows reparse point."""


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
        raise UnsafePath('A local text path is required')
    windows = text.replace('\\', '/')
    # Includes UNC, extended-length, NT/device namespace and POSIX double-root paths.
    if windows.startswith('//') or windows.startswith('/??/'):
        raise UnsafePath('Nonlocal and device roots are refused')
    if text.startswith('\\'):
        raise UnsafePath('Root-relative Windows paths are refused')
    drive, tail = ntpath.splitdrive(text)
    if drive:
        if not re.fullmatch('[A-Za-z]:', drive) or not tail.startswith(('\\', '/')):
            raise UnsafePath('Ambiguous or nonlocal Windows root is refused')
        try:
            local = (_drive_type(drive + '\\') in {2, 3, 5, 6}
                     and _local_drive_mapping(_drive_mapping(drive)))
        except (OSError, AttributeError):
            local = False
        if not local:
            raise UnsafePath('Remote, missing, aliased or unclassified drives are refused')
    return path


def guarded_path(path, *, root=None):
    """Check lexical components before resolution can erase a link or junction.

    lstat's reparse attribute works at the Python 3.11 floor; Path.is_junction
    is newer and symlink mode alone does not detect Windows junctions. Refuse
    all reparse points, including in-scope ones, rather than guessing tag safety.
    """
    admit_local_root(path)
    if root is not None:
        admit_local_root(root)
    absolute = Path(path).expanduser().absolute()
    admit_local_root(absolute)
    for component in reversed((absolute, *absolute.parents)):
        info = component.lstat()
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
            raise UnsafePath('Symlinks, junctions and reparse paths are refused')
    resolved = absolute.resolve(strict=True)
    if root is not None and not resolved.is_relative_to(guarded_path(root)):
        raise ValueError('Path must remain inside the selected directory')
    return resolved


def read_regular(path, *, root=None, max_bytes, remaining_bytes=None):
    """Read a guarded regular file with pre/post size bounds and POSIX nofollow."""
    path = guarded_path(path, root=root)
    limit = max_bytes if remaining_bytes is None else min(max_bytes, remaining_bytes)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Not a regular file')
        if info.st_size > limit:
            raise ValueError('Byte budget exceeded')
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('File grew past byte budget')
    return raw
