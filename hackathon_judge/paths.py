"""Stable local path guards, not a sandbox against concurrent ancestor swaps."""
import os
from pathlib import Path
import stat


class UnsafePath(ValueError):
    """A lexical path component is a link or Windows reparse point."""


def guarded_path(path, *, root=None):
    """Check lexical components before resolution can erase a link or junction.

    lstat's reparse attribute works at the Python 3.11 floor; Path.is_junction
    is newer and symlink mode alone does not detect Windows junctions. Refuse
    all reparse points, including in-scope ones, rather than guessing tag safety.
    """
    absolute = Path(path).expanduser().absolute()
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
