#!/usr/bin/env python3
"""Deterministic stdlib-only source archive builder for hermetic plugin releases.

Usage:
    python scripts/build-source-archive.py [SOURCE_DIR] [--output DIR]

Produces a reproducible .zip (fixed timestamps, sorted entries, no absolute
paths) plus a SHA-256 manifest of every included source file.  Fails hard on
secret-like, binary, bytecode or archive payloads found within the include
set.  Refuses to write inside the source tree or inside an evidence directory.

Designed for PYTHONDONTWRITEBYTECODE=1 environments; bytecode is always
rejected regardless of setting.
"""

import argparse
import hashlib
import json
import os
import stat
import struct
import sys
import zipfile
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hackathon_judge import __version__
from hackathon_judge.paths import guarded_path, read_regular


# ---------------------------------------------------------------------------
# Inclusion / exclusion rules
# ---------------------------------------------------------------------------

# Files matching these root-relative patterns are explicitly INCLUDED.
# Ordinary wildcards match one component; ** matches zero or more directories.
INCLUDE_PATTERNS = (
    # Root metadata files
    "plugin.yaml",
    "__init__.py",
    "requirements-test.txt",
    "LICENSE",
    ".gitignore",
    ".gitattributes",
    "README.md",
    "PLAN.md",
    # Python package
    "hackathon_judge/*.py",
    "hackathon_judge/**/*.py",
    "hackathon_judge/*.json",
    # Sources (rule captures)
    "sources/*.md",
    "sources/*.json",
    # Skill definition
    "skills/judge-plugin/SKILL.md",
    # Tests (always included for transparency)
    "tests/*.py",
    # Release tooling
    "scripts/*.py",
    "scripts/*.sh",
    "docs/*",
    ".github/workflows/*",
    "submission/*",
)

# Directory subtrees that are ALWAYS excluded from crawling (even if a parent
# matched).  These are safe: generated cache, virtual envs, evidence, git.
EXCLUDE_DIRS = frozenset({
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    "node_modules",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".coverage_cache",
    "evidence",
})

SENSITIVE_DIRS = frozenset({'.ssh', '.aws', '.gnupg', '.codex', '.kube'})

# Secret-like filenames — inclusion of any of these is a HARD REJECT that
# fails the build.
SECRET_FILENAMES = frozenset({
    ".env",
    "auth.json",
    "credentials.json",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_ed448",
    "id_dsa",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".dockercfg",
    ".git-credentials",
})

SECRET_SUFFIXES = frozenset({
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".kdbx",
    ".kdb",
    ".ovpn",
    ".age",
    ".gpg",
})

# Bytecode / compiled-python suffixes — rejected wherever found.
BYTECODE_SUFFIXES = frozenset({".pyc", ".pyo", ".pyd"})

# Magic bytes for executable binaries, shared libraries, and archives.
# These are rejected inside the include set.
BINARY_MAGICS = {
    # ELF (Linux executables / shared libs)
    b"\x7fELF",
    # Mach-O (macOS)
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    # PE / MZ (Windows)
    b"MZ",
    # WebAssembly
    b"\x00asm",
    # Java / Dalvik
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}

ARCHIVE_MAGICS = {
    b"PK\x03\x04",       # zip / jar / docx / …
    b"\x1f\x8b",         # gzip
    b"BZh",              # bzip2
    b"\xfd7zXZ\x00",     # XZ
    b"7z\xbc\xaf\x27\x1c",  # 7-zip
    b"Rar!",             # RAR
}

# tar archives are detected by ustar signature at offset 257
USTAR_MAGIC = b"ustar"


class RejectedFile(ValueError):
    """Raised when a file matches a rejection rule during include scanning."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_magic(raw: bytes) -> str | None:
    """Return a description string if *raw* begins with a rejected magic, else None."""
    for magic in BINARY_MAGICS:
        if raw.startswith(magic):
            return f"executable binary magic {magic!r}"
    for magic in ARCHIVE_MAGICS:
        if raw.startswith(magic):
            return f"archive magic {magic!r}"
    if len(raw) > 262 and raw[257:262] == USTAR_MAGIC:
        return "ustar (tar) archive magic"
    return None


def _load_gitignore(source_root: Path) -> list[str]:
    """Return .gitignore patterns, if present."""
    gi = source_root / ".gitignore"
    if gi.is_file():
        return [line.strip() for line in gi.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")]
    return []


def _iter_included(source_root: Path) -> list[tuple[str, Path, bool]]:
    """Inventory before filtering: unknown paths must not hide unsafe inputs."""
    for component in (source_root, *source_root.parents):
        if component.name.casefold() in SENSITIVE_DIRS:
            raise RejectedFile('REJECTED: credential-store source path')
        _reject_secret(component.name, component.name)
    source_root = guarded_path(source_root)
    results: list[tuple[str, Path, bool]] = []
    def walk_error(error):
        raise RejectedFile('REJECTED: unreadable source directory')
    directory_count = 1
    for directory, dirs, files in os.walk(source_root, followlinks=False, onerror=walk_error):
        directory_count += len(dirs)
        if directory_count > 10000:
            raise RejectedFile('REJECTED: directory budget exceeded')
        kept = []
        for name in sorted(dirs):
            path = Path(directory) / name
            try:
                guarded_path(path, root=source_root)
            except (OSError, ValueError) as exc:
                raise RejectedFile('REJECTED: unsafe source directory') from exc
            if name.casefold() in SENSITIVE_DIRS:
                raise RejectedFile('REJECTED: credential-store directory')
            _reject_secret(path.relative_to(source_root).as_posix(), name)
            if name not in EXCLUDE_DIRS:
                kept.append(name)
        dirs[:] = kept
        for name in sorted(files):
            path = Path(directory) / name
            try:
                guarded_path(path, root=source_root)
            except (OSError, ValueError) as exc:
                raise RejectedFile('REJECTED: unsafe source file') from exc
            if not stat.S_ISREG(path.lstat().st_mode):
                raise RejectedFile('REJECTED: non-regular source file')
            results.append((path.relative_to(source_root).as_posix(), path, False))
            if len(results) > 10000:
                raise RejectedFile('REJECTED: file-count budget exceeded')
    return sorted(results)


def _included(rel):
    """Match the entire root-relative POSIX path, never a trailing lookalike."""
    def matches(parts, pattern):
        if not pattern:
            return not parts
        if pattern[0] == '**':
            return any(matches(parts[index:], pattern[1:])
                       for index in range(len(parts) + 1))
        return (bool(parts) and fnmatchcase(parts[0], pattern[0])
                and matches(parts[1:], pattern[1:]))

    return any(matches(rel.split('/'), pattern.split('/'))
               for pattern in INCLUDE_PATTERNS)


# ---------------------------------------------------------------------------
# File validation
# ---------------------------------------------------------------------------

def _reject_secret(rel: str, name: str) -> None:
    """Raise RejectedFile if *name* looks like a secret file."""
    comparison = name.casefold()
    if comparison in SECRET_FILENAMES or comparison.startswith('.env.'):
        raise RejectedFile(f"REJECTED: {rel} matches secret filename {name!r}")
    if any(comparison.endswith(suf) for suf in SECRET_SUFFIXES):
        raise RejectedFile(f"REJECTED: {rel} has secret suffix")


def _reject_bytecode(rel: str, name: str) -> None:
    """Raise RejectedFile if *name* is Python bytecode."""
    if any(name.endswith(suf) for suf in BYTECODE_SUFFIXES):
        raise RejectedFile(f"REJECTED: {rel} is compiled Python bytecode ({name})")


def _reject_binary_or_archive(rel: str, raw: bytes) -> None:
    """Raise RejectedFile if *raw* starts with a rejected binary or archive magic."""
    reason = _check_magic(raw)
    if reason:
        raise RejectedFile(f"REJECTED: {rel} — {reason}")


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_archive(
    source_root: Path,
    output_dir: Path,
    *,
    verbose: bool = False,
) -> dict:
    """Build the deterministic source archive and return a result dict.

    Returns:
        {
            "ok": bool,
            "archive": "path/to/output.zip",
            "manifest": "path/to/manifest.json",
            "files_included": N,
            "total_bytes": N,
            "rejected": [str, ...],
            "changed_during_build": [str, ...],
        }
    """
    # ── Gather included files ──────────────────────────────────────────
    try:
        source_root = guarded_path(source_root)
        if not source_root.is_dir():
            return {"ok": False, "error": "Source root is not a directory"}
        included = _iter_included(source_root)
    except (OSError, ValueError) as exc:
        return {'ok': False, 'error': str(exc)}

    # Collect warnings / rejections
    rejects: list[str] = []
    valid: list[tuple[str, Path]] = []  # (rel, abs_path)
    change_fingerprints: dict[str, str] = {}  # rel → sha256 before packaging
    snapshot = {}
    total_read = 0

    for rel, fpath, excluded in included:
        name = fpath.name
        rel_for_error = rel

        # Reject secrets (even in excluded dirs — they must not appear)
        try:
            _reject_secret(rel_for_error, name)
        except RejectedFile as e:
            rejects.append(str(e))
            continue

        # Reject bytecode at any path
        try:
            _reject_bytecode(rel_for_error, name)
        except RejectedFile as e:
            rejects.append(str(e))
            continue

        # If inside an excluded dir, skip (don't reject)
        if excluded:
            continue

        # Read and validate content
        try:
            raw = read_regular(fpath, root=source_root, max_bytes=2_000_000,
                               remaining_bytes=32_000_000 - total_read)
            total_read += len(raw)
        except (OSError, ValueError) as e:
            rejects.append(f"CANNOT_READ: {rel_for_error} — {e}")
            continue

        # Reject binary/archive content
        try:
            _reject_binary_or_archive(rel_for_error, raw)
        except RejectedFile as e:
            rejects.append(str(e))
            continue

        change_fingerprints[rel] = hashlib.sha256(raw).hexdigest()
        if _included(rel):
            snapshot[rel] = raw
            valid.append((rel, fpath))

    # ── Bail on rejections ─────────────────────────────────────────────
    error_count = len(rejects)
    if error_count:
        for r in rejects:
            print(r, file=sys.stderr)
        print(f"\nERROR: {error_count} file(s) rejected; archive not built.",
              file=sys.stderr)
        return {"ok": False, "rejected": rejects}

    if not valid:
        return {"ok": False, "error": "No files matched the include rules"}

    # ── Prepare archive output path ────────────────────────────────────
    output_dir = output_dir.resolve()
    # Refuse to write inside source tree
    if output_dir == source_root or output_dir.is_relative_to(source_root):
        return {"ok": False, "error": f"Output directory {output_dir} is inside the source tree"}

    # Refuse to write inside any evidence directory
    parents_list = list(output_dir.parents) + [output_dir]
    if any(p.name == "evidence" for p in parents_list):
        return {"ok": False, "error": f"Output directory {output_dir} is inside an evidence directory"}

    output_dir.mkdir(parents=True, exist_ok=True)

    archive_path = output_dir / "hackathon-judge-source.zip"
    manifest_path = output_dir / "hackathon-judge-manifest.json"
    if archive_path.exists() or manifest_path.exists():
        return {'ok': False, 'error': 'Refusing to overwrite an existing archive or manifest'}

    # ── Build deterministic ZIP ────────────────────────────────────────
    # Deterministic fixed timestamp (zipinfo epoch, no timezone ambiguity).
    FIXED_MTIME = (2026, 1, 1, 0, 0, 0)  # (y, m, d, H, M, S) UTC

    manifest_entries: list[dict] = []

    with zipfile.ZipFile(archive_path, "x", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel, fpath in valid:
            raw = snapshot[rel]
            info = zipfile.ZipInfo(
                filename=rel,
                date_time=FIXED_MTIME,
            )
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = ((0o755 if rel.endswith('.sh') else 0o644) << 16)
            # No extra attributes, no comment — fully deterministic
            zf.writestr(info, raw)

            sha = hashlib.sha256(raw).hexdigest()
            manifest_entries.append({
                "path": rel,
                "bytes": len(raw),
                "sha256": sha,
            })

    # ── Change detection: re-check source tree ─────────────────────────
    changed: list[str] = []
    try:
        current_files = _iter_included(source_root)
    except (OSError, ValueError):
        return {'ok': False, 'error': 'Source became unsafe or inaccessible during packaging'}
    changed.extend(sorted(set(change_fingerprints) ^ {rel for rel, _, _ in current_files}))
    for rel, fpath, _ in current_files:
        try:
            raw = read_regular(fpath, root=source_root, max_bytes=2_000_000)
            current = hashlib.sha256(raw).hexdigest()
        except (OSError, ValueError):
            current = ""
        original = change_fingerprints.get(rel, "")
        if current != original:
            changed.append(rel)

    changed = sorted(set(changed))
    if changed:
        for c in changed:
            print(f"SOURCE_CHANGED: {c}", file=sys.stderr)
        print(f"\nERROR: {len(changed)} source file(s) changed during packaging.",
              file=sys.stderr)
        # Retain failed artifacts as evidence; never label them qualified.
        return {"ok": False, "changed_during_build": changed, "rejected": rejects}

    # ── Build manifest ─────────────────────────────────────────────────
    total_bytes = sum(e["bytes"] for e in manifest_entries)

    manifest = {
        "tool": "scripts/build-source-archive.py",
        "version": __version__,

        "archive": archive_path.name,
        "files_included": len(manifest_entries),
        "total_bytes": total_bytes,
        "files": manifest_entries,
        "tree_sha256": _tree_digest(manifest_entries),
        "warnings": [],
    }

    with manifest_path.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n')

    # Verify archive is readable
    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            if zf.testzip() is not None:
                return {'ok': False, 'error': 'Archive member verification failed'}
            if any(hashlib.sha256(zf.read(item['path'])).hexdigest() != item['sha256'] for item in manifest_entries):
                return {'ok': False, 'error': 'Archive member hash mismatch'}
    except zipfile.BadZipFile as e:
        return {"ok": False, "error": f"Archive verification failed: {e}"}

    return {
        "ok": True,
        "archive": str(archive_path),
        "manifest": str(manifest_path),
        "files_included": len(manifest_entries),
        "total_bytes": total_bytes,
        "rejected": rejects,
    }


def _tree_digest(entries: list[dict]) -> str:
    """Compute a SHA-256 over the sorted (path, hash) pairs."""
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda e: e["path"]):
        digest.update(entry["path"].encode() + b"\0" + entry["sha256"].encode() + b"\n")
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a deterministic source-only archive of a Hermes plugin.",
    )
    parser.add_argument(
        "source",
        nargs="?",
        default=".",
        help="Source root directory (default: current dir)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output directory (default: parent of source root named "
             "<source>-source-archive)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print detailed progress",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    source_root = Path(args.source).expanduser().absolute()

    output_dir: Path
    if args.output:
        output_dir = Path(args.output).expanduser().resolve()
    else:
        # Default: sibling directory named "<source-dir>-source-archive"
        output_dir = source_root.parent / (source_root.name + "-source-archive")

    result = build_archive(source_root, output_dir, verbose=args.verbose)

    if not result.get("ok"):
        print(f"\nBuild FAILED.", file=sys.stderr)
        if "error" in result:
            print(f"  {result['error']}", file=sys.stderr)
        return 1

    print(f"Archive:     {result['archive']}")
    print(f"Manifest:    {result['manifest']}")
    print(f"Files:       {result['files_included']}")
    print(f"Total bytes: {result['total_bytes']}")
    if result.get("rejected"):
        print(f"Rejected:    {len(result['rejected'])} file(s)")
    print("\nBuild OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())