"""Find the Python files to scan, without ever leaving the project root."""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from .errors import ScanTargetError

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        ".env",
        "env",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".eggs",
        "node_modules",
        "site-packages",
        "build",
        "dist",
        "htmlcov",
    }
)


@dataclass(frozen=True)
class SkippedPath:
    path: str  # POSIX path relative to the root
    reason: str


@dataclass(frozen=True)
class DiscoveryResult:
    root: Path  # resolved absolute root
    files: tuple[Path, ...]  # resolved absolute paths, all inside root
    skipped: tuple[SkippedPath, ...]

    def relative(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()


def resolve_root(root: str | os.PathLike[str]) -> Path:
    path = Path(root)
    try:
        resolved: Path | None = path.resolve(strict=True)
    except (FileNotFoundError, OSError):
        resolved = None
    if resolved is None:  # raised outside the handler: no chained OSError
        raise ScanTargetError(f"project directory does not exist: {path}") from None
    if not resolved.is_dir():
        raise ScanTargetError(f"project path is not a directory: {path}")
    return resolved


def _normalize_patterns(patterns: Iterable[str]) -> tuple[str, ...]:
    cleaned = []
    for pattern in patterns:
        p = pattern.strip().replace("\\", "/").rstrip("/")
        while p.startswith("./"):
            p = p[2:]
        if p:
            cleaned.append(p)
    return tuple(cleaned)


def is_excluded(relative_path: str, patterns: Sequence[str]) -> bool:
    """True if the POSIX ``relative_path`` or any of its components matches a
    glob pattern (case-sensitive)."""
    parts = relative_path.split("/")
    for pattern in patterns:
        if fnmatchcase(relative_path, pattern) or any(fnmatchcase(p, pattern) for p in parts):
            return True
    return False


def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve(strict=True).is_relative_to(root)
    except (FileNotFoundError, OSError):
        return False


def discover_python_files(
    root: str | os.PathLike[str], exclude: Iterable[str] = ()
) -> DiscoveryResult:
    """Recursively list ``*.py`` files under ``root``.

    * Default generated/tool directories are always skipped.
    * ``exclude`` glob patterns match the relative path or any path component.
    * Symlinked directories are not followed. Symlinked files are skipped
      (targets inside the root are scanned directly, targets outside are
      refused). Any path that resolves outside the root (e.g. through a
      Windows junction) is refused.
    """
    base = resolve_root(root)
    patterns = _normalize_patterns(exclude)
    files: list[Path] = []
    skipped: list[SkippedPath] = []

    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        current = Path(dirpath)
        kept = []
        for name in sorted(dirnames):
            full = current / name
            rel = full.relative_to(base).as_posix()
            if name in DEFAULT_EXCLUDED_DIRS or name.endswith(".egg-info"):
                continue
            if is_excluded(rel, patterns):
                continue
            if full.is_symlink():
                skipped.append(SkippedPath(rel, "symlinked directory not followed"))
                continue
            if not _inside(full, base):
                skipped.append(SkippedPath(rel, "directory resolves outside the project root"))
                continue
            kept.append(name)
        dirnames[:] = kept

        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            full = current / name
            rel = full.relative_to(base).as_posix()
            if is_excluded(rel, patterns):
                continue
            if full.is_symlink():
                reason = (
                    "symlink to a file inside the project (target is scanned directly)"
                    if _inside(full, base)
                    else "symlink points outside the project root"
                )
                skipped.append(SkippedPath(rel, reason))
                continue
            if not _inside(full, base):
                skipped.append(SkippedPath(rel, "file resolves outside the project root"))
                continue
            if full.is_file():
                files.append(full.resolve())

    files.sort(key=lambda p: p.relative_to(base).as_posix())
    skipped.sort(key=lambda s: s.path)
    return DiscoveryResult(root=base, files=tuple(files), skipped=tuple(skipped))
