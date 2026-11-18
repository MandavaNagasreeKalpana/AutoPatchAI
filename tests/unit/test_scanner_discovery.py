"""File discovery: recursion, exclusions, and root containment."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from autopatch.scanner import ScanTargetError, discover_python_files
from autopatch.scanner.file_discovery import is_excluded


def touch(root: Path, rel: str, text: str = "x = 1\n") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def rels(result) -> list[str]:
    return [result.relative(f) for f in result.files]


def try_symlink(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks not available on this system: {exc}")


def test_discovers_python_files_recursively(tmp_path):
    touch(tmp_path, "main.py")
    touch(tmp_path, "pkg/__init__.py")
    touch(tmp_path, "pkg/sub/mod.py")
    touch(tmp_path, "README.md")
    touch(tmp_path, "script.pyc")

    result = discover_python_files(tmp_path)

    assert rels(result) == ["main.py", "pkg/__init__.py", "pkg/sub/mod.py"]
    assert all(f.is_absolute() and f.is_relative_to(result.root) for f in result.files)


@pytest.mark.parametrize(
    "excluded_dir",
    [".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", "node_modules",
     "build", "dist", "site-packages", "mypkg.egg-info", ".tox"],
)
def test_default_generated_directories_ignored(tmp_path, excluded_dir):
    touch(tmp_path, "app.py")
    touch(tmp_path, f"{excluded_dir}/hidden.py")
    touch(tmp_path, f"src/{excluded_dir}/nested.py")

    assert rels(discover_python_files(tmp_path)) == ["app.py"]


def test_custom_exclusions(tmp_path):
    touch(tmp_path, "app.py")
    touch(tmp_path, "tests/test_app.py")
    touch(tmp_path, "legacy/old.py")
    touch(tmp_path, "src/generated_pb2.py")
    touch(tmp_path, "src/keep.py")

    result = discover_python_files(tmp_path, exclude=["tests", "legacy/*", "*_pb2.py"])

    assert rels(result) == ["app.py", "src/keep.py"]


def test_exclusion_patterns_are_normalized(tmp_path):
    touch(tmp_path, "a/b/c.py")
    touch(tmp_path, "keep.py")
    assert rels(discover_python_files(tmp_path, exclude=[".\\a\\"])) == ["keep.py"]


@pytest.mark.parametrize(
    ("path", "patterns", "expected"),
    [
        ("tests/test_x.py", ["tests"], True),
        ("src/tests/test_x.py", ["tests"], True),
        ("src/app.py", ["tests"], False),
        ("src/app.py", ["src/*"], True),
        ("Src/app.py", ["src"], False),  # case-sensitive
    ],
)
def test_is_excluded(path, patterns, expected):
    assert is_excluded(path, patterns) is expected


def test_missing_root_rejected(tmp_path):
    with pytest.raises(ScanTargetError, match="does not exist"):
        discover_python_files(tmp_path / "nope")


def test_file_as_root_rejected(tmp_path):
    with pytest.raises(ScanTargetError, match="not a directory"):
        discover_python_files(touch(tmp_path, "single.py"))


def test_empty_project(tmp_path):
    result = discover_python_files(tmp_path)
    assert result.files == () and result.skipped == ()


def test_relative_root_resolves(tmp_path, monkeypatch):
    touch(tmp_path, "proj/app.py")
    monkeypatch.chdir(tmp_path)
    result = discover_python_files("proj")
    assert result.root == (tmp_path / "proj").resolve()
    assert rels(result) == ["app.py"]


def test_symlinked_file_outside_root_refused(tmp_path):
    outside = touch(tmp_path, "outside/secret.py")
    project = tmp_path / "project"
    touch(project, "app.py")
    try_symlink(project / "link.py", outside)

    result = discover_python_files(project)

    assert rels(result) == ["app.py"]
    assert [(s.path, s.reason) for s in result.skipped] == [
        ("link.py", "symlink points outside the project root")
    ]


def test_symlinked_directory_not_followed(tmp_path):
    outside = tmp_path / "outside"
    touch(outside, "evil.py")
    project = tmp_path / "project"
    touch(project, "app.py")
    try_symlink(project / "linked_dir", outside, directory=True)

    result = discover_python_files(project)

    assert rels(result) == ["app.py"]
    assert result.skipped[0].path == "linked_dir"
    assert "not followed" in result.skipped[0].reason


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junctions only")
def test_windows_junction_outside_root_refused(tmp_path):
    """Junctions need no special privilege, so this runs on every Windows box."""
    import _winapi

    outside = tmp_path / "outside"
    touch(outside, "evil.py")
    project = tmp_path / "project"
    touch(project, "app.py")
    _winapi.CreateJunction(str(outside), str(project / "junction_dir"))

    result = discover_python_files(project)

    assert rels(result) == ["app.py"]
    assert [s.path for s in result.skipped] == ["junction_dir"]
    assert "outside the project root" in result.skipped[0].reason


def test_file_resolving_outside_root_refused(tmp_path, monkeypatch):
    """Simulates a link that resolves outside the root (platform-independent)."""
    from autopatch.scanner import file_discovery

    touch(tmp_path, "app.py")
    touch(tmp_path, "escape.py")
    real_inside = file_discovery._inside
    monkeypatch.setattr(
        file_discovery, "_inside", lambda p, root: p.name != "escape.py" and real_inside(p, root)
    )

    result = discover_python_files(tmp_path)

    assert rels(result) == ["app.py"]
    assert [(s.path, s.reason) for s in result.skipped] == [
        ("escape.py", "file resolves outside the project root")
    ]


def test_symlink_inside_root_not_scanned_twice(tmp_path):
    target = touch(tmp_path, "real.py")
    try_symlink(tmp_path / "alias.py", target)

    result = discover_python_files(tmp_path)

    assert rels(result) == ["real.py"]
    assert "inside the project" in result.skipped[0].reason
