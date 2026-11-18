"""Load and check the benchmark manifest.

Sample files are intentionally vulnerable. This module only reads them as
text and parses them with :func:`ast.parse` (which builds a syntax tree and
does not run code). It never imports, compiles to bytecode or executes them.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from pydantic import ValidationError

from .models.benchmark import BenchmarkManifest

DEFAULT_BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks"
MANIFEST_NAME = "manifest.json"


class BenchmarkError(ValueError):
    """Raised when the manifest or a sample file is invalid."""


def load_manifest(benchmark_dir: Path = DEFAULT_BENCHMARK_DIR) -> BenchmarkManifest:
    """Parse and schema-validate ``manifest.json`` (no sample files are read)."""
    path = Path(benchmark_dir) / MANIFEST_NAME
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise BenchmarkError(f"manifest not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise BenchmarkError(f"manifest is not valid JSON: {exc}") from None
    try:
        return BenchmarkManifest.model_validate(data)
    except ValidationError as exc:
        raise BenchmarkError(f"manifest failed validation:\n{exc}") from None


def check_sample_files(
    manifest: BenchmarkManifest, benchmark_dir: Path = DEFAULT_BENCHMARK_DIR
) -> list[str]:
    """Return a list of problems with the sample files (empty when all good).

    Checks that each file exists, stays inside ``benchmark_dir`` after
    resolving symlinks, is valid Python syntax, and that every expected line
    exists and is not blank.
    """
    root = Path(benchmark_dir).resolve()
    problems: list[str] = []
    for sample in manifest.samples:
        path = (root / sample.vulnerable_file).resolve()
        label = f"{sample.sample_id} ({sample.vulnerable_file})"
        if not path.is_relative_to(root):
            problems.append(f"{label}: resolves outside the benchmark directory")
            continue
        if not path.is_file():
            problems.append(f"{label}: file not found")
            continue
        source = path.read_text(encoding="utf-8")
        try:
            ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            problems.append(f"{label}: syntax error at line {exc.lineno}")
            continue
        lines = source.splitlines()
        for line_no in sample.expected_lines:
            if line_no > len(lines) or not lines[line_no - 1].strip():
                problems.append(f"{label}: expected line {line_no} is missing or blank")
    return problems
