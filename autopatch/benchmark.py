"""Load and check the benchmark manifest.

Sample files are intentionally vulnerable. This module only reads them as
text and parses them with :func:`ast.parse` (which builds a syntax tree and
does not run code). It never imports, compiles to bytecode or executes them.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from .models.benchmark import BenchmarkManifest, BenchmarkSample
from .models.finding import Finding
from .models.scan import ScanResult

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


@dataclass(frozen=True)
class SampleOutcome:
    """How a scan performed on one benchmark sample."""

    sample: BenchmarkSample
    matched: tuple[Finding, ...]  # findings satisfying an expectation
    missing_lines: tuple[int, ...]  # expected lines with no matching finding
    unexpected: tuple[Finding, ...]  # other supported findings in the same file
    related: tuple[Finding, ...]  # informational findings (e.g. B403) in the file

    @property
    def detected(self) -> bool:
        return not self.missing_lines


def _matches(finding: Finding, sample: BenchmarkSample, line: int) -> bool:
    return (
        finding.category is sample.category
        and finding.rule_id in sample.expected_rule_ids
        and finding.line <= line <= (finding.end_line or finding.line)
    )


def compare_scan_to_manifest(
    manifest: BenchmarkManifest, scan: ScanResult
) -> tuple[list[SampleOutcome], list[Finding]]:
    """Compare a scan of the benchmark directory with the manifest.

    The scan must have been run with the benchmark directory as its root, so
    finding paths line up with ``vulnerable_file``. Returns per-sample
    outcomes plus supported findings in files the manifest does not list.
    """
    outcomes = []
    for sample in manifest.samples:
        in_file = [f for f in scan.findings if f.file_path == sample.vulnerable_file]
        matched = [f for f in in_file if any(_matches(f, sample, n) for n in sample.expected_lines)]
        missing = [n for n in sample.expected_lines if not any(_matches(f, sample, n) for f in in_file)]
        outcomes.append(
            SampleOutcome(
                sample=sample,
                matched=tuple(matched),
                missing_lines=tuple(missing),
                unexpected=tuple(f for f in in_file if f not in matched),
                related=tuple(
                    f for f in scan.related_findings if f.file_path == sample.vulnerable_file
                ),
            )
        )
    listed = {s.vulnerable_file for s in manifest.samples}
    extras = [f for f in scan.findings if f.file_path not in listed]
    return outcomes, extras
