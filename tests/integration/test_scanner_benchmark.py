"""Real Bandit against the intentionally vulnerable benchmark fixtures.

The fixtures are only read and parsed (by Bandit and ast). They are never
imported or executed. These tests also check that scanning is read-only.
"""

from __future__ import annotations

import builtins
import hashlib
import io
import sys
from pathlib import Path

import pytest

from autopatch.benchmark import DEFAULT_BENCHMARK_DIR, compare_scan_to_manifest, load_manifest
from autopatch.scanner import ScannerAgent

MANIFEST = load_manifest()


def snapshot(root: Path) -> dict[str, tuple[str, int]]:
    return {
        p.relative_to(root).as_posix(): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


@pytest.fixture(scope="module")
def scan_run():
    """Scan once, recording file state and every open() mode used."""
    before = snapshot(DEFAULT_BENCHMARK_DIR)
    opened: list[tuple[str, str]] = []
    real_open = builtins.open

    def recording_open(file, mode="r", *args, **kwargs):
        opened.append((str(file), mode))
        return real_open(file, mode, *args, **kwargs)

    mp = pytest.MonkeyPatch()
    mp.setattr(builtins, "open", recording_open)
    mp.setattr(io, "open", recording_open)
    try:
        result = ScannerAgent().scan(DEFAULT_BENCHMARK_DIR)
    finally:
        mp.undo()
    after = snapshot(DEFAULT_BENCHMARK_DIR)
    return result, before, after, opened


def test_all_nine_samples_scanned(scan_run):
    result = scan_run[0]
    assert result.ok, result.errors
    assert sorted(result.files_scanned) == sorted(s.vulnerable_file for s in MANIFEST.samples)
    assert len(result.files_scanned) == 9
    assert result.skipped_files == []


@pytest.mark.parametrize("sample", MANIFEST.samples, ids=lambda s: s.sample_id)
def test_sample_detected_as_expected(scan_run, sample):
    outcomes, _ = compare_scan_to_manifest(MANIFEST, scan_run[0])
    outcome = next(o for o in outcomes if o.sample.sample_id == sample.sample_id)
    assert outcome.detected, f"missing expected line(s) {outcome.missing_lines}"
    assert outcome.unexpected == ()
    [finding] = outcome.matched
    assert finding.category is sample.category
    assert finding.rule_id in sample.expected_rule_ids
    assert finding.line in sample.expected_lines
    assert finding.ast_context is not None


def test_no_findings_outside_manifest(scan_run):
    _, extras = compare_scan_to_manifest(MANIFEST, scan_run[0])
    assert extras == []


def test_b403_reported_as_related_only(scan_run):
    result = scan_run[0]
    assert [(f.rule_id, f.file_path, f.line) for f in result.related_findings] == [
        ("B403", "samples/insecure_deserialization/deser_001/app.py", 6)
    ]
    assert all(f.rule_id != "B403" for f in result.findings)


def test_no_unsupported_rules_fired(scan_run):
    assert scan_run[0].ignored_issues == []


def test_credentials_never_appear_in_results(scan_run):
    assert "fake-benchmark-" not in scan_run[0].model_dump_json()


def test_scan_is_read_only(scan_run):
    _, before, after, opened = scan_run
    assert before == after  # same files, same content hashes, same mtimes
    write_modes = [(f, m) for f, m in opened if any(c in m for c in "wax+")]
    assert write_modes == []
    assert not list(DEFAULT_BENCHMARK_DIR.rglob("__pycache__"))


def test_samples_are_never_imported(scan_run):
    sample_files = {str((DEFAULT_BENCHMARK_DIR / s.vulnerable_file).resolve()) for s in MANIFEST.samples}
    loaded = {str(Path(m.__file__).resolve()) for m in list(sys.modules.values()) if getattr(m, "__file__", None)}
    assert not sample_files & loaded


def test_top_level_code_is_never_executed(tmp_path):
    """A file whose import would create a marker is scanned but never run."""
    marker = tmp_path / "executed.txt"
    project = tmp_path / "proj"
    project.mkdir()
    (project / "evil.py").write_text(
        "import pickle\n"
        f"open({str(marker)!r}, 'w').write('ran')\n"
        "data = pickle.loads(b'')\n",
        encoding="utf-8",
    )
    result = ScannerAgent().scan(project)
    assert [f.rule_id for f in result.findings] == ["B301"]
    assert not marker.exists()
