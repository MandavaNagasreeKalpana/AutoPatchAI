"""Benchmark manifest validation.

Sample files are read as text and parsed with ast.parse only; they are never
imported or executed.
"""

from __future__ import annotations

import copy
import json
import sys

import pytest
from pydantic import ValidationError

from autopatch.benchmark import (
    DEFAULT_BENCHMARK_DIR,
    BenchmarkError,
    check_sample_files,
    load_manifest,
)
from autopatch.models import BenchmarkManifest, VulnerabilityCategory


@pytest.fixture(scope="module")
def manifest_data():
    return json.loads((DEFAULT_BENCHMARK_DIR / "manifest.json").read_text(encoding="utf-8"))


# --- the real manifest --------------------------------------------------------


def test_real_manifest_is_valid():
    manifest = load_manifest()
    assert manifest.schema_version == 1
    assert len(manifest.samples) == 9


def test_every_category_has_at_least_three_samples():
    manifest = load_manifest()
    for category in VulnerabilityCategory:
        assert len(manifest.by_category(category)) >= 3, category


def test_real_sample_files_exist_parse_and_match_lines():
    manifest = load_manifest()
    assert check_sample_files(manifest) == []


def test_samples_are_not_imported_by_checks():
    manifest = load_manifest()
    check_sample_files(manifest)
    loaded = {getattr(m, "__file__", "") or "" for m in list(sys.modules.values())}
    assert not any("benchmarks" in f.replace("\\", "/").split("/") for f in loaded)


def test_sample_credentials_are_marked_fake():
    manifest = load_manifest()
    for sample in manifest.by_category(VulnerabilityCategory.HARDCODED_CREDENTIALS):
        text = (DEFAULT_BENCHMARK_DIR / sample.vulnerable_file).read_text(encoding="utf-8")
        assert "fake-benchmark-" in text


# --- schema validation --------------------------------------------------------


def _mutate(data, **sample_overrides):
    bad = copy.deepcopy(data)
    bad["samples"][0].update(sample_overrides)
    return bad


def test_duplicate_sample_id_rejected(manifest_data):
    bad = copy.deepcopy(manifest_data)
    bad["samples"][1]["sample_id"] = bad["samples"][0]["sample_id"]
    with pytest.raises(ValidationError, match="duplicate sample_id"):
        BenchmarkManifest.model_validate(bad)


def test_duplicate_file_rejected(manifest_data):
    bad = copy.deepcopy(manifest_data)
    bad["samples"][1]["vulnerable_file"] = bad["samples"][0]["vulnerable_file"]
    with pytest.raises(ValidationError, match="duplicate vulnerable_file"):
        BenchmarkManifest.model_validate(bad)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"category": "xss"}, "category"),
        ({"expected_vulnerability": "hardcoded_credentials"}, "must match category"),
        ({"expected_cwe": "CWE-502"}, "not mapped to category"),
        ({"expected_cwe": "89"}, "CWE id"),
        ({"expected_rule_ids": []}, "expected_rule_ids"),
        ({"expected_rule_ids": ["b608 "]}, "rule id"),
        ({"expected_lines": [0]}, "expected_lines"),
        ({"expected_lines": []}, "expected_lines"),
        ({"description": ""}, "description"),
        ({"sample_id": ""}, "sample_id"),
        ({"vulnerable_file": "../outside.py"}, "traversal"),
        ({"vulnerable_file": "/abs/app.py"}, "absolute"),
        ({"vulnerable_file": "samples/hardcoded_credentials/x/app.py"}, "must be under"),
        ({"vulnerable_file": "samples/sql_injection/sqli_001/app.txt"}, ".py"),
        ({"unexpected": 1}, "extra"),
    ],
)
def test_invalid_sample_rejected(manifest_data, overrides, message):
    with pytest.raises(ValidationError, match=message):
        BenchmarkManifest.model_validate(_mutate(manifest_data, **overrides))


def test_wrong_schema_version_rejected(manifest_data):
    with pytest.raises(ValidationError, match="schema_version"):
        BenchmarkManifest.model_validate({**manifest_data, "schema_version": 2})


def test_empty_sample_list_rejected(manifest_data):
    with pytest.raises(ValidationError, match="samples"):
        BenchmarkManifest.model_validate({**manifest_data, "samples": []})


# --- loader and file checks against a temporary benchmark --------------------


def _write_benchmark(tmp_path, manifest_data, source="x = 1\n", lines=(1,)):
    sample = copy.deepcopy(manifest_data["samples"][0])
    sample["expected_lines"] = list(lines)
    data = {**manifest_data, "samples": [sample]}
    (tmp_path / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
    target = tmp_path / sample["vulnerable_file"]
    target.parent.mkdir(parents=True)
    target.write_text(source, encoding="utf-8")
    return target


def test_missing_manifest_raises(tmp_path):
    with pytest.raises(BenchmarkError, match="not found"):
        load_manifest(tmp_path)


def test_malformed_json_raises(tmp_path):
    (tmp_path / "manifest.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(BenchmarkError, match="not valid JSON"):
        load_manifest(tmp_path)


def test_schema_error_wrapped(tmp_path):
    (tmp_path / "manifest.json").write_text('{"schema_version": 1}', encoding="utf-8")
    with pytest.raises(BenchmarkError, match="failed validation"):
        load_manifest(tmp_path)


def test_missing_sample_file_reported(tmp_path, manifest_data):
    target = _write_benchmark(tmp_path, manifest_data)
    target.unlink()
    problems = check_sample_files(load_manifest(tmp_path), tmp_path)
    assert len(problems) == 1 and "file not found" in problems[0]


def test_syntax_error_reported_without_execution(tmp_path, manifest_data):
    _write_benchmark(tmp_path, manifest_data, source="def broken(:\n")
    problems = check_sample_files(load_manifest(tmp_path), tmp_path)
    assert "syntax error" in problems[0]


def test_sample_code_is_parsed_not_executed(tmp_path, manifest_data):
    marker = tmp_path / "executed.txt"
    source = f"open({str(marker)!r}, 'w').write('ran')\n"
    _write_benchmark(tmp_path, manifest_data, source=source)
    assert check_sample_files(load_manifest(tmp_path), tmp_path) == []
    assert not marker.exists()


@pytest.mark.parametrize("line", [2, 99])
def test_blank_or_missing_expected_line_reported(tmp_path, manifest_data, line):
    _write_benchmark(tmp_path, manifest_data, source="x = 1\n\n", lines=(line,))
    problems = check_sample_files(load_manifest(tmp_path), tmp_path)
    assert f"expected line {line}" in problems[0]
