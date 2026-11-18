"""`autopatch scan` CLI behaviour (real Bandit, read-only)."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from autopatch import cli
from autopatch.benchmark import DEFAULT_BENCHMARK_DIR
from autopatch.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from autopatch.models import ScanResult
from autopatch.scanner import BanditNotInstalledError


def test_scan_benchmark_writes_valid_report(tmp_path, capsys):
    output = tmp_path / "reports" / "findings.json"
    code = main(["scan", str(DEFAULT_BENCHMARK_DIR), "--output", str(output)])
    out = capsys.readouterr().out

    assert code == EXIT_OK
    assert "Supported findings: 9" in out
    assert "B403 x1" in out
    assert "Result: 9 supported finding(s)." in out
    result = ScanResult.model_validate_json(output.read_text(encoding="utf-8"))
    assert len(result.findings) == 9
    assert "fake-benchmark-" not in output.read_text(encoding="utf-8")


def test_fail_on_findings_exit_code(capsys):
    assert main(["scan", str(DEFAULT_BENCHMARK_DIR), "--fail-on-findings"]) == EXIT_FINDINGS


def test_zero_findings_is_success(tmp_path, capsys):
    (tmp_path / "safe.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    code = main(["scan", str(tmp_path), "--fail-on-findings"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "Supported findings: 0" in out
    assert "no supported vulnerabilities found" in out


def test_missing_directory_is_operational_error(tmp_path, capsys):
    code = main(["scan", str(tmp_path / "missing")])
    assert code == EXIT_ERROR
    assert "scan failed" in capsys.readouterr().err


def test_missing_bandit_is_operational_error(tmp_path, monkeypatch, capsys):
    def no_bandit(files, *, ignore_nosec=False):
        raise BanditNotInstalledError("Bandit is not installed in this environment.")

    real_agent = cli.ScannerAgent
    monkeypatch.setattr(cli, "ScannerAgent", lambda **kw: real_agent(runner=no_bandit, **kw))
    code = main(["scan", str(tmp_path)])
    assert code == EXIT_ERROR
    assert "Bandit is not installed" in capsys.readouterr().err


def test_malformed_results_are_operational_error(tmp_path, monkeypatch, capsys):
    from autopatch.scanner.bandit_runner import BanditRun

    def bad_runner(files, *, ignore_nosec=False):
        return BanditRun(version="x", malformed=("malformed Bandit result ignored: bad",))

    real_agent = cli.ScannerAgent
    monkeypatch.setattr(cli, "ScannerAgent", lambda **kw: real_agent(runner=bad_runner, **kw))
    assert main(["scan", str(tmp_path)]) == EXIT_ERROR
    assert "malformed" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["report.txt", "report"])
def test_output_must_be_json(tmp_path, capsys, name):
    assert main(["scan", str(tmp_path), "--output", str(tmp_path / name)]) == EXIT_ERROR
    assert ".json" in capsys.readouterr().err


def test_output_cannot_overwrite_scanned_source(tmp_path, capsys):
    src = tmp_path / "data.json.py"
    src.write_text("x = 1\n", encoding="utf-8")
    target = tmp_path / "pkg" / "mod.py"
    target.parent.mkdir()
    target.write_text("y = 2\n", encoding="utf-8")
    # A .py target is refused by the extension rule before anything is written.
    assert main(["scan", str(tmp_path), "--output", str(target)]) == EXIT_ERROR
    assert target.read_text(encoding="utf-8") == "y = 2\n"


def test_exclude_option(tmp_path, capsys):
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "old.py").write_text("import pickle\npickle.loads(b'')\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--exclude", "legacy", "--fail-on-findings"]) == EXIT_OK


def test_console_script_module_entry(tmp_path):
    output = tmp_path / "out.json"
    proc = subprocess.run(
        [sys.executable, "-m", "autopatch.cli", "scan", str(DEFAULT_BENCHMARK_DIR), "-o", str(output)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == EXIT_OK, proc.stderr
    assert json.loads(output.read_text(encoding="utf-8"))["scanner"] == "bandit"
