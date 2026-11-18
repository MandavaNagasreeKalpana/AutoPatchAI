"""Bandit result parsing, missing-Bandit handling, and secret-safe errors."""

from __future__ import annotations

import sys

import pytest

from autopatch.scanner import BanditExecutionError, BanditNotInstalledError
from autopatch.scanner.bandit_runner import parse_issue, run_bandit
from autopatch.scanner.errors import MalformedBanditResultError, redact_secrets, safe_error_message

FAKE_SECRET = "s3cr3t-value-FOR-TESTS-0123456789"


def valid_issue(**overrides):
    data = {
        "filename": "/proj/app.py",
        "test_name": "hardcoded_sql_expressions",
        "test_id": "B608",
        "issue_severity": "MEDIUM",
        "issue_confidence": "LOW",
        "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"},
        "issue_text": "Possible SQL injection vector.",
        "line_number": 10,
        "line_range": [10, 11],
        "col_offset": 4,
        "end_col_offset": 20,
    }
    data.update(overrides)
    return data


# --- parsing ---------------------------------------------------------------


def test_parse_valid_issue():
    issue = parse_issue(valid_issue())
    assert issue.test_id == "B608"
    assert issue.severity == "MEDIUM"
    assert issue.confidence == "LOW"
    assert issue.line == 10 and issue.end_line == 11
    assert issue.cwe_id == 89
    assert issue.col_offset == 4


def test_parse_normalizes_case_and_defaults_range():
    issue = parse_issue(valid_issue(issue_severity="high", line_range=[]))
    assert issue.severity == "HIGH"
    assert issue.line_range == (10,) and issue.end_line == 10


def test_parse_tolerates_missing_optional_fields():
    data = valid_issue()
    for key in ("issue_cwe", "col_offset", "end_col_offset", "test_name", "line_range"):
        del data[key]
    issue = parse_issue(data)
    assert issue.cwe_id is None and issue.col_offset == 0


@pytest.mark.parametrize(
    "data",
    [
        "not a mapping",
        {k: v for k, v in valid_issue().items() if k != "test_id"},
        {k: v for k, v in valid_issue().items() if k != "line_number"},
        valid_issue(test_id="X608"),
        valid_issue(test_id="B60"),
        valid_issue(issue_severity="EXTREME"),
        valid_issue(issue_confidence=3),
        valid_issue(line_number=0),
        valid_issue(line_number="10"),
        valid_issue(line_number=True),
        valid_issue(line_range=[10, "x"]),
        valid_issue(line_range="10"),
        valid_issue(filename="  "),
        valid_issue(filename=None),
    ],
)
def test_parse_rejects_malformed(data):
    with pytest.raises(MalformedBanditResultError):
        parse_issue(data)


# --- missing Bandit ----------------------------------------------------------


@pytest.fixture
def no_bandit(monkeypatch):
    for name in ("bandit", "bandit.core", "bandit.core.manager", "bandit.core.config"):
        monkeypatch.setitem(sys.modules, name, None)


def test_missing_bandit_raises_clear_error(no_bandit, tmp_path):
    with pytest.raises(BanditNotInstalledError, match="uv sync"):
        run_bandit([tmp_path / "x.py"])


# --- real Bandit (safe inputs) ---------------------------------------------


def test_run_bandit_empty_file_list_returns_version():
    run = run_bandit([])
    assert run.version and run.issues == ()


def test_run_bandit_reports_absolute_filenames(tmp_path):
    target = tmp_path / "q.py"
    target.write_text('def f(c, x):\n    c.execute("SELECT * FROM t WHERE a = %s" % x)\n', encoding="utf-8")
    run = run_bandit([target])
    assert [(i.test_id, i.line) for i in run.issues] == [("B608", 2)]
    assert run.issues[0].filename == str(target)


def test_run_bandit_records_syntax_errors_as_skipped(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("def broken(:\n", encoding="utf-8")
    run = run_bandit([bad])
    assert run.issues == ()
    assert run.skipped[0][0] == str(bad)
    assert "syntax error" in run.skipped[0][1]


def test_malformed_results_are_collected_not_raised(monkeypatch, tmp_path):
    from bandit.core import manager

    def fake_run_tests(self):
        self.results = [{"test_id": "nope"}, valid_issue(filename=str(tmp_path / "a.py"))]

    monkeypatch.setattr(manager.BanditManager, "run_tests", fake_run_tests)
    run = run_bandit([tmp_path / "a.py"])
    assert len(run.issues) == 1
    assert len(run.malformed) == 1 and "malformed" in run.malformed[0]


def test_bandit_crash_is_wrapped_without_leaking_secrets(monkeypatch, tmp_path):
    from bandit.core import manager

    monkeypatch.setenv("SOME_SERVICE_API_KEY", FAKE_SECRET)

    def explode(self):
        raise RuntimeError(f"internal failure while using {FAKE_SECRET}")

    monkeypatch.setattr(manager.BanditManager, "run_tests", explode)
    with pytest.raises(BanditExecutionError) as exc_info:
        run_bandit([tmp_path / "a.py"])
    assert FAKE_SECRET not in str(exc_info.value)
    assert "RuntimeError" in str(exc_info.value)


# --- redaction helpers ---------------------------------------------------------


def test_redact_secrets_env_values_and_token_patterns():
    fake_groq = "gsk" + "_" + "ABCDEFGHIJKLMNOP"  # assembled so secret scanners don't flag the repo
    text = f"key={FAKE_SECRET} groq={fake_groq} user=alice"
    out = redact_secrets(text, environ={"MY_TOKEN": FAKE_SECRET, "USERNAME": "alice"})
    assert FAKE_SECRET not in out and fake_groq not in out
    assert "user=alice" in out  # non-secret env values are kept


def test_safe_error_message_is_bounded():
    message = safe_error_message(ValueError("x" * 1000), limit=50)
    assert len(message) == 50 and message.startswith("ValueError")
