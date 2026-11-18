"""ScannerAgent conversion logic with a mocked Bandit runner."""

from __future__ import annotations

from pathlib import Path

import pytest

from autopatch.models import Finding, Severity, VulnerabilityCategory
from autopatch.scanner import BanditNotInstalledError, ScannerAgent, ScanTargetError
from autopatch.scanner.bandit_runner import BanditIssue, BanditRun

SQL_CODE = (
    "import sqlite3\n"
    "\n"
    "def find(conn, name):\n"
    "    q = \"SELECT * FROM t WHERE n = '%s'\" % name\n"
    "    return conn.execute(q)\n"
)
CRED_CODE = 'API_PASSWORD = "very-secret-value-123"\n'


class FakeRunner:
    def __init__(self, *issues, skipped=(), malformed=(), version="9.9.9-test"):
        self.issues, self.skipped, self.malformed, self.version = issues, skipped, malformed, version
        self.calls: list[list[Path]] = []

    def __call__(self, files, *, ignore_nosec=False):
        self.calls.append(list(files))
        return BanditRun(self.version, tuple(self.issues), tuple(self.skipped), tuple(self.malformed))


def issue(path: Path, test_id="B608", line=4, **kw) -> BanditIssue:
    defaults = dict(
        test_name="hardcoded_sql_expressions",
        severity="MEDIUM",
        confidence="HIGH",
        text="Possible SQL injection vector through string-based query construction.",
        line_range=(line,),
        col_offset=8,
        cwe_id=89,
    )
    defaults.update(kw)
    return BanditIssue(filename=str(path), test_id=test_id, line=line, **defaults)


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proj"
    (root / "app").mkdir(parents=True)
    # write_bytes keeps "\n" endings on Windows, so snippets compare exactly.
    (root / "app" / "db.py").write_bytes(SQL_CODE.encode("utf-8"))
    (root / "settings.py").write_bytes(CRED_CODE.encode("utf-8"))
    return root


def scan(project, *issues, **kw):
    runner = FakeRunner(*issues, **{k: kw.pop(k) for k in ("skipped", "malformed") if k in kw})
    return ScannerAgent(runner=runner, **kw).scan(project), runner


def test_supported_issue_becomes_finding(project):
    result, runner = scan(project, issue(project / "app" / "db.py"))

    assert result.ok and result.scanner_version == "9.9.9-test"
    assert result.files_scanned == ["app/db.py", "settings.py"]
    assert sorted(p.name for p in runner.calls[0]) == ["db.py", "settings.py"]

    [finding] = result.findings
    assert isinstance(finding, Finding)
    assert finding.category is VulnerabilityCategory.SQL_INJECTION
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence == 0.9
    assert finding.file_path == "app/db.py"
    assert (finding.line, finding.end_line) == (4, 4)
    assert finding.rule_id == "B608"
    assert finding.scanner == "bandit"
    assert finding.description.startswith("Possible SQL injection")
    assert "B608" in finding.explanation and "CWE-89" in finding.explanation
    assert finding.code_snippet == "    q = \"SELECT * FROM t WHERE n = '%s'\" % name\n"
    assert finding.ast_context.enclosing_function == "find"
    assert (finding.ast_context.start_line, finding.ast_context.end_line) == (3, 5)
    assert finding.finding_id.startswith("finding-")


def test_finding_ids_are_deterministic(project):
    first, _ = scan(project, issue(project / "app" / "db.py"))
    second, _ = scan(project, issue(project / "app" / "db.py"))
    assert first.findings[0].finding_id == second.findings[0].finding_id


def test_duplicate_issues_are_merged(project):
    result, _ = scan(project, issue(project / "app" / "db.py"), issue(project / "app" / "db.py"))
    assert len(result.findings) == 1


@pytest.mark.parametrize("rule_id", ["B311", "B303", "B304", "B305", "B306", "B101"])
def test_unsupported_rules_are_ignored_not_classified(project, rule_id):
    result, _ = scan(project, issue(project / "app" / "db.py", test_id=rule_id, test_name="other"))
    assert result.findings == [] and result.related_findings == []
    [ignored] = result.ignored_issues
    assert ignored.rule_id == rule_id and ignored.file_path == "app/db.py"


def test_related_rule_reported_separately(project):
    result, _ = scan(
        project,
        issue(project / "app" / "db.py", test_id="B403", line=1, test_name="blacklist",
              text="Consider possible security implications associated with pickle module."),
    )
    assert result.findings == []
    [related] = result.related_findings
    assert related.category is VulnerabilityCategory.INSECURE_DESERIALIZATION
    assert related.rule_id == "B403"


def test_credentials_are_redacted_everywhere(project):
    result, _ = scan(
        project,
        issue(project / "settings.py", test_id="B105", line=1, severity="LOW", confidence="MEDIUM",
              test_name="hardcoded_password_string",
              text="Possible hardcoded password: 'very-secret-value-123'"),
    )
    [finding] = result.findings
    assert "very-secret-value-123" not in finding.model_dump_json()
    assert finding.description == "Possible hardcoded password (literal value redacted)"
    assert "***REDACTED***" in finding.code_snippet
    assert finding.ast_context.node_type == "Assign"
    # Source file itself is untouched.
    assert (project / "settings.py").read_bytes() == CRED_CODE.encode("utf-8")


def test_crlf_line_endings_are_preserved_in_snippet(tmp_path):
    (tmp_path / "db.py").write_bytes(SQL_CODE.replace("\n", "\r\n").encode("utf-8"))
    result, _ = scan(tmp_path, issue(tmp_path / "db.py"))
    assert result.findings[0].code_snippet.endswith("% name\r\n")


def test_undefined_severity_maps_to_low(project):
    result, _ = scan(project, issue(project / "app" / "db.py", severity="UNDEFINED", confidence="UNDEFINED"))
    assert result.findings[0].severity is Severity.LOW
    assert result.findings[0].confidence == 0.3


def test_issue_outside_root_is_rejected(project, tmp_path):
    outside = tmp_path / "elsewhere.py"
    outside.write_text(SQL_CODE, encoding="utf-8")
    result, _ = scan(project, issue(outside))
    assert result.findings == [] and not result.ok
    assert "not selected for scanning" in result.errors[0]


def test_issue_for_excluded_file_is_rejected(project):
    result, _ = scan(project, issue(project / "app" / "db.py"), exclude=["app"])
    assert result.findings == [] and not result.ok


def test_malformed_runner_output_is_reported(project):
    result, _ = scan(project, malformed=["malformed Bandit result ignored: missing field"])
    assert not result.ok and result.errors == ["malformed Bandit result ignored: missing field"]


def test_bandit_skipped_files_are_listed(project):
    result, _ = scan(project, skipped=[(str(project / "settings.py"), "syntax error while parsing AST from file")])
    assert result.files_scanned == ["app/db.py"]
    assert [(s.file_path, s.reason) for s in result.skipped_files] == [
        ("settings.py", "syntax error while parsing AST from file")
    ]


def test_finding_in_unparseable_file_has_no_context(project):
    bad = project / "bad.py"
    bad.write_text("q = 'SELECT %s' % x\ndef broken(:\n", encoding="utf-8")
    result, _ = scan(project, issue(bad, line=1))
    [finding] = result.findings
    assert finding.ast_context is None
    assert "AST context unavailable" in finding.explanation


def test_empty_project_has_zero_findings(tmp_path):
    result, runner = scan(tmp_path)
    assert result.ok and result.findings == [] and result.files_scanned == []
    assert runner.calls == [[]]


def test_missing_root_raises(tmp_path):
    with pytest.raises(ScanTargetError):
        ScannerAgent(runner=FakeRunner()).scan(tmp_path / "missing")


def test_runner_errors_propagate(project):
    def broken_runner(files, *, ignore_nosec=False):
        raise BanditNotInstalledError("Bandit is not installed")

    with pytest.raises(BanditNotInstalledError):
        ScannerAgent(runner=broken_runner).scan(project)
