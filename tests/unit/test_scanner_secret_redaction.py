"""Regression tests for scanner secret leaks (audit H1/H2) and oversized source.

All secrets here are synthetic. Token-shaped values are assembled at runtime
so secret scanners do not flag the repository.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from autopatch import cli
from autopatch.models import AstContext, Finding, ScanResult
from autopatch.models.common import MAX_CODE_CHARS
from autopatch.scanner import ScannerAgent, ScannerError
from autopatch.scanner import bandit_runner
from autopatch.scanner import scanner as scanner_mod
from autopatch.scanner.ast_context import (
    REDACTED_LITERAL,
    TRUNCATION_TAG,
    bound_text,
    extract_snippet,
    parse_source,
    redact_string_literals,
)
from autopatch.scanner.bandit_runner import BanditIssue, BanditRun
from autopatch.scanner.errors import describe_validation_error
from autopatch.common.sensitive import NONE, STRONG, WEAK, name_strength, redact_file

PW_1 = "synthetic-pw-one-1111"
PW_2 = "synthetic-pw-two-2222"
SQLI_CTX_SECRET = "synthetic-sqli-context-secret"
DESER_CTX_SECRET = "synthetic-deser-context-secret"
GH_TOKEN = "ghp" + "_" + "S" * 36
ERROR_SECRET = "synthetic-error-secret-9999"


class FakeRunner:
    def __init__(self, *issues: BanditIssue):
        self.issues = issues

    def __call__(self, files, *, ignore_nosec=False):
        return BanditRun("9.9.9-test", tuple(self.issues))


def issue(path: Path, test_id: str, line: int, end_line: int | None = None, text: str = "") -> BanditIssue:
    names = {"B105": "hardcoded_password_string", "B608": "hardcoded_sql_expressions",
             "B301": "blacklist", "B106": "hardcoded_password_funcarg"}  # fmt: skip
    return BanditIssue(
        filename=str(path),
        test_id=test_id,
        test_name=names.get(test_id, ""),
        severity="MEDIUM",
        confidence="HIGH",
        text=text or f"Synthetic {test_id} issue",
        line=line,
        line_range=tuple(range(line, (end_line or line) + 1)),
        col_offset=4,
    )


def write(root: Path, rel: str, code: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(code.encode("utf-8"))  # keep "\n" endings on Windows
    return path


def dump(result: ScanResult) -> str:
    return result.model_dump_json()


def assert_absent(text: str, *secrets: str) -> None:
    for secret in secrets:
        assert secret not in text, f"secret leaked: {secret[:12]}..."


MULTI = f'''import pickle


def login():
    password = "{PW_1}"
    db_password = "{PW_2}"
    return password, db_password


def find(conn, name):
    admin_pw = "{SQLI_CTX_SECRET}"
    conn.execute("SELECT * FROM t WHERE n = '%s'" % name)
    return admin_pw


def load(blob):
    api_token = "{GH_TOKEN}"
    signing_key = "{DESER_CTX_SECRET}"
    return pickle.loads(blob)
'''


@pytest.fixture
def multi_project(tmp_path):
    root = tmp_path / "proj"
    path = write(root, "app/multi.py", MULTI)
    issues = (
        issue(path, "B105", 5, text=f"Possible hardcoded password: '{PW_1}'"),
        issue(path, "B105", 6, text=f"Possible hardcoded password: '{PW_2}'"),
        issue(path, "B608", 12),
        issue(path, "B301", 19),
    )
    return root, issues


# --- H1: secrets in AST context --------------------------------------------------


def test_multiple_secrets_in_one_function_are_hidden(multi_project):
    root, issues = multi_project
    result = ScannerAgent(runner=FakeRunner(*issues)).scan(root)
    assert result.errors == []
    creds = [f for f in result.findings if f.rule_id == "B105"]
    assert len(creds) == 2
    for finding in creds:  # each credential finding's context holds both secrets
        assert finding.ast_context is not None and finding.ast_context.start_line == 4
        assert_absent(finding.model_dump_json(), PW_1, PW_2)
        assert finding.ast_context.source.count(REDACTED_LITERAL) == 2


def test_secret_inside_sql_injection_context_is_hidden(multi_project):
    root, issues = multi_project
    result = ScannerAgent(runner=FakeRunner(*issues)).scan(root)
    sqli = next(f for f in result.findings if f.rule_id == "B608")
    text = sqli.model_dump_json()
    assert_absent(text, SQLI_CTX_SECRET)
    source = sqli.ast_context.source
    assert "admin_pw = " + REDACTED_LITERAL in source  # name stays readable
    assert "SELECT * FROM t WHERE n = '%s'" in source  # ordinary strings stay readable
    assert sqli.code_snippet == "    conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)\n"


def test_secret_inside_deserialization_context_is_hidden(multi_project):
    root, issues = multi_project
    result = ScannerAgent(runner=FakeRunner(*issues)).scan(root)
    deser = next(f for f in result.findings if f.rule_id == "B301")
    assert_absent(deser.model_dump_json(), GH_TOKEN, DESER_CTX_SECRET)
    assert "signing_key = " + REDACTED_LITERAL in deser.ast_context.source
    assert "pickle.loads(blob)" in deser.ast_context.source


def test_credential_findings_sharing_a_function_and_whole_result_json(multi_project):
    root, issues = multi_project
    result = ScannerAgent(runner=FakeRunner(*issues)).scan(root)
    full = dump(result)
    assert_absent(full, PW_1, PW_2, SQLI_CTX_SECRET, DESER_CTX_SECRET, GH_TOKEN)
    assert ScanResult.model_validate_json(full) == result  # JSON round trip
    for finding in result.findings:
        assert_absent(finding.description + finding.explanation, PW_1, PW_2)


def test_same_value_is_hidden_everywhere_in_the_file(tmp_path):
    code = (
        "def connect(db):\n"
        f'    password = "{PW_1}"\n'
        f'    # fallback copy: {PW_1}\n'
        f'    other = "{PW_1}"\n'
        f'    dsn = f"postgres://app:{PW_1}@db/app"\n'
        "    db.execute(\"SELECT * FROM t WHERE x = '%s'\" % other)\n"
    )
    path = write(tmp_path, "c.py", code)
    result = ScannerAgent(runner=FakeRunner(issue(path, "B608", 6))).scan(tmp_path)
    assert_absent(dump(result), PW_1)


def test_comments_and_docstrings_with_credential_pairs_are_hidden(tmp_path):
    code = (
        "import pickle\n"
        "def load(d):\n"
        f'    """Example config: password = "{PW_2}"."""\n'
        f'    # token: "{PW_1}"\n'
        "    return pickle.loads(d)\n"
    )
    path = write(tmp_path, "d.py", code)
    result = ScannerAgent(runner=FakeRunner(issue(path, "B301", 5))).scan(tmp_path)
    assert_absent(dump(result), PW_1, PW_2)
    assert "Example config: password =" in result.findings[0].ast_context.source


def test_ordinary_identifiers_keys_and_strings_stay_readable(tmp_path):
    code = (
        "import pickle\n"
        "def build(d):\n"
        f'    config = {{"host": "db.internal", "user": "alice", "password": "{PW_1}"}}\n'
        '    password_field = "password"\n'
        '    token_url = "https://auth.example.invalid/token"\n'
        '    cache_key = "users"\n'
        "    return pickle.loads(d), config\n"
    )
    path = write(tmp_path, "r.py", code)
    result = ScannerAgent(runner=FakeRunner(issue(path, "B301", 7))).scan(tmp_path)
    source = result.findings[0].ast_context.source
    assert_absent(source, PW_1)
    for readable in ('"host": "db.internal"', '"user": "alice"', '"password": ' + REDACTED_LITERAL,
                     'password_field = "password"', '"https://auth.example.invalid/token"',
                     'cache_key = "users"'):  # fmt: skip
        assert readable in source


def test_credential_snippet_matches_the_patcher_contract(tmp_path):
    """On a credential line only the credential is hidden (ordinary literals
    such as a base URL stay visible and stale-checkable), and the Patch
    Generator recomputes exactly the scanner's snippet."""
    from autopatch.patch_generator.context import expected_snippets

    code = 'def build():\n    return Client(base_url="https://x.invalid", token="%s")\n' % PW_1
    path = write(tmp_path, "k.py", code)
    result = ScannerAgent(runner=FakeRunner(issue(path, "B106", 2))).scan(tmp_path)
    finding = result.findings[0]
    parsed = parse_source(code)
    assert finding.code_snippet == '    return Client(base_url="https://x.invalid", token=%s)\n' % REDACTED_LITERAL
    assert finding.code_snippet in expected_snippets(finding, parsed)
    # The older all-literals view is no longer produced for this line.
    assert finding.code_snippet != extract_snippet(redact_string_literals(parsed, 2, 2)[0], 2, 2)
    assert_absent(finding.model_dump_json(), PW_1)


@pytest.mark.parametrize(
    ("name", "strength"),
    [("password", STRONG), ("DB_PASS", STRONG), ("apiKey", STRONG), ("client_secret", STRONG),
     ("signing_key", STRONG), ("cache_key", WEAK), ("password_field", NONE), ("token_url", NONE),
     ("username", NONE), ("bypass", NONE), ("author", NONE)],
)  # fmt: skip
def test_name_strength(name, strength):
    assert name_strength(name) == strength


def test_redact_file_preserves_line_structure():
    code = 'a = 1\r\npassword = (\r\n    "x-secret-a"\r\n    "x-secret-b"\r\n)\r\nb = "plain"\r\n'
    parsed = parse_source(code)
    view = redact_file(parsed)
    assert len(view.lines) == len(parsed.lines)
    assert all(v.endswith("\r\n") for v in view.lines)
    assert "x-secret" not in "".join(view.lines)
    assert view.lines[5] == 'b = "plain"\r\n'


# --- H2: validation errors -----------------------------------------------------------


def test_validation_error_summary_never_contains_input():
    short_secret = "S3cr3t-77"  # pydantic quotes only the first ~25 input characters
    with pytest.raises(ValidationError) as exc_info:
        AstContext(node_type="Assign", start_line=1, end_line=1,
                   source=f'pw="{short_secret}"' + "x" * MAX_CODE_CHARS)  # fmt: skip
    assert short_secret in str(exc_info.value)  # what the old error path leaked
    summary = describe_validation_error(exc_info.value)
    assert short_secret not in summary
    assert "source" in summary and "string_too_long" in summary


def _leaky_id(*args, **kwargs):  # forces a Finding validation error with a secret input
    return f"bad id {ERROR_SECRET}"


def test_finding_validation_error_does_not_leak_into_scan_result(multi_project, monkeypatch):
    root, issues = multi_project
    monkeypatch.setattr(scanner_mod, "stable_finding_id", _leaky_id)
    result = ScannerAgent(runner=FakeRunner(*issues)).scan(root)
    assert result.findings == [] and len(result.errors) == len(issues)
    assert not result.ok  # a lost finding is never reported as a clean scan
    assert "finding_id" in result.errors[0]
    assert_absent(dump(result), ERROR_SECRET, PW_1, PW_2, SQLI_CTX_SECRET, GH_TOKEN)


def test_cli_output_and_json_do_not_leak_validation_errors(tmp_path, monkeypatch, capsys):
    root = tmp_path / "proj"
    write(root, "app.py", f'import pickle\ndef f(d):\n    password = "{PW_1}"\n    return pickle.loads(d)\n')
    monkeypatch.setattr(scanner_mod, "stable_finding_id", _leaky_id)
    report = tmp_path / "out" / "report.json"
    code = cli.main(["scan", str(root), "-o", str(report)])  # real Bandit
    captured = capsys.readouterr()
    assert code == cli.EXIT_ERROR
    assert "could not convert" in captured.err
    for text in (captured.out, captured.err, report.read_text(encoding="utf-8")):
        assert_absent(text, ERROR_SECRET, PW_1)
    assert json.loads(report.read_text(encoding="utf-8"))["errors"]


def test_scan_result_validation_error_is_sanitized(multi_project, monkeypatch):
    root, issues = multi_project

    def broken_result(**kwargs):
        return ScanResult.model_validate({**kwargs, "errors": [ERROR_SECRET * 2000]})

    monkeypatch.setattr(scanner_mod, "ScanResult", broken_result)
    with pytest.raises(ScannerError) as exc_info:
        ScannerAgent(runner=FakeRunner(*issues)).scan(root)
    assert ERROR_SECRET not in str(exc_info.value)
    assert exc_info.value.__cause__ is None and exc_info.value.__suppress_context__


def test_bandit_crash_message_never_quotes_source(monkeypatch, tmp_path):
    from bandit.core import manager

    def explode(self):
        raise SyntaxError(f'bad line: password = "{ERROR_SECRET}"')

    monkeypatch.setattr(manager.BanditManager, "run_tests", explode)
    with pytest.raises(bandit_runner.BanditExecutionError) as exc_info:
        bandit_runner.run_bandit([tmp_path / "a.py"])
    assert ERROR_SECRET not in str(exc_info.value)
    assert "SyntaxError" in str(exc_info.value)


def test_unreadable_bandit_result_message_never_quotes_source(monkeypatch, tmp_path):
    from bandit.core import manager

    class Weird:
        def as_dict(self, with_code=False):
            raise ValueError(f'cannot render: token = "{ERROR_SECRET}"')

    def fake_run_tests(self):
        self.results = [Weird()]

    monkeypatch.setattr(manager.BanditManager, "run_tests", fake_run_tests)
    run = bandit_runner.run_bandit([tmp_path / "a.py"])
    assert len(run.malformed) == 1 and "ValueError" in run.malformed[0]
    assert ERROR_SECRET not in run.malformed[0]


# --- oversized source --------------------------------------------------------------


def test_oversized_line_keeps_the_finding_with_a_truncation_marker(tmp_path):
    """Previously this finding was dropped with a ValidationError (audit)."""
    long_literal = "B" * (MAX_CODE_CHARS + 10_000)
    code = (
        "import pickle\n"
        "def f(d):\n"
        f'    api_token = "{GH_TOKEN}"\n'
        f'    filler = "{long_literal}"\n'
        "    return pickle.loads(d)\n"
    )
    write(tmp_path, "big.py", code)
    result = ScannerAgent().scan(tmp_path)  # real Bandit
    assert result.errors == [] and result.ok
    finding = next(f for f in result.findings if f.rule_id == "B301")
    assert finding.line == 5 and finding.ast_context.start_line == 2
    assert TRUNCATION_TAG in finding.ast_context.source
    assert len(finding.ast_context.source) <= MAX_CODE_CHARS
    assert "truncated" in finding.explanation
    assert_absent(dump(result), GH_TOKEN)


def test_oversized_snippet_is_bounded(tmp_path):
    long_literal = "C" * (MAX_CODE_CHARS + 5)
    code = f'def f(c, x):\n    c.execute("SELECT * FROM t WHERE x = %s" % x); y = "{long_literal}"\n'
    path = write(tmp_path, "s.py", code)
    result = ScannerAgent(runner=FakeRunner(issue(path, "B608", 2))).scan(tmp_path)
    finding = result.findings[0]
    assert TRUNCATION_TAG in finding.code_snippet and len(finding.code_snippet) <= MAX_CODE_CHARS


def test_bound_text():
    assert bound_text("short", 10) == "short"
    out = bound_text("x" * 100, 80)
    assert len(out) <= 80 and TRUNCATION_TAG in out
