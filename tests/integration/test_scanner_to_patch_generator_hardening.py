"""Scanner <-> Patch Generator boundary hardening (post H-1..H-4 audit).

1. Exceptions never keep the original (possibly source-quoting) exception.
2. Bandit metadata is treated as untrusted input.
3. Name-like secret values do not hide ordinary keys, identifiers or SQL.
4. Stale-source validation: hidden literals are secrets only, and what
   cannot be compared is reported, never silently accepted.
5. Extra cases: unparseable files, escaped values, multi-line comments and
   docstrings, multiple secrets, no leaks in prompts/errors/logs/CLI.

Real Bandit and the real GroqClient over a fake SDK (no network). All
secrets are synthetic; token-shaped values are assembled at runtime.
"""

from __future__ import annotations

import json
import logging
import traceback
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from autopatch import cli
from autopatch.config import Settings
from autopatch.llm import GroqClient
from autopatch.models import Finding
from autopatch.patch_generator import PatchGeneratorAgent, build_patch_context
from autopatch.patch_generator.context import (
    LEGACY_NOT_COMPARED,
    SECRET_NOT_COMPARED,
    TEXT_NOT_COMPARED,
    expected_snippets,
)
from autopatch.patch_generator.diff import parse_unified_diff
from autopatch.patch_generator.errors import (
    DiffPathError,
    InsufficientContextError,
    PatchGenerationError,
    SourceMismatchError,
    UnsafePatchError,
)
from autopatch.scanner import ScannerAgent, ScannerError
from autopatch.common import sensitive
from autopatch.scanner import bandit_runner
from autopatch.scanner import scanner as scanner_mod
from autopatch.common.source import (
    REDACTED_LITERAL,
    extract_snippet,
    parse_source,
    redact_string_literals,
)
from autopatch.scanner.bandit_runner import (
    WITHHELD_SKIP_REASON,
    BanditIssue,
    BanditRun,
    parse_issue,
    run_bandit,
)
from autopatch.scanner.errors import (
    BanditExecutionError,
    BanditNotInstalledError,
    MalformedBanditResultError,
    ScanTargetError,
    clean_text,
    escape_for_terminal,
)
from autopatch.common.sensitive import key_literal_ids, name_like_values, redact_file

SECRET = "SYNTH_HARD_secret_0123456789"
GH_TOKEN = "ghp" + "_" + "H" * 36
ESC = "\x1b"
BIDI = "‮"
R = REDACTED_LITERAL


# -- helpers ---------------------------------------------------------------------------


class FakeSDK:
    def __init__(self, content: str):
        self.content = content
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        choice = SimpleNamespace(message=SimpleNamespace(content=self.content), finish_reason="stop")
        usage = SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2)
        return SimpleNamespace(id="x", model="test-model", choices=[choice], usage=usage)

    def sent(self) -> str:
        return "\n".join(m["content"] for call in self.calls for m in call["messages"])


def scan_file(tmp_path: Path, code: str, name: str = "app.py", **kwargs):
    root = tmp_path / "proj"
    root.mkdir(exist_ok=True)
    (root / name).write_bytes(code.encode("utf-8"))  # exact line endings
    return ScannerAgent(**kwargs).scan(root), root


def finding_for(result, rule_id: str) -> Finding:
    return next(f for f in result.findings if f.rule_id == rule_id)


def generate(finding: Finding, source: str, hunks: str):
    reply = {
        "finding_id": finding.finding_id,
        "category": finding.category.value,
        "vulnerability_summary": "Synthetic test vulnerability.",
        "remediation_rationale": "Minimal safe replacement.",
        "unified_diff": f"--- a/{finding.file_path}\n+++ b/{finding.file_path}\n" + hunks,
        "security_improvements": ["Removes the unsafe construct."],
        "assumptions": [],
        "limitations": [],
        "new_dependencies": [],
        "confidence": 0.7,
    }
    sdk = FakeSDK(json.dumps(reply))
    settings = Settings(groq_api_key="test-api-key-not-real-0000", groq_model="test-model")
    result = PatchGeneratorAgent(GroqClient(settings, sdk_client=sdk)).generate(finding, source)
    return result, sdk


def assert_absent(text: str, *secrets: str) -> None:
    for secret in secrets:
        assert secret not in text, f"secret leaked: {secret[:14]}..."


def exposed_text(exc: BaseException) -> str:
    """Everything a caller can reach from an exception object."""
    parts = [str(exc), repr(exc), repr(exc.args), repr(vars(exc))]
    parts += traceback.format_exception(exc)
    parts += traceback.format_exception(exc, chain=True)
    parts.append("".join(traceback.TracebackException.from_exception(exc).format(chain=True)))
    return "\n".join(parts)


def assert_clean_exception(exc: BaseException, *secrets: str) -> None:
    assert exc.__cause__ is None
    assert exc.__context__ is None  # not merely suppressed: gone
    assert_absent(exposed_text(exc), *secrets)


def fake_runner(*issues: BanditIssue, skipped=(), malformed=(), version="9.9.9-test"):
    def runner(files, *, ignore_nosec=False):
        return BanditRun(version, tuple(issues), tuple(skipped), tuple(malformed))

    return runner


def raw_issue(path: Path, test_id: str, line: int, **overrides) -> BanditIssue:
    data = dict(
        filename=str(path),
        test_id=test_id,
        test_name="blacklist",
        severity="MEDIUM",
        confidence="HIGH",
        text="Synthetic issue text.",
        line=line,
        line_range=(line,),
        col_offset=0,
    )
    data.update(overrides)
    return BanditIssue(**data)


# == 1. Exception-context leakage =========================================================

PICKLE_SRC = f'import pickle\npassword = "{SECRET}"\npickle.loads(b"x")\n'


def test_scan_result_validation_error_is_not_chained(tmp_path, monkeypatch):
    def broken(**_):
        raise ValidationError.from_exception_data(
            "ScanResult", [{"type": "string_too_short", "loc": ("errors", 0), "input": SECRET,
                            "ctx": {"min_length": 99}}]  # fmt: skip
        )

    monkeypatch.setattr(scanner_mod, "ScanResult", broken)
    root = tmp_path / "p"
    root.mkdir()
    (root / "a.py").write_bytes(PICKLE_SRC.encode())
    with pytest.raises(ScannerError) as info:
        ScannerAgent().scan(root)
    assert "string_too_short" in str(info.value)  # still diagnosable
    assert_clean_exception(info.value, SECRET)


def test_bandit_crash_quoting_source_is_not_chained(tmp_path, monkeypatch):
    import bandit.core.manager as manager

    def crash(self, *args, **kwargs):
        raise ValueError(f"bad node: password = '{SECRET}'")

    monkeypatch.setattr(manager.BanditManager, "run_tests", crash)
    root = tmp_path / "p"
    root.mkdir()
    (root / "a.py").write_bytes(PICKLE_SRC.encode())
    with pytest.raises(BanditExecutionError) as info:
        ScannerAgent().scan(root)
    assert "ValueError" in str(info.value)  # the type is kept for debugging
    assert_clean_exception(info.value, SECRET)


def test_bandit_import_error_is_not_chained(monkeypatch):
    def missing(name, *args, **kwargs):
        raise ImportError(f"cannot import {SECRET}")

    monkeypatch.setattr(bandit_runner.importlib, "import_module", missing)
    with pytest.raises(BanditNotInstalledError) as info:
        run_bandit([])
    assert_clean_exception(info.value, SECRET)


def test_missing_project_root_is_not_chained(tmp_path):
    with pytest.raises(ScanTargetError) as info:
        ScannerAgent().scan(tmp_path / "does-not-exist")
    assert_clean_exception(info.value)


def test_unexpected_conversion_error_is_recorded_not_raised(tmp_path, monkeypatch):
    def explode(self, issue, rel, path):
        raise KeyError(SECRET)

    monkeypatch.setattr(scanner_mod._Converter, "_finding", explode)
    result, _ = scan_file(tmp_path, PICKLE_SRC)
    assert result.findings == [] and not result.ok
    assert any("internal error (KeyError; details withheld)" in e for e in result.errors)
    assert_absent(result.model_dump_json(), SECRET)


def test_finding_validation_error_is_summarised_without_input(tmp_path, monkeypatch):
    def invalid(**_):
        raise ValidationError.from_exception_data(
            "Finding", [{"type": "string_too_long", "loc": ("code_snippet",), "input": SECRET,
                         "ctx": {"max_length": 1}}]  # fmt: skip
        )

    monkeypatch.setattr(scanner_mod, "Finding", invalid)
    result, _ = scan_file(tmp_path, PICKLE_SRC)
    assert any("code_snippet: string_too_long" in e for e in result.errors)
    assert_absent(result.model_dump_json(), SECRET)


def test_conversion_error_object_is_not_chained(tmp_path, monkeypatch):
    def explode(self, issue, rel, path):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(scanner_mod._Converter, "_finding", explode)
    root = tmp_path / "p"
    root.mkdir()
    path = root / "a.py"
    path.write_bytes(PICKLE_SRC.encode())
    discovery = scanner_mod.discover_python_files(root)
    converter = scanner_mod._Converter(discovery)
    with pytest.raises(scanner_mod._ConversionError) as info:
        converter.convert(raw_issue(path.resolve(), "B301", 3))
    assert_clean_exception(info.value, SECRET)


def test_patcher_errors_are_not_chained(tmp_path):
    result, _ = scan_file(tmp_path, PICKLE_SRC)
    finding = finding_for(result, "B301")
    with pytest.raises(SourceMismatchError) as info:
        build_patch_context(finding, PICKLE_SRC.replace("b\"x\"", "b\"y\""))
    assert_clean_exception(info.value, SECRET)
    with pytest.raises(InsufficientContextError) as info2:
        build_patch_context(finding, f'password = "{SECRET}"\npickle.loads(\n')
    assert_clean_exception(info2.value, SECRET)
    diff = f"--- a/../{SECRET}.py\n+++ b/../{SECRET}.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"
    with pytest.raises(DiffPathError) as info3:
        parse_unified_diff(diff, "app.py")
    assert info3.value.__context__ is None and info3.value.__cause__ is None


def test_cli_scan_failure_output_is_clean(tmp_path, monkeypatch, capsys):
    import bandit.core.manager as manager

    def crash(self, *args, **kwargs):
        raise ValueError(f"{ESC}[2J{SECRET}")

    monkeypatch.setattr(manager.BanditManager, "run_tests", crash)
    root = tmp_path / "p"
    root.mkdir()
    (root / "a.py").write_bytes(PICKLE_SRC.encode())
    assert cli.main(["scan", str(root)]) == cli.EXIT_ERROR
    out = capsys.readouterr()
    assert_absent(out.out + out.err, SECRET, ESC)
    assert "Bandit failed: ValueError" in out.err


# == 2. Untrusted Bandit metadata =======================================================


def test_parse_issue_sanitises_and_never_echoes_values():
    base = {"filename": "a.py", "test_id": "B301", "issue_severity": "MEDIUM", "issue_confidence": "HIGH",
            "line_number": 3, "line_range": [3]}  # fmt: skip
    issue = parse_issue({**base, "test_name": f"pickle{ESC}]0;pwn\x07", "col_offset": -5,
                         "issue_cwe": {"id": True},
                         "issue_text": f"Evil {ESC}[31mred{ESC}[0m {BIDI}gpj.exe\n\nnext"})  # fmt: skip
    assert issue.test_name == ""  # not a plain identifier: dropped
    assert issue.col_offset == 0 and issue.cwe_id is None
    assert ESC not in issue.text and BIDI not in issue.text and "\n" not in issue.text
    assert issue.text.startswith("Evil")  # still useful
    for field, value in (("test_id", f"B301{SECRET}"), ("issue_severity", SECRET), ("issue_confidence", SECRET)):
        with pytest.raises(MalformedBanditResultError) as info:
            parse_issue({**base, field: value})
        assert_absent(str(info.value), SECRET)


@pytest.mark.parametrize(
    ("reason", "kept"),
    [("Permission denied", True), ("syntax error while parsing AST from file", True),
     ("exception while scanning file", True), (f"reason {ESC}[1m{SECRET}", False),
     (f"line 3: password = '{SECRET}'", False), (SECRET, False)],
)  # fmt: skip
def test_skip_reasons_are_allowlisted(reason, kept):
    shown = bandit_runner.skip_reason(reason)
    assert (shown == reason) is kept
    if not kept:
        assert shown == WITHHELD_SKIP_REASON


def test_malicious_runner_metadata_never_reaches_report_or_cli(tmp_path, capsys):
    root = tmp_path / "p"
    root.mkdir()
    path = root / "a.py"
    path.write_bytes(PICKLE_SRC.encode())
    path = path.resolve()
    evil_text = f"Pickle issue {ESC}[31mred{ESC}[0m '{SECRET}' {BIDI}txt.exe {GH_TOKEN}"
    runner = fake_runner(
        raw_issue(path, "B301", 3, text=evil_text, test_name=f"x{ESC}[2J"),
        raw_issue(path, "B105", 2, text=f"Possible hardcoded password: '{SECRET}'", test_name="hardcoded_password_string"),
        raw_issue(path, "B608", 99, text="Possible SQL injection"),  # line beyond the file
        raw_issue(path, "B301", 3, line_range=(3, 10**9), col_offset=7),  # absurd range: clamped
        skipped=((str(path), f"reason {ESC}[1m{SECRET}"),),
        malformed=(f"malformed {ESC}[2J {GH_TOKEN}",),
        version=f"1.0{ESC}[2J",
    )
    result = ScannerAgent(runner=runner).scan(root)
    report = result.model_dump_json()
    for marker in (SECRET, GH_TOKEN, ESC, BIDI):
        assert marker not in report, repr(marker[:10])
    deser = next(f for f in result.findings if f.rule_id == "B301" and f.end_line == 3)
    assert deser.description.startswith("Pickle issue")  # legitimate text kept
    assert "<withheld>" in deser.description  # quoted value withheld
    assert "(pickle)" in deser.explanation  # rule table name replaces the bad test name
    assert any("line 99" in e and "has 3 lines" in e for e in result.errors)
    assert all(f.end_line <= 3 for f in result.findings)
    assert result.skipped_files[0].reason == WITHHELD_SKIP_REASON

    # CLI: same project through the command line with this runner.
    original = cli.ScannerAgent
    try:
        cli.ScannerAgent = lambda **kw: ScannerAgent(runner=runner, **kw)  # type: ignore[assignment]
        cli.main(["scan", str(root), "-o", str(tmp_path / "out.json")])
    finally:
        cli.ScannerAgent = original  # type: ignore[assignment]
    out = capsys.readouterr()
    for marker in (SECRET, GH_TOKEN, ESC, BIDI):
        assert marker not in out.out + out.err
    assert_absent((tmp_path / "out.json").read_text(encoding="utf-8"), SECRET, GH_TOKEN)


def test_terminal_escaping_helpers():
    assert escape_for_terminal(f"a{ESC}[2Jb{BIDI}c​d\x07") == "a\\x1b[2Jb\\u202ec\\u200bd\\x07"
    assert escape_for_terminal("café/über.py") == "café/über.py"  # ordinary text kept
    assert clean_text(f"x{ESC}y\r\nz", 100) == "x y z"
    assert len(clean_text("a" * 1000, 50)) == 50


# == 3. Over-redaction of ordinary code =================================================

VOCAB = (
    "import pickle\n"
    "password = \"password\"\n"
    "\n"
    "\n"
    "def login(form, db, user, blob, environ):\n"
    "    user_pw = form[\"password\"]\n"
    "    row = db.execute(\"SELECT password FROM users WHERE name = '%s'\" % form[\"user\"])\n"
    "    data = {\"password\": user_pw, \"user\": \"bob\"}\n"
    "    hint = environ.get(\"password\"), getattr(user, \"password\")\n"
    "    check(user, \"password\")  # the same value used as data\n"
    "    return pickle.loads(blob), row, data, hint\n"
)
VOCAB_DIFF = (
    "@@ -1,1 +1,1 @@\n"
    "-import pickle\n"
    "+import json\n"
    "@@ -11,1 +11,1 @@\n"
    "-    return pickle.loads(blob), row, data, hint\n"
    "+    return json.loads(blob), row, data, hint\n"
)


def test_name_like_value_does_not_hide_keys_identifiers_or_sql(tmp_path):
    result, _ = scan_file(tmp_path, VOCAB)
    deser = finding_for(result, "B301")
    source = deser.ast_context.source
    for readable in ('form["password"]', '"SELECT password FROM users', '{"password": user_pw',
                     'environ.get("password")', 'getattr(user, "password")'):  # fmt: skip
        assert readable in source, readable
    assert f"check(user, {R})" in source  # used as data: still hidden
    cred = finding_for(result, "B105")
    assert cred.code_snippet == f"password = {R}\n"

    context = build_patch_context(deser, VOCAB)  # used to fail with RedactionError
    rendered = context.render_excerpts()
    assert 'form["password"]' in rendered and '"SELECT password FROM users' in rendered
    assert f"password = {R}" in rendered and f"check(user, {R})" in rendered
    generation, sdk = generate(deser, VOCAB, VOCAB_DIFF)
    assert "json.loads" in generation.patched_source.reveal_for_verification()
    assert 'form["password"]' in sdk.sent()


def test_real_secret_elsewhere_is_still_hidden_even_as_a_key(tmp_path):
    secret = "Xk9-SYNTH-77-q"  # not an identifier: real secret material
    code = (
        "import pickle\n"
        f"password = \"{secret}\"\n"
        "def f(blob, cache, log):\n"
        f"    cache[\"{secret}\"] = 1\n"
        f"    log(\"using {secret} now\")  # {secret}\n"
        f"    return pickle.loads(blob), {{\"{secret}\": 1}}\n"
    )
    result, _ = scan_file(tmp_path, code)
    assert_absent(result.model_dump_json(), secret)
    deser = finding_for(result, "B301")
    _, sdk = generate(deser, code, "@@ -6,1 +6,1 @@\n"
                      f"-    return pickle.loads(blob), {{{R}: 1}}\n"
                      "+    return blob, None\n")  # fmt: skip
    assert_absent(sdk.sent(), secret)


def test_value_used_as_identifier_is_ordinary_vocabulary():
    code = (
        "password = \"admin\"\n"
        "def admin():\n"
        "    return \"SELECT * FROM t WHERE role = 'admin'\", lookup(\"admin\"), roles[\"admin\"]\n"
    )
    parsed = parse_source(code)
    assert name_like_values(parsed.tree, {"admin", "Zq-91-xx"}) == {"admin"}
    view = "".join(redact_file(parsed).lines)
    assert f"password = {R}" in view
    assert "role = 'admin'" in view and 'roles["admin"]' in view  # SQL text and key readable
    assert f"lookup({R})" in view  # data position: hidden


def test_key_positions():
    code = 'd = {"a": x}; y = d["b"]; z = e.get("c"); w = getattr(o, "d"); f("e")\n'
    tree = parse_source(code).tree
    keys = {n.value for n in __import__("ast").walk(tree) if id(n) in key_literal_ids(tree)}
    assert keys == {"a", "b", "c", "d"}


def test_bandit_style_name_with_neutral_suffix_does_not_hide_keys(tmp_path):
    code = (
        "import pickle\n"
        "password_field = \"password\"\n"  # Bandit B105 flags this name
        "def f(form, blob):\n"
        "    return form[\"password\"], pickle.loads(blob)\n"
    )
    result, _ = scan_file(tmp_path, code)
    deser = finding_for(result, "B301")
    assert 'form["password"]' in deser.ast_context.source
    build_patch_context(deser, code)


def test_credential_fix_may_keep_the_word_as_a_key(tmp_path):
    code = (
        "import os\n"
        "password = \"password\"\n"
        "def f(form):\n"
        "    return form[\"password\"] == password\n"
    )
    result, _ = scan_file(tmp_path, code)
    cred = finding_for(result, "B105")
    generation, _ = generate(cred, code, "@@ -2,1 +2,1 @@\n"
                             f"-password = {R}\n"
                             "+password = os.environ[\"APP_PASSWORD\"]\n")  # fmt: skip
    patched = generation.patched_source.reveal_for_verification()
    assert 'form["password"]' in patched and 'os.environ["APP_PASSWORD"]' in patched
    with pytest.raises(UnsafePatchError, match="does not remove"):
        generate(cred, code, "@@ -2,1 +2,2 @@\n"
                 f"-password = {R}\n"
                 "+password = os.environ[\"APP_PASSWORD\"]\n"
                 "+fallback = check(\"password\")\n")  # fmt: skip


# == 4. Stale-source validation =========================================================

SQL_ON_CRED_LINE = (
    "def q(c, n):\n"
    "    return c.execute(\"SELECT * FROM t WHERE n = '%s'\" % n, password=\"SYNTH_pw_abcdef\")\n"
)


def test_sql_on_a_credential_line_is_visible_and_compared(tmp_path):
    result, _ = scan_file(tmp_path, SQL_ON_CRED_LINE)
    finding = finding_for(result, "B608")
    assert "SELECT * FROM t" in finding.code_snippet  # was hidden before this fix
    assert build_patch_context(finding, SQL_ON_CRED_LINE).notes == (SECRET_NOT_COMPARED,)
    with pytest.raises(SourceMismatchError):  # was silently accepted before this fix
        build_patch_context(finding, SQL_ON_CRED_LINE.replace("SELECT * FROM t", "DELETE FROM t"))


def test_unrelated_literal_change_on_a_credential_line_is_rejected(tmp_path):
    code = 'def build():\n    return Client(base_url="https://a.invalid", token="SYNTH_tok_abcdef")\n'
    result, _ = scan_file(tmp_path, code)
    finding = finding_for(result, "B106")
    build_patch_context(finding, code)
    with pytest.raises(SourceMismatchError):
        build_patch_context(finding, code.replace("https://a.invalid", "https://evil.invalid"))


def test_secret_only_change_is_reported_not_silent(tmp_path):
    result, _ = scan_file(tmp_path, SQL_ON_CRED_LINE)
    finding = finding_for(result, "B608")
    rotated = SQL_ON_CRED_LINE.replace("SYNTH_pw_abcdef", "SYNTH_pw_rotated")
    generation, sdk = generate(finding, rotated, (
        "@@ -2,1 +2,1 @@\n"
        f"-    return c.execute(\"SELECT * FROM t WHERE n = '%s'\" % n, password={R})\n"
        "+    return c.execute(\"SELECT * FROM t WHERE n = ?\", (n,), password=get_password())\n"
    ))
    assert SECRET_NOT_COMPARED in generation.candidate.warnings
    assert_absent(sdk.sent(), "SYNTH_pw_rotated", "SYNTH_pw_abcdef")
    assert "SYNTH_pw_rotated" not in generation.patched_source.reveal_for_verification()


def test_no_note_when_nothing_is_hidden(tmp_path):
    result, _ = scan_file(tmp_path, PICKLE_SRC)
    assert build_patch_context(finding_for(result, "B301"), PICKLE_SRC).notes == ()


def test_legitimate_credential_remediation(tmp_path):
    code = "import os\nSMTP_PASSWORD = \"SYNTH_smtp_pw_42\"\n"
    result, _ = scan_file(tmp_path, code)
    finding = finding_for(result, "B105")
    generation, sdk = generate(finding, code, "@@ -2,1 +2,1 @@\n"
                               f"-SMTP_PASSWORD = {R}\n"
                               "+SMTP_PASSWORD = os.environ[\"SMTP_PASSWORD\"]\n")  # fmt: skip
    patched = generation.patched_source.reveal_for_verification()
    assert "SYNTH_smtp_pw_42" not in patched and 'os.environ["SMTP_PASSWORD"]' in patched
    assert SECRET_NOT_COMPARED in generation.candidate.warnings
    assert_absent(sdk.sent(), "SYNTH_smtp_pw_42")


def test_legacy_snippet_is_accepted_only_with_an_explicit_note(tmp_path):
    code = 'def build():\n    return Client(base_url="https://a.invalid", token="SYNTH_tok_abcdef")\n'
    result, _ = scan_file(tmp_path, code)
    finding = finding_for(result, "B106")
    parsed = parse_source(code)
    legacy = extract_snippet(redact_string_literals(parsed, 2, 2)[0], 2, 2)
    old = finding.model_copy(update={"code_snippet": legacy})
    assert build_patch_context(old, code).notes == (LEGACY_NOT_COMPARED,)
    assert build_patch_context(finding, code).notes == (SECRET_NOT_COMPARED,)
    with pytest.raises(SourceMismatchError):  # structure outside the literals is still exact
        build_patch_context(old, code.replace("Client(", "Other("))


def test_fail_closed_view_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(sensitive, "_token_edits", lambda *a, **k: None)
    code = 'import pickle\ndef f(b):\n    return pickle.loads(b, encoding="latin-1")  # note\n'
    result, _ = scan_file(tmp_path, code)
    finding = finding_for(result, "B301")
    assert "# ***REDACTED: comment hidden***" in finding.code_snippet
    assert build_patch_context(finding, code).notes == (TEXT_NOT_COMPARED,)


def test_placeholders_are_not_wildcards(tmp_path):
    result, _ = scan_file(tmp_path, SQL_ON_CRED_LINE)
    finding = finding_for(result, "B608")
    parsed = parse_source(SQL_ON_CRED_LINE.replace('password="SYNTH_pw_abcdef"', "password=get_pw()"))
    assert finding.code_snippet not in expected_snippets(finding, parsed)


# == 5. Additional regression cases ====================================================


def test_unparseable_file_with_secrets(tmp_path):
    code = f'password = "{SECRET}"\ntoken = "{GH_TOKEN}"  # api key: {SECRET}\ndef broken(:\n'
    result, _ = scan_file(tmp_path, code)
    assert_absent(result.model_dump_json(), SECRET, GH_TOKEN)
    view = "".join(redact_file(parse_source(code), [(1, 1)]).lines)
    assert_absent(view, SECRET, GH_TOKEN)
    fake = Finding(category="hardcoded_credentials", severity="low", file_path="app.py", line=1,
                   rule_id="B105", description="x", confidence=0.5)  # fmt: skip
    with pytest.raises(PatchGenerationError) as info:
        build_patch_context(fake, code)
    assert_clean_exception(info.value, SECRET, GH_TOKEN)


def test_escaped_representations_of_secrets(tmp_path):
    value = "SYNTH_esc_value_77"
    code = (
        "import pickle\n"
        "password = \"SYNTH_\\x65sc_value_77\"\n"  # escaped in source, same value
        "def f(blob, log):\n"
        "    log(\"SYNTH_\\u0065sc_value_77\")\n"  # another escape of the same value
        f"    log(r\"prefix {value}\")  # plain copy: {value}\n"
        "    raw = b\"SYNTH_esc_value_77\"\n"
        "    return pickle.loads(blob)\n"
    )
    result, _ = scan_file(tmp_path, code)
    report = result.model_dump_json()
    assert_absent(report, value, "SYNTH_\\\\x65sc", "SYNTH_\\\\u0065sc")
    _, sdk = generate(finding_for(result, "B301"), code,
                      "@@ -7,1 +7,1 @@\n-    return pickle.loads(blob)\n+    return blob\n")  # fmt: skip
    assert_absent(sdk.sent(), value, "SYNTH_\\x65sc", "SYNTH_\\u0065sc")


def test_multiline_comments_and_docstrings(tmp_path):
    code = (
        '"""Billing service.\n'
        "\n"
        "Admin password: SYNTH_doc_pw_1\n"
        "api_key = 'SYNTH_doc_key_2'\n"
        '"""\n'
        "import pickle\n"
        "# Deployment notes:\n"
        "#   db token = SYNTH_cmt_tok_3\n"
        "#   old password was SYNTH_cmt_pw_4\n"
        "#   password is required (plain prose stays)\n"
        "def f(blob):\n"
        "    '''Load it.\n\n    secret: SYNTH_fn_doc_5\n    '''\n"
        "    return pickle.loads(blob)\n"
    )
    secrets = ("SYNTH_doc_pw_1", "SYNTH_doc_key_2", "SYNTH_cmt_tok_3", "SYNTH_cmt_pw_4", "SYNTH_fn_doc_5")
    result, _ = scan_file(tmp_path, code)
    assert_absent(result.model_dump_json(), *secrets)
    finding = finding_for(result, "B301")
    view = "".join(redact_file(parse_source(code)).lines)
    assert "#   password is required (plain prose stays)" in view
    assert len(view.splitlines()) == len(code.splitlines())
    _, sdk = generate(finding, code, "@@ -15,1 +15,1 @@\n-    return pickle.loads(blob)\n+    return blob\n")
    assert_absent(sdk.sent(), *secrets)


def test_multiple_secrets_in_one_file(tmp_path):
    secrets = ("SYNTH_m_pw_1111", "SYNTH_m_key_22222222", "SYNTH_m_tok_3333", GH_TOKEN, "SYNTH_m_sig_44444444")
    code = (
        "import pickle\n"
        "import sqlite3\n"
        f"DB_PASSWORD = \"{secrets[0]}\"\n"
        f"API_KEY = \"{secrets[1]}\"\n"
        f"CONFIG = {{\"token\": \"{secrets[2]}\", \"gh\": \"{secrets[3]}\"}}\n"
        "def run(conn, name, blob):\n"
        f"    signing_key = \"{secrets[4]}\"\n"
        f"    conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % name, password=\"{secrets[0]}\")\n"
        "    return pickle.loads(blob), signing_key\n"
    )
    result, _ = scan_file(tmp_path, code)
    assert_absent(result.model_dump_json(), *secrets)
    assert {f.rule_id for f in result.findings} >= {"B105", "B106", "B608", "B301"}
    for finding in result.findings:  # every finding is still accepted by the patcher
        context = build_patch_context(finding, code)
        assert_absent(context.render_excerpts(), *secrets)
    sqli = finding_for(result, "B608")
    assert "SELECT * FROM t" in sqli.code_snippet
    _, sdk = generate(sqli, code, (
        "@@ -8,1 +8,1 @@\n"
        f"-    conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % name, password={R})\n"
        "+    conn.execute(\"SELECT * FROM t WHERE n = ?\", (name,), password=DB_PASSWORD)\n"
    ))
    assert_absent(sdk.sent(), *secrets)


def test_no_secrets_in_prompts_errors_logs_or_cli(tmp_path, capsys, caplog):
    secrets = ("SYNTH_all_pw_9999", "SYNTH_all_key_88888888", GH_TOKEN)
    code = (
        "import pickle\n"
        f"password = \"{secrets[0]}\"  # password: {secrets[0]}\n"
        f"api_key = \"{secrets[1]}\"\n"
        f"GH = \"{secrets[2]}\"\n"
        "def f(blob):\n"
        "    return pickle.loads(blob)\n"
    )
    result, root = scan_file(tmp_path, code)
    caplog.set_level(logging.DEBUG)
    finding = finding_for(result, "B301")
    _, sdk = generate(finding, code, "@@ -6,1 +6,1 @@\n-    return pickle.loads(blob)\n+    return blob\n")
    assert_absent(sdk.sent(), *secrets)
    with pytest.raises(PatchGenerationError) as info:  # a failing generation
        generate(finding, code, "@@ -6,1 +6,1 @@\n-    return nothing\n+    return blob\n")
    assert_clean_exception(info.value, *secrets)
    out_json = tmp_path / "report.json"
    assert cli.main(["scan", str(root), "-o", str(out_json)]) in (cli.EXIT_OK, cli.EXIT_FINDINGS)
    streams = capsys.readouterr()
    everything = caplog.text + streams.out + streams.err + out_json.read_text(encoding="utf-8")
    assert_absent(everything, *secrets)
