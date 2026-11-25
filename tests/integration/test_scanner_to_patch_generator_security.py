"""Scanner -> Patch Generator security regressions (audit H-1 to H-4).

Real Bandit scans of temporary files, then the real Patch Generator with the
real GroqClient over a fake SDK (no network). All secrets are synthetic;
token-shaped values are assembled at runtime.
"""

from __future__ import annotations

import ast
import json
import tokenize
from pathlib import Path
from types import SimpleNamespace

import pytest

from autopatch.config import Settings
from autopatch.llm import GroqClient
from autopatch.models import Finding
from autopatch.patch_generator import PatchGeneratorAgent, build_messages, build_patch_context
from autopatch.patch_generator.errors import SourceMismatchError, UnsafePatchError
from autopatch.scanner import ScannerAgent
from autopatch.scanner import scanner as scanner_mod
from autopatch.common import sensitive
from autopatch.common.source import (
    parse_source,
    split_lines,
)
from autopatch.scanner.ast_context import module_imports

GH_TOKEN = "ghp" + "_" + "T" * 36


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


def scan_file(tmp_path: Path, code: str, name: str = "app.py"):
    root = tmp_path / "proj"
    root.mkdir(exist_ok=True)
    (root / name).write_bytes(code.encode("utf-8"))  # exact line endings
    return ScannerAgent().scan(root), root


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


# --- workflow cases ---------------------------------------------------------------

SQLI_PW_ON_LINE = (
    "import sqlite3\n\n\n"
    "def find(conn, name):\n"
    "    return conn.execute(\"SELECT * FROM users WHERE name = '%s'\" % name, password=\"SYNTH_S1_pw_0123\")\n"
)
SQLI_PW_ON_LINE_DIFF = (
    "@@ -1,5 +1,6 @@\n"
    "+import os\n"
    " import sqlite3\n \n \n"
    " def find(conn, name):\n"
    "-    return conn.execute(\"SELECT * FROM users WHERE name = '%s'\" % name, password=\"***REDACTED***\")\n"
    "+    return conn.execute(\"SELECT * FROM users WHERE name = ?\", (name,), password=os.environ[\"DB_PASSWORD\"])\n"
)

SQLI_KEY_ON_LINE = SQLI_PW_ON_LINE.replace('password="SYNTH_S1_pw_0123"', 'api_key="SYNTH_S2_key_0123456789"')
SQLI_KEY_ON_LINE_DIFF = SQLI_PW_ON_LINE_DIFF.replace("password=", "api_key=").replace("DB_PASSWORD", "API_KEY")

SQLI_ELSEWHERE = (
    "def find(conn, name):\n"
    "    database_password = \"SYNTH_DB_0123456789\"\n"
    "    conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)\n"
    "    return database_password\n"
)
SQLI_ELSEWHERE_DIFF = (
    "@@ -3,1 +3,1 @@\n"
    "-    conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)\n"
    "+    conn.execute(\"SELECT * FROM t WHERE n = ?\", (name,))\n"
)

DESER_ON_LINE = (
    "import pickle\n\n\n"
    "def load(blob):\n"
    "    return pickle.loads(blob), {\"api_key\": \"SYNTH_S3_key_0123456789\"}\n"
)
DESER_ON_LINE_DIFF = (
    "@@ -1,5 +1,6 @@\n"
    "-import pickle\n"
    "+import json\n"
    "+import os\n"
    " \n \n"
    " def load(blob):\n"
    "-    return pickle.loads(blob), {\"api_key\": \"***REDACTED***\"}\n"
    "+    return json.loads(blob), {\"api_key\": os.environ[\"API_KEY\"]}\n"
)

DESER_ELSEWHERE = (
    "import pickle\n\n\n"
    "def load(blob):\n"
    "    signing_key = \"SYNTH_D_0123456789\"\n"
    "    return pickle.loads(blob), signing_key\n"
)
DESER_ELSEWHERE_DIFF = (
    "@@ -1,6 +1,6 @@\n"
    "-import pickle\n"
    "+import json\n"
    " \n \n"
    " def load(blob):\n"
    "     signing_key = \"***REDACTED***\"\n"
    "-    return pickle.loads(blob), signing_key\n"
    "+    return json.loads(blob), signing_key\n"
)

CREDS = (
    "import smtplib\n\n"
    "SMTP_PASSWORD = \"SYNTH_CRED_pw_0123\"\n\n\n"
    "def send(server):\n"
    "    server.login(\"bot\", SMTP_PASSWORD)\n"
)
CREDS_DIFF = (
    "@@ -1,3 +1,4 @@\n"
    "+import os\n"
    " import smtplib\n \n"
    "-SMTP_PASSWORD = \"***REDACTED***\"\n"
    "+SMTP_PASSWORD = os.environ[\"SMTP_PASSWORD\"]\n"
)

WORKFLOW = {
    "sqli_password_on_flagged_line": (SQLI_PW_ON_LINE, "B608", SQLI_PW_ON_LINE_DIFF, "SYNTH_S1_pw_0123"),
    "sqli_api_key_on_flagged_line": (SQLI_KEY_ON_LINE, "B608", SQLI_KEY_ON_LINE_DIFF, "SYNTH_S2_key_0123456789"),
    "sqli_secret_elsewhere": (SQLI_ELSEWHERE, "B608", SQLI_ELSEWHERE_DIFF, "SYNTH_DB_0123456789"),
    "deser_dict_secret_on_flagged_line": (DESER_ON_LINE, "B301", DESER_ON_LINE_DIFF, "SYNTH_S3_key_0123456789"),
    "deser_signing_key_elsewhere": (DESER_ELSEWHERE, "B301", DESER_ELSEWHERE_DIFF, "SYNTH_D_0123456789"),
    "hardcoded_credential": (CREDS, "B105", CREDS_DIFF, "SYNTH_CRED_pw_0123"),
}


@pytest.mark.parametrize("case", sorted(WORKFLOW))
def test_scanner_to_patch_generator_workflow(tmp_path, case):
    code, rule, diff, secret = WORKFLOW[case]
    result, _ = scan_file(tmp_path, code)
    assert result.errors == []
    finding = finding_for(result, rule)  # detected by real Bandit
    assert_absent(result.model_dump_json(), secret)  # scanner report redacted
    assert "***REDACTED***" in finding.ast_context.source

    context = build_patch_context(finding, code)  # H-1: no false SourceMismatchError
    assert_absent(context.render_excerpts(), secret)

    generation, sdk = generate(finding, code, diff)  # completes with a mocked Groq reply
    assert len(sdk.calls) == 1
    assert_absent(sdk.sent(), secret)  # H-4: nothing secret reaches the model
    assert_absent(generation.candidate.patch.model_dump_json(), secret)
    patched = generation.patched_source.reveal_for_verification()
    assert parse_source(patched).tree is not None
    assert "***REDACTED***" not in patched  # real values restored, never placeholders


# --- H-1: stale-source protection with redacted snippets -------------------------------


def test_genuine_change_on_flagged_line_is_rejected(tmp_path):
    result, _ = scan_file(tmp_path, SQLI_KEY_ON_LINE)
    finding = finding_for(result, "B608")
    changed = SQLI_KEY_ON_LINE.replace("FROM users", "FROM accounts")
    with pytest.raises(SourceMismatchError):
        build_patch_context(finding, changed)


TWO_SECRETS_ON_LINE = SQLI_PW_ON_LINE.replace(
    'password="SYNTH_S1_pw_0123")', 'password="SYNTH_S1_pw_0123", timeout=name, token="SYNTH_S1_tk_4567")'
)


def test_change_between_two_placeholders_is_rejected(tmp_path):
    result, _ = scan_file(tmp_path, TWO_SECRETS_ON_LINE)  # B106 x2 + B608 share the line
    finding = finding_for(result, "B608")
    assert finding.code_snippet.count("***REDACTED***") == 2  # multiple placeholders
    assert "SELECT * FROM users" in finding.code_snippet  # the SQL itself is not hidden
    build_patch_context(finding, TWO_SECRETS_ON_LINE)  # unchanged source is accepted
    changed = TWO_SECRETS_ON_LINE.replace("timeout=name,", "timeout=other,")
    with pytest.raises(SourceMismatchError):
        build_patch_context(finding, changed)


def test_changed_secret_value_only_is_accepted(tmp_path):
    """The hidden value itself cannot be compared (it is never stored), but
    this is reported in the context notes rather than passed silently."""
    from autopatch.patch_generator.context import SECRET_NOT_COMPARED

    result, _ = scan_file(tmp_path, SQLI_KEY_ON_LINE)
    finding = finding_for(result, "B608")
    rotated = SQLI_KEY_ON_LINE.replace("SYNTH_S2_key_0123456789", "SYNTH_S2_new_9876543210")
    context = build_patch_context(finding, rotated)
    assert_absent(context.render_excerpts(), "SYNTH_S2_new")
    assert context.notes == (SECRET_NOT_COMPARED,)


@pytest.mark.parametrize(
    "forged",
    [
        "    return conn.execute(\"***REDACTED***\")\n",  # placeholder standing in for code
        "    return conn.execute(\"SELECT * FROM users WHERE name = '%s'\" % name, api_key=\"***REDACTED**\")\n",
        "    return conn.execute(\"SELECT * FROM users WHERE name = '%s'\" % name, api_key=***REDACTED***)\n",
    ],
)
def test_forged_or_malformed_placeholders_are_rejected(tmp_path, forged):
    result, _ = scan_file(tmp_path, SQLI_KEY_ON_LINE)
    finding = finding_for(result, "B608").model_copy(update={"code_snippet": forged})
    with pytest.raises(SourceMismatchError):
        build_patch_context(finding, SQLI_KEY_ON_LINE)


def test_source_that_contains_the_placeholder_text(tmp_path):
    code = (
        "def find(conn, name):\n"
        "    conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % name, note=\"***REDACTED***\")\n"
    )
    result, _ = scan_file(tmp_path, code)
    finding = finding_for(result, "B608")
    context = build_patch_context(finding, code)
    assert 'note="***REDACTED***"' in context.render_excerpts()


# --- H-2: import context ---------------------------------------------------------------

IMPORTS = (
    "from os import (path,  # password = \"SYNTH_IMP_pw_0123\"\n"
    "    sep)\n"
    f"from json import (loads,  # spare token {GH_TOKEN}\n"
    "    dumps)\n"
    "import pickle\n\n\n"
    "def load(conn, blob, name):\n"
    "    conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)\n"
    "    return pickle.loads(blob)\n"
)


def test_import_comments_never_reach_findings(tmp_path):
    result, _ = scan_file(tmp_path, IMPORTS)
    assert {f.rule_id for f in result.findings} >= {"B608", "B301"}
    assert_absent(result.model_dump_json(), "SYNTH_IMP_pw_0123", GH_TOKEN)
    for finding in (finding_for(result, "B608"), finding_for(result, "B301")):
        assert finding.ast_context.imports == [
            "from os import path, sep",
            "from json import loads, dumps",
            "import pickle",
        ]


def test_imports_are_computed_once_per_file(tmp_path, monkeypatch):
    calls = []

    def counting(parsed):
        calls.append(1)
        return module_imports(parsed)

    monkeypatch.setattr(scanner_mod, "module_imports", counting)
    result, _ = scan_file(tmp_path, IMPORTS)
    assert len(result.findings) + len(result.related_findings) >= 3
    assert len(calls) == 1


# --- H-3: line endings ------------------------------------------------------------------

LE_LINES = [
    "import pickle",
    "def load(conn, blob, name):",
    "    api_token = \"SYNTH_LE_tok_0123456789\"",
    "    # copy: SYNTH_LE_tok_0123456789",
    "    msg = f\"key={api_token} raw SYNTH_LE_tok_0123456789\"",
    "    conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)",
    "    return pickle.loads(blob), msg",
]


def _join(endings: list[str]) -> str:
    return "".join(line + endings[i % len(endings)] for i, line in enumerate(LE_LINES))


@pytest.mark.parametrize(
    "endings", [["\n"], ["\r\n"], ["\r"], ["\n", "\r\n", "\r"], ["\r", "\n"]], ids=["lf", "crlf", "cr", "mixed3", "mixed2"]
)
def test_line_endings_do_not_break_redaction(tmp_path, endings):
    code = _join(endings)
    result, _ = scan_file(tmp_path, code)
    assert result.errors == []
    sqli, deser = finding_for(result, "B608"), finding_for(result, "B301")
    assert (sqli.line, deser.line) == (6, 7)  # line numbers unchanged
    assert_absent(result.model_dump_json(), "SYNTH_LE_tok_0123456789")

    view = sensitive.redact_file(parse_source(code))
    assert view.complete
    original = split_lines(code)
    assert len(view.lines) == len(original)
    assert [l[len(l.rstrip("\r\n")):] for l in view.lines] == [l[len(l.rstrip("\r\n")):] for l in original]
    text = "".join(view.lines)
    assert "def load(conn, blob, name):" in text and "api_token = " in text
    assert "conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)" in text
    assert "msg = " in text and "return pickle.loads(blob), msg" in text
    assert parse_source(text).tree is not None  # still valid code

    context = build_patch_context(sqli, code)  # and the Patch Generator agrees
    assert_absent(context.render_excerpts(), "SYNTH_LE_tok_0123456789")


def _assert_fail_closed(view, code):
    assert not view.complete
    text = "".join(view.lines)
    assert "SYNTH_LE" not in text
    assert len(view.lines) == len(split_lines(code))
    assert sensitive.HIDDEN_COMMENT in text  # every comment hidden
    assert "def load(conn, blob, name):" in text and "return pickle.loads(blob), msg" in text
    tree = ast.parse(text)
    assert all(
        n.value == "***REDACTED***"
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    )


def test_untokenizable_source_fails_closed(monkeypatch):
    code = _join(["\r"])

    def broken(readline):
        raise tokenize.TokenError("synthetic failure")

    monkeypatch.setattr(sensitive.tokenize, "generate_tokens", broken)
    _assert_fail_closed(sensitive.redact_file(parse_source(code)), code)


def test_unmappable_token_positions_fail_closed(monkeypatch):
    code = _join(["\n", "\r"])
    monkeypatch.setattr(sensitive, "_token_text_matches", lambda lines, tok: False)
    _assert_fail_closed(sensitive.redact_file(parse_source(code)), code)


# --- H-4: shared detection before the prompt ---------------------------------------------

MANY = (
    "import pickle\n\n\n"
    "def load(blob, log):\n"
    "    \"\"\"Loader. Example: password = \"SYNTH_M_doc_0123\".\"\"\"\n"
    "    private_key = \"SYNTH_M_priv_0123456789\"\n"
    "    access_token = \"SYNTH_M_tok_0123456789\"\n"
    "    # rotate SYNTH_M_tok_0123456789 monthly\n"
    "    log(f\"using {access_token[:4]} / SYNTH_M_priv_0123456789\")\n"
    "    return pickle.loads(blob)\n"
)
MANY_DIFF = (
    "@@ -1,1 +1,1 @@\n"
    "-import pickle\n"
    "+import json\n"
    "@@ -10,1 +10,1 @@\n"
    "-    return pickle.loads(blob)\n"
    "+    return json.loads(blob)\n"
)
MANY_SECRETS = ("SYNTH_M_doc_0123", "SYNTH_M_priv_0123456789", "SYNTH_M_tok_0123456789")


def test_many_secret_forms_never_reach_the_model(tmp_path):
    result, _ = scan_file(tmp_path, MANY)
    finding = finding_for(result, "B301")
    assert_absent(result.model_dump_json(), *MANY_SECRETS)
    messages = build_messages(build_patch_context(finding, MANY))
    assert_absent("\n".join(m.content for m in messages), *MANY_SECRETS)
    generation, sdk = generate(finding, MANY, MANY_DIFF)
    assert_absent(sdk.sent(), *MANY_SECRETS)
    real = generation.patched_source.reveal_for_verification()
    assert all(secret in real for secret in MANY_SECRETS[1:])  # real file keeps its code


def test_placeholder_copied_into_code_is_still_rejected(tmp_path):
    result, _ = scan_file(tmp_path, SQLI_PW_ON_LINE)
    finding = finding_for(result, "B608")
    keep_placeholder = (
        "@@ -5,1 +5,1 @@\n"
        "-    return conn.execute(\"SELECT * FROM users WHERE name = '%s'\" % name, password=\"***REDACTED***\")\n"
        "+    return conn.execute(\"SELECT * FROM users WHERE name = ?\", (name,), password=\"***REDACTED***\")\n"
    )
    with pytest.raises(UnsafePatchError):
        generate(finding, SQLI_PW_ON_LINE, keep_placeholder)


def test_patcher_and_scanner_agree_on_secret_names():
    from autopatch.patch_generator.secrets import is_sensitive

    for name in ("signing_key", "database_password", "private_key", "access_token", "auth", "bearer"):
        assert is_sensitive(name), name
    for name in ("username", "cache", "author", "base_url"):
        assert not is_sensitive(name), name
