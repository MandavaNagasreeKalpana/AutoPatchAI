"""Patch context: input validation, bounds, and redaction."""

from __future__ import annotations

import pytest
from _patch_generator_support import (
    CREDS_PATH,
    CREDS_SOURCE,
    OTHER_SECRET,
    SECRET,
    SQL_SOURCE,
    case_finding,
    make_finding,
)

from autopatch.models import AstContext, Finding
from autopatch.patch_generator import (
    ContextTooLargeError,
    InsufficientContextError,
    InvalidFindingError,
    RedactionError,
    SourceMismatchError,
    build_patch_context,
)
from autopatch.patch_generator.context import MAX_CONTEXT_LINES, MAX_SOURCE_CHARS

REDACTED = '"***REDACTED***"'


def test_sql_context_is_bounded_and_numbered():
    finding, source, _ = case_finding("sql_injection")
    context = build_patch_context(finding, source)
    assert context.target_file == "app/db.py"
    assert [(r.start, r.end) for r in context.excerpts] == [(1, 8)]
    rendered = context.render_excerpts()
    assert "6|     query = f\"SELECT * FROM users WHERE name = '{name}'\"" in rendered
    assert context.display_lines == context.original_lines  # nothing secret to mask
    assert context.newline == "\n"


@pytest.mark.parametrize("category", ["sql_injection", "hardcoded_credentials", "insecure_deserialization"])
def test_context_for_all_categories(category):
    finding, source, _ = case_finding(category)
    context = build_patch_context(finding, source)
    assert finding.line in context.shown_lines
    assert context.finding is finding


def test_credentials_are_redacted_before_anything_is_sent():
    finding, source, _ = case_finding("hardcoded_credentials")
    context = build_patch_context(finding, source)
    rendered = context.render_excerpts()

    assert SECRET not in rendered and OTHER_SECRET not in rendered
    assert f"SMTP_PASSWORD = {REDACTED}" in rendered
    assert f"BACKUP_TOKEN = {REDACTED}" in rendered  # secret-looking name, not just the flagged line
    assert SECRET in context.redacted_values and OTHER_SECRET in context.redacted_values
    assert SECRET in "".join(context.original_lines)  # real content kept only in memory
    assert SECRET not in repr(context) and "smtplib" not in repr(context)


def test_secret_looking_names_redacted_in_any_category():
    source = (
        "import sqlite3\n"
        'API_KEY = "abcd-efgh-ijkl"\n'
        "\n"
        "def q(conn, name, password='hunter2-default'):\n"
        "    return conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % name)\n"
    )
    finding = make_finding(source, 5)
    rendered = build_patch_context(finding, source).render_excerpts()
    assert "abcd-efgh-ijkl" not in rendered and "hunter2-default" not in rendered
    assert "SELECT * FROM t WHERE n = '%s'" in rendered  # the SQL being fixed is not masked


def test_known_token_formats_redacted():
    token = "gsk" + "_" + "A" * 24  # assembled at runtime
    source = SQL_SOURCE.replace("import sqlite3\n", f"import sqlite3  # debug key {token}\n")
    finding = make_finding(source, 6)
    assert token not in build_patch_context(finding, source).render_excerpts()


def test_keyword_and_default_credentials_redacted():
    source = 'def build():\n    return Client(url="https://x.invalid", token="tok-123456789")\n'
    finding = make_finding(source, 2, category="hardcoded_credentials", rule_id="B106", path=CREDS_PATH)
    rendered = build_patch_context(finding, source).render_excerpts()
    assert "tok-123456789" not in rendered and REDACTED in rendered


def test_credential_without_literal_fails_closed():
    source = "import os\n\n\ndef f(x):\n    password = x + os.sep\n    return password\n"
    finding = make_finding(source, 5, category="hardcoded_credentials", rule_id="B105", path=CREDS_PATH)
    with pytest.raises(RedactionError, match="cannot be masked"):
        build_patch_context(finding, source)


@pytest.mark.parametrize("source", ["", "   \n", None, b"bytes"])
def test_missing_source_rejected(source):
    finding, _, _ = case_finding("sql_injection")
    with pytest.raises(InsufficientContextError, match="No source content"):
        build_patch_context(finding, source)


@pytest.mark.parametrize("bad", [None, {"finding_id": "x"}, "finding"])
def test_missing_or_invalid_finding_rejected(bad):
    with pytest.raises(InvalidFindingError):
        build_patch_context(bad, SQL_SOURCE)


def test_finding_without_ast_context_rejected():
    finding = make_finding(SQL_SOURCE, 6, with_context=False)
    with pytest.raises(InsufficientContextError, match="no AST context"):
        build_patch_context(finding, SQL_SOURCE)


def test_unparseable_source_rejected():
    finding, _, _ = case_finding("sql_injection")
    with pytest.raises(InsufficientContextError, match="cannot be parsed"):
        build_patch_context(finding, SQL_SOURCE + "def broken(:\n")


def test_source_shorter_than_finding_rejected():
    finding, _, _ = case_finding("sql_injection")
    with pytest.raises(SourceMismatchError, match="only 3 lines"):
        build_patch_context(finding, "import sqlite3\n\n\n")


def test_stale_source_rejected():
    finding, _, _ = case_finding("sql_injection")
    changed = SQL_SOURCE.replace("SELECT * FROM users", "SELECT id FROM users")
    with pytest.raises(SourceMismatchError, match="does not match"):
        build_patch_context(finding, changed)


def test_oversized_source_rejected():
    finding, _, _ = case_finding("sql_injection")
    huge = SQL_SOURCE + "#" * MAX_SOURCE_CHARS
    with pytest.raises(ContextTooLargeError, match="too large"):
        build_patch_context(finding, huge)


def test_too_many_context_lines_rejected_not_truncated():
    body = "".join(f"    v{i} = {i}\n" for i in range(MAX_CONTEXT_LINES + 20))
    source = "def big(conn, name):\n" + body + "    return 1\n"
    total = len(source.splitlines())
    span = AstContext(node_type="FunctionDef", start_line=1, end_line=total, source="x")
    finding = Finding(
        finding_id="f-big", category="sql_injection", severity="low", file_path="app/big.py",
        line=5, rule_id="B608", description="d", ast_context=span, confidence=0.5,
    )
    with pytest.raises(ContextTooLargeError, match="Refusing to truncate"):
        build_patch_context(finding, source)


def test_too_many_context_characters_rejected():
    long_line = "    x = '" + "y" * 400 + "'\n"
    source = "def f(conn, name):\n" + long_line * 70 + "    return conn.execute('SELECT %s' % name)\n"
    finding = make_finding(source, 72)
    with pytest.raises(ContextTooLargeError, match="characters"):
        build_patch_context(finding, source)


def test_crlf_newline_detected():
    source = SQL_SOURCE.replace("\n", "\r\n")
    finding = make_finding(source, 6)
    assert build_patch_context(finding, source).newline == "\r\n"


B107_SOURCE = (
    "import os\n"
    "\n"
    "\n"
    'def admin_login(host: str, username: str = "admin", password: str = "Adm1n-Default-99") -> dict:\n'
    '    return {"host": host, "username": username, "password_length": len(password)}\n'
)


def test_b107_masks_only_the_password_default():
    finding = make_finding(B107_SOURCE, 4, end_line=5, category="hardcoded_credentials",
                           rule_id="B107", path=CREDS_PATH)
    context = build_patch_context(finding, B107_SOURCE)
    rendered = context.render_excerpts()
    assert context.flagged_values == ("Adm1n-Default-99",)
    assert context.fallback_redaction is False
    assert "Adm1n-Default-99" not in rendered
    assert f'def admin_login(host: str, username: str = "admin", password: str = {REDACTED}) -> dict:' in rendered
    assert '{"host": host, "username": username, "password_length": len(password)}' in rendered


def test_b105_masks_only_the_assigned_value():
    source = 'import os\nSMTP_HOST = "smtp.example.invalid"\nSMTP_PASSWORD = "S3cret-Value-1"\n'
    finding = make_finding(source, 3, category="hardcoded_credentials", rule_id="B105", path=CREDS_PATH)
    rendered = build_patch_context(finding, source).render_excerpts()
    assert 'SMTP_HOST = "smtp.example.invalid"' in rendered
    assert f"SMTP_PASSWORD = {REDACTED}" in rendered


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_multiple_secrets_on_one_line_unicode_and_line_endings(newline):
    source = (
        "import os\n"
        "\n"
        "\n"
        "def connect():\n"
        '    db(user="ünïcode-user", password="pässwörd-123", token="tök-AAAA-1111")  # old pw pässwörd-123\n'
        "    return 1\n"
    ).replace("\n", newline)
    finding = make_finding(source, 5, category="hardcoded_credentials", rule_id="B106", path=CREDS_PATH)
    context = build_patch_context(finding, source)
    rendered = context.render_excerpts()
    assert set(context.flagged_values) == {"pässwörd-123", "tök-AAAA-1111"}
    assert "pässwörd-123" not in rendered and "tök-AAAA-1111" not in rendered
    assert 'user="ünïcode-user"' in rendered  # ordinary value on the same line is kept
    assert "def connect():" in rendered and "db(" in rendered
    assert len(context.display_lines) == len(context.original_lines)
    assert all(d.endswith(newline) == o.endswith(newline)
               for d, o in zip(context.display_lines, context.original_lines))


def test_multiline_string_secret_keeps_line_positions():
    source = 'import os\nPASSWORD = """first-part\nsecond-part-SECRET\n"""\nAFTER = 1\n'
    finding = make_finding(source, 2, category="hardcoded_credentials", rule_id="B105", path=CREDS_PATH)
    context = build_patch_context(finding, source)
    assert "second-part-SECRET" not in context.render_excerpts()
    assert len(context.display_lines) == len(context.original_lines) == 5
    assert context.display_lines[4] == "AFTER = 1\n"


def test_credential_phrases_in_comments_and_docstrings_are_hidden():
    source = (
        "import sqlite3\n"
        "# admin password is Winter2026!Pass\n"
        '"""Ops note: api key: AK-12345-ZZ."""\n'
        "\n"
        "def q(conn, n):\n"
        "    return conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % n)\n"
    )
    rendered = build_patch_context(make_finding(source, 6), source).render_excerpts()
    assert "Winter2026!Pass" not in rendered and "AK-12345-ZZ" not in rendered
    assert "SELECT * FROM t WHERE n = '%s'" in rendered  # code strings are not phrase-masked


def test_short_secret_masked_wherever_it_is_a_literal():
    source = 'import os\nPASSWORD = "abc"\n\n\ndef f():\n    return PASSWORD + "abc"\n'
    finding = make_finding(source, 2, category="hardcoded_credentials", rule_id="B105", path=CREDS_PATH)
    context = build_patch_context(finding, source)
    assert context.display_lines[5] == f"    return PASSWORD + {REDACTED}\n"


def test_identifiers_and_authorization_code_are_never_rewritten():
    source = (
        "import requests\n"
        'API_TOKEN = "tok-live-1234567"\n'
        "\n"
        "def call(conn, name, token):\n"
        '    headers = {"Authorization": token}\n'
        "    return conn.execute(\"SELECT * FROM t WHERE n = '%s'\" % name, headers)\n"
    )
    rendered = build_patch_context(make_finding(source, 6), source).render_excerpts()
    assert '    headers = {"Authorization": token}' in rendered
    assert "def call(conn, name, token):" in rendered
    assert "tok-live-1234567" not in rendered


def test_unidentifiable_credential_uses_fallback_line_masking():
    source = 'import os\nconn = connect("s3cr3t-positional", "localhost")\n'
    finding = make_finding(source, 2, category="hardcoded_credentials", rule_id="B105", path=CREDS_PATH)
    context = build_patch_context(finding, source)
    assert context.fallback_redaction is True
    assert "s3cr3t-positional" not in context.render_excerpts()
    assert context.display_lines[1] == f"conn = connect({REDACTED}, {REDACTED})\n"


def test_far_away_code_is_not_included():
    source = SQL_SOURCE + "\n" * 30 + "def unrelated_helper():\n    return 'UNRELATED-MARKER'\n"
    finding = make_finding(source, 6)
    rendered = build_patch_context(finding, source).render_excerpts()
    assert "UNRELATED-MARKER" not in rendered
    assert "not shown" in rendered
