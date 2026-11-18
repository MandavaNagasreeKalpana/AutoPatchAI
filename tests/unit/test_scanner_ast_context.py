"""AST context extraction and literal redaction (parse-only, never executed)."""

from __future__ import annotations

import textwrap

from autopatch.scanner.ast_context import (
    MAX_CONTEXT_LINES,
    REDACTED_LITERAL,
    build_context,
    decode_source,
    extract_snippet,
    parse_source,
    redact_string_literals,
    split_lines,
)


def parse(code: str):
    return parse_source(textwrap.dedent(code).lstrip("\n"))


def test_function_context():
    parsed = parse(
        """
        import sqlite3
        from os import path

        def find(conn, name):
            q = f"SELECT * FROM t WHERE n = '{name}'"
            return conn.execute(q)
        """
    )
    ctx = build_context(parsed, 5, 5)
    assert ctx.node_type == "FunctionDef"
    assert (ctx.start_line, ctx.end_line) == (4, 6)
    assert ctx.enclosing_function == "find"
    assert ctx.enclosing_class is None
    assert ctx.source.startswith("def find(conn, name):")
    assert ctx.imports == ["import sqlite3", "from os import path"]


def test_method_context_has_qualified_name_and_class():
    parsed = parse(
        """
        class Repo:
            table = "users"

            def find(self, name):
                return self.db.execute("SELECT * FROM t WHERE n = '%s'" % name)
        """
    )
    ctx = build_context(parsed, 5, 5)
    assert ctx.node_type == "FunctionDef"
    assert ctx.enclosing_function == "Repo.find"
    assert ctx.enclosing_class == "Repo"
    assert (ctx.start_line, ctx.end_line) == (4, 5)


def test_class_level_finding_uses_class_context():
    parsed = parse(
        """
        class Settings:
            debug = False
            password = "hunter2"
        """
    )
    ctx = build_context(parsed, 3, 3)
    assert ctx.node_type == "ClassDef"
    assert ctx.enclosing_class == "Settings"
    assert ctx.enclosing_function is None


def test_nested_and_async_functions():
    parsed = parse(
        """
        def outer():
            async def inner(x):
                return await load(x)
            return inner
        """
    )
    ctx = build_context(parsed, 3, 3)
    assert ctx.node_type == "AsyncFunctionDef"
    assert ctx.enclosing_function == "outer.inner"
    assert (ctx.start_line, ctx.end_line) == (2, 3)


def test_decorators_are_included_in_span():
    parsed = parse(
        """
        @app.route("/x")
        @login_required
        def view(req):
            return pickle.loads(req.body)
        """
    )
    ctx = build_context(parsed, 4, 4)
    assert ctx.start_line == 1
    assert ctx.source.startswith('@app.route("/x")')


def test_module_level_statement_context():
    parsed = parse(
        """
        import os

        PASSWORD = "hunter2"
        """
    )
    ctx = build_context(parsed, 3, 3)
    assert ctx.node_type == "Assign"
    assert (ctx.start_line, ctx.end_line) == (3, 3)
    assert ctx.enclosing_function is None and ctx.enclosing_class is None


def test_large_function_falls_back_to_statement():
    body = "".join(f"    v{i} = {i}\n" for i in range(MAX_CONTEXT_LINES + 10))
    code = "def huge():\n" + body + "    return pickle.loads(data)\n"
    parsed = parse_source(code)
    last = len(parsed.lines)
    ctx = build_context(parsed, last, last)
    assert ctx.node_type == "Return"
    assert (ctx.start_line, ctx.end_line) == (last, last)
    assert ctx.enclosing_function == "huge"  # still reported


def test_multiline_statement_context():
    parsed = parse(
        """
        x = run(
            "SELECT * FROM t WHERE a = %s"
            % value
        )
        """
    )
    ctx = build_context(parsed, 2, 3)
    assert (ctx.start_line, ctx.end_line) == (1, 4)


def test_syntax_error_is_handled():
    parsed = parse_source("def broken(:\n    pass\n")
    assert parsed.tree is None
    assert "syntax error" in parsed.error
    assert build_context(parsed, 1, 1) is None


def test_null_bytes_are_handled():
    parsed = parse_source("x = 1\x00\n")
    assert parsed.tree is None and parsed.error


def test_line_out_of_range_returns_none():
    parsed = parse_source("x = 1\n")
    assert build_context(parsed, 5, 5) is None
    assert build_context(parsed, 0, 0) is None


def test_parse_does_not_execute(tmp_path):
    marker = tmp_path / "ran.txt"
    parsed = parse_source(f"open({str(marker)!r}, 'w').write('x')\n")
    build_context(parsed, 1, 1)
    assert not marker.exists()


def test_snippet_is_bounded():
    lines = [f"line{i}\n" for i in range(1, 101)]
    assert extract_snippet(lines, 3, 4) == "line3\nline4\n"
    assert extract_snippet(lines, 1, 100).count("\n") == 20


def test_split_lines_matches_ast_numbering():
    text = "a = 1\x0c\nb = 2\r\nc = 3"
    assert split_lines(text) == ["a = 1\x0c\n", "b = 2\r\n", "c = 3"]


def test_decode_source_honours_coding_declaration():
    data = "# -*- coding: latin-1 -*-\nname = 'caf\xe9'\n".encode("latin-1")
    assert "café" in decode_source(data)


# --- redaction ---------------------------------------------------------------


def test_redacts_literals_on_flagged_line_only():
    parsed = parse(
        """
        USER = "admin"
        PASSWORD = "hunter2"  # comment
        """
    )
    lines, values = redact_string_literals(parsed, 2, 2)
    assert lines[0] == 'USER = "admin"\n'
    assert lines[1] == f"PASSWORD = {REDACTED_LITERAL}  # comment\n"
    assert values == ["hunter2"]


def test_redacts_several_literals_with_unicode_prefix():
    parsed = parse_source('connect(host="hé", password="päss", token=b"tok")\n')
    lines, values = redact_string_literals(parsed, 1, 1)
    assert lines[0] == (
        f"connect(host={REDACTED_LITERAL}, password={REDACTED_LITERAL}, token={REDACTED_LITERAL})\n"
    )
    assert set(values) == {"hé", "päss", "tok"}


def test_redacts_fstrings_and_keeps_line_count():
    parsed = parse(
        '''
        key = f"prefix-{x}"
        doc = """first
        secret line
        last"""
        after = 1
        '''
    )
    lines, _ = redact_string_literals(parsed, 1, 2)
    assert len(lines) == len(parsed.lines)
    assert lines[0] == f"key = {REDACTED_LITERAL}\n"
    assert "secret" not in "".join(lines)
    assert lines[-1] == "after = 1\n"


def test_redaction_without_tree_blanks_lines():
    parsed = parse_source('password = "x"\ndef broken(:\n')
    lines, _ = redact_string_literals(parsed, 1, 1)
    assert "x" not in lines[0].split("#", 1)[0]
    assert lines[0].startswith("# ***REDACTED")


def test_context_uses_redacted_display_lines():
    parsed = parse(
        """
        def login(user, password="hunter2"):
            return user
        """
    )
    lines, _ = redact_string_literals(parsed, 1, 1)
    ctx = build_context(parsed, 1, 2, lines)
    assert "hunter2" not in ctx.source
    assert REDACTED_LITERAL in ctx.source
