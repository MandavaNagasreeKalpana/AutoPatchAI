"""Locate code context for a finding with Python's ``ast`` module.

Source code is only parsed (``ast.parse`` builds a syntax tree); it is never
compiled to bytecode, imported or executed.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass

from autopatch.models import AstContext

MAX_CONTEXT_LINES = 150
MAX_SNIPPET_LINES = 20
MAX_IMPORTS = 50
REDACTED_LITERAL = '"***REDACTED***"'

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
# ast counts only \r\n, \r and \n as line breaks (unlike str.splitlines).
_LINE_RE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n|$)")


def decode_source(data: bytes) -> str:
    """Decode bytes using the PEP 263 encoding declaration (default UTF-8)."""
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    except SyntaxError:
        encoding = "utf-8"
    return data.decode(encoding, errors="replace")


def split_lines(text: str) -> list[str]:
    lines = _LINE_RE.findall(text)
    if lines and lines[-1] == "":
        lines.pop()
    return lines


@dataclass(frozen=True)
class ParsedSource:
    text: str
    lines: tuple[str, ...]  # with line endings, numbered from 1 via index+1
    tree: ast.Module | None
    error: str | None = None


def parse_source(text: str, filename: str = "<scanned>") -> ParsedSource:
    lines = tuple(split_lines(text))
    try:
        tree = ast.parse(text, filename=filename)
    except SyntaxError as exc:
        return ParsedSource(text, lines, None, f"syntax error at line {exc.lineno}")
    except ValueError as exc:  # e.g. NUL bytes
        return ParsedSource(text, lines, None, f"cannot parse source: {exc}")
    return ParsedSource(text, lines, tree)


def node_span(node: ast.AST) -> tuple[int, int]:
    start = node.lineno  # type: ignore[attr-defined]
    for decorator in getattr(node, "decorator_list", ()):
        start = min(start, decorator.lineno)
    end = getattr(node, "end_lineno", None) or start
    return start, end


def _contains(node: ast.AST, line: int, end_line: int) -> bool:
    start, end = node_span(node)
    return start <= line and end_line <= end


def _size(node: ast.AST) -> int:
    start, end = node_span(node)
    return end - start + 1


def enclosing_scopes(tree: ast.Module, line: int, end_line: int) -> list[ast.AST]:
    """Function/class nodes containing the lines, ordered outermost first."""
    scopes = [n for n in ast.walk(tree) if isinstance(n, _SCOPES) and _contains(n, line, end_line)]
    return sorted(scopes, key=_size, reverse=True)


def innermost_statement(tree: ast.Module, line: int, end_line: int) -> ast.stmt | None:
    stmts = [n for n in ast.walk(tree) if isinstance(n, ast.stmt) and _contains(n, line, end_line)]
    return min(stmts, key=_size) if stmts else None


def _module_imports(parsed: ParsedSource) -> list[str]:
    assert parsed.tree is not None
    imports = []
    for node in parsed.tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            segment = ast.get_source_segment(parsed.text, node) or ast.unparse(node)
            imports.append(" ".join(segment.split()))
            if len(imports) >= MAX_IMPORTS:
                break
    return imports


def build_context(
    parsed: ParsedSource,
    line: int,
    end_line: int,
    display_lines: tuple[str, ...] | list[str] | None = None,
) -> AstContext | None:
    """Return the smallest replaceable unit around the finding.

    Preference: the innermost enclosing function/class if it has at most
    ``MAX_CONTEXT_LINES`` lines; otherwise the innermost statement containing
    the lines. Returns ``None`` when the file does not parse or no bounded
    node contains the lines.

    ``display_lines`` (e.g. with redacted literals) supplies the text; spans
    always come from the real syntax tree.
    """
    tree = parsed.tree
    if tree is None or line < 1 or line > len(parsed.lines):
        return None
    end_line = max(line, min(end_line, len(parsed.lines)))
    text_lines = parsed.lines if display_lines is None else display_lines

    scopes = enclosing_scopes(tree, line, end_line)
    chosen: ast.AST | None = None
    if scopes and _size(scopes[-1]) <= MAX_CONTEXT_LINES:
        chosen = scopes[-1]
    else:
        stmt = innermost_statement(tree, line, end_line)
        if stmt is not None and _size(stmt) <= MAX_CONTEXT_LINES:
            chosen = stmt
    if chosen is None:
        return None

    start, end = node_span(chosen)
    names: list[str] = []
    function_name: str | None = None
    class_name: str | None = None
    for scope in scopes:
        names.append(scope.name)  # type: ignore[attr-defined]
        if isinstance(scope, _FUNCTIONS):
            function_name = ".".join(names)
        else:
            class_name = scope.name  # type: ignore[attr-defined]

    return AstContext(
        node_type=type(chosen).__name__,
        start_line=start,
        end_line=end,
        source="".join(text_lines[start - 1 : end]),
        enclosing_function=function_name,
        enclosing_class=class_name,
        imports=_module_imports(parsed),
    )


def extract_snippet(lines: tuple[str, ...] | list[str], line: int, end_line: int) -> str:
    last = min(end_line, line + MAX_SNIPPET_LINES - 1, len(lines))
    return "".join(lines[line - 1 : last])


def redact_string_literals(
    parsed: ParsedSource, line: int, end_line: int
) -> tuple[list[str], list[str]]:
    """Replace string/bytes literals that start on lines ``line..end_line``
    with a placeholder, keeping line numbers unchanged.

    Returns ``(display_lines, redacted_values)``. Without a syntax tree, every
    line in the range is replaced entirely.
    """
    lines = list(parsed.lines)
    if parsed.tree is None:
        for i in range(line - 1, min(end_line, len(lines))):
            ending = lines[i][len(lines[i].rstrip("\r\n")) :]
            lines[i] = "# ***REDACTED: line could not be parsed***" + ending
        return lines, []

    nested: set[int] = set()
    for node in ast.walk(parsed.tree):
        if isinstance(node, ast.JoinedStr):
            nested.update(id(child) for child in ast.walk(node) if child is not node)

    targets = []
    values: list[str] = []
    for node in ast.walk(parsed.tree):
        if id(node) in nested:
            continue
        is_literal = isinstance(node, ast.JoinedStr) or (
            isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))
        )
        if is_literal and line <= node.lineno <= end_line:
            targets.append(node)
            if isinstance(node, ast.Constant):
                value = node.value
                values.append(value if isinstance(value, str) else value.decode("latin-1"))

    # Replace right-to-left so earlier byte offsets stay valid.
    for node in sorted(targets, key=lambda n: (n.lineno, n.col_offset), reverse=True):
        first, last = node.lineno - 1, node.end_lineno - 1
        head = lines[first].encode("utf-8")[: node.col_offset].decode("utf-8", "replace")
        tail = lines[last].encode("utf-8")[node.end_col_offset :].decode("utf-8", "replace")
        if first == last:
            lines[first] = head + REDACTED_LITERAL + tail
        else:
            ending = lines[first][len(lines[first].rstrip("\r\n")) :]
            lines[first] = head + REDACTED_LITERAL + ending
            for i in range(first + 1, last):
                lines[i] = lines[i][len(lines[i].rstrip("\r\n")) :]
            lines[last] = tail
    return lines, values
