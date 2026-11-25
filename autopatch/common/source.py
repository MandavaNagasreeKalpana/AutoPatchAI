"""Source handling shared by every agent (parse only, never executed).

Decoding, line splitting, parsing with ``ast.parse``, bounded snippets and
line-preserving literal redaction. Agents import these from here instead of
from each other.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass

MAX_SNIPPET_LINES = 20
REDACTED_LITERAL = '"***REDACTED***"'
TRUNCATION_TAG = "[AutoPatch: truncated,"
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


def bound_text(text: str, limit: int) -> str:
    """Return ``text`` unchanged if it fits in ``limit`` characters, otherwise
    its beginning followed by an explicit truncation marker (total <= limit)."""
    if len(text) <= limit:
        return text
    marker = f"\n# {TRUNCATION_TAG} {len(text) - limit} or more characters omitted]\n"
    return text[: max(0, limit - len(marker))] + marker


def is_truncated(text: str) -> bool:
    return TRUNCATION_TAG in text


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
