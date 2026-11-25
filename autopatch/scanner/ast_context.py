"""Locate code context for a finding with Python's ``ast`` module.

Source code is only parsed (``ast.parse`` builds a syntax tree); it is never
compiled to bytecode, imported or executed.
"""

from __future__ import annotations

import ast

from autopatch.models import AstContext
from autopatch.models.common import MAX_CODE_CHARS

# Shared source helpers (also re-exported here for existing scanner callers).
from autopatch.common.source import (  # noqa: F401
    MAX_SNIPPET_LINES,
    REDACTED_LITERAL,
    TRUNCATION_TAG,
    ParsedSource,
    bound_text,
    decode_source,
    extract_snippet,
    is_truncated,
    parse_source,
    redact_string_literals,
    split_lines,
)

MAX_IMPORT_CHARS = 2_000
MAX_CONTEXT_LINES = 150
MAX_IMPORTS = 50

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


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


def module_imports(parsed: ParsedSource) -> list[str]:
    """Top-level imports rendered from the syntax tree with ``ast.unparse``.

    The text is regenerated from AST nodes, never copied from the source, so
    comments (which can hold secrets, e.g. inside a parenthesised multi-line
    import) cannot appear. Compute once per file and pass to
    :func:`build_context`.
    """
    if parsed.tree is None:
        return []
    imports = []
    for node in parsed.tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imports.append(bound_text(ast.unparse(node), MAX_IMPORT_CHARS))
            if len(imports) >= MAX_IMPORTS:
                break
    return imports


def build_context(
    parsed: ParsedSource,
    line: int,
    end_line: int,
    display_lines: tuple[str, ...] | list[str] | None = None,
    imports: list[str] | None = None,
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
        source=bound_text("".join(text_lines[start - 1 : end]), MAX_CODE_CHARS),
        enclosing_function=function_name,
        enclosing_class=class_name,
        imports=list(module_imports(parsed) if imports is None else imports),
    )
