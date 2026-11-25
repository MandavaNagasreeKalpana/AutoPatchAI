"""Locate hardcoded credential literals with the AST (parse only).

Shared by context redaction (what to hide from the LLM) and the static
safety checks (whether a patch removed or introduced a hardcoded secret).
The rule-specific kinds mirror Bandit's checks:

* B105 ``assign``:  ``password = "x"``, ``obj.token = "x"``, ``d["secret"] = "x"``,
  ``password == "x"`` and ``{"password": "x"}``
* B106 ``keyword``: ``connect(password="x")``
* B107 ``default``: ``def f(password="x")``
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from autopatch.common.sensitive import CREDENTIAL_NAME, STRONG, name_strength

ASSIGN = "assign"
KEYWORD = "keyword"
DEFAULT = "default"
ALL_KINDS = frozenset({ASSIGN, KEYWORD, DEFAULT})
RULE_KINDS = {"B105": frozenset({ASSIGN}), "B106": frozenset({KEYWORD}), "B107": frozenset({DEFAULT})}

SENSITIVE_NAME = CREDENTIAL_NAME  # one definition, shared with the scanner


def is_sensitive(name: str | None) -> bool:
    """Secret-looking name: this module's Bandit-style pattern, or a strong
    match from the scanner's shared detector (``signing_key``, ``auth``,
    ``bearer``, ...), so the two components agree on what is a secret."""
    if not name:
        return False
    return bool(SENSITIVE_NAME.search(name)) or name_strength(name) == STRONG


def is_str_literal(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def literal_value(node: ast.Constant) -> str:
    value = node.value
    return value if isinstance(value, str) else value.decode("latin-1")


def _target_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
        return node.slice.value
    return None


def credential_literals(
    tree: ast.AST, kinds: Iterable[str] = ALL_KINDS, lines: range | None = None
) -> list[ast.Constant]:
    """String literals bound to secret-looking names (optionally limited to
    ``lines``, matched on the literal's first line)."""
    wanted = frozenset(kinds)
    found: dict[int, ast.Constant] = {}

    def add(node: ast.AST | None) -> None:
        if is_str_literal(node) and (lines is None or node.lineno in lines):  # type: ignore[union-attr]
            found[id(node)] = node  # type: ignore[assignment]

    for node in ast.walk(tree):
        if ASSIGN in wanted:
            if isinstance(node, ast.Assign) and any(is_sensitive(_target_name(t)) for t in node.targets):
                add(node.value)
            elif isinstance(node, ast.AnnAssign) and is_sensitive(_target_name(node.target)):
                add(node.value)
            elif isinstance(node, ast.Compare):
                operands = [node.left, *node.comparators]
                if any(is_sensitive(_target_name(op)) for op in operands):
                    for op in operands:
                        add(op)
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and isinstance(key.value, str) and is_sensitive(key.value):
                        add(value)
        if KEYWORD in wanted and isinstance(node, ast.keyword) and is_sensitive(node.arg):
            add(node.value)
        if DEFAULT in wanted and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            positional = [*args.posonlyargs, *args.args]
            for arg, default in zip(positional[len(positional) - len(args.defaults):], args.defaults):
                if is_sensitive(arg.arg):
                    add(default)
            for arg, default in zip(args.kwonlyargs, args.kw_defaults):
                if default is not None and is_sensitive(arg.arg):
                    add(default)
    return sorted(found.values(), key=lambda n: (n.lineno, n.col_offset))
