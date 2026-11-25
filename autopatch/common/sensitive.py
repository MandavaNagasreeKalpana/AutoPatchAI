"""File-wide secret redaction shared by every agent (parse only, never executed).

Every finding shows code from its file (snippet and AST context), so secrets
must be hidden in the whole file view, not only on the line Bandit flagged.
:func:`redact_file` builds one redacted, line-preserving view per file that
all findings in that file share, so a value is hidden consistently.

What is hidden:

* String literals bound to a secret-looking name: assignments, annotated
  assignments, attributes, ``d["password"] = ...``, keyword arguments,
  parameter defaults, dictionary values and comparisons
  (``password == "x"``). Dictionary *keys* and the names themselves stay
  readable.
* On a line Bandit flagged as a hardcoded credential: every literal bound
  to a credential-looking name (Bandit's own naming rule included). Only if
  none is found there is *every* literal on the line hidden (fallback), so
  ordinary code on the same line, such as a SQL string, stays visible and
  stays covered by the Patch Generator's stale-source check.
* Literals that look like well-known token formats (GitHub, Groq, OpenAI,
  AWS, Slack, Google, JWT, PEM private keys), wherever they are.
* Any other occurrence of an already-hidden value inside a string literal or
  a comment, ``name = "value"`` pairs written in any string or comment, and
  unquoted ``password: value`` / ``api key = value`` / ``token is value``
  phrases in comments and triple-quoted strings (docstrings).

Names alone never trigger redaction of ordinary code: identifiers, keys and
non-secret strings are left as they are.

A hidden value that is itself *name-like* (an identifier that is
secret-looking, e.g. ``password = "password"``, or that the file uses as an
identifier) is still hidden where it is bound and wherever the same literal
is used as data, but not where that literal is a key (``form["password"]``,
``{"password": ...}``, ``environ.get("password")``) and not inside other
text (``"SELECT password FROM users"``): there it is ordinary vocabulary, and
hiding it would only remove code context. Such values are also left out of
:attr:`FileRedaction.values`, so callers do not substring-search for them.
"""

from __future__ import annotations

import ast
import io
import keyword
import re
import tokenize
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from autopatch.models import VulnerabilityCategory

from .source import REDACTED_LITERAL, ParsedSource

REDACTED_TEXT = "***REDACTED***"
# Finding categories whose flagged lines hold a literal secret.
REDACT_LITERALS = frozenset({VulnerabilityCategory.HARDCODED_CREDENTIALS})
UNPARSED_LINE = "# ***REDACTED: line could not be parsed***"
MIN_PROPAGATED_VALUE = 4  # shorter values are hidden in place only
MIN_KEY_VALUE = 16  # a value bound to a bare "...key" name must look like a key

# Scanner-local token formats. Deliberately not the shared error-message
# patterns: those also rewrite "Authorization: ..." text, which would mangle
# ordinary code such as header-building f-strings.
TOKEN_PATTERNS = (
    re.compile(r"gsk_[A-Za-z0-9]{8,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[abposr]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

_STRONG_WORDS = frozenset(
    {
        "password", "passwd", "passphrase", "passcode", "pass", "pwd", "pw",
        "secret", "secrets", "token", "tokens", "credential", "credentials",
        "creds", "auth", "authorization", "bearer", "apikey", "accesskey",
        "privatekey", "secretkey", "signingkey",
    }
)  # fmt: skip
_STRONG_PAIRS = frozenset(
    {
        ("api", "key"), ("access", "key"), ("private", "key"), ("secret", "key"),
        ("signing", "key"), ("encryption", "key"), ("master", "key"), ("session", "key"),
    }
)  # fmt: skip
# A trailing word that makes the name describe *about* a secret, not hold one
# (``password_field = "password"``, ``token_url = "https://..."``).
_NEUTRAL_SUFFIXES = frozenset(
    {
        "name", "names", "field", "fields", "label", "labels", "hint", "hints",
        "prompt", "type", "types", "url", "urls", "uri", "path", "paths", "file",
        "files", "env", "var", "header", "headers", "length", "len", "min", "max",
        "count", "regex", "pattern", "policy", "id", "ids", "expiry", "ttl", "timeout",
    }
)  # fmt: skip
_DEFAULT_GETTERS = frozenset({"get", "getenv", "pop", "setdefault"})
_SEGMENT = re.compile(r"[A-Z]{2,}(?=[A-Z][a-z]|[^A-Za-z]|$)|[A-Z]?[a-z]+|[A-Z]+|\d+")
# Anchored at an identifier start and bounded, so very long literals cannot
# cause quadratic backtracking.
_TEXT_PAIR = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]{0,63})(['\"]?)[ \t]{0,8}[:=][ \t]{0,8}(['\"])([^'\"\r\n]{1,512})\3"
)

# Names Bandit B105-B107 (or the Patch Generator's matching rule) treat as
# credentials. Re-exported by ``autopatch.patcher.secrets`` as SENSITIVE_NAME.
CREDENTIAL_NAME = re.compile(
    r"(?i)(pass(word|wd|phrase)?\b|passw(or)?d|pwd|secret|token|api_?key|access_?key|private_?key|credential)"
)
_KEY_GETTERS = frozenset({"get", "pop", "setdefault", "getenv", "__getitem__", "__contains__"})
_ATTR_FUNCS = frozenset({"getattr", "hasattr", "setattr", "delattr"})

# Unquoted credential phrases in prose (comments, docstrings): one or two
# words, then ':', '=', 'is' or 'was', then the value. Bounded, no nesting.
_FREE_PAIR = re.compile(
    r"(?<![A-Za-z0-9_])((?:[A-Za-z_][A-Za-z0-9_]{0,63}[ 	])?[A-Za-z_][A-Za-z0-9_]{0,63})"
    r"[ 	]{0,8}(:|=|[ 	](?:is|was)(?=[ 	]))[ 	]{0,8}([^\s'\"`]{1,256})"
)
_FREE_VALUE_END = ".,;:)]}>"
_PLACEHOLDER_START = tuple("%?{$<(:*")  # %s, ?, {name}, $1, <value>, :name, ***REDACTED***
MIN_FREE_VALUE = 4

STRONG, WEAK, NONE = 2, 1, 0
# f-string text is a STRING token before Python 3.12 and FSTRING_MIDDLE after.
_TEXT_TOKENS = frozenset(
    t for t in (tokenize.COMMENT, tokenize.STRING, getattr(tokenize, "FSTRING_MIDDLE", None)) if t is not None
)


def name_strength(name: str | None) -> int:
    """How strongly an identifier or key suggests that it holds a secret."""
    if not name:
        return NONE
    segments = [s.lower() for chunk in re.split(r"[^A-Za-z0-9]+", name) for s in _SEGMENT.findall(chunk)]
    if not segments:
        return NONE
    if len(segments) > 1 and segments[-1] in _NEUTRAL_SUFFIXES:
        return NONE
    if any(s in _STRONG_WORDS for s in segments) or any(p in _STRONG_PAIRS for p in zip(segments, segments[1:])):
        return STRONG
    if "key" in segments:
        return WEAK
    return NONE


def looks_like_token(value: str) -> bool:
    return any(p.search(value) for p in TOKEN_PATTERNS)


@dataclass(frozen=True)
class FileRedaction:
    lines: tuple[str, ...]  # same count and line endings as the source
    values: frozenset[str]  # hidden values long enough to search for elsewhere
    # False when comment/string token positions could not be mapped safely and
    # the conservative fallback was used (every string literal and every
    # comment hidden). Never a partially redacted view.
    complete: bool = True

    def scrub(self, text: str) -> str:
        """Hide known values and token formats in free text (descriptions)."""
        return scrub_text(text, self.values)


@dataclass(frozen=True)
class _Edit:
    start: tuple[int, int]  # (1-based row, character column)
    end: tuple[int, int]
    text: str


def redact_file(
    parsed: ParsedSource,
    credential_ranges: Iterable[tuple[int, int]] = (),
    extra_nodes: Iterable[ast.expr] = (),
) -> FileRedaction:
    """Return the redacted view of a whole file.

    ``credential_ranges`` are the ``(line, end_line)`` spans of Bandit
    credential findings in this file; every literal starting on those lines
    is hidden. ``extra_nodes`` are additional literal nodes (from
    ``parsed.tree``) that a caller has identified as secret.

    The result is deterministic for the same source and arguments, so the
    Patch Generator can recompute exactly the view the scanner produced.
    """
    ranges = sorted({(a, max(a, b)) for a, b in credential_ranges})
    if parsed.tree is None:
        return _redact_unparsed(parsed, ranges)

    lines = parsed.lines
    tree = parsed.tree
    nested_parent = _fstring_parents(tree)
    sensitive: dict[int, ast.expr] = {}

    def add(node: ast.expr) -> None:
        node = nested_parent.get(id(node), node)
        sensitive[id(node)] = node

    for node in [*_secret_literals(tree), *extra_nodes]:
        add(node)
    targeted = list(sensitive.values())
    found = {v for v in map(_literal_text, targeted) if _propagatable(v)}
    for start, end in ranges:
        hidden, _ = _range_literals(tree, start, end, nested_parent)
        for node in hidden:
            add(node)
        # Only when no secret was identified on the flagged lines do the
        # hidden literals' values become searchable elsewhere; otherwise
        # ordinary neighbours such as a base URL would be hidden file-wide.
        if not any(start <= n.lineno <= end for n in targeted):
            found |= {v for v in map(_literal_text, hidden) if _propagatable(v)}

    name_like = name_like_values(tree, found)
    values = found - name_like
    keys = key_literal_ids(tree)

    # Consistency: the same value used as another plain literal is hidden too
    # (a name-like value only where the literal is data, not a key).
    for node in ast.walk(tree):
        if id(node) in nested_parent or id(node) in sensitive or not _is_text_literal(node):
            continue
        text = _literal_text(node)
        if text in values or (text in name_like and id(node) not in keys):
            add(node)  # type: ignore[arg-type]

    edits = [_node_edit(lines, n) for n in sensitive.values()]
    token_edits = _token_edits(lines, edits, values)
    if token_edits is None:  # positions could not be mapped safely: fail closed
        return FileRedaction(_hide_all_text(parsed, nested_parent), frozenset(values), complete=False)
    return FileRedaction(_apply(lines, edits + token_edits), frozenset(values))


def is_credential_name(name: str | None) -> bool:
    """Bandit-style credential name (B105-B107) or a strong shared match."""
    if not name:
        return False
    return bool(CREDENTIAL_NAME.search(name)) or name_strength(name) == STRONG


def identifiers(tree: ast.AST) -> frozenset[str]:
    """Every identifier the code itself uses (variables, attributes,
    parameters, keyword arguments, function/class and import names)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.keyword) and node.arg:
            names.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.alias):
            names.update((node.asname or node.name).split("."))
    return frozenset(names)


def name_like_values(tree: ast.AST, values: Iterable[str]) -> frozenset[str]:
    """Values that are ordinary vocabulary rather than secret material: an
    identifier that is secret-looking itself (``"password"``, ``"api_key"``)
    or that this file uses as an identifier."""
    names = identifiers(tree)
    return frozenset(
        v for v in values
        if v.isidentifier() and not keyword.iskeyword(v)
        and (v in names or name_strength(v) != NONE or CREDENTIAL_NAME.search(v))
    )  # fmt: skip


def key_literal_ids(tree: ast.AST) -> frozenset[int]:
    """``id()`` of string literals used as keys or attribute names: dict
    keys, subscripts (``form["password"]``), ``.get("password")`` and the
    like, and ``getattr(obj, "password")``."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            found.update(id(k) for k in node.keys if k is not None and _is_text_literal(k))
        elif isinstance(node, ast.Subscript) and _is_text_literal(node.slice):
            found.add(id(node.slice))
        elif isinstance(node, ast.Call):
            func = node.func
            callee = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            index = 0 if callee in _KEY_GETTERS else 1 if callee in _ATTR_FUNCS else None
            if index is not None and len(node.args) > index and _is_text_literal(node.args[index]):
                found.add(id(node.args[index]))
    return frozenset(found)


def range_literals(parsed: ParsedSource, start: int, end: int) -> tuple[list[ast.expr], list[ast.expr]]:
    """``(hidden, every)`` literals starting on lines ``start..end`` under the
    credential-line rule of :func:`redact_file`."""
    assert parsed.tree is not None
    return _range_literals(parsed.tree, start, end, _fstring_parents(parsed.tree))


def _range_literals(
    tree: ast.AST, start: int, end: int, nested: Mapping[int, ast.AST]
) -> tuple[list[ast.expr], list[ast.expr]]:
    """Literals on a Bandit credential line: those bound to a credential
    name (any value for Bandit-style and strong names) and identified
    secrets; every literal on the lines only if none of those is there."""
    every = _literals_on_lines(tree, [(start, end)], nested)
    on_rows = {id(n) for n in every}
    chosen: dict[int, ast.expr] = {}
    candidates = [
        n for name, value in _bindings(tree)
        for n in (_value_nodes(value) if is_credential_name(name) else _bound(name, value))
    ]  # fmt: skip
    for node in [*candidates, *_secret_literals(tree)]:
        node = nested.get(id(node), node)  # type: ignore[assignment]
        if id(node) in on_rows:
            chosen[id(node)] = node
    return (list(chosen.values()) or every), every


def _propagatable(value: str) -> bool:
    return len(value) >= MIN_PROPAGATED_VALUE and REDACTED_TEXT not in value


def scrub_text(text: str, values: Iterable[str] = ()) -> str:
    for value in sorted(values, key=len, reverse=True):
        text = _value_regex(value).sub(REDACTED_TEXT, text)
    for pattern in TOKEN_PATTERNS:
        text = pattern.sub(REDACTED_TEXT, text)
    return text


# -- AST detection ------------------------------------------------------------


def _is_text_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def _literal_text(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        value = node.value
        return value if isinstance(value, str) else value.decode("latin-1")
    if isinstance(node, ast.JoinedStr):
        return "".join(
            v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)
        )
    return ""


def _fstring_parents(tree: ast.AST) -> dict[int, ast.JoinedStr]:
    """Map nodes inside an f-string to the f-string (inner positions are not
    reliable on every Python version, so the whole f-string is replaced)."""
    parents: dict[int, ast.JoinedStr] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for child in ast.walk(node):
                if child is not node:
                    parents.setdefault(id(child), node)
    return parents


def _value_nodes(expr: ast.AST | None) -> list[ast.expr]:
    """Literal nodes that make up the value bound to a secret-looking name."""
    if expr is None:
        return []
    if _is_text_literal(expr):
        return [expr] if expr.value else []  # type: ignore[attr-defined,list-item]
    if isinstance(expr, ast.JoinedStr):
        return [expr] if _literal_text(expr) else []
    if isinstance(expr, ast.BinOp):
        return _value_nodes(expr.left) + _value_nodes(expr.right)
    if isinstance(expr, (ast.Tuple, ast.List)):
        return [n for e in expr.elts for n in _value_nodes(e)]
    if isinstance(expr, ast.IfExp):
        return _value_nodes(expr.body) + _value_nodes(expr.orelse)
    if isinstance(expr, ast.BoolOp):
        return [n for v in expr.values for n in _value_nodes(v)]
    if isinstance(expr, ast.Call):  # os.environ.get("NAME", "default-secret")
        func = expr.func
        callee = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if callee in _DEFAULT_GETTERS:
            found = _value_nodes(expr.args[1]) if len(expr.args) >= 2 else []
            found += [n for kw in expr.keywords if kw.arg == "default" for n in _value_nodes(kw.value)]
            return found
    return []


def _bound(name: str | None, value: ast.AST | None) -> list[ast.expr]:
    strength = name_strength(name)
    if strength == NONE:
        return []
    nodes = _value_nodes(value)
    if strength == WEAK:
        nodes = [
            n for n in nodes
            if len(text := _literal_text(n)) >= MIN_KEY_VALUE and not any(c.isspace() for c in text)
        ]  # fmt: skip
    return nodes


def _target_name(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript) and _is_text_literal(target.slice):
        return _literal_text(target.slice)
    return None


def _pairs(target: ast.AST, value: ast.AST | None) -> list[tuple[str | None, ast.AST | None]]:
    if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)):
        if len(target.elts) == len(value.elts):
            return [p for t, v in zip(target.elts, value.elts) for p in _pairs(t, v)]
        return []
    return [(_target_name(target), value)]


def _default_pairs(args: ast.arguments) -> list[tuple[str | None, ast.AST | None]]:
    positional = [*args.posonlyargs, *args.args]
    pairs = list(zip(positional[len(positional) - len(args.defaults) :], args.defaults))
    pairs += [(a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None]
    return [(arg.arg, default) for arg, default in pairs]


def _operand_name(node: ast.AST) -> str | None:
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return _target_name(node)
    return None


def _bindings(tree: ast.AST) -> list[tuple[str | None, ast.AST | None]]:
    """``(name, value expression)`` wherever a value is bound to a name:
    assignments, keyword arguments, parameter defaults, dictionary entries
    and comparisons."""
    found: list[tuple[str | None, ast.AST | None]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                found += _pairs(target, node.value)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            found += _pairs(node.target, node.value)
        elif isinstance(node, ast.Call):
            found += [(kw.arg, kw.value) for kw in node.keywords]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            found += _default_pairs(node.args)
        elif isinstance(node, ast.Dict):
            found += [
                (_literal_text(k), v) for k, v in zip(node.keys, node.values) if k is not None and _is_text_literal(k)
            ]
        elif isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            for name in filter(None, map(_operand_name, operands)):
                found += [(name, other) for other in operands if _is_text_literal(other)]
    return found


def _secret_literals(tree: ast.AST) -> list[ast.expr]:
    found = [n for name, value in _bindings(tree) for n in _bound(name, value)]
    found += [
        node for node in ast.walk(tree)  # type: ignore[misc]
        if _is_text_literal(node) and looks_like_token(_literal_text(node))
    ]  # fmt: skip
    return found


def _literals_on_lines(
    tree: ast.AST, ranges: Sequence[tuple[int, int]], nested: Mapping[int, ast.AST]
) -> list[ast.expr]:
    if not ranges:
        return []
    found = []
    for node in ast.walk(tree):
        if id(node) in nested:
            continue
        if _is_text_literal(node) or isinstance(node, ast.JoinedStr):
            row = node.lineno  # type: ignore[attr-defined]
            if any(a <= row <= b for a, b in ranges):
                found.append(node)
    return found  # type: ignore[return-value]


# -- edits --------------------------------------------------------------------


def _char_col(line: str, byte_col: int) -> int:
    return len(line.encode("utf-8")[:byte_col].decode("utf-8", "replace"))


def _node_edit(lines: Sequence[str], node: ast.expr) -> _Edit:
    first, last = node.lineno, node.end_lineno or node.lineno
    start = _char_col(lines[first - 1], node.col_offset)
    end = _char_col(lines[last - 1], node.end_col_offset or 0)
    return _Edit((first, start), (last, end), REDACTED_LITERAL)


def _value_regex(value: str) -> re.Pattern[str]:
    before = r"(?<![A-Za-z0-9_])" if re.match(r"\w", value[0]) else ""
    after = r"(?![A-Za-z0-9_])" if re.match(r"\w", value[-1]) else ""
    return re.compile(before + re.escape(value) + after)


def _overlaps(a: _Edit, b: _Edit) -> bool:
    return a.start < b.end and b.start < a.end


def _normalized(lines: Sequence[str]) -> str:
    """The source with every line break (``\\r\\n``, ``\\r`` or ``\\n``) as
    ``\\n``. Line *N* and column *C* here are line *N* and column *C* of
    ``lines``, which is exactly how ``ast`` and :func:`split_lines` count, so
    token positions map onto the parser's lines for any mix of endings."""
    return "".join(_content(line) + "\n" for line in lines)


def _content(line: str) -> str:
    return line[: len(line) - len(_ending(line))]


def _token_text_matches(lines: Sequence[str], tok: tokenize.TokenInfo) -> bool:
    (r1, c1), (r2, c2) = tok.start, tok.end
    if not (1 <= r1 <= r2 <= len(lines)):
        return False
    if r1 == r2:
        return _content(lines[r1 - 1])[c1:c2] == tok.string
    parts = [_content(lines[r1 - 1])[c1:], *(_content(lines[r - 1]) for r in range(r1 + 1, r2))]
    parts.append(_content(lines[r2 - 1])[:c2])
    return "\n".join(parts) == tok.string


def _token_edits(
    lines: Sequence[str], node_edits: Sequence[_Edit], values: Iterable[str]
) -> list[_Edit] | None:
    """Hide secrets inside comments and string tokens not already replaced.

    Returns ``None`` (caller fails closed) if the source cannot be tokenized
    or any token's position does not map exactly onto ``lines``.
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(_normalized(lines)).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError, ValueError):
        return None
    regexes = [_value_regex(v) for v in sorted(values, key=len, reverse=True)]
    edits: list[_Edit] = []
    for tok in tokens:
        if tok.type not in _TEXT_TOKENS:
            continue
        if not _token_text_matches(lines, tok):
            return None
        span = _Edit(tok.start, tok.end, "")
        if any(_overlaps(span, e) for e in node_edits):
            continue
        prose = tok.type == tokenize.COMMENT or _is_triple_quoted(tok.string)
        for start, end in _secret_spans(tok.string, regexes, prose=prose):
            edits.append(_Edit(_offset(tok, start), _offset(tok, end), REDACTED_TEXT))
    return edits


HIDDEN_COMMENT = "# ***REDACTED: comment hidden***"


def _hide_all_text(parsed: ParsedSource, nested: Mapping[int, ast.AST]) -> tuple[str, ...]:
    """Conservative view: every string literal and every comment hidden.

    Used when token positions cannot be trusted. After all literals are
    replaced, a ``#`` left on a line can only start a comment.
    """
    assert parsed.tree is not None
    literals = [
        n for n in ast.walk(parsed.tree)
        if id(n) not in nested and (_is_text_literal(n) or isinstance(n, ast.JoinedStr))
    ]  # fmt: skip
    out = list(_apply(parsed.lines, [_node_edit(parsed.lines, n) for n in literals]))  # type: ignore[arg-type]
    for i, line in enumerate(out):
        content = _content(line)
        if "#" in content:
            out[i] = content[: content.index("#")] + HIDDEN_COMMENT + _ending(line)
    return tuple(out)


def _is_triple_quoted(token_text: str) -> bool:
    body = token_text.lstrip("rRbBuUfF")
    return body.startswith(('"""', "'''"))


def _free_pair_spans(text: str) -> list[tuple[int, int]]:
    """Values of unquoted credential phrases (``password: hunter2``)."""
    spans = []
    for match in _FREE_PAIR.finditer(text):
        value = match.group(3).rstrip(_FREE_VALUE_END)
        if len(value) < MIN_FREE_VALUE or value.startswith(_PLACEHOLDER_START):
            continue
        if match.group(2).strip() in ("is", "was") and value.isalpha():
            continue  # prose ("password is required", "the credential is fake")
        if _names_credential(match.group(1)):
            spans.append((match.start(3), match.start(3) + len(value)))
    return spans


def _names_credential(phrase: str) -> bool:
    """The phrase *ends* with a credential word ("admin password",
    "api key"), so "credential below" does not count."""
    segments = [s.lower() for chunk in re.split(r"[^A-Za-z0-9]+", phrase) for s in _SEGMENT.findall(chunk)]
    if not segments:
        return False
    return segments[-1] in _STRONG_WORDS or tuple(segments[-2:]) in _STRONG_PAIRS


def _secret_spans(
    token_text: str, regexes: Sequence[re.Pattern[str]], *, prose: bool = False
) -> list[tuple[int, int]]:
    spans = [m.span(4) for m in _TEXT_PAIR.finditer(token_text) if name_strength(m.group(1)) == STRONG]
    if prose:
        spans += _free_pair_spans(token_text)
    spans += [m.span() for r in regexes for m in r.finditer(token_text)]
    spans += [m.span() for p in TOKEN_PATTERNS for m in p.finditer(token_text)]
    return spans


def _offset(tok: tokenize.TokenInfo, index: int) -> tuple[int, int]:
    """Translate an index inside a (possibly multi-line) token to (row, col)."""
    before = tok.string[:index]
    newlines = before.count("\n")
    if newlines == 0:
        return tok.start[0], tok.start[1] + index
    return tok.start[0] + newlines, index - before.rfind("\n") - 1


def _apply(lines: Sequence[str], edits: Sequence[_Edit]) -> tuple[str, ...]:
    kept: list[_Edit] = []
    for edit in sorted(edits, key=lambda e: (e.start, (-e.end[0], -e.end[1]))):
        if kept and edit.start < kept[-1].end:
            continue  # contained in (or overlapping) an earlier, wider edit
        kept.append(edit)
    out = list(lines)
    for edit in reversed(kept):
        (r1, c1), (r2, c2) = edit.start, edit.end
        first, last = r1 - 1, r2 - 1
        head, tail = out[first][:c1], out[last][c2:]
        if first == last:
            out[first] = head + edit.text + tail
            continue
        out[first] = head + edit.text + _ending(out[first])
        for i in range(first + 1, last):
            out[i] = _ending(out[i])
        out[last] = tail
    return tuple(out)


def _merge(spans: Iterable[tuple[int, int]], *, reverse: bool = False) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    out = [(a, b) for a, b in merged]
    return out[::-1] if reverse else out


def _ending(line: str) -> str:
    return line[len(line.rstrip("\r\n")) :]


def _redact_unparsed(parsed: ParsedSource, ranges: Sequence[tuple[int, int]]) -> FileRedaction:
    """No syntax tree: blank flagged lines, then hide ``name = "value"`` pairs
    and token formats line by line."""
    out = []
    for row, line in enumerate(parsed.lines, start=1):
        if any(a <= row <= b for a, b in ranges):
            out.append(UNPARSED_LINE + _ending(line))
            continue
        spans = [m.span(4) for m in _TEXT_PAIR.finditer(line) if name_strength(m.group(1)) == STRONG]
        if "#" in line:  # degraded mode: prose phrases after a '#' as well
            cut = line.index("#")
            spans += [(cut + a, cut + b) for a, b in _free_pair_spans(line[cut:])]
        for start, end in _merge(spans, reverse=True):
            line = line[:start] + REDACTED_TEXT + line[end:]
        out.append(scrub_text(line))
    return FileRedaction(tuple(out), frozenset())
