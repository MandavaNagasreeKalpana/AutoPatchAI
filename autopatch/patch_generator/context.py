"""Build the bounded, redacted source context sent to the LLM.

Nothing here reads or writes files: the caller supplies the source text.
Source is parsed with ``ast.parse`` / ``tokenize`` only (never run).

Redaction is line-preserving (line N of the redacted view is line N of the
real file) and only ever rewrites string literals and comments, never
identifiers or other code:

1. Credential findings: the actual credential literal on the flagged lines,
   chosen by rule (B105 assigned value, B106 keyword value, B107 parameter
   default). Only if none can be identified are *all* literals on the
   flagged lines masked (fallback). If nothing can be masked: fail closed.
2. Any category: string literals bound to secret-looking names anywhere in
   the file, and any other literal whose value equals a masked secret.
3. Inside remaining string literals and comments: known token formats,
   secret-looking environment values and masked secret values; comments
   and docstrings that state a credential (``password: ...``) are hidden.
4. Finally the scanner's shared file-wide detector
   (:func:`autopatch.common.sensitive.redact_file`) runs over that view, so
   the Patch Generator never shows the model anything the scanner's own
   report would hide.

A hidden value that is ordinary vocabulary (``password = "password"``) is
masked where it is bound and where the same literal is used as data, but
not where it is a key (``form["password"]``) or a word inside other text;
see :func:`autopatch.common.sensitive.name_like_values`.

The stale-source check recomputes the scanner's snippet views from the
supplied source and requires an exact match (see :func:`expected_snippets`).
Only literals the scanner classifies as secrets can be hidden in those views,
so the one thing the check cannot compare is a hidden secret value itself;
when that applies, :attr:`PatchContext.notes` says so and the agent adds it
to the candidate's warnings (it is never silently assumed unchanged).

The real secret values are kept only in memory (``PatchContext``) for the
leak check and for verifying that a patch removed the flagged credential.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from dataclasses import dataclass, field

from autopatch.models import Finding, VulnerabilityCategory
from autopatch.models.common import MAX_CODE_CHARS
from autopatch.redaction import redact_secrets
from autopatch.common.source import (
    REDACTED_LITERAL,
    ParsedSource,
    bound_text,
    extract_snippet,
    parse_source,
    redact_string_literals,
    split_lines,
)
from autopatch.common.sensitive import REDACT_LITERALS
from autopatch.common.sensitive import (
    REDACTED_TEXT,
    key_literal_ids,
    name_like_values,
    range_literals,
    redact_file,
)

from .errors import (
    ContextTooLargeError,
    InsufficientContextError,
    InvalidFindingError,
    RedactionError,
    SourceMismatchError,
)
from .secrets import ALL_KINDS, RULE_KINDS, credential_literals, is_str_literal, literal_value

MAX_SOURCE_CHARS = 500_000  # whole file supplied by the caller (not sent)
MAX_CONTEXT_LINES = 200  # lines actually shown to the model
MAX_CONTEXT_CHARS = 24_000
CONTEXT_MARGIN = 3  # extra lines around the AST span
MAX_HEADER_LINES = 40  # module header (imports) shown so imports can be added
DEFAULT_HEADER_LINES = 5
MIN_CHECKED_SECRET = 4  # shorter values are masked positionally but not substring-checked

SUPPORTED_CATEGORIES = frozenset(VulnerabilityCategory)
HIDDEN_COMMENT = "# [comment hidden: may contain a credential]"
_BREAK = re.compile(r"\r\n|\r|\n")
_CREDENTIAL_PHRASE = re.compile(
    r"(?i)\b(pass(word|wd|phrase)?|pwd|secret|token|api[_ -]?key|credential)s?\b\s*(is|was|=|:)\s*\S+"
)


@dataclass(frozen=True)
class LineRange:
    start: int  # 1-based, inclusive
    end: int


@dataclass(frozen=True)
class PatchContext:
    """Everything the generator needs; ``repr`` shows identifiers only."""

    finding: Finding
    target_file: str
    excerpts: tuple[LineRange, ...]
    newline: str
    original_lines: tuple[str, ...] = field(repr=False)  # real file, with line endings
    display_lines: tuple[str, ...] = field(repr=False)  # redacted view, same length
    redacted_values: tuple[str, ...] = field(repr=False)  # every masked secret value
    flagged_values: tuple[str, ...] = field(repr=False)  # the finding's own credential value(s)
    fallback_redaction: bool = False
    # Limits of the stale-source check for this finding (shown as warnings).
    notes: tuple[str, ...] = ()

    def __repr__(self) -> str:
        ranges = ", ".join(f"{r.start}-{r.end}" for r in self.excerpts)
        return (
            f"PatchContext(finding_id={self.finding.finding_id!r}, target_file={self.target_file!r}, "
            f"excerpts=[{ranges}], redacted={self.redaction_applied})"
        )

    @property
    def shown_lines(self) -> frozenset[int]:
        return frozenset(n for r in self.excerpts for n in range(r.start, r.end + 1))

    @property
    def redaction_applied(self) -> bool:
        return self.display_lines != self.original_lines

    def render_excerpts(self) -> str:
        """Numbered, redacted excerpt text (the only source the LLM sees)."""
        width = len(str(self.excerpts[-1].end))
        blocks = []
        previous_end = 0
        for excerpt in self.excerpts:
            if excerpt.start > previous_end + 1:
                blocks.append(f"... (lines {previous_end + 1}-{excerpt.start - 1} not shown) ...")
            for n in range(excerpt.start, excerpt.end + 1):
                text = self.display_lines[n - 1].rstrip("\r\n")
                blocks.append(f"{n:>{width}}| {text}")
            previous_end = excerpt.end
        if previous_end < len(self.display_lines):
            blocks.append(f"... (lines {previous_end + 1}-{len(self.display_lines)} not shown) ...")
        return "\n".join(blocks)


def build_patch_context(finding: Finding, source: str) -> PatchContext:
    """Validate inputs and build a bounded, redacted context.

    Raises :class:`InvalidFindingError`, :class:`InsufficientContextError`,
    :class:`SourceMismatchError`, :class:`ContextTooLargeError` or
    :class:`RedactionError`. Oversized input is rejected, never truncated.
    """
    if not isinstance(finding, Finding):
        raise InvalidFindingError("A validated Finding is required to generate a patch.")
    if finding.category not in SUPPORTED_CATEGORIES:
        raise InvalidFindingError(f"Unsupported vulnerability category: {finding.category}.")
    if not isinstance(source, str) or not source.strip():
        raise InsufficientContextError(
            f"No source content was supplied for {finding.file_path}; cannot build a patch context."
        )
    if len(source) > MAX_SOURCE_CHARS:
        raise ContextTooLargeError(
            f"Source file is too large ({len(source)} characters; limit {MAX_SOURCE_CHARS})."
        )
    span = finding.ast_context
    if span is None:
        raise InsufficientContextError(
            "The finding has no AST context (the file could not be parsed); a safe, "
            "bounded patch context cannot be built."
        )

    parsed = parse_source(source)
    if parsed.tree is None:
        raise InsufficientContextError(f"The supplied source cannot be parsed ({parsed.error}).")
    lines = parsed.lines
    end_line = finding.end_line or finding.line
    if max(end_line, span.end_line) > len(lines):
        raise SourceMismatchError(
            f"The finding refers to line {max(end_line, span.end_line)}, but the supplied "
            f"source has only {len(lines)} lines. Rescan the file."
        )

    notes = _check_snippet(finding, parsed)
    display, secrets, flagged, fallback = _redact(parsed, finding)

    excerpts = _excerpts(parsed, span.start_line, span.end_line)
    shown = sum(r.end - r.start + 1 for r in excerpts)
    if shown > MAX_CONTEXT_LINES:
        raise ContextTooLargeError(
            f"The code context is too large ({shown} lines; limit {MAX_CONTEXT_LINES}). "
            "Refusing to truncate it, because a patch built from partial code could be wrong."
        )
    context = PatchContext(
        finding=finding,
        target_file=finding.file_path,
        excerpts=excerpts,
        newline=_detect_newline(lines),
        original_lines=tuple(lines),
        display_lines=tuple(display),
        redacted_values=tuple(secrets),
        flagged_values=tuple(flagged),
        fallback_redaction=fallback,
        notes=notes,
    )
    rendered = context.render_excerpts()
    if len(rendered) > MAX_CONTEXT_CHARS:
        raise ContextTooLargeError(
            f"The code context is too large ({len(rendered)} characters; limit {MAX_CONTEXT_CHARS})."
        )
    verify_no_secrets(rendered, context.redacted_values)
    if finding.category in REDACT_LITERALS:
        flagged_rows = range(finding.line - 1, end_line)
        if not any(REDACTED_LITERAL in context.display_lines[i] for i in flagged_rows):
            raise RedactionError("The flagged credential could not be masked; refusing to send it.")
    return context


def verify_no_secrets(text: str, secrets: tuple[str, ...] | list[str]) -> None:
    """Raise :class:`RedactionError` if a masked secret value still appears
    in ``text`` as a standalone value.

    A match must not be glued to identifier characters on either side, so an
    ordinary identifier that merely contains a short secret-like word is not
    treated as a leak. Values shorter than 4 characters are not checked here
    (they are masked by exact literal matching instead).
    """
    for value in secrets:
        if len(value) < MIN_CHECKED_SECRET:
            continue
        before = r"(?<![A-Za-z0-9_])" if re.match(r"\w", value[0]) else ""
        after = r"(?![A-Za-z0-9_])" if re.match(r"\w", value[-1]) else ""
        if re.search(before + re.escape(value) + after, text):
            raise RedactionError("A redacted value is still present in the LLM context; refusing to send it.")


# -- internals ----------------------------------------------------------------------


SECRET_NOT_COMPARED = (
    "The finding's code snippet hides secret value(s); they are never stored in scan results, so "
    "they could not be compared with the supplied source. Everything else on the flagged lines "
    "matched the scan exactly, and the patch was built from the supplied source."
)
LEGACY_NOT_COMPARED = (
    "The finding's code snippet uses the older format that hid every string literal on the flagged "
    "credential line(s), so the non-secret literals hidden there could not be compared with the "
    "supplied source. Rescan the file for a fully checkable snippet."
)
TEXT_NOT_COMPARED = (
    "The scanner hid every comment and string literal in this file (their positions could not be "
    "mapped safely), so changes inside them since the scan could not be detected."
)


def _check_snippet(finding: Finding, parsed: ParsedSource) -> tuple[str, ...]:
    """Stale-source check: the finding's snippet must equal, exactly, a view
    that the scanner could have produced from *this* source.

    The candidate views are recomputed deterministically from the supplied
    source (redaction placeholders are never treated as wildcards). In those
    views only literals classified as secrets are hidden (or, in the rare
    fail-closed view, every comment and literal), so any other change to the
    flagged lines is detected. Returns notes describing what could not be
    compared; raises :class:`SourceMismatchError` on a mismatch.
    """
    if not finding.code_snippet:
        return ()
    views = _snippet_views(finding, parsed)
    matched = [kind for snippet, kind in views if snippet == finding.code_snippet]
    if not matched:
        raise SourceMismatchError(
            f"The supplied source does not match finding {finding.finding_id} at "
            f"{finding.file_path}:{finding.line} (the file changed since the scan?). Rescan it."
        )
    if "raw" in matched or "***REDACTED" not in finding.code_snippet:
        return ()  # nothing hidden on the flagged lines: compared in full
    if "redacted" in matched:
        return (SECRET_NOT_COMPARED,)
    if "legacy" in matched:
        return (LEGACY_NOT_COMPARED,)
    return (TEXT_NOT_COMPARED,)


def expected_snippets(finding: Finding, parsed: ParsedSource) -> frozenset[str]:
    """Every snippet the scanner can legitimately emit for ``finding``:

    * the scanner's file-wide redacted view (:func:`redact_file`);
    * the same with a credential finding covering the flagged lines, for a
      credential finding, or for another finding whose lines hold a
      Bandit-style credential literal (the two can share a line);
    * for credential findings, the older view that hid every literal on the
      flagged lines (earlier scan results and callers still build it); when
      that hides more than the current credential-line rule, the context
      carries :data:`LEGACY_NOT_COMPARED` instead of passing silently;
    * for other categories, the unredacted lines.

    Each candidate is bounded exactly as the scanner bounds snippets.
    """
    return frozenset(snippet for snippet, _ in _snippet_views(finding, parsed))


def _snippet_views(finding: Finding, parsed: ParsedSource) -> list[tuple[str, str]]:
    assert parsed.tree is not None
    end_line = finding.end_line or finding.line
    rows = range(finding.line, end_line + 1)
    credential = finding.category in REDACT_LITERALS
    views: list[tuple[tuple[str, ...] | list[str], str]] = []

    def add(redaction_lines: tuple[str, ...] | list[str], complete: bool, kind: str = "redacted") -> None:
        views.append((redaction_lines, kind if complete else "hidden"))

    plain = redact_file(parsed)
    add(plain.lines, plain.complete)
    if credential or credential_literals(parsed.tree, ALL_KINDS, rows):
        shared = redact_file(parsed, ((finding.line, end_line),))
        add(shared.lines, shared.complete)
    if credential:
        hidden, every = range_literals(parsed, finding.line, end_line)
        legacy = "redacted" if len(hidden) == len(every) else "legacy"
        add(redact_string_literals(parsed, finding.line, end_line)[0], True, legacy)
    else:
        add(parsed.lines, True, "raw")
    return [
        (bound_text(extract_snippet(lines, finding.line, end_line), MAX_CODE_CHARS), kind)
        for lines, kind in views
    ]


def _nested_in_fstring(tree: ast.AST) -> set[int]:
    nested: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            nested.update(id(child) for child in ast.walk(node) if child is not node)
    return nested


def _flagged_literals(tree: ast.AST, finding: Finding) -> tuple[list[ast.AST], bool]:
    """The finding's credential literal(s) and whether the fallback was used."""
    end_line = finding.end_line or finding.line
    rows = range(finding.line, end_line + 1)
    kinds = RULE_KINDS.get(finding.rule_id, ALL_KINDS)
    found: list[ast.AST] = list(credential_literals(tree, kinds, rows))
    if not found and kinds != ALL_KINDS:
        found = list(credential_literals(tree, ALL_KINDS, rows))
    if found:
        return found, False
    nested = _nested_in_fstring(tree)
    fallback = [
        node
        for node in ast.walk(tree)
        if id(node) not in nested
        and (is_str_literal(node) or isinstance(node, ast.JoinedStr))
        and node.lineno in rows  # type: ignore[attr-defined]
    ]
    return fallback, True


def _redact(parsed: ParsedSource, finding: Finding) -> tuple[list[str], list[str], list[str], bool]:
    tree = parsed.tree
    assert tree is not None
    targets: list[ast.AST] = []
    flagged_values: list[str] = []
    fallback = False

    if finding.category in REDACT_LITERALS:
        flagged_nodes, fallback = _flagged_literals(tree, finding)
        if not flagged_nodes:
            raise RedactionError(
                "No string literal was found on the flagged credential lines, so the "
                "secret cannot be masked reliably; refusing to send this context."
            )
        targets += flagged_nodes
        flagged_values = [literal_value(n) for n in flagged_nodes if is_str_literal(n)]

    targets += credential_literals(tree)  # secret-looking names anywhere in the file
    secrets = {literal_value(n) for n in targets if is_str_literal(n)}  # type: ignore[arg-type]
    secrets.discard("")
    # Ordinary vocabulary (``password = "password"``): masked where bound and
    # where the same literal is data, but not as a key or inside other text.
    name_like = name_like_values(tree, secrets)
    keys = key_literal_ids(tree)
    nested = _nested_in_fstring(tree)
    targets += [
        node for node in ast.walk(tree)
        if id(node) not in nested and is_str_literal(node)
        and literal_value(node) in secrets  # type: ignore[arg-type]
        and not (literal_value(node) in name_like and id(node) in keys)  # type: ignore[arg-type]
    ]  # fmt: skip

    text = parsed.text
    starts = _line_starts(parsed.lines)
    spans = [_node_span(node, parsed.lines, starts) for node in _dedupe(targets)]
    long_secrets = sorted(
        (s for s in secrets if len(s) >= MIN_CHECKED_SECRET and s not in name_like), key=len, reverse=True
    )
    token_spans = _token_spans(parsed, starts, long_secrets, spans)
    if token_spans is None:  # unusual line endings: conservative line-wide scrub
        display = split_lines(_apply_spans(text, spans))
        display = [redact_secrets(line, extra_secrets=long_secrets) for line in display]
    else:
        display = split_lines(_apply_spans(text, spans + token_spans))

    # Second pass: the scanner's shared file-wide detector over the view built
    # so far, so both components hide the same things (names such as
    # ``signing_key``, token formats, repeated values, comments, f-strings).
    # It only rewrites string literals and comments; the credential-specific
    # masking above is kept.
    view = parse_source("".join(display))
    if view.tree is None:
        raise RedactionError("The redacted view could not be re-parsed; refusing to continue.")
    shared = redact_file(view)
    display = list(shared.lines)
    secrets |= {v for v in shared.values if v and REDACTED_TEXT not in v}

    if len(display) != len(parsed.lines) or any(
        _ending(a) != _ending(b) for a, b in zip(display, parsed.lines)
    ):
        raise RedactionError("Redaction changed the line structure; refusing to continue.")
    # Name-like values are masked positionally (like values shorter than
    # MIN_CHECKED_SECRET) and not substring-checked: the same word is a
    # legitimate identifier or key elsewhere in the code.
    return display, sorted(secrets - name_like), flagged_values, fallback


def _dedupe(nodes: list[ast.AST]) -> list[ast.AST]:
    seen: dict[int, ast.AST] = {}
    for node in nodes:
        seen.setdefault(id(node), node)
    return list(seen.values())


def _ending(line: str) -> str:
    return line[len(line.rstrip("\r\n")):]


def _line_starts(lines: tuple[str, ...]) -> list[int]:
    starts, offset = [], 0
    for line in lines:
        starts.append(offset)
        offset += len(line)
    return starts


def _char_col(line: str, byte_col: int) -> int:
    return len(line.encode("utf-8")[:byte_col].decode("utf-8", "replace"))


def _node_span(node: ast.AST, lines: tuple[str, ...], starts: list[int]) -> tuple[int, int, str]:
    first, last = node.lineno - 1, node.end_lineno - 1  # type: ignore[attr-defined]
    start = starts[first] + _char_col(lines[first], node.col_offset)  # type: ignore[attr-defined]
    end = starts[last] + _char_col(lines[last], node.end_col_offset)  # type: ignore[attr-defined]
    return start, end, REDACTED_LITERAL


def _token_spans(
    parsed: ParsedSource, starts: list[int], secrets: list[str], taken: list[tuple[int, int, str]]
) -> list[tuple[int, int, str]] | None:
    """Scrub string and comment tokens only (identifiers are never touched)."""
    text = parsed.text
    if "\r" in text.replace("\r\n", ""):
        return None
    assert parsed.tree is not None
    docstrings = {
        (node.value.lineno, _char_col(parsed.lines[node.value.lineno - 1], node.value.col_offset))
        for node in ast.walk(parsed.tree)
        if isinstance(node, ast.Expr) and is_str_literal(node.value)
    }
    spans: list[tuple[int, int, str]] = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError):
        return None
    for tok in tokens:
        if tok.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        start = starts[tok.start[0] - 1] + tok.start[1]
        end = starts[tok.end[0] - 1] + tok.end[1]
        if any(s < end and start < e for s, e, _ in taken):
            continue  # already masked as a whole literal
        if tok.type == tokenize.COMMENT and _CREDENTIAL_PHRASE.search(tok.string):
            replacement = HIDDEN_COMMENT
        elif tok.type == tokenize.STRING and tok.start in docstrings and _CREDENTIAL_PHRASE.search(tok.string):
            replacement = REDACTED_LITERAL
        else:
            replacement = redact_secrets(tok.string, extra_secrets=secrets)
        if replacement != tok.string:
            spans.append((start, end, replacement))
    return spans


def _apply_spans(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Replace character spans, keeping every line break inside a span."""
    kept: list[tuple[int, int, str]] = []
    for start, end, replacement in sorted(spans, key=lambda s: (s[0], -s[1])):
        if kept and start < kept[-1][1]:
            continue  # overlaps a span already being replaced
        kept.append((start, end, replacement))
    out, cursor = [], 0
    for start, end, replacement in kept:
        original_breaks = _BREAK.findall(text[start:end])
        if len(_BREAK.findall(replacement)) != len(original_breaks):
            # e.g. a multi-line string masked by a one-line placeholder:
            # keep its line breaks after the placeholder so line N stays line N.
            replacement = _BREAK.sub(" ", replacement) + "".join(original_breaks)
        out.append(text[cursor:start])
        out.append(replacement)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def _excerpts(parsed: ParsedSource, span_start: int, span_end: int) -> tuple[LineRange, ...]:
    assert parsed.tree is not None
    total = len(parsed.lines)
    import_ends = [
        node.end_lineno or node.lineno
        for node in parsed.tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    header_end = max(import_ends) if import_ends else DEFAULT_HEADER_LINES
    header = LineRange(1, min(header_end, MAX_HEADER_LINES, total))
    main = LineRange(max(1, span_start - CONTEXT_MARGIN), min(total, span_end + CONTEXT_MARGIN))
    if main.start <= header.end + 1:
        return (LineRange(1, max(header.end, main.end)),)
    return (header, main)


def _detect_newline(lines: tuple[str, ...]) -> str:
    for line in lines:
        if line.endswith("\r\n"):
            return "\r\n"
        if line.endswith("\n"):
            return "\n"
        if line.endswith("\r"):
            return "\r"
    return "\n"
