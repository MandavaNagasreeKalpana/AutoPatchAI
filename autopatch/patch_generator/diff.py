"""Strict unified-diff parsing and in-memory application.

Nothing here touches the filesystem or runs code. Diffs are applied to lists
of strings; the caller's original source is never modified.

Rules enforced:
* exactly one ``---``/``+++`` file pair, both naming the expected
  project-relative path (absolute paths and ``..`` are rejected);
* no file creation, deletion, rename, mode or binary changes;
* every hunk header is well formed and its line counts match its body;
* hunks are ordered and non-overlapping, with at least one real change;
* each hunk's context and removed lines match the source exactly (trailing
  whitespace aside) at the declared ``-OLD_START`` line or, if not there, at
  the nearest unique position within ``MAX_HUNK_OFFSET`` (20) lines;
* optionally, only lines shown to the model may be touched.

Tolerances (documented, deliberate):
* ``+NEW_START`` is not checked; positions come from content matching.
* A bare empty line inside a hunk is read as an empty context line (a common
  way diffs lose the leading space).
* ``\\ No newline at end of file`` markers are accepted but ignored: the
  original file's end-of-file state is kept (a file without a final line
  break still has none after patching).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from autopatch.models.common import normalize_project_path

from .errors import (
    DiffApplyError,
    DiffFormatError,
    DiffHunkError,
    DiffPathError,
    DiffScopeError,
    EmptyDiffError,
    MultiFileDiffError,
    NoOpDiffError,
)

MAX_DIFF_CHARS = 50_000
MAX_HUNKS = 20
MAX_HUNK_OFFSET = 20  # lines a hunk may be away from its declared position

_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")
_PREAMBLE = ("diff --git ", "index ")
_FORBIDDEN = (
    "new file mode",
    "deleted file mode",
    "old mode",
    "new mode",
    "rename from",
    "rename to",
    "copy from",
    "copy to",
    "similarity index",
    "dissimilarity index",
    "Binary files",
    "GIT binary patch",
)


@dataclass(frozen=True)
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: tuple[tuple[str, str], ...]  # (op, text) with op in " ", "-", "+"

    @property
    def old_lines(self) -> list[str]:
        return [text for op, text in self.lines if op in " -"]

    @property
    def changes(self) -> int:
        return sum(op in "+-" for op, _ in self.lines)


@dataclass(frozen=True)
class ParsedDiff:
    path: str
    hunks: tuple[Hunk, ...]

    @property
    def added_lines(self) -> list[str]:
        return [text for h in self.hunks for op, text in h.lines if op == "+"]

    @property
    def stats(self) -> tuple[int, int]:
        added = sum(op == "+" for h in self.hunks for op, _ in h.lines)
        removed = sum(op == "-" for h in self.hunks for op, _ in h.lines)
        return added, removed


def _header_path(line: str, prefix: str, expected: str) -> str:
    raw = line[4:].split("\t", 1)[0].strip()
    if not raw:
        raise DiffFormatError("A diff file header has no path.")
    if raw == "/dev/null":
        raise DiffPathError("Creating or deleting files is not allowed.")
    if raw.startswith(prefix):
        raw = raw[len(prefix):]
    problem: str | None = None
    try:
        path = normalize_project_path(raw)
    except ValueError as exc:
        problem = str(exc)
    if problem is not None:  # raised outside the handler: no chained ValueError
        raise DiffPathError(f"The diff file path is unsafe: {problem}.") from None
    if path != expected:
        raise DiffPathError(f"The diff targets {path!r}, but the expected file is {expected!r}.")
    return path


def parse_unified_diff(text: str, expected_path: str) -> ParsedDiff:
    """Parse and structurally validate a single-file unified diff."""
    if not isinstance(text, str) or not text.strip():
        raise EmptyDiffError("The diff is empty.")
    if len(text) > MAX_DIFF_CHARS:
        raise DiffFormatError(f"The diff is too large ({len(text)} characters; limit {MAX_DIFF_CHARS}).")
    expected = normalize_project_path(expected_path)
    lines = [line[:-1] if line.endswith("\r") else line for line in text.strip("\r\n").split("\n")]

    i = 0
    while i < len(lines) and lines[i].startswith(_PREAMBLE):
        i += 1
    for line in lines:
        if line.startswith(_FORBIDDEN):
            raise DiffFormatError("File creation, deletion, rename, mode or binary changes are not allowed.")
    if i >= len(lines) or not lines[i].startswith("--- "):
        raise DiffFormatError("The diff must start with a '--- a/<file>' header.")
    if i + 1 >= len(lines) or not lines[i + 1].startswith("+++ "):
        raise DiffFormatError("The '---' header must be followed by a '+++ b/<file>' header.")
    _header_path(lines[i], "a/", expected)
    _header_path(lines[i + 1], "b/", expected)
    i += 2

    hunks: list[Hunk] = []
    while i < len(lines):
        line = lines[i]
        if line.startswith(("--- ", "+++ ", "diff --git ")):
            raise MultiFileDiffError("The diff changes more than one file; only the flagged file may change.")
        if not line.startswith("@@"):
            raise DiffFormatError(f"Unexpected line after hunk {len(hunks)}; expected a '@@' hunk header.")
        match = _HUNK_HEADER.match(line)
        if not match:
            raise DiffHunkError(f"Hunk {len(hunks) + 1} has a malformed '@@' header.")
        old_start, old_count, new_start, new_count = (
            int(match.group(1)),
            int(match.group(2) or 1),
            int(match.group(3)),
            int(match.group(4) or 1),
        )
        number = len(hunks) + 1
        if old_count == 0 and new_count == 0:
            raise DiffHunkError(f"Hunk {number} is empty.")
        i += 1
        body: list[tuple[str, str]] = []
        old_seen = new_seen = 0
        while old_seen < old_count or new_seen < new_count:
            if i >= len(lines):
                raise DiffHunkError(f"Hunk {number} has fewer lines than its header declares.")
            raw = lines[i]
            op, content = (" ", "") if raw == "" else (raw[0], raw[1:])
            if op == "\\":
                i += 1
                continue
            if op not in " -+":
                raise DiffHunkError(f"Hunk {number} contains a line without a ' ', '-' or '+' prefix.")
            if op in " -":
                old_seen += 1
            if op in " +":
                new_seen += 1
            if old_seen > old_count or new_seen > new_count:
                raise DiffHunkError(f"Hunk {number} has more lines than its header declares.")
            body.append((op, content))
            i += 1
        while i < len(lines) and lines[i].startswith("\\"):
            i += 1
        if i < len(lines) and lines[i][:1] in (" ", "-", "+", "") and not lines[i].startswith(("--- ", "+++ ")):
            raise DiffHunkError(f"Hunk {number} has more lines than its header declares.")
        hunk = Hunk(old_start, old_count, new_start, new_count, tuple(body))
        if hunks:
            previous = hunks[-1]
            if hunk.old_start < previous.old_start + max(previous.old_count, 1):
                raise DiffHunkError(f"Hunk {number} overlaps or precedes the previous hunk.")
        hunks.append(hunk)
        if len(hunks) > MAX_HUNKS:
            raise DiffFormatError(f"The diff has too many hunks (limit {MAX_HUNKS}).")

    if not hunks:
        raise EmptyDiffError("The diff has no hunks.")
    if not any(h.changes for h in hunks):
        raise NoOpDiffError("The diff contains no added or removed lines.")
    return ParsedDiff(path=expected, hunks=tuple(hunks))


def _key(line: str) -> str:
    return line.rstrip("\r\n").rstrip(" \t")


@dataclass(frozen=True)
class AppliedDiff:
    display_lines: tuple[str, ...]  # patched view matching what the model saw
    real_lines: tuple[str, ...]  # patched real file


def apply_diff(
    parsed: ParsedDiff,
    display_lines: Sequence[str],
    real_lines: Sequence[str] | None = None,
    *,
    allowed_lines: frozenset[int] | None = None,
    newline: str = "\n",
) -> AppliedDiff:
    """Apply ``parsed`` in memory.

    Hunks are matched against ``display_lines`` (the view the model saw).
    Unchanged lines are copied from ``real_lines`` (same length), so values
    redacted in the display are restored in the real result.
    """
    real = list(display_lines if real_lines is None else real_lines)
    display = list(display_lines)
    if len(real) != len(display):
        raise DiffApplyError("Internal error: display and real sources differ in length.")
    keys = [_key(line) for line in display]
    out_display: list[str] = []
    out_real: list[str] = []
    pos = 0

    for number, hunk in enumerate(parsed.hunks, 1):
        block = [_key(line) for line in hunk.old_lines]
        if block:
            start = _locate(keys, block, hunk.old_start - 1, pos, number)
        else:  # pure insertion after line old_start
            start = hunk.old_start
            if start < pos or start > len(keys):
                raise DiffApplyError(f"Hunk {number} inserts at line {hunk.old_start}, outside the file.")
        _check_scope(number, start, len(block), allowed_lines)

        out_display += display[pos:start]
        out_real += real[pos:start]
        index = start
        for op, text in hunk.lines:
            if op == " ":
                out_display.append(display[index])
                out_real.append(real[index])
                index += 1
            elif op == "-":
                index += 1
            else:
                out_display.append(text + newline)
                out_real.append(text + newline)
        pos = index

    out_display += display[pos:]
    out_real += real[pos:]
    _fix_line_breaks(out_display, newline)
    _fix_line_breaks(out_real, newline)
    _keep_final_newline_state(display, out_display)
    _keep_final_newline_state(real, out_real)
    if out_real == real and out_display == display:
        raise NoOpDiffError("Applying the diff does not change the source.")
    return AppliedDiff(tuple(out_display), tuple(out_real))


def _locate(keys: list[str], block: list[str], expected: int, pos: int, number: int) -> int:
    size = len(block)
    candidates = [p for p in range(pos, len(keys) - size + 1) if keys[p : p + size] == block]
    if not candidates:
        raise DiffApplyError(
            f"Hunk {number} does not apply: its context and removed lines do not match the "
            f"source near line {expected + 1}."
        )
    best = min(abs(p - expected) for p in candidates)
    nearest = [p for p in candidates if abs(p - expected) == best]
    if len(nearest) > 1:
        raise DiffApplyError(f"Hunk {number} matches the source ambiguously; refusing to guess.")
    if best > MAX_HUNK_OFFSET:
        raise DiffApplyError(
            f"Hunk {number} only matches {best} lines away from its declared position "
            f"(limit {MAX_HUNK_OFFSET}); refusing to guess."
        )
    return nearest[0]


def _check_scope(number: int, start: int, size: int, allowed: frozenset[int] | None) -> None:
    if allowed is None:
        return
    if size:
        outside = [n for n in range(start + 1, start + size + 1) if n not in allowed]
        if outside:
            raise DiffScopeError(
                f"Hunk {number} touches line {outside[0]}, which was not in the code shown to the model."
            )
    elif start not in allowed and start + 1 not in allowed:
        raise DiffScopeError(f"Hunk {number} inserts code outside the code shown to the model.")


def _keep_final_newline_state(original: list[str], patched: list[str]) -> None:
    """If the original file did not end with a line break, neither does the result."""
    if original and patched and not original[-1].endswith(("\n", "\r")):
        patched[-1] = patched[-1].rstrip("\r\n")


def _fix_line_breaks(lines: list[str], newline: str) -> None:
    """Ensure every line except the last ends with a line break."""
    for i in range(len(lines) - 1):
        if not lines[i].endswith(("\n", "\r")):
            lines[i] += newline
