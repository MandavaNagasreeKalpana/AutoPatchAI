"""Unified diff parsing and in-memory application."""

from __future__ import annotations

import pytest
from _patch_generator_support import SQL_DIFF, SQL_SOURCE

from autopatch.patch_generator import (
    DiffApplyError,
    DiffFormatError,
    DiffHunkError,
    DiffPathError,
    DiffScopeError,
    EmptyDiffError,
    MultiFileDiffError,
    NoOpDiffError,
    apply_diff,
    parse_unified_diff,
)
from autopatch.patch_generator.diff import MAX_DIFF_CHARS, MAX_HUNK_OFFSET, MAX_HUNKS
from autopatch.common.source import split_lines

PATH = "app/db.py"
LINES = split_lines(SQL_SOURCE)


def diff(*body: str, path: str = PATH, old: str | None = None, new: str | None = None) -> str:
    return f"--- {old or 'a/' + path}\n+++ {new or 'b/' + path}\n" + "".join(body)


# --- parsing: valid ---------------------------------------------------------------


def test_valid_single_file_diff():
    parsed = parse_unified_diff(SQL_DIFF, PATH)
    assert parsed.path == PATH and len(parsed.hunks) == 1
    assert parsed.stats == (2, 2)
    hunk = parsed.hunks[0]
    assert (hunk.old_start, hunk.old_count, hunk.new_start, hunk.new_count) == (5, 4, 5, 4)


def test_git_preamble_timestamps_and_crlf_accepted():
    text = "diff --git a/app/db.py b/app/db.py\nindex 1234567..89abcde 100644\n" + SQL_DIFF.replace(
        "--- a/app/db.py", "--- a/app/db.py\t2026-11-18 10:00:00"
    )
    parsed = parse_unified_diff(text.replace("\n", "\r\n"), PATH)
    assert len(parsed.hunks) == 1


def test_no_newline_marker_accepted():
    text = SQL_DIFF + "\\ No newline at end of file\n"
    assert parse_unified_diff(text, PATH).stats == (2, 2)


def test_bare_empty_line_is_blank_context():
    text = diff("@@ -1,3 +1,3 @@\n", "-import sqlite3\n", "+import sqlite3 as db\n", "\n", " \n")
    parsed = parse_unified_diff(text, PATH)
    assert parsed.hunks[0].lines[2] == (" ", "")  # the bare "\n" line


# --- parsing: paths -----------------------------------------------------------------


def test_wrong_target_path_rejected():
    with pytest.raises(DiffPathError, match="expected file is 'app/db.py'"):
        parse_unified_diff(diff("@@ -1 +1 @@\n", "-a\n", "+b\n", path="app/other.py"), PATH)


@pytest.mark.parametrize("bad", ["/etc/passwd", "C:/Windows/win.ini", "C:\\app\\db.py", "\\\\srv\\share\\db.py"])
def test_absolute_paths_rejected(bad):
    with pytest.raises(DiffPathError, match="unsafe"):
        parse_unified_diff(diff("@@ -1 +1 @@\n", "-a\n", "+b\n", old=bad, new=bad), PATH)


@pytest.mark.parametrize("bad", ["a/../../etc/passwd", "a/app/../../secrets.py", "a/..\\x.py"])
def test_path_traversal_rejected(bad):
    with pytest.raises(DiffPathError, match="traversal"):
        parse_unified_diff(diff("@@ -1 +1 @@\n", "-a\n", "+b\n", old=bad), PATH)


def test_dev_null_rejected():
    with pytest.raises(DiffPathError, match="Creating or deleting"):
        parse_unified_diff(diff("@@ -0,0 +1 @@\n", "+x\n", old="/dev/null"), PATH)


def test_header_mismatch_between_old_and_new_rejected():
    with pytest.raises(DiffPathError):
        parse_unified_diff(diff("@@ -1 +1 @@\n", "-a\n", "+b\n", new="b/app/evil.py"), PATH)


# --- parsing: structure ----------------------------------------------------------------


def test_multiple_files_rejected():
    second = "--- a/app/other.py\n+++ b/app/other.py\n@@ -1 +1 @@\n-x\n+y\n"
    with pytest.raises(MultiFileDiffError):
        parse_unified_diff(SQL_DIFF + second, PATH)


def test_second_git_header_rejected():
    with pytest.raises(MultiFileDiffError):
        parse_unified_diff(SQL_DIFF + "diff --git a/x.py b/x.py\n", PATH)


@pytest.mark.parametrize(
    "text",
    [
        "```diff\n" + SQL_DIFF + "```\n",
        "Here is the patch:\n" + SQL_DIFF,
        "@@ -1 +1 @@\n-a\n+b\n",
        "--- a/app/db.py\n@@ -1 +1 @@\n-a\n+b\n",
    ],
)
def test_malformed_diff_rejected(text):
    with pytest.raises(DiffFormatError):
        parse_unified_diff(text, PATH)


@pytest.mark.parametrize("marker", ["new file mode 100644", "deleted file mode 100644", "rename from x.py", "Binary files a and b differ"])
def test_file_level_operations_rejected(marker):
    with pytest.raises(DiffFormatError, match="not allowed"):
        parse_unified_diff(f"diff --git a/app/db.py b/app/db.py\n{marker}\n" + SQL_DIFF, PATH)


@pytest.mark.parametrize("text", ["", "   \n\n", None])
def test_empty_diff_rejected(text):
    with pytest.raises(EmptyDiffError):
        parse_unified_diff(text, PATH)


def test_headers_without_hunks_rejected():
    with pytest.raises(EmptyDiffError, match="no hunks"):
        parse_unified_diff(diff(), PATH)


def test_context_only_diff_is_noop():
    with pytest.raises(NoOpDiffError):
        parse_unified_diff(diff("@@ -1,2 +1,2 @@\n", " import sqlite3\n", " \n"), PATH)


@pytest.mark.parametrize(
    ("body", "match"),
    [
        (["@@ -1,3 +1,3 @@\n", " import sqlite3\n", "-\n", "+# x\n"], "fewer lines"),
        (["@@ -1,1 +1,1 @@\n", "-import sqlite3\n", "+import os\n", " \n"], "more lines"),
        (["@@ -1,2 +1,1 @@\n", "-import sqlite3\n", "+a\n", "+b\n"], "more lines"),
        (["@@ -1,0 +1,0 @@\n"], "empty"),
        (["@@ -1 +1 @@ \n", "*import sqlite3\n"], "prefix"),
        (["@@ bogus @@\n", "-a\n"], "malformed"),
    ],
)
def test_hunk_line_count_and_format_errors(body, match):
    with pytest.raises(DiffHunkError, match=match):
        parse_unified_diff(diff(*body), PATH)


def test_overlapping_hunks_rejected():
    text = diff("@@ -5,2 +5,2 @@\n", " a\n", "-b\n", "+c\n", "@@ -4,1 +4,1 @@\n", "-d\n", "+e\n")
    with pytest.raises(DiffHunkError, match="overlaps"):
        parse_unified_diff(text, PATH)


def test_too_many_hunks_and_oversized_diff_rejected():
    many = diff(*[f"@@ -{n},1 +{n},1 @@\n-x{n}\n+y{n}\n" for n in range(1, MAX_HUNKS * 2 + 2, 2)])
    with pytest.raises(DiffFormatError, match="too many hunks"):
        parse_unified_diff(many, PATH)
    with pytest.raises(DiffFormatError, match="too large"):
        parse_unified_diff(SQL_DIFF + "#" * MAX_DIFF_CHARS, PATH)


# --- application ------------------------------------------------------------------------


def test_apply_produces_expected_source_without_mutating_input():
    original = list(LINES)
    result = apply_diff(parse_unified_diff(SQL_DIFF, PATH), original)
    text = "".join(result.real_lines)
    assert 'query = "SELECT * FROM users WHERE name = ?"' in text
    assert "cursor.execute(query, (name,))" in text
    assert original == LINES  # input list untouched


def test_apply_with_small_line_offset():
    shifted = SQL_DIFF.replace("@@ -5,4 +5,4 @@", "@@ -3,4 +3,4 @@")
    result = apply_diff(parse_unified_diff(shifted, PATH), LINES)
    assert "(name,)" in "".join(result.real_lines)


def test_patch_that_does_not_apply_rejected():
    wrong = SQL_DIFF.replace("     cursor = conn.cursor()", "     cursor = conn.cursor(dictionary=True)")
    with pytest.raises(DiffApplyError, match="does not apply"):
        apply_diff(parse_unified_diff(wrong, PATH), LINES)


def test_offset_beyond_limit_rejected():
    lines = ["# filler\n"] * (MAX_HUNK_OFFSET + 10) + list(LINES)
    with pytest.raises(DiffApplyError, match="away from its declared position"):
        apply_diff(parse_unified_diff(SQL_DIFF, PATH), lines)


def test_ambiguous_match_rejected():
    lines = ["x = 1\n", "y = 2\n", "x = 1\n"]
    text = diff("@@ -2,1 +2,1 @@\n", "-x = 1\n", "+x = 3\n")
    with pytest.raises(DiffApplyError, match="ambiguously"):
        apply_diff(parse_unified_diff(text, PATH), lines)


def test_lines_outside_shown_context_rejected():
    with pytest.raises(DiffScopeError, match="not in the code shown"):
        apply_diff(parse_unified_diff(SQL_DIFF, PATH), LINES, allowed_lines=frozenset({1, 2, 3, 4, 5}))


def test_identical_replacement_is_noop():
    text = diff("@@ -1,1 +1,1 @@\n", "-import sqlite3\n", "+import sqlite3\n")
    with pytest.raises(NoOpDiffError):
        apply_diff(parse_unified_diff(text, PATH), LINES)


def test_redacted_context_lines_restored_from_real_source():
    real = ["import os\n", 'TOKEN = "real-secret-value"\n', 'PASSWORD = "other-secret"\n']
    display = ["import os\n", 'TOKEN = "***REDACTED***"\n', 'PASSWORD = "***REDACTED***"\n']
    text = diff(
        "@@ -1,3 +1,3 @@\n", " import os\n", ' TOKEN = "***REDACTED***"\n',
        '-PASSWORD = "***REDACTED***"\n', '+PASSWORD = os.environ["PASSWORD"]\n',
    )
    result = apply_diff(parse_unified_diff(text, PATH), display, real)
    assert result.real_lines[1] == 'TOKEN = "real-secret-value"\n'
    assert result.display_lines[1] == 'TOKEN = "***REDACTED***"\n'
    assert "other-secret" not in "".join(result.real_lines)


def test_crlf_and_trailing_whitespace_tolerance():
    lines = [line.replace("\n", "\r\n") for line in LINES]
    lines[4] = lines[4].replace("\r\n", "   \r\n")  # trailing spaces on a context line
    result = apply_diff(parse_unified_diff(SQL_DIFF, PATH), lines, newline="\r\n")
    assert all(line.endswith("\r\n") for line in result.real_lines)
    assert result.real_lines[4] == lines[4]


def test_insertion_after_last_line_without_newline_keeps_eof_state():
    lines = ["a = 1\n", "b = 2"]
    text = diff("@@ -2,1 +2,2 @@\n", " b = 2\n", "+c = 3\n")
    result = apply_diff(parse_unified_diff(text, PATH), lines)
    assert "".join(result.real_lines) == "a = 1\nb = 2\nc = 3"


def test_editing_last_line_without_newline_keeps_eof_state():
    lines = ["a = 1\n", "b = 2"]
    text = diff("@@ -2,1 +2,1 @@\n", "-b = 2\n", "+b = 3\n", "\\ No newline at end of file\n")
    assert "".join(apply_diff(parse_unified_diff(text, PATH), lines).real_lines) == "a = 1\nb = 3"


def test_file_with_final_newline_keeps_it():
    text = diff("@@ -6,1 +6,1 @@\n", "-f = 6\n", "+f = 60\n")
    lines = split_lines("a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\n")
    assert "".join(apply_diff(parse_unified_diff(text, PATH), lines).real_lines).endswith("f = 60\n")


def test_new_start_is_not_checked_and_small_offsets_are_tolerated():
    """Documented tolerance: positions come from content matching, not +NEW_START."""
    text = diff("@@ -7,1 +99,1 @@\n", "-    cursor.execute(query)\n", "+    cursor.execute(query, ())\n")
    result = apply_diff(parse_unified_diff(text, PATH), LINES)
    assert "cursor.execute(query, ())" in "".join(result.real_lines)


def test_multiple_hunks_apply_in_order():
    lines = split_lines("a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\n")
    text = diff("@@ -1,1 +1,1 @@\n", "-a = 1\n", "+a = 10\n", "@@ -5,1 +5,1 @@\n", "-e = 5\n", "+e = 50\n")
    assert "".join(apply_diff(parse_unified_diff(text, PATH), lines).real_lines) == (
        "a = 10\nb = 2\nc = 3\nd = 4\ne = 50\nf = 6\n"
    )


def test_unicode_source_applies():
    lines = split_lines("naïve = 'çé'\nx = '日本'\n")
    text = diff("@@ -2,1 +2,1 @@\n", "-x = '日本'\n", "+x = '日本語'\n")
    assert "".join(apply_diff(parse_unified_diff(text, PATH), lines).real_lines) == "naïve = 'çé'\nx = '日本語'\n"
