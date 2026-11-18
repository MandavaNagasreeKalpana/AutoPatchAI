"""Enum values and project-path validation."""

from __future__ import annotations

import pytest

from autopatch.models import (
    CATEGORY_INFO,
    PatchStatus,
    Severity,
    VerificationStatus,
    VulnerabilityCategory,
    normalize_project_path,
)

# --- enums -------------------------------------------------------------------


def test_initial_vulnerability_categories():
    assert {c.value for c in VulnerabilityCategory} == {
        "sql_injection",
        "hardcoded_credentials",
        "insecure_deserialization",
    }


def test_every_category_has_metadata():
    """Adding a category without metadata must fail this test."""
    assert set(CATEGORY_INFO) == set(VulnerabilityCategory)
    for category in VulnerabilityCategory:
        assert category.display_name
        assert all(cwe.startswith("CWE-") for cwe in category.cwe_ids)


def test_category_metadata_values():
    assert VulnerabilityCategory.SQL_INJECTION.display_name == "SQL Injection"
    assert VulnerabilityCategory.SQL_INJECTION.cwe_ids == ("CWE-89",)
    assert "CWE-502" in VulnerabilityCategory.INSECURE_DESERIALIZATION.cwe_ids


def test_severity_values_and_ordering():
    assert [s.value for s in Severity] == ["low", "medium", "high", "critical"]
    assert sorted(Severity, key=lambda s: s.rank)[-1] is Severity.CRITICAL
    assert Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank


def test_patch_and_verification_status_values():
    assert {s.value for s in PatchStatus} == {"generated", "verified", "failed", "rejected"}
    assert {s.value for s in VerificationStatus} == {
        "passed",
        "failed",
        "error",
        "skipped",
        "unverified",
    }


@pytest.mark.parametrize("raw", ["HIGH", "High", " high "])
def test_enums_accept_any_case(raw):
    assert Severity(raw) is Severity.HIGH


def test_enums_are_strings():
    assert VulnerabilityCategory.SQL_INJECTION == "sql_injection"
    assert f"{Severity.LOW}" == "low"


def test_unknown_enum_value_rejected():
    with pytest.raises(ValueError):
        VulnerabilityCategory("xss")


# --- project paths ------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("app/db.py", "app/db.py"),
        ("app\\db.py", "app/db.py"),
        ("./app/db.py", "app/db.py"),
        ("app//sub/./db.py", "app/sub/db.py"),
        ("main.py", "main.py"),
    ],
)
def test_valid_relative_paths_are_normalized(raw, expected):
    assert normalize_project_path(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "/etc/passwd",
        "\\Windows\\system.ini",
        "C:\\Windows\\system.ini",
        "C:/Windows/system.ini",
        "C:relative.py",
        "\\\\server\\share\\file.py",
        "//server/share/file.py",
    ],
)
def test_absolute_paths_rejected(raw):
    with pytest.raises(ValueError):
        normalize_project_path(raw)


@pytest.mark.parametrize(
    "raw",
    ["../secrets.py", "app/../../etc/passwd", "app\\..\\..\\x.py", "..", "app/.."],
)
def test_path_traversal_rejected(raw):
    with pytest.raises(ValueError, match="traversal"):
        normalize_project_path(raw)


@pytest.mark.parametrize("raw", ["", "   ", ".", "./", "app/db.py\x00.txt", "a\nb.py", "db.py:stream"])
def test_empty_or_malformed_paths_rejected(raw):
    with pytest.raises(ValueError):
        normalize_project_path(raw)
