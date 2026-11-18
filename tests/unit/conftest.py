"""Factories for building valid model instances in tests.

Each factory returns a valid object; tests pass keyword overrides to make one
field invalid at a time.
"""

from __future__ import annotations

from typing import Any

import pytest

from autopatch.models import Finding, Patch, VerificationResult

ORIGINAL = (
    "def find_user(conn, username):\n"
    "    query = f\"SELECT * FROM users WHERE name = '{username}'\"\n"
    "    return conn.execute(query).fetchone()\n"
)
PROPOSED = (
    "def find_user(conn, username):\n"
    '    query = "SELECT * FROM users WHERE name = ?"\n'
    "    return conn.execute(query, (username,)).fetchone()\n"
)
DIFF = (
    "--- a/app/db.py\n"
    "+++ b/app/db.py\n"
    "@@ -1,3 +1,3 @@\n"
    " def find_user(conn, username):\n"
    "-    query = f\"SELECT * FROM users WHERE name = '{username}'\"\n"
    "-    return conn.execute(query).fetchone()\n"
    '+    query = "SELECT * FROM users WHERE name = ?"\n'
    "+    return conn.execute(query, (username,)).fetchone()\n"
)


def finding_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "finding_id": "finding-1",
        "category": "sql_injection",
        "severity": "medium",
        "file_path": "app/db.py",
        "line": 2,
        "end_line": 2,
        "rule_id": "B608",
        "description": "Possible SQL injection via string-based query construction.",
        "explanation": "User input is interpolated into SQL.",
        "code_snippet": "query = f\"SELECT * FROM users WHERE name = '{username}'\"",
        "ast_context": {
            "node_type": "FunctionDef",
            "start_line": 1,
            "end_line": 3,
            "source": ORIGINAL,
            "enclosing_function": "find_user",
        },
        "confidence": 0.8,
        "scanner": "bandit",
    }
    data.update(overrides)
    return data


def patch_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "patch_id": "patch-1",
        "finding_id": "finding-1",
        "target_file": "app/db.py",
        "original_code": ORIGINAL,
        "proposed_code": PROPOSED,
        "explanation": "Use a parameterized query.",
        "unified_diff": DIFF,
        "model_name": "test-model",
        "confidence": 0.9,
        "assumptions": ["conn is a DB-API connection using qmark style"],
    }
    data.update(overrides)
    return data


def passed_check(**overrides: Any) -> dict[str, Any]:
    return {"status": "passed", **overrides}


def passed_rescan(**overrides: Any) -> dict[str, Any]:
    return {"status": "passed", "target_finding_resolved": True, **overrides}


def verification_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "verification_id": "verification-1",
        "patch_id": "patch-1",
        "syntax_check": passed_check(),
        "unit_tests": passed_check(),
        "security_rescan": passed_rescan(),
        "duration_seconds": 1.5,
    }
    data.update(overrides)
    return data


@pytest.fixture
def make_finding():
    """Build a Finding; keyword arguments override fields of a valid default."""
    return lambda **kw: Finding.model_validate(finding_data(**kw))


@pytest.fixture
def make_patch():
    return lambda **kw: Patch.model_validate(patch_data(**kw))


@pytest.fixture
def make_verification():
    return lambda **kw: VerificationResult.model_validate(verification_data(**kw))


@pytest.fixture
def raw():
    """Raw dict builders, for tests that need to tweak nested data."""

    class _Raw:
        finding = staticmethod(finding_data)
        patch = staticmethod(patch_data)
        verification = staticmethod(verification_data)
        passed_check = staticmethod(passed_check)
        passed_rescan = staticmethod(passed_rescan)

    return _Raw
