"""Shared enumerations.

To add a vulnerability category:
1. Add a member to :class:`VulnerabilityCategory`.
2. Add its metadata to :data:`CATEGORY_INFO` (a test enforces this).
Detection rules (e.g. Bandit test IDs) are mapped to categories by the
Scanner Agent's rule registry, not here.
"""

from __future__ import annotations

from enum import StrEnum
from typing import NamedTuple


class _CaseInsensitiveStrEnum(StrEnum):
    """String enum that also accepts its values in any letter case.

    Lets external tool output such as Bandit's ``"HIGH"`` map onto ``"high"``.
    """

    @classmethod
    def _missing_(cls, value: object) -> _CaseInsensitiveStrEnum | None:
        if isinstance(value, str):
            lowered = value.strip().lower()
            for member in cls:
                if member.value == lowered:
                    return member
        return None


class VulnerabilityCategory(_CaseInsensitiveStrEnum):
    SQL_INJECTION = "sql_injection"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    INSECURE_DESERIALIZATION = "insecure_deserialization"

    @property
    def display_name(self) -> str:
        return CATEGORY_INFO[self].display_name

    @property
    def cwe_ids(self) -> tuple[str, ...]:
        return CATEGORY_INFO[self].cwe_ids


class CategoryInfo(NamedTuple):
    display_name: str
    cwe_ids: tuple[str, ...]


CATEGORY_INFO: dict[VulnerabilityCategory, CategoryInfo] = {
    VulnerabilityCategory.SQL_INJECTION: CategoryInfo("SQL Injection", ("CWE-89",)),
    VulnerabilityCategory.HARDCODED_CREDENTIALS: CategoryInfo(
        "Hardcoded Credentials", ("CWE-798", "CWE-259")
    ),
    VulnerabilityCategory.INSECURE_DESERIALIZATION: CategoryInfo(
        "Insecure Deserialization", ("CWE-502",)
    ),
}


class Severity(_CaseInsensitiveStrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric order for sorting (higher is more severe)."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class PatchStatus(_CaseInsensitiveStrEnum):
    """Lifecycle of a candidate patch. No status means 'applied': patches are
    never applied automatically."""

    GENERATED = "generated"  # produced by the generator, not yet verified
    VERIFIED = "verified"  # passed every verification check
    FAILED = "failed"  # failed verification
    REJECTED = "rejected"  # discarded (invalid output, or by a reviewer)


class VerificationStatus(_CaseInsensitiveStrEnum):
    """Outcome of a single check or of a whole verification run.

    ``SKIPPED`` applies only to individual checks (e.g. tests skipped because
    Docker is unavailable). ``UNVERIFIED`` applies only to the overall result
    when no check failed but at least one was skipped.
    """

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"
    UNVERIFIED = "unverified"
