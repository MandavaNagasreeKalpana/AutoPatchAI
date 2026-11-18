"""Shared data models used by every AutoPatch agent."""

from .benchmark import BenchmarkManifest, BenchmarkSample
from .common import new_id, normalize_project_path
from .enums import (
    CATEGORY_INFO,
    PatchStatus,
    Severity,
    VerificationStatus,
    VulnerabilityCategory,
)
from .finding import AstContext, Finding
from .patch import Patch
from .report import RemediationReport
from .scan import IgnoredIssue, ScanResult, SkippedFile
from .verification import (
    CheckResult,
    RescanResult,
    VerificationResult,
    derive_overall_status,
)

__all__ = [
    "CATEGORY_INFO",
    "AstContext",
    "BenchmarkManifest",
    "BenchmarkSample",
    "CheckResult",
    "Finding",
    "IgnoredIssue",
    "Patch",
    "PatchStatus",
    "RemediationReport",
    "RescanResult",
    "ScanResult",
    "Severity",
    "SkippedFile",
    "VerificationResult",
    "VerificationStatus",
    "VulnerabilityCategory",
    "derive_overall_status",
    "new_id",
    "normalize_project_path",
]
