"""Result of one Scanner Agent run."""

from __future__ import annotations

from pydantic import Field, model_validator

from .common import (
    AwareDatetime,
    LineNumber,
    NonEmptyStr,
    ProjectPath,
    StrictModel,
    Text,
    find_duplicates,
    utc_now,
)
from .enums import Severity, VulnerabilityCategory
from .finding import Finding


class SkippedFile(StrictModel):
    file_path: ProjectPath
    reason: NonEmptyStr


class IgnoredIssue(StrictModel):
    """A Bandit result for a rule AutoPatch does not support (not patched)."""

    rule_id: NonEmptyStr
    test_name: Text = ""
    file_path: ProjectPath
    line: LineNumber
    severity: Severity


class ScanResult(StrictModel):
    project_root: NonEmptyStr  # absolute path, for display only
    scanner: NonEmptyStr = "bandit"
    scanner_version: NonEmptyStr
    files_scanned: list[ProjectPath] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    related_findings: list[Finding] = Field(default_factory=list)
    ignored_issues: list[IgnoredIssue] = Field(default_factory=list)
    skipped_files: list[SkippedFile] = Field(default_factory=list)
    errors: list[Text] = Field(default_factory=list)
    started_at: AwareDatetime = Field(default_factory=utc_now)
    duration_seconds: float = Field(default=0.0, ge=0.0, allow_inf_nan=False)

    @model_validator(mode="after")
    def _unique_ids(self) -> ScanResult:
        ids = [f.finding_id for f in (*self.findings, *self.related_findings)]
        if dupes := find_duplicates(ids):
            raise ValueError(f"duplicate finding_id values: {dupes}")
        return self

    @property
    def ok(self) -> bool:
        """True when the scan completed without operational errors."""
        return not self.errors

    def counts_by_category(self) -> dict[VulnerabilityCategory, int]:
        counts = {c: 0 for c in VulnerabilityCategory}
        for finding in self.findings:
            counts[finding.category] += 1
        return counts
