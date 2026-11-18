"""Complete remediation report tying findings, patches and verifications together."""

from __future__ import annotations

from functools import partial

from pydantic import Field, model_validator

from .common import (
    AwareDatetime,
    Identifier,
    StrictModel,
    Text,
    find_duplicates,
    new_id,
    utc_now,
)
from .enums import PatchStatus
from .finding import Finding
from .patch import Patch
from .verification import VerificationResult


class RemediationReport(StrictModel):
    report_id: Identifier = Field(default_factory=partial(new_id, "report"))
    project_id: Identifier
    findings: list[Finding] = Field(default_factory=list)
    patches: list[Patch] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)
    summary: Text = ""
    created_at: AwareDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _references_are_consistent(self) -> RemediationReport:
        for label, ids in (
            ("finding_id", [f.finding_id for f in self.findings]),
            ("patch_id", [p.patch_id for p in self.patches]),
            ("verification_id", [v.verification_id for v in self.verifications]),
        ):
            if dupes := find_duplicates(ids):
                raise ValueError(f"duplicate {label} values: {dupes}")

        findings = {f.finding_id: f for f in self.findings}
        for patch in self.patches:
            finding = findings.get(patch.finding_id)
            if finding is None:
                raise ValueError(
                    f"patch {patch.patch_id!r} references unknown finding {patch.finding_id!r}"
                )
            if patch.target_file != finding.file_path:
                raise ValueError(
                    f"patch {patch.patch_id!r} targets {patch.target_file!r} but finding "
                    f"{finding.finding_id!r} is in {finding.file_path!r}"
                )

        patch_ids = {p.patch_id for p in self.patches}
        for ver in self.verifications:
            if ver.patch_id not in patch_ids:
                raise ValueError(
                    f"verification {ver.verification_id!r} references unknown patch "
                    f"{ver.patch_id!r}"
                )

        passed = {v.patch_id for v in self.verifications if v.passed}
        for patch in self.patches:
            if patch.status is PatchStatus.VERIFIED and patch.patch_id not in passed:
                raise ValueError(
                    f"patch {patch.patch_id!r} is marked verified without a passed verification"
                )
        return self

    def patches_for(self, finding_id: str) -> list[Patch]:
        return [p for p in self.patches if p.finding_id == finding_id]

    def verifications_for(self, patch_id: str) -> list[VerificationResult]:
        return [v for v in self.verifications if v.patch_id == patch_id]

    @property
    def statistics(self) -> dict[str, int]:
        verified_findings = {p.finding_id for p in self.patches if p.status is PatchStatus.VERIFIED}
        return {
            "findings": len(self.findings),
            "patches": len(self.patches),
            "verifications": len(self.verifications),
            "verified_patches": sum(p.status is PatchStatus.VERIFIED for p in self.patches),
            "findings_with_verified_patch": len(verified_findings),
        }
