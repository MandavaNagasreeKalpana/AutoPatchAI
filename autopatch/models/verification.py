"""Verification results produced by the Verification Agent."""

from __future__ import annotations

from functools import partial

from pydantic import Field, model_validator

from .common import Identifier, StrictModel, Text, new_id
from .enums import VerificationStatus

_CHECK_STATUSES = frozenset(
    {
        VerificationStatus.PASSED,
        VerificationStatus.FAILED,
        VerificationStatus.ERROR,
        VerificationStatus.SKIPPED,
    }
)


class CheckResult(StrictModel):
    """Result of one verification check (syntax, unit tests, ...)."""

    status: VerificationStatus
    message: Text = ""
    output: Text = ""  # trimmed tool output / log tail
    duration_seconds: float = Field(default=0.0, ge=0.0, allow_inf_nan=False)

    @model_validator(mode="after")
    def _status_allowed(self) -> CheckResult:
        if self.status not in _CHECK_STATUSES:
            raise ValueError(f"a single check cannot have status {self.status.value!r}")
        return self


class RescanResult(CheckResult):
    """Security rescan of the patched file."""

    target_finding_resolved: bool | None = None
    new_finding_ids: list[Text] = Field(default_factory=list)

    @model_validator(mode="after")
    def _passed_means_clean(self) -> RescanResult:
        if self.status is VerificationStatus.PASSED and (
            self.target_finding_resolved is not True or self.new_finding_ids
        ):
            raise ValueError(
                "a passed rescan requires target_finding_resolved=True and no new findings"
            )
        return self


def derive_overall_status(*checks: CheckResult) -> VerificationStatus:
    """FAILED if any check failed, else ERROR if any errored, else UNVERIFIED
    if any was skipped, else PASSED."""
    statuses = {c.status for c in checks}
    for status in (
        VerificationStatus.FAILED,
        VerificationStatus.ERROR,
    ):
        if status in statuses:
            return status
    if VerificationStatus.SKIPPED in statuses:
        return VerificationStatus.UNVERIFIED
    return VerificationStatus.PASSED


class VerificationResult(StrictModel):
    verification_id: Identifier = Field(default_factory=partial(new_id, "verification"))
    patch_id: Identifier
    syntax_check: CheckResult
    unit_tests: CheckResult
    security_rescan: RescanResult
    overall_status: VerificationStatus | None = None  # derived when omitted
    failure_details: list[Text] = Field(default_factory=list)
    duration_seconds: float = Field(ge=0.0, allow_inf_nan=False)

    @model_validator(mode="after")
    def _overall_is_consistent(self) -> VerificationResult:
        derived = derive_overall_status(self.syntax_check, self.unit_tests, self.security_rescan)
        if self.overall_status is None:
            object.__setattr__(self, "overall_status", derived)
        elif self.overall_status is not derived:
            raise ValueError(
                f"overall_status {self.overall_status.value!r} contradicts the check "
                f"results (expected {derived.value!r})"
            )
        if derived in (VerificationStatus.FAILED, VerificationStatus.ERROR) and not any(
            d.strip() for d in self.failure_details
        ):
            raise ValueError("failure_details are required when verification fails or errors")
        return self

    @property
    def passed(self) -> bool:
        return self.overall_status is VerificationStatus.PASSED
