"""VerificationResult validation and overall-status rules."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from autopatch.models import (
    CheckResult,
    RescanResult,
    VerificationResult,
    VerificationStatus,
    derive_overall_status,
)

S = VerificationStatus


def test_all_checks_passed(make_verification):
    result = make_verification()
    assert result.overall_status is S.PASSED
    assert result.passed is True


def test_explicit_matching_overall_status_accepted(make_verification):
    assert make_verification(overall_status="passed").overall_status is S.PASSED


def test_failed_check_gives_failed_overall(make_verification):
    result = make_verification(
        unit_tests={"status": "failed", "message": "2 tests failed"},
        failure_details=["test_find_user failed: AssertionError"],
    )
    assert result.overall_status is S.FAILED
    assert result.passed is False


def test_skipped_tests_give_unverified_overall(make_verification):
    result = make_verification(
        unit_tests={"status": "skipped", "message": "Docker unavailable"},
    )
    assert result.overall_status is S.UNVERIFIED
    assert result.passed is False


def test_error_check_gives_error_overall(make_verification):
    result = make_verification(
        syntax_check={"status": "error", "message": "parser crashed"},
        failure_details=["syntax check could not run"],
    )
    assert result.overall_status is S.ERROR


def test_failed_takes_precedence_over_error_and_skip():
    checks = [
        CheckResult(status=S.SKIPPED),
        CheckResult(status=S.ERROR),
        CheckResult(status=S.FAILED),
    ]
    assert derive_overall_status(*checks) is S.FAILED


def test_overall_status_contradicting_checks_rejected(make_verification):
    with pytest.raises(ValidationError, match="contradicts"):
        make_verification(
            overall_status="passed",
            unit_tests={"status": "failed"},
            failure_details=["x"],
        )


def test_failure_details_required_on_failure(make_verification):
    with pytest.raises(ValidationError, match="failure_details"):
        make_verification(unit_tests={"status": "failed"}, failure_details=["  "])


@pytest.mark.parametrize("status", ["unverified"])
def test_single_check_cannot_be_unverified(status):
    with pytest.raises(ValidationError, match="single check"):
        CheckResult(status=status)


def test_passed_rescan_requires_resolution():
    with pytest.raises(ValidationError, match="target_finding_resolved"):
        RescanResult(status="passed", target_finding_resolved=False)
    with pytest.raises(ValidationError, match="target_finding_resolved"):
        RescanResult(status="passed")


def test_passed_rescan_cannot_have_new_findings():
    with pytest.raises(ValidationError, match="no new findings"):
        RescanResult(status="passed", target_finding_resolved=True, new_finding_ids=["B105"])


def test_failed_rescan_with_new_findings(make_verification):
    result = make_verification(
        security_rescan={
            "status": "failed",
            "target_finding_resolved": True,
            "new_finding_ids": ["B105"],
        },
        failure_details=["patch introduced B105"],
    )
    assert result.overall_status is S.FAILED


@pytest.mark.parametrize("duration", [-1.0, float("nan"), float("inf")])
def test_invalid_duration_rejected(make_verification, duration):
    with pytest.raises(ValidationError, match="duration_seconds"):
        make_verification(duration_seconds=duration)


def test_zero_duration_accepted(make_verification):
    assert make_verification(duration_seconds=0).duration_seconds == 0


@pytest.mark.parametrize("field", ["verification_id", "patch_id"])
def test_empty_ids_rejected(make_verification, field):
    with pytest.raises(ValidationError, match=field):
        make_verification(**{field: ""})


def test_json_round_trip(make_verification):
    result = make_verification()
    restored = VerificationResult.model_validate_json(result.model_dump_json())
    assert restored == result
    assert isinstance(restored.security_rescan, RescanResult)
