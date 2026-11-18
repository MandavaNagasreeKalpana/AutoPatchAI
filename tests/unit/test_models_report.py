"""RemediationReport construction and cross-reference validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from autopatch.models import RemediationReport


def build(findings=(), patches=(), verifications=(), **kw):
    return RemediationReport(
        project_id=kw.pop("project_id", "demo-project"),
        findings=list(findings),
        patches=list(patches),
        verifications=list(verifications),
        **kw,
    )


def test_empty_report():
    report = build()
    assert report.report_id.startswith("report-")
    assert report.created_at.tzinfo is not None
    assert report.statistics["findings"] == 0


def test_complete_report(make_finding, make_patch, make_verification):
    report = build(
        [make_finding()],
        [make_patch(status="verified")],
        [make_verification()],
        summary="1 finding, 1 verified patch.",
    )
    assert report.patches_for("finding-1")[0].patch_id == "patch-1"
    assert report.verifications_for("patch-1")[0].passed
    assert report.statistics == {
        "findings": 1,
        "patches": 1,
        "verifications": 1,
        "verified_patches": 1,
        "findings_with_verified_patch": 1,
    }


def test_report_with_retry_attempts(make_finding, make_patch, make_verification):
    report = build(
        [make_finding()],
        [make_patch(patch_id="patch-1", status="failed"), make_patch(patch_id="patch-2", attempt=2)],
        [
            make_verification(
                verification_id="v-1",
                patch_id="patch-1",
                unit_tests={"status": "failed"},
                failure_details=["tests failed"],
            ),
        ],
    )
    assert len(report.patches_for("finding-1")) == 2


def test_json_round_trip(make_finding, make_patch, make_verification):
    report = build([make_finding()], [make_patch()], [make_verification()])
    assert RemediationReport.model_validate_json(report.model_dump_json()) == report


def test_empty_project_id_rejected():
    with pytest.raises(ValidationError, match="project_id"):
        build(project_id="")


def test_patch_with_unknown_finding_rejected(make_finding, make_patch):
    with pytest.raises(ValidationError, match="unknown finding"):
        build([make_finding()], [make_patch(finding_id="finding-404")])


def test_patch_for_wrong_file_rejected(make_finding, make_patch, raw):
    diff = raw.patch()["unified_diff"].replace("app/db.py", "app/other.py")
    patch = make_patch(target_file="app/other.py", unified_diff=diff)
    with pytest.raises(ValidationError, match="targets"):
        build([make_finding()], [patch])


def test_verification_with_unknown_patch_rejected(make_finding, make_patch, make_verification):
    with pytest.raises(ValidationError, match="unknown patch"):
        build([make_finding()], [make_patch()], [make_verification(patch_id="patch-404")])


def test_verified_patch_without_passed_verification_rejected(make_finding, make_patch):
    with pytest.raises(ValidationError, match="marked verified"):
        build([make_finding()], [make_patch(status="verified")])


@pytest.mark.parametrize("kind", ["finding", "patch", "verification"])
def test_duplicate_ids_rejected(kind, make_finding, make_patch, make_verification):
    findings, patches, verifications = [make_finding()], [make_patch()], [make_verification()]
    {"finding": findings, "patch": patches, "verification": verifications}[kind].append(
        {"finding": findings, "patch": patches, "verification": verifications}[kind][0]
    )
    with pytest.raises(ValidationError, match=f"duplicate {kind}_id"):
        build(findings, patches, verifications)
