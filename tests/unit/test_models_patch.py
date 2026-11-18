"""Patch model validation."""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from autopatch.models import Patch, PatchStatus


def test_valid_patch(make_patch):
    patch = make_patch()
    assert patch.status is PatchStatus.GENERATED
    assert patch.attempt == 1
    assert patch.generated_at.tzinfo is not None
    assert patch.assumptions


def test_generated_id_and_timestamp_when_omitted(raw):
    data = raw.patch()
    del data["patch_id"]
    patch = Patch.model_validate(data)
    assert patch.patch_id.startswith("patch-")
    assert patch.generated_at.tzinfo is not None


def test_json_round_trip(make_patch):
    patch = make_patch()
    assert Patch.model_validate_json(patch.model_dump_json()) == patch


def test_naive_timestamp_rejected(make_patch):
    with pytest.raises(ValidationError, match="timezone-aware"):
        make_patch(generated_at=datetime(2026, 11, 18, 12, 0, 0))


@pytest.mark.parametrize("confidence", [0, 1])
def test_confidence_boundaries_accepted(make_patch, confidence):
    assert make_patch(confidence=confidence).confidence == confidence


@pytest.mark.parametrize("confidence", [-0.1, 1.5])
def test_confidence_out_of_range_rejected(make_patch, confidence):
    with pytest.raises(ValidationError, match="confidence"):
        make_patch(confidence=confidence)


@pytest.mark.parametrize("field", ["patch_id", "finding_id"])
def test_empty_ids_rejected(make_patch, field):
    with pytest.raises(ValidationError, match=field):
        make_patch(**{field: ""})


@pytest.mark.parametrize("field", ["explanation", "model_name"])
def test_blank_required_text_rejected(make_patch, field):
    with pytest.raises(ValidationError, match=field):
        make_patch(**{field: " "})


def test_no_op_patch_rejected(make_patch, raw):
    original = raw.patch()["original_code"]
    with pytest.raises(ValidationError, match="identical"):
        make_patch(proposed_code=original)


def test_empty_original_code_rejected(make_patch):
    with pytest.raises(ValidationError, match="original_code"):
        make_patch(original_code="  \n")


def test_attempt_must_be_positive(make_patch):
    with pytest.raises(ValidationError, match="attempt"):
        make_patch(attempt=0)


@pytest.mark.parametrize("path", ["/etc/passwd", "../../evil.py", "D:\\x\\y.py"])
def test_unsafe_target_file_rejected(make_patch, path):
    with pytest.raises(ValidationError, match="target_file"):
        make_patch(target_file=path)


def test_diff_without_hunk_rejected(make_patch):
    with pytest.raises(ValidationError, match="@@"):
        make_patch(unified_diff="--- a/app/db.py\n+++ b/app/db.py\n")


def test_diff_for_other_file_rejected(make_patch, raw):
    diff = raw.patch()["unified_diff"].replace("app/db.py", "app/other.py")
    with pytest.raises(ValidationError, match="target_file"):
        make_patch(unified_diff=diff)


def test_diff_with_traversal_header_rejected(make_patch, raw):
    diff = raw.patch()["unified_diff"].replace("+++ b/app/db.py", "+++ b/../../etc/passwd")
    with pytest.raises(ValidationError, match="unsafe"):
        make_patch(unified_diff=diff)


def test_diff_header_with_timestamp_accepted(make_patch, raw):
    diff = raw.patch()["unified_diff"].replace(
        "--- a/app/db.py", "--- a/app/db.py\t2026-11-18 10:00:00"
    )
    assert make_patch(unified_diff=diff).target_file == "app/db.py"
