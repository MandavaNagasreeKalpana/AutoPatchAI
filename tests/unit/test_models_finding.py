"""Finding model validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from autopatch.models import Finding, Severity, VulnerabilityCategory


def test_valid_finding(make_finding):
    finding = make_finding()
    assert finding.category is VulnerabilityCategory.SQL_INJECTION
    assert finding.severity is Severity.MEDIUM
    assert finding.file_path == "app/db.py"
    assert finding.ast_context is not None
    assert finding.ast_context.enclosing_function == "find_user"


def test_bandit_style_uppercase_severity_accepted(make_finding):
    assert make_finding(severity="HIGH").severity is Severity.HIGH


def test_end_line_defaults_to_line(make_finding):
    finding = make_finding(end_line=None)
    assert finding.end_line == finding.line == 2


def test_generated_id_when_omitted(raw):
    data = raw.finding()
    del data["finding_id"]
    finding = Finding.model_validate(data)
    assert finding.finding_id.startswith("finding-")


def test_minimal_finding_without_context(make_finding):
    finding = make_finding(ast_context=None, explanation="", code_snippet="")
    assert finding.ast_context is None


def test_json_round_trip(make_finding):
    finding = make_finding()
    assert Finding.model_validate_json(finding.model_dump_json()) == finding


def test_findings_are_immutable(make_finding):
    finding = make_finding()
    with pytest.raises(ValidationError):
        finding.line = 5  # type: ignore[misc]


@pytest.mark.parametrize("line", [0, -1])
def test_invalid_line_rejected(make_finding, line):
    with pytest.raises(ValidationError, match="line"):
        make_finding(line=line, end_line=None)


def test_end_line_before_line_rejected(make_finding):
    with pytest.raises(ValidationError, match="end_line must be >= line"):
        make_finding(line=3, end_line=2)


def test_finding_outside_ast_context_rejected(make_finding):
    with pytest.raises(ValidationError, match="must contain the finding lines"):
        make_finding(line=10, end_line=10)


def test_ast_context_reversed_span_rejected(make_finding, raw):
    ctx = raw.finding()["ast_context"] | {"start_line": 5, "end_line": 1}
    with pytest.raises(ValidationError, match="end_line must be >= start_line"):
        make_finding(ast_context=ctx)


@pytest.mark.parametrize("confidence", [0.0, 0.5, 1.0])
def test_confidence_boundaries_accepted(make_finding, confidence):
    assert make_finding(confidence=confidence).confidence == confidence


@pytest.mark.parametrize("confidence", [-0.01, 1.01, float("nan"), float("inf")])
def test_confidence_out_of_range_rejected(make_finding, confidence):
    with pytest.raises(ValidationError, match="confidence"):
        make_finding(confidence=confidence)


@pytest.mark.parametrize("bad_id", ["", "   ", "has space", "-leading-dash", "x" * 129, "id/with/slash"])
def test_invalid_identifier_rejected(make_finding, bad_id):
    with pytest.raises(ValidationError, match="finding_id"):
        make_finding(finding_id=bad_id)


@pytest.mark.parametrize("field", ["rule_id", "description", "scanner"])
def test_required_text_fields_cannot_be_blank(make_finding, field):
    with pytest.raises(ValidationError, match=field):
        make_finding(**{field: "  "})


def test_invalid_category_rejected(make_finding):
    with pytest.raises(ValidationError, match="category"):
        make_finding(category="cross_site_scripting")


def test_invalid_severity_rejected(make_finding):
    with pytest.raises(ValidationError, match="severity"):
        make_finding(severity="extreme")


@pytest.mark.parametrize("path", ["/abs/app.py", "C:\\app.py", "../outside.py", "a/../../b.py"])
def test_unsafe_file_path_rejected(make_finding, path):
    with pytest.raises(ValidationError, match="file_path"):
        make_finding(file_path=path)


def test_windows_separators_normalized(make_finding):
    assert make_finding(file_path="app\\db.py").file_path == "app/db.py"


def test_unknown_fields_rejected(make_finding):
    with pytest.raises(ValidationError, match="extra"):
        make_finding(unexpected="x")
