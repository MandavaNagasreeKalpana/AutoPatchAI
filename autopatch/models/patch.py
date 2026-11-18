"""Candidate patch produced by the Patch Generator Agent.

A patch is only a proposal. Nothing in this model applies it to disk.
"""

from __future__ import annotations

from functools import partial

from pydantic import Field, model_validator

from .common import (
    AwareDatetime,
    CodeStr,
    Confidence,
    Identifier,
    NonEmptyStr,
    ProjectPath,
    StrictModel,
    Text,
    new_id,
    normalize_project_path,
    utc_now,
)
from .enums import PatchStatus


def _diff_header_path(line: str) -> str | None:
    """Extract the path from a ``--- a/x`` or ``+++ b/x`` header line."""
    raw = line[4:].split("\t", 1)[0].strip()
    if raw == "/dev/null":
        return None
    if raw.startswith(("a/", "b/")):
        raw = raw[2:]
    return raw


class Patch(StrictModel):
    patch_id: Identifier = Field(default_factory=partial(new_id, "patch"))
    finding_id: Identifier
    target_file: ProjectPath
    original_code: CodeStr
    proposed_code: CodeStr
    explanation: NonEmptyStr
    unified_diff: CodeStr
    model_name: NonEmptyStr
    generated_at: AwareDatetime = Field(default_factory=utc_now)
    confidence: Confidence
    assumptions: list[Text] = Field(default_factory=list)
    status: PatchStatus = PatchStatus.GENERATED
    attempt: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def _check_content(self) -> Patch:
        if not self.original_code.strip():
            raise ValueError("original_code must not be empty")
        if self.proposed_code == self.original_code:
            raise ValueError("proposed_code is identical to original_code (no change)")
        self._check_diff()
        return self

    def _check_diff(self) -> None:
        lines = self.unified_diff.splitlines()
        old = [ln for ln in lines if ln.startswith("--- ")]
        new = [ln for ln in lines if ln.startswith("+++ ")]
        if not old or not new or not any(ln.startswith("@@") for ln in lines):
            raise ValueError("unified_diff must contain '---', '+++' headers and a '@@' hunk")
        for header in old + new:
            path = _diff_header_path(header)
            if path is None:
                continue
            try:
                normalized = normalize_project_path(path)
            except ValueError as exc:
                raise ValueError(f"unified_diff header path is unsafe: {exc}") from None
            if normalized != self.target_file:
                raise ValueError(
                    f"unified_diff touches {normalized!r} but target_file is "
                    f"{self.target_file!r}"
                )
