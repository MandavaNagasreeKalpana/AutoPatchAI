"""Security finding produced by the Scanner Agent."""

from __future__ import annotations

from functools import partial

from pydantic import Field, model_validator

from .common import (
    CodeStr,
    Confidence,
    Identifier,
    LineNumber,
    NonEmptyStr,
    ProjectPath,
    StrictModel,
    Text,
    new_id,
)
from .enums import Severity, VulnerabilityCategory


class AstContext(StrictModel):
    """Code context located with Python's ``ast`` module.

    ``start_line``/``end_line`` describe the span (usually the enclosing
    function) that a patch is allowed to replace.
    """

    node_type: NonEmptyStr  # e.g. "FunctionDef", "Module"
    start_line: LineNumber
    end_line: LineNumber
    source: CodeStr
    enclosing_function: Text | None = None  # qualified, e.g. "UserRepo.find"
    enclosing_class: Text | None = None
    imports: list[Text] = Field(default_factory=list)

    @model_validator(mode="after")
    def _span_is_ordered(self) -> AstContext:
        if self.end_line < self.start_line:
            raise ValueError("ast_context.end_line must be >= start_line")
        return self


class Finding(StrictModel):
    finding_id: Identifier = Field(default_factory=partial(new_id, "finding"))
    category: VulnerabilityCategory
    severity: Severity
    file_path: ProjectPath
    line: LineNumber
    end_line: LineNumber | None = None  # defaults to ``line``
    rule_id: NonEmptyStr  # e.g. Bandit "B608"
    description: NonEmptyStr  # short, one line
    explanation: Text = ""  # longer explanation of the risk
    code_snippet: CodeStr = ""
    ast_context: AstContext | None = None
    confidence: Confidence
    scanner: NonEmptyStr = "bandit"

    @model_validator(mode="after")
    def _lines_are_consistent(self) -> Finding:
        if self.end_line is None:
            object.__setattr__(self, "end_line", self.line)
        assert self.end_line is not None
        if self.end_line < self.line:
            raise ValueError("end_line must be >= line")
        ctx = self.ast_context
        if ctx is not None and not (ctx.start_line <= self.line and self.end_line <= ctx.end_line):
            raise ValueError(
                "ast_context span "
                f"{ctx.start_line}-{ctx.end_line} must contain the finding lines "
                f"{self.line}-{self.end_line}"
            )
        return self
