"""Schema for ``benchmarks/manifest.json``.

These models validate structure only. Loading and file checks live in
:mod:`autopatch.benchmark`, which reads sample files as text and never
imports or executes them.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from .common import (
    Identifier,
    LineNumber,
    NonEmptyStr,
    ProjectPath,
    StrictModel,
    find_duplicates,
)
from .enums import VulnerabilityCategory

_CWE_RE = re.compile(r"^CWE-\d{1,5}$")
_RULE_RE = re.compile(r"^[A-Z]{1,5}\d{1,5}$")


def _check_cwe(value: str) -> str:
    if not _CWE_RE.fullmatch(value):
        raise ValueError("CWE id must look like 'CWE-89'")
    return value


def _check_rule(value: str) -> str:
    if not _RULE_RE.fullmatch(value):
        raise ValueError("rule id must look like 'B608'")
    return value


CweId = Annotated[str, AfterValidator(_check_cwe)]
RuleId = Annotated[str, AfterValidator(_check_rule)]


class BenchmarkSample(StrictModel):
    sample_id: Identifier
    category: VulnerabilityCategory
    description: NonEmptyStr
    vulnerable_file: ProjectPath  # relative to the benchmarks/ directory
    expected_vulnerability: VulnerabilityCategory
    expected_cwe: CweId
    expected_rule_ids: list[RuleId] = Field(min_length=1)
    expected_lines: list[LineNumber] = Field(min_length=1)

    @model_validator(mode="after")
    def _consistent(self) -> BenchmarkSample:
        if self.expected_vulnerability is not self.category:
            raise ValueError("expected_vulnerability must match category")
        if self.expected_cwe not in self.category.cwe_ids:
            raise ValueError(
                f"expected_cwe {self.expected_cwe} is not mapped to category "
                f"{self.category.value} ({', '.join(self.category.cwe_ids)})"
            )
        prefix = f"samples/{self.category.value}/"
        if not self.vulnerable_file.startswith(prefix):
            raise ValueError(f"vulnerable_file must be under {prefix}")
        if not self.vulnerable_file.endswith(".py"):
            raise ValueError("vulnerable_file must be a .py file")
        return self


class BenchmarkManifest(StrictModel):
    schema_version: Literal[1]
    name: NonEmptyStr
    description: NonEmptyStr
    samples: list[BenchmarkSample] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique(self) -> BenchmarkManifest:
        if dupes := find_duplicates(s.sample_id for s in self.samples):
            raise ValueError(f"duplicate sample_id values: {dupes}")
        if dupes := find_duplicates(s.vulnerable_file for s in self.samples):
            raise ValueError(f"duplicate vulnerable_file values: {dupes}")
        return self

    def by_category(self, category: VulnerabilityCategory) -> list[BenchmarkSample]:
        return [s for s in self.samples if s.category is category]
