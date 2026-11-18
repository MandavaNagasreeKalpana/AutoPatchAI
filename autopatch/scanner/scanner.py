"""Scanner Agent: Bandit + AST context -> validated ``Finding`` objects.

The agent is strictly read-only. It lists files inside the project root, lets
Bandit parse them, and reads them (as bytes) to build AST context. It never
writes to, imports, or executes the scanned project.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from pydantic import ValidationError

from autopatch.models import Finding, Severity
from autopatch.models.common import utc_now
from autopatch.models.scan import IgnoredIssue, ScanResult, SkippedFile

from .ast_context import (
    ParsedSource,
    build_context,
    decode_source,
    extract_snippet,
    parse_source,
    redact_string_literals,
)
from .bandit_runner import BanditIssue, BanditRun, run_bandit
from .errors import safe_error_message
from .file_discovery import DiscoveryResult, discover_python_files
from .rule_mapping import (
    CATEGORY_EXPLANATIONS,
    CONFIDENCE_SCORES,
    REDACT_LITERALS,
    RuleKind,
    classify_rule,
    rule_spec,
)

BanditRunner = Callable[..., BanditRun]


def stable_finding_id(rel_path: str, rule_id: str, line: int, col: int) -> str:
    digest = hashlib.sha256(f"{rel_path}:{rule_id}:{line}:{col}".encode()).hexdigest()
    return f"finding-{digest[:12]}"


def _severity(value: str) -> Severity:
    return Severity.LOW if value == "UNDEFINED" else Severity(value)


class ScannerAgent:
    """Scan a Python project and return a :class:`ScanResult`."""

    def __init__(
        self,
        *,
        exclude: Iterable[str] = (),
        ignore_nosec: bool = False,
        runner: BanditRunner = run_bandit,
    ) -> None:
        self.exclude = tuple(exclude)
        self.ignore_nosec = ignore_nosec
        self._runner = runner

    def scan(self, project_root: str | os.PathLike[str]) -> ScanResult:
        """Raise :class:`~autopatch.scanner.errors.ScannerError` on operational
        failures (bad root, Bandit missing or crashing). Per-file and
        per-result problems are recorded in the result instead."""
        started_at = utc_now()
        clock = time.perf_counter()
        discovery = discover_python_files(project_root, self.exclude)
        run = self._runner(discovery.files, ignore_nosec=self.ignore_nosec)

        converter = _Converter(discovery)
        findings: list[Finding] = []
        related: list[Finding] = []
        ignored: list[IgnoredIssue] = []
        errors = list(run.malformed)

        for issue in run.issues:
            try:
                kind, item = converter.convert(issue)
            except _ConversionError as exc:
                errors.append(str(exc))
                continue
            if kind is RuleKind.SUPPORTED:
                findings.append(item)  # type: ignore[arg-type]
            elif kind is RuleKind.RELATED:
                related.append(item)  # type: ignore[arg-type]
            else:
                ignored.append(item)  # type: ignore[arg-type]

        skipped = [SkippedFile(file_path=s.path, reason=s.reason) for s in discovery.skipped]
        skipped_names: set[str] = set()
        for filename, reason in run.skipped:
            rel = converter.relative_or_none(filename)
            if rel is None:
                errors.append("Bandit skipped a file outside the project root")
                continue
            skipped.append(SkippedFile(file_path=rel, reason=reason))
            skipped_names.add(rel)

        def order(f: Finding) -> tuple[str, int, str]:
            return (f.file_path, f.line, f.rule_id)

        return ScanResult(
            project_root=str(discovery.root),
            scanner_version=run.version,
            files_scanned=[
                rel for rel in map(discovery.relative, discovery.files) if rel not in skipped_names
            ],
            findings=sorted(_dedupe(findings), key=order),
            related_findings=sorted(_dedupe(related), key=order),
            ignored_issues=sorted(ignored, key=lambda i: (i.file_path, i.line, i.rule_id)),
            skipped_files=skipped,
            errors=errors,
            started_at=started_at,
            duration_seconds=round(time.perf_counter() - clock, 4),
        )


def _dedupe(findings: Sequence[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.finding_id, f)
    return list(seen.values())


class _ConversionError(Exception):
    pass


class _Converter:
    def __init__(self, discovery: DiscoveryResult) -> None:
        self.root = discovery.root
        self.allowed = set(discovery.files)
        self._sources: dict[Path, ParsedSource] = {}

    def relative_or_none(self, filename: str) -> str | None:
        try:
            path = Path(filename).resolve()
        except OSError:
            return None
        if not path.is_relative_to(self.root):
            return None
        return path.relative_to(self.root).as_posix()

    def _source(self, path: Path) -> ParsedSource:
        if path not in self._sources:
            data = path.read_bytes()  # read-only access
            self._sources[path] = parse_source(decode_source(data), filename=path.name)
        return self._sources[path]

    def convert(self, issue: BanditIssue) -> tuple[RuleKind, Finding | IgnoredIssue]:
        path = Path(issue.filename).resolve()
        if path not in self.allowed:
            raise _ConversionError(
                f"Bandit reported {issue.test_id} for a file that was not selected for "
                "scanning; result ignored"
            )
        rel = path.relative_to(self.root).as_posix()
        kind = classify_rule(issue.test_id)
        try:
            if kind is RuleKind.UNSUPPORTED:
                return kind, IgnoredIssue(
                    rule_id=issue.test_id,
                    test_name=issue.test_name,
                    file_path=rel,
                    line=issue.line,
                    severity=_severity(issue.severity),
                )
            return kind, self._finding(issue, rel, path)
        except (ValidationError, OSError) as exc:
            raise _ConversionError(
                f"could not convert {issue.test_id} at {rel}:{issue.line}: "
                f"{safe_error_message(exc)}"
            ) from None

    def _finding(self, issue: BanditIssue, rel: str, path: Path) -> Finding:
        spec = rule_spec(issue.test_id)
        assert spec is not None
        parsed = self._source(path)
        line, end_line = issue.line, issue.end_line

        display_lines: tuple[str, ...] | list[str] = parsed.lines
        description = issue.text.strip() or spec.title
        if spec.category in REDACT_LITERALS:
            display_lines, _ = redact_string_literals(parsed, line, end_line)
            # Bandit's text for B105-B107 quotes the secret value: keep the prefix only.
            description = description.split(":", 1)[0].strip() + " (literal value redacted)"

        context = build_context(parsed, line, end_line, display_lines)
        explanation = CATEGORY_EXPLANATIONS[spec.category] + (
            f" Detected by Bandit {issue.test_id} ({issue.test_name or spec.bandit_name})"
            + (f", CWE-{issue.cwe_id}." if issue.cwe_id else ".")
        )
        if parsed.error:
            explanation += f" AST context unavailable: {parsed.error}."

        return Finding(
            finding_id=stable_finding_id(rel, issue.test_id, line, issue.col_offset),
            category=spec.category,
            severity=_severity(issue.severity),
            file_path=rel,
            line=line,
            end_line=end_line,
            rule_id=issue.test_id,
            description=description,
            explanation=explanation,
            code_snippet=extract_snippet(display_lines, line, end_line),
            ast_context=context,
            confidence=CONFIDENCE_SCORES.get(issue.confidence, 0.3),
            scanner="bandit",
        )
