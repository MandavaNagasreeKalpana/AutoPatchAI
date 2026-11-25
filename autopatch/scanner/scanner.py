"""Scanner Agent: Bandit + AST context -> validated ``Finding`` objects.

The agent is strictly read-only. It lists files inside the project root, lets
Bandit parse them, and reads them (as bytes) to build AST context. It never
writes to, imports, or executes the scanned project.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path

from pydantic import ValidationError

from autopatch.models import Finding, Severity
from autopatch.models.common import MAX_CODE_CHARS, MAX_TEXT_CHARS, utc_now
from autopatch.models.scan import IgnoredIssue, ScanResult, SkippedFile

from .ast_context import (
    ParsedSource,
    bound_text,
    build_context,
    decode_source,
    extract_snippet,
    is_truncated,
    module_imports,
    parse_source,
)
from .bandit_runner import MAX_DETAIL, MAX_ISSUE_TEXT, BanditIssue, BanditRun, run_bandit, safe_test_name, skip_reason
from .errors import ScannerError, clean_text, describe_validation_error, redact_secrets, safe_error_message
from .file_discovery import DiscoveryResult, discover_python_files
from .rule_mapping import (
    CATEGORY_EXPLANATIONS,
    CONFIDENCE_SCORES,
    REDACT_LITERALS,
    RuleKind,
    classify_rule,
    rule_spec,
)
from autopatch.common.sensitive import FileRedaction, redact_file

BanditRunner = Callable[..., BanditRun]

# Bandit's text for the supported rules never quotes code except the B105-B107
# credential value. Any other quoted part of untrusted metadata is withheld.
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"|`[^`]*`")
WITHHELD = "<withheld>"


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

        converter = _Converter(discovery, _credential_ranges(run.issues))
        findings: list[Finding] = []
        related: list[Finding] = []
        ignored: list[IgnoredIssue] = []
        # A runner's output is untrusted even when it bypassed parse_issue().
        errors = [clean_text(redact_secrets(clean_text(m, 4 * MAX_DETAIL)), MAX_DETAIL) for m in run.malformed]

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
            skipped.append(SkippedFile(file_path=rel, reason=skip_reason(reason)))
            skipped_names.add(rel)

        def order(f: Finding) -> tuple[str, int, str]:
            return (f.file_path, f.line, f.rule_id)

        problem: str | None = None
        try:
            return ScanResult(
                project_root=str(discovery.root),
                scanner_version=clean_text(run.version, 40) or "unknown",
                files_scanned=[
                    rel
                    for rel in map(discovery.relative, discovery.files)
                    if rel not in skipped_names
                ],
                findings=sorted(_dedupe(findings), key=order),
                related_findings=sorted(_dedupe(related), key=order),
                ignored_issues=sorted(ignored, key=lambda i: (i.file_path, i.line, i.rule_id)),
                skipped_files=skipped,
                errors=errors,
                started_at=started_at,
                duration_seconds=round(time.perf_counter() - clock, 4),
            )
        except ValidationError as exc:  # never let input values (source code) escape
            problem = describe_validation_error(exc)
        # Raised outside the ``except`` block, so neither ``__cause__`` nor
        # ``__context__`` keeps the original error (whose input is source code).
        raise ScannerError(f"scan result could not be assembled: {problem}") from None


def _credential_ranges(issues: Iterable[BanditIssue]) -> dict[Path, list[tuple[int, int]]]:
    """Line spans of supported credential findings, per resolved file."""
    ranges: dict[Path, list[tuple[int, int]]] = defaultdict(list)
    for issue in issues:
        spec = rule_spec(issue.test_id)
        if classify_rule(issue.test_id) is RuleKind.SUPPORTED and spec and spec.category in REDACT_LITERALS:
            try:
                ranges[Path(issue.filename).resolve()].append((issue.line, issue.end_line))
            except OSError:
                continue
    return dict(ranges)


def _dedupe(findings: Sequence[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.finding_id, f)
    return list(seen.values())


class _ConversionError(Exception):
    pass


class _InvalidLocation(Exception):
    """Bandit reported a line that does not exist in the file."""


class _Converter:
    def __init__(
        self,
        discovery: DiscoveryResult,
        credential_ranges: Mapping[Path, Sequence[tuple[int, int]]] | None = None,
    ) -> None:
        self.root = discovery.root
        self.allowed = set(discovery.files)
        self._credential_ranges = credential_ranges or {}
        self._sources: dict[Path, ParsedSource] = {}
        self._redactions: dict[Path, FileRedaction] = {}
        self._import_cache: dict[Path, list[str]] = {}

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

    def _redaction(self, path: Path) -> FileRedaction:
        """One redacted view per file, shared by all of its findings."""
        if path not in self._redactions:
            ranges = self._credential_ranges.get(path, ())
            self._redactions[path] = redact_file(self._source(path), ranges)
        return self._redactions[path]

    def _imports(self, path: Path) -> list[str]:
        """Import context, computed once per file (rendered from the AST)."""
        if path not in self._import_cache:
            self._import_cache[path] = module_imports(self._source(path))
        return self._import_cache[path]

    def convert(self, issue: BanditIssue) -> tuple[RuleKind, Finding | IgnoredIssue]:
        path = Path(issue.filename).resolve()
        if path not in self.allowed:
            raise _ConversionError(
                f"Bandit reported {issue.test_id} for a file that was not selected for "
                "scanning; result ignored"
            )
        rel = path.relative_to(self.root).as_posix()
        kind = classify_rule(issue.test_id)
        problem = "unknown error"
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
        except _InvalidLocation as exc:
            problem = str(exc)
        except ValidationError as exc:
            # str(ValidationError) embeds the offending input (source code).
            problem = describe_validation_error(exc)
        except OSError as exc:
            problem = safe_error_message(exc)
        except Exception as exc:  # unexpected: the type only, a message may quote source
            problem = f"internal error ({type(exc).__name__}; details withheld)"
        # Raised after the handlers, so the original exception is not chained.
        raise _ConversionError(
            f"could not convert {issue.test_id} at {rel}:{issue.line}: {problem}"
        ) from None

    def _finding(self, issue: BanditIssue, rel: str, path: Path) -> Finding:
        spec = rule_spec(issue.test_id)
        assert spec is not None
        parsed = self._source(path)
        redaction = self._redaction(path)
        line, end_line = issue.line, issue.end_line
        if line > len(parsed.lines):
            raise _InvalidLocation(f"Bandit reported line {line}, but the file has {len(parsed.lines)} lines")
        end_line = min(end_line, len(parsed.lines))  # untrusted line_range

        # Every category uses the same file-wide redacted view, so secrets on
        # unrelated lines never reach a SQL injection or deserialization context.
        display_lines = redaction.lines
        # Bandit metadata is untrusted (already stripped of control characters
        # by the runner): quoted parts are withheld, then known secret values,
        # token formats and secret environment values are scrubbed.
        description = clean_text(issue.text, MAX_ISSUE_TEXT) or spec.title
        if spec.category in REDACT_LITERALS:
            # Bandit's text for B105-B107 quotes the secret value: keep the prefix only.
            description = description.split(":", 1)[0].strip() + " (literal value redacted)"
        description = _QUOTED.sub(WITHHELD, description)
        description = redact_secrets(redaction.scrub(description))
        description = bound_text(" ".join(description.split()), MAX_TEXT_CHARS) or spec.title

        context = build_context(parsed, line, end_line, display_lines, self._imports(path))
        snippet = bound_text(extract_snippet(display_lines, line, end_line), MAX_CODE_CHARS)
        explanation = CATEGORY_EXPLANATIONS[spec.category] + (
            # Bandit's test name only if it is a plain identifier (untrusted metadata).
            f" Detected by Bandit {issue.test_id} ({safe_test_name(issue.test_name) or spec.bandit_name})"
            + (f", CWE-{issue.cwe_id}." if issue.cwe_id else ".")
        )
        if parsed.error:
            explanation += f" AST context unavailable: {parsed.error}."
        if not redaction.complete:
            explanation += (
                " Comments and string literals in this file are hidden in full because "
                "their positions could not be mapped safely for selective redaction."
            )
        if is_truncated(snippet) or (context is not None and is_truncated(context.source)):
            explanation += (
                f" Code shown in this finding was truncated to {MAX_CODE_CHARS} characters "
                "(see the truncation marker); the AST span and line numbers are exact."
            )

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
            code_snippet=snippet,
            ast_context=context,
            confidence=CONFIDENCE_SCORES.get(issue.confidence, 0.3),
            scanner="bandit",
        )
