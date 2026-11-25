"""Run Bandit in-process through its Python API and normalize the results.

Bandit only reads files and parses them with :mod:`ast`; it never imports or
executes the code it scans. No subprocess is used.
"""

from __future__ import annotations

import importlib
import logging
import re
from contextlib import contextmanager
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import (
    BanditExecutionError,
    BanditNotInstalledError,
    MalformedBanditResultError,
    clean_text,
    redact_secrets,
)

_RULE_ID = re.compile(r"^B\d{3}$")
MAX_DETAIL = 200


def _exception_type(exc: BaseException) -> str:
    """Exception type only: messages from Bandit or the result objects may
    quote scanned source code, so they are withheld."""
    return f"{type(exc).__name__} (details withheld: they may contain source code)"


def _short(text: str) -> str:
    return clean_text(redact_secrets(clean_text(text, 4 * MAX_DETAIL)), MAX_DETAIL)


# Bandit metadata is untrusted input: it comes from a library processing
# attacker-controlled files, and a custom runner can return anything.
MAX_ISSUE_TEXT = 500
_TEST_NAME = re.compile(r"^[A-Za-z0-9_]{1,64}$")
# Bandit's own skip reasons are fixed phrases or OS error strings
# (``e.strerror``). Anything else may quote file content and is withheld.
_KNOWN_SKIP_REASONS = frozenset(
    {"syntax error while parsing AST from file", "exception while scanning file"}
)
_STRERROR_LIKE = re.compile(r"^[A-Za-z]+(?: [A-Za-z]+){1,9}$")
WITHHELD_SKIP_REASON = "Bandit could not scan this file (reason withheld: it may quote file content)"


def safe_test_name(name: object) -> str:
    """Bandit's test name if it is a plain identifier, else ``""``."""
    return name if isinstance(name, str) and _TEST_NAME.fullmatch(name) else ""


def skip_reason(reason: object) -> str:
    """A Bandit skip reason that is safe to show, or a generic one."""
    text = clean_text(reason, MAX_DETAIL)
    if text in _KNOWN_SKIP_REASONS or (len(text) <= 60 and _STRERROR_LIKE.fullmatch(text)):
        return text
    return WITHHELD_SKIP_REASON


_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "UNDEFINED"})


@dataclass(frozen=True)
class BanditIssue:
    filename: str
    test_id: str
    test_name: str
    severity: str  # LOW / MEDIUM / HIGH / UNDEFINED
    confidence: str  # LOW / MEDIUM / HIGH / UNDEFINED
    text: str
    line: int
    line_range: tuple[int, ...]
    col_offset: int = 0
    cwe_id: int | None = None

    @property
    def end_line(self) -> int:
        return max((self.line, *self.line_range))


@dataclass(frozen=True)
class BanditRun:
    version: str
    issues: tuple[BanditIssue, ...] = ()
    skipped: tuple[tuple[str, str], ...] = ()  # (filename, reason)
    malformed: tuple[str, ...] = field(default=())


def _require(data: Mapping[str, Any], key: str, kind: type | tuple[type, ...]) -> Any:
    if key not in data:
        raise MalformedBanditResultError(f"missing field {key!r}")
    value = data[key]
    if not isinstance(value, kind) or isinstance(value, bool):
        raise MalformedBanditResultError(f"field {key!r} has unexpected type")
    return value


def parse_issue(data: Mapping[str, Any]) -> BanditIssue:
    """Validate one issue in Bandit's ``Issue.as_dict()`` / JSON format."""
    if not isinstance(data, Mapping):
        raise MalformedBanditResultError("issue is not a mapping")
    filename = _require(data, "filename", str)
    test_id = _require(data, "test_id", str)
    if not _RULE_ID.fullmatch(test_id):  # the value is not echoed: it is untrusted
        raise MalformedBanditResultError("invalid test_id (expected 'B' and three digits)")
    severity = _require(data, "issue_severity", str).upper()
    confidence = _require(data, "issue_confidence", str).upper()
    for label, value in (("issue_severity", severity), ("issue_confidence", confidence)):
        if value not in _SEVERITIES:
            raise MalformedBanditResultError(f"invalid {label} (expected LOW, MEDIUM, HIGH or UNDEFINED)")
    line = _require(data, "line_number", int)
    if line < 1:
        raise MalformedBanditResultError("line_number must be >= 1")
    raw_range = data.get("line_range") or [line]
    if not isinstance(raw_range, (list, tuple)) or not all(
        isinstance(n, int) and not isinstance(n, bool) and n >= 1 for n in raw_range
    ):
        raise MalformedBanditResultError("line_range must be a list of positive integers")
    if not filename.strip():
        raise MalformedBanditResultError("filename is empty")

    cwe = data.get("issue_cwe")
    cwe_id = cwe.get("id") if isinstance(cwe, Mapping) else None
    col = data.get("col_offset", 0)
    test_name = data.get("test_name", "")
    return BanditIssue(
        filename=filename,
        test_id=test_id,
        # Names that are not plain identifiers are dropped (the scanner uses
        # its own rule table for display names).
        test_name=safe_test_name(test_name),
        severity=severity,
        confidence=confidence,
        text=clean_text(data.get("issue_text", ""), MAX_ISSUE_TEXT),
        line=line,
        line_range=tuple(raw_range),
        col_offset=col if isinstance(col, int) and not isinstance(col, bool) and col >= 0 else 0,
        cwe_id=cwe_id if isinstance(cwe_id, int) and not isinstance(cwe_id, bool) and 0 < cwe_id < 100_000 else None,
    )


def _load_bandit() -> tuple[Any, Any, str]:
    try:
        bandit = importlib.import_module("bandit")
        manager = importlib.import_module("bandit.core.manager")
        config = importlib.import_module("bandit.core.config")
    except ImportError:
        bandit = None
    if bandit is None:  # raised outside the handler: no chained ImportError
        raise BanditNotInstalledError(
            "Bandit is not installed in this environment. Run 'uv sync' in the "
            "project directory to install it."
        ) from None
    return manager, config, str(getattr(bandit, "__version__", "unknown"))


@contextmanager
def _quiet_bandit_logs() -> Iterator[None]:
    """Bandit logs every issue at DEBUG level, including the hardcoded
    password it found. Cap its logger at WARNING while it runs here, so an
    application-wide DEBUG configuration cannot copy secrets into logs."""
    logger = logging.getLogger("bandit")
    previous = logger.level
    if logger.getEffectiveLevel() < logging.WARNING:
        logger.setLevel(logging.WARNING)
    try:
        yield
    finally:
        logger.setLevel(previous)


def bandit_version() -> str:
    return _load_bandit()[2]


def run_bandit(files: Sequence[Path], *, ignore_nosec: bool = False) -> BanditRun:
    """Scan exactly ``files`` (already validated by file discovery)."""
    manager_mod, config_mod, version = _load_bandit()
    if not files:
        return BanditRun(version=version)
    failure: str | None = None
    try:
        config = config_mod.BanditConfig()
        manager = manager_mod.BanditManager(
            config, "file", quiet=True, ignore_nosec=ignore_nosec
        )
        manager.files_list = [str(f) for f in files]
        manager.excluded_files = []
        with _quiet_bandit_logs():
            manager.run_tests()
        raw_results = list(manager.results)
        raw_skipped = list(manager.skipped)
    except Exception as exc:  # Bandit internals may quote scanned source: type only
        failure = _exception_type(exc)
    if failure is not None:
        # Raised outside the handler, so the original exception (and its
        # message, which may quote source) is not kept as ``__context__``.
        raise BanditExecutionError(f"Bandit failed: {failure}") from None

    issues: list[BanditIssue] = []
    malformed: list[str] = []
    for raw in raw_results:
        try:
            data = raw.as_dict(with_code=False) if hasattr(raw, "as_dict") else raw
            issues.append(parse_issue(data))
        except MalformedBanditResultError as exc:
            # Our own messages: a field name plus a short, non-source value.
            malformed.append(f"malformed Bandit result ignored: {_short(str(exc))}")
        except Exception as exc:
            malformed.append(f"unreadable Bandit result ignored: {_exception_type(exc)}")

    skipped = []
    for entry in raw_skipped:
        try:
            name, reason = entry
            skipped.append((str(name), skip_reason(reason)))
        except (TypeError, ValueError):
            malformed.append("malformed Bandit skip entry ignored")
    return BanditRun(
        version=version, issues=tuple(issues), skipped=tuple(skipped), malformed=tuple(malformed)
    )
