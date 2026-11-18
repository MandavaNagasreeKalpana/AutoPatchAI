"""Run Bandit in-process through its Python API and normalize the results.

Bandit only reads files and parses them with :mod:`ast`; it never imports or
executes the code it scans. No subprocess is used.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import (
    BanditExecutionError,
    BanditNotInstalledError,
    MalformedBanditResultError,
    safe_error_message,
)

_RULE_ID = re.compile(r"^B\d{3}$")
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
    if not _RULE_ID.fullmatch(test_id):
        raise MalformedBanditResultError(f"invalid test_id {test_id!r}")
    severity = _require(data, "issue_severity", str).upper()
    confidence = _require(data, "issue_confidence", str).upper()
    for label, value in (("issue_severity", severity), ("issue_confidence", confidence)):
        if value not in _SEVERITIES:
            raise MalformedBanditResultError(f"invalid {label} {value!r}")
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
    return BanditIssue(
        filename=filename,
        test_id=test_id,
        test_name=str(data.get("test_name", "")),
        severity=severity,
        confidence=confidence,
        text=str(data.get("issue_text", "")),
        line=line,
        line_range=tuple(raw_range),
        col_offset=col if isinstance(col, int) and not isinstance(col, bool) else 0,
        cwe_id=cwe_id if isinstance(cwe_id, int) and cwe_id > 0 else None,
    )


def _load_bandit() -> tuple[Any, Any, str]:
    try:
        bandit = importlib.import_module("bandit")
        manager = importlib.import_module("bandit.core.manager")
        config = importlib.import_module("bandit.core.config")
    except ImportError:
        raise BanditNotInstalledError(
            "Bandit is not installed in this environment. Run 'uv sync' in the "
            "project directory to install it."
        ) from None
    return manager, config, str(getattr(bandit, "__version__", "unknown"))


def bandit_version() -> str:
    return _load_bandit()[2]


def run_bandit(files: Sequence[Path], *, ignore_nosec: bool = False) -> BanditRun:
    """Scan exactly ``files`` (already validated by file discovery)."""
    manager_mod, config_mod, version = _load_bandit()
    if not files:
        return BanditRun(version=version)
    try:
        config = config_mod.BanditConfig()
        manager = manager_mod.BanditManager(
            config, "file", quiet=True, ignore_nosec=ignore_nosec
        )
        manager.files_list = [str(f) for f in files]
        manager.excluded_files = []
        manager.run_tests()
        raw_results = list(manager.results)
        raw_skipped = list(manager.skipped)
    except Exception as exc:  # Bandit internals: report safely, never leak env
        raise BanditExecutionError(f"Bandit failed: {safe_error_message(exc)}") from None

    issues: list[BanditIssue] = []
    malformed: list[str] = []
    for raw in raw_results:
        try:
            data = raw.as_dict(with_code=False) if hasattr(raw, "as_dict") else raw
            issues.append(parse_issue(data))
        except MalformedBanditResultError as exc:
            malformed.append(f"malformed Bandit result ignored: {exc}")
        except Exception as exc:
            malformed.append(f"unreadable Bandit result ignored: {safe_error_message(exc)}")

    skipped = []
    for entry in raw_skipped:
        try:
            name, reason = entry
            skipped.append((str(name), str(reason)))
        except (TypeError, ValueError):
            malformed.append("malformed Bandit skip entry ignored")
    return BanditRun(
        version=version, issues=tuple(issues), skipped=tuple(skipped), malformed=tuple(malformed)
    )
