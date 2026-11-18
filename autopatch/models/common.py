"""Reusable validated types shared by all models.

Validation here is purely structural: it never touches the filesystem and
never executes or imports user code.
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import PurePosixPath, PureWindowsPath
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

MAX_CODE_CHARS = 200_000
MAX_TEXT_CHARS = 20_000

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")


class StrictModel(BaseModel):
    """Base for all AutoPatch models: immutable, unknown fields rejected.

    Whitespace is *not* stripped globally because code fields must be kept
    byte-for-byte.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")


def new_id(prefix: str) -> str:
    """Return a random identifier such as ``patch-3f9c2a1b7d4e``."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def utc_now() -> datetime:
    return datetime.now(UTC)


def find_duplicates(values: Iterable[str]) -> list[str]:
    """Return the sorted values that occur more than once."""
    return sorted(v for v, n in Counter(values).items() if n > 1)


def _check_identifier(value: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError(
            "identifier must be 1-128 characters, start with a letter or digit, "
            "and contain only letters, digits, '.', '_', ':' or '-'"
        )
    return value


def _check_non_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be empty or whitespace")
    return value


def _check_timezone_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value


def normalize_project_path(value: str) -> str:
    """Validate a project-relative file path and return it in POSIX form.

    Rejects: empty paths, NUL/control characters, absolute POSIX or Windows
    paths, drive-relative paths (``C:foo``), UNC paths, ``:`` anywhere
    (drive letters / NTFS alternate data streams) and any ``..`` component.
    """
    if not isinstance(value, str):
        raise ValueError("path must be a string")
    if not value.strip():
        raise ValueError("path must not be empty")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("path must not contain control characters")
    if ":" in value:
        raise ValueError("path must not contain ':' (drive letters or streams)")

    unified = value.replace("\\", "/")
    win = PureWindowsPath(value)
    if unified.startswith("/") or win.drive or win.root or PurePosixPath(unified).is_absolute():
        raise ValueError("path must be relative to the project root, not absolute")

    parts = [p for p in unified.split("/") if p not in ("", ".")]
    if not parts:
        raise ValueError("path must name a file inside the project")
    if any(p == ".." for p in parts):
        raise ValueError("path must not contain '..' (path traversal)")
    return "/".join(parts)


Identifier = Annotated[str, AfterValidator(_check_identifier)]
NonEmptyStr = Annotated[str, Field(max_length=MAX_TEXT_CHARS), AfterValidator(_check_non_blank)]
Text = Annotated[str, Field(max_length=MAX_TEXT_CHARS)]
CodeStr = Annotated[str, Field(max_length=MAX_CODE_CHARS)]
ProjectPath = Annotated[str, AfterValidator(normalize_project_path)]
Confidence = Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]
LineNumber = Annotated[int, Field(ge=1)]
AwareDatetime = Annotated[datetime, AfterValidator(_check_timezone_aware)]
