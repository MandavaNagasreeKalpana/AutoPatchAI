"""Scanner exceptions. Redaction helpers live in :mod:`autopatch.redaction`
and are re-exported here for existing callers."""

from __future__ import annotations

import unicodedata

from pydantic import ValidationError

from autopatch.redaction import REDACTED, redact_secrets, safe_error_message

__all__ = [
    "REDACTED",
    "BanditExecutionError",
    "BanditNotInstalledError",
    "MalformedBanditResultError",
    "ScanTargetError",
    "ScannerError",
    "clean_text",
    "describe_validation_error",
    "escape_for_terminal",
    "redact_secrets",
    "safe_error_message",
]

# Control (Cc), format (Cf: bidi overrides, zero-width), line/paragraph
# separators, private-use and surrogate code points. They can move the
# terminal cursor, recolour or clear the screen, or reorder displayed text.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cs"})


def _unsafe(char: str) -> bool:
    return unicodedata.category(char) in _UNSAFE_CATEGORIES


def clean_text(text: object, limit: int) -> str:
    """One line of plain text from an untrusted value (e.g. Bandit metadata):
    control and formatting characters become spaces, whitespace is collapsed
    and the result is at most ``limit`` characters."""
    raw = text if isinstance(text, str) else str(text)
    flat = " ".join("".join(" " if _unsafe(c) else c for c in raw).split())
    return flat if len(flat) <= limit else flat[: max(0, limit - 3)] + "..."


def escape_for_terminal(text: str) -> str:
    """Show control and formatting characters as visible escapes (``\\x1b``,
    ``\\u202e``) so printed paths and messages cannot drive the terminal."""
    return "".join(
        (f"\\x{ord(c):02x}" if ord(c) < 0x100 else f"\\u{ord(c):04x}") if _unsafe(c) else c
        for c in text
    )

MAX_LISTED_VALIDATION_ERRORS = 5


def describe_validation_error(exc: ValidationError) -> str:
    """Summarise a Pydantic error by field location, error type and message.

    ``str(exc)`` embeds each offending ``input_value`` (which for findings is
    scanned source code, possibly with secrets), so it is never used. The
    per-error messages come from Pydantic and our own validators and describe
    the constraint, not the input.
    """
    try:
        details = exc.errors(include_url=False, include_context=False, include_input=False)
    except Exception:  # pragma: no cover - defensive
        return f"{type(exc).__name__}: details withheld"
    parts = []
    for err in details[:MAX_LISTED_VALIDATION_ERRORS]:
        loc = ".".join(str(p) for p in err.get("loc", ())) or "<model>"
        message = " ".join(str(err.get("msg", "")).split())[:160]
        parts.append(f"{loc}: {err.get('type', 'error')} ({message})")
    if len(details) > MAX_LISTED_VALIDATION_ERRORS:
        parts.append(f"... {len(details) - MAX_LISTED_VALIDATION_ERRORS} more")
    summary = f"{exc.error_count()} validation error(s) for {exc.title}: " + "; ".join(parts)
    return redact_secrets(summary)


class ScannerError(Exception):
    """Operational failure: the scan could not be completed."""


class ScanTargetError(ScannerError):
    """The requested project root is missing, not a directory, or unsafe."""


class BanditNotInstalledError(ScannerError):
    """Bandit cannot be imported in the current environment."""


class BanditExecutionError(ScannerError):
    """Bandit raised an unexpected exception while scanning."""


class MalformedBanditResultError(ScannerError):
    """A Bandit result did not have the expected structure."""
