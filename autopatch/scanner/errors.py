"""Scanner exceptions. Redaction helpers live in :mod:`autopatch.redaction`
and are re-exported here for existing callers."""

from __future__ import annotations

from autopatch.redaction import REDACTED, redact_secrets, safe_error_message

__all__ = [
    "REDACTED",
    "BanditExecutionError",
    "BanditNotInstalledError",
    "MalformedBanditResultError",
    "ScanTargetError",
    "ScannerError",
    "redact_secrets",
    "safe_error_message",
]


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
