"""Scanner exceptions and secret-safe error formatting."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping


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


_SECRET_ENV_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSW|CREDENTIAL|AUTH", re.IGNORECASE)
_TOKEN_PATTERNS = (
    re.compile(r"gsk_[A-Za-z0-9]{8,}"),  # Groq
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),  # OpenAI-style
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub
)
REDACTED = "***REDACTED***"


def redact_secrets(text: str, environ: Mapping[str, str] | None = None) -> str:
    """Remove values of secret-looking environment variables and known
    token formats from ``text``."""
    env = os.environ if environ is None else environ
    for name, value in env.items():
        if value and len(value) >= 8 and _SECRET_ENV_NAME.search(name):
            text = text.replace(value, REDACTED)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def safe_error_message(exc: BaseException, limit: int = 300) -> str:
    """One-line, length-limited, secret-redacted description of ``exc``."""
    detail = " ".join(str(exc).split())
    message = f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__
    message = redact_secrets(message)
    return message if len(message) <= limit else message[: limit - 3] + "..."
