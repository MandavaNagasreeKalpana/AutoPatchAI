"""Secret redaction for error messages and logs (shared by scanner and LLM code)."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping

REDACTED = "***REDACTED***"

_SECRET_ENV_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSW|CREDENTIAL|AUTH", re.IGNORECASE)
_TOKEN_PATTERNS = (
    re.compile(r"gsk_[A-Za-z0-9]{8,}"),  # Groq API keys
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),  # OpenAI-style keys
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key ids
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub tokens
    # Authorization headers, including quoted dict/JSON forms.
    re.compile(r"(?i)(authorization['\"]?\s*[:=]\s*['\"]?)(bearer\s+)?[^\s'\",}]+"),
)


def redact_secrets(
    text: str,
    environ: Mapping[str, str] | None = None,
    extra_secrets: Iterable[str | None] = (),
) -> str:
    """Remove secrets from ``text``.

    Removes, in order: explicitly supplied secret values (e.g. the configured
    API key, which may come from ``.env`` rather than the environment), values
    of secret-looking environment variables, and known token/header formats.
    """
    for secret in extra_secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, REDACTED)
    env = os.environ if environ is None else environ
    for name, value in env.items():
        if value and len(value) >= 8 and _SECRET_ENV_NAME.search(name):
            text = text.replace(value, REDACTED)
    for pattern in _TOKEN_PATTERNS:
        if pattern.groups:
            text = pattern.sub(lambda m: m.group(1) + REDACTED, text)
        else:
            text = pattern.sub(REDACTED, text)
    return text


def safe_error_message(
    exc: BaseException, limit: int = 300, extra_secrets: Iterable[str | None] = ()
) -> str:
    """One-line, length-limited, secret-redacted description of ``exc``."""
    detail = " ".join(str(exc).split())
    message = f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__
    message = redact_secrets(message, extra_secrets=extra_secrets)
    return message if len(message) <= limit else message[: limit - 3] + "..."
