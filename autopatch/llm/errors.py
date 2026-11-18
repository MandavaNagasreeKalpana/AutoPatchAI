"""LLM error hierarchy.

Every Groq SDK exception is translated into one of these. Messages are short,
secret-redacted, and never include request headers. Missing configuration is
reported with :class:`autopatch.config.MissingLLMConfigError` (raised before
any request is made).
"""

from __future__ import annotations


class LLMError(Exception):
    """Base class. ``retryable`` marks transient failures."""

    retryable = False

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after
        self.attempts: int | None = None  # set when the client gives up


class LLMAuthenticationError(LLMError):
    """HTTP 401/403: the key is invalid or lacks permission. Never retried."""


class LLMRateLimitError(LLMError):
    """HTTP 429. Retried only for short waits; a daily quota stops at once."""

    def __init__(self, message: str, *, quota_exhausted: bool = False, **kwargs: object) -> None:
        super().__init__(message, **kwargs)  # type: ignore[arg-type]
        self.quota_exhausted = quota_exhausted
        self.retryable = not quota_exhausted


class LLMTimeoutError(LLMError):
    retryable = True


class LLMConnectionError(LLMError):
    retryable = True


class LLMServerError(LLMError):
    """HTTP 5xx from Groq."""

    retryable = True


class LLMInvalidRequestError(LLMError):
    """The request was rejected (bad parameters, unknown model, too large).
    Also raised locally before sending invalid input."""


class LLMUnsupportedFeatureError(LLMInvalidRequestError):
    """The configured model does not support a requested feature (e.g. JSON
    mode). AutoPatch never switches models automatically."""


class LLMResponseError(LLMError):
    """The response did not have the expected structure."""


class LLMEmptyResponseError(LLMResponseError):
    """The model returned no content."""


class LLMStructuredOutputError(LLMResponseError):
    """JSON output was malformed, truncated, or did not match the schema.

    ``raw_content`` keeps the model output for debugging; it is deliberately
    not part of ``str(exc)``.
    """

    def __init__(self, message: str, *, raw_content: str | None = None, **kwargs: object) -> None:
        super().__init__(message, **kwargs)  # type: ignore[arg-type]
        self.raw_content = raw_content
