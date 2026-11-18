"""Groq chat-completion client with bounded retries and safe errors.

* The SDK's built-in retries are disabled (``max_retries=0``); this wrapper
  owns the retry policy so attempts are never doubled.
* Only transient failures are retried: short rate limits, timeouts,
  connection errors and 5xx responses. Authentication errors, invalid
  requests, a daily quota, and bad output are never retried.
* There is no fallback model or provider.
* Logs record only error type, status, wait and attempt numbers: never
  prompts, responses, headers or keys.
"""

from __future__ import annotations

import logging
import os
import random
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Generic, TypeVar

import groq
from pydantic import BaseModel, ValidationError

from autopatch.config import Settings, load_settings
from autopatch.redaction import redact_secrets

from .errors import (
    LLMAuthenticationError,
    LLMConnectionError,
    LLMEmptyResponseError,
    LLMError,
    LLMInvalidRequestError,
    LLMRateLimitError,
    LLMResponseError,
    LLMServerError,
    LLMStructuredOutputError,
    LLMTimeoutError,
    LLMUnsupportedFeatureError,
)
from .structured import parse_json_object, validate_json
from .types import MAX_PROMPT_CHARS, ChatMessage, ChatResult, TokenUsage

logger = logging.getLogger("autopatch.llm")

MAX_RETRY_WAIT = 30.0  # never sleep longer than this for one retry
BACKOFF_BASE = 1.0
BACKOFF_CAP = 20.0
_DETAIL_LIMIT = 200
_QUOTA_MARKERS = ("per day", "(tpd)", "(rpd)", "daily", "quota")
_JSON_MODE_MARKERS = ("response_format", "json mode", "json_object")

T = TypeVar("T", bound=BaseModel)
MessageInput = ChatMessage | Mapping[str, Any]


@dataclass(frozen=True)
class StructuredResult(Generic[T]):
    data: dict[str, Any]
    parsed: T | None
    raw: ChatResult


class GroqClient:
    """Thin wrapper over ``groq.Groq`` for chat completions.

    ``sdk_client`` lets tests inject a fake; production code leaves it unset.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        sdk_client: Any | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_retry_wait: float = MAX_RETRY_WAIT,
        rng: Callable[[], float] = random.random,
    ) -> None:
        api_key, model = settings.require_llm()  # MissingLLMConfigError if unset
        self.__api_key = api_key
        self.model = model
        self.timeout = settings.llm_timeout
        self.max_retries = settings.llm_max_retries
        self._sleep = sleep
        self._max_retry_wait = max_retry_wait
        self._rng = rng
        self._sdk = sdk_client if sdk_client is not None else self._build_sdk()

    @classmethod
    def from_env(cls, env_file: str | os.PathLike[str] | None = ".env", **kwargs: Any) -> GroqClient:
        return cls(load_settings(env_file=env_file), **kwargs)

    def _build_sdk(self) -> Any:
        return groq.Groq(api_key=self.__api_key, timeout=float(self.timeout), max_retries=0)

    def __repr__(self) -> str:
        return (
            f"GroqClient(model={self.model!r}, timeout={self.timeout}, "
            f"max_retries={self.max_retries}, api_key=<set>)"
        )

    __str__ = __repr__

    # -- public API -----------------------------------------------------------

    def chat(
        self,
        messages: Sequence[MessageInput],
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> ChatResult:
        """Plain chat completion. Raises an :class:`LLMError` subclass on failure."""
        checked = self._validate_messages(messages)
        return self._complete(checked, json_mode=False, temperature=temperature, max_tokens=max_tokens)

    def chat_json(
        self,
        messages: Sequence[MessageInput],
        *,
        schema: type[T] | None = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> StructuredResult[T]:
        """Chat completion in Groq JSON mode (``response_format=json_object``).

        The prompt must mention JSON (an API requirement for JSON mode). The
        reply must be one JSON object; with ``schema`` it is also validated.
        If the configured model does not support JSON mode, an
        :class:`LLMUnsupportedFeatureError` is raised. No other model is tried.
        """
        checked = self._validate_messages(messages)
        if not any("json" in m.content.lower() for m in checked):
            raise LLMInvalidRequestError(
                "JSON mode requires the prompt to ask for JSON explicitly "
                "(mention 'JSON' in a system or user message)."
            )
        result = self._complete(checked, json_mode=True, temperature=temperature, max_tokens=max_tokens)
        if result.truncated:
            raise LLMStructuredOutputError(
                "The JSON response was cut off at max_tokens (finish_reason=length).",
                raw_content=result.content,
            )
        data = parse_json_object(result.content)
        parsed = validate_json(data, schema, raw_content=result.content) if schema else None
        return StructuredResult(data=data, parsed=parsed, raw=result)

    # -- internals ------------------------------------------------------------

    def _validate_messages(self, messages: Sequence[MessageInput]) -> list[ChatMessage]:
        if isinstance(messages, (str, bytes)) or not messages:
            raise LLMInvalidRequestError("messages must be a non-empty list of chat messages.")
        try:
            checked = [m if isinstance(m, ChatMessage) else ChatMessage.model_validate(m) for m in messages]
        except ValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
                for e in exc.errors(include_url=False, include_input=False)[:5]
            )
            raise LLMInvalidRequestError(f"Invalid chat message: {problems}.") from None
        total = sum(len(m.content) for m in checked)
        if total > MAX_PROMPT_CHARS:
            raise LLMInvalidRequestError(
                f"Prompt is too large ({total} characters; limit {MAX_PROMPT_CHARS}). "
                "Send only the relevant code context, not whole files or repositories."
            )
        return checked

    def _complete(
        self, messages: list[ChatMessage], *, json_mode: bool, temperature: float, max_tokens: int
    ) -> ChatResult:
        request: dict[str, Any] = {
            "model": self.model,
            "messages": [m.model_dump() for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            request["response_format"] = {"type": "json_object"}

        attempt = 0
        while True:
            attempt += 1
            started = time.perf_counter()
            try:
                completion = self._sdk.chat.completions.create(**request)
            except Exception as exc:  # translated below; original never re-raised
                error = self._translate(exc, json_mode=json_mode)
            else:
                return self._to_result(completion, attempt, time.perf_counter() - started)

            if not error.retryable or attempt > self.max_retries:
                error.attempts = attempt
                if error.retryable:
                    error.args = (f"{error.args[0]} Gave up after {attempt} attempt(s).",)
                raise error from None

            wait = self._wait_seconds(error, attempt)
            if wait is None:
                error.attempts = attempt
                error.args = (
                    f"{error.args[0]} The server asked to wait {error.retry_after:.0f}s, longer "
                    f"than the {self._max_retry_wait:.0f}s AutoPatch will wait; stopping.",
                )
                raise error from None
            logger.warning(
                "Groq request failed (%s, status=%s); retrying in %.1fs (attempt %d of %d).",
                type(error).__name__,
                error.status_code,
                wait,
                attempt,
                self.max_retries + 1,
            )
            self._sleep(wait)

    def _wait_seconds(self, error: LLMError, attempt: int) -> float | None:
        if error.retry_after is not None:
            if error.retry_after > self._max_retry_wait:
                return None
            return max(0.0, error.retry_after)
        backoff = min(BACKOFF_CAP, BACKOFF_BASE * 2 ** (attempt - 1))
        return min(self._max_retry_wait, backoff * (0.5 + self._rng() / 2))

    def _to_result(self, completion: Any, attempts: int, latency: float) -> ChatResult:
        choices = getattr(completion, "choices", None)
        if not choices:
            raise LLMResponseError("Groq returned a response with no choices.")
        choice = choices[0]
        finish_reason = getattr(choice, "finish_reason", None)
        content = getattr(getattr(choice, "message", None), "content", None)
        if content is None or not isinstance(content, str) or not content.strip():
            raise LLMEmptyResponseError(
                f"Groq returned an empty response (finish_reason={finish_reason})."
            )
        usage = getattr(completion, "usage", None)
        try:
            return ChatResult(
                content=content,
                model=str(getattr(completion, "model", None) or self.model),
                finish_reason=finish_reason,
                usage=TokenUsage(
                    prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
                    completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
                    total_tokens=getattr(usage, "total_tokens", 0) or 0,
                ),
                attempts=attempts,
                latency_seconds=round(latency, 4),
                response_id=getattr(completion, "id", None),
            )
        except ValidationError:
            raise LLMResponseError("Groq returned a response with an unexpected structure.") from None

    # -- error translation ------------------------------------------------------

    def _clean(self, text: str) -> str:
        text = " ".join(redact_secrets(text, extra_secrets=[self.__api_key]).split())
        return text if len(text) <= _DETAIL_LIMIT else text[: _DETAIL_LIMIT - 3] + "..."

    def _detail(self, exc: groq.APIError) -> tuple[str, str | None]:
        """Server-provided error message and code, redacted and truncated."""
        body = exc.body
        message, code = None, None
        if isinstance(body, Mapping):
            err = body.get("error", body)
            if isinstance(err, Mapping):
                message = err.get("message")
                code = err.get("code")
        return self._clean(str(message or exc.message or "")), (str(code) if code else None)

    def _translate(self, exc: Exception, *, json_mode: bool) -> LLMError:
        if isinstance(exc, groq.APITimeoutError):
            return LLMTimeoutError(f"The Groq request timed out after {self.timeout}s.")
        if isinstance(exc, groq.APIConnectionError):
            return LLMConnectionError("Could not connect to the Groq API (network error).")
        if isinstance(exc, groq.APIStatusError):
            return self._translate_status(exc, json_mode=json_mode)
        if isinstance(exc, groq.APIResponseValidationError):
            return LLMResponseError("Groq returned data that does not match the expected schema.")
        return LLMError(
            f"Unexpected error while calling Groq ({type(exc).__name__}): {self._clean(str(exc))}"
        )

    def _translate_status(self, exc: groq.APIStatusError, *, json_mode: bool) -> LLMError:
        status = exc.status_code
        detail, code = self._detail(exc)
        suffix = f" Server message: {detail}" if detail else ""

        if status == 401:
            return LLMAuthenticationError(
                "Groq rejected the API key (HTTP 401). Check GROQ_API_KEY in your local .env file.",
                status_code=status,
            )
        if status == 403:
            return LLMAuthenticationError(
                f"Groq denied access (HTTP 403); the key may not be allowed to use model "
                f"'{self.model}'.{suffix}",
                status_code=status,
            )
        if status == 429:
            quota = any(marker in detail.lower() for marker in _QUOTA_MARKERS)
            if quota:
                message = (
                    "Groq usage quota appears to be exhausted (HTTP 429). Stopping without "
                    "retrying; no other model or provider is used."
                )
            else:
                message = "Groq rate limit reached (HTTP 429). No other model or provider is used."
            return LLMRateLimitError(
                message + suffix,
                status_code=status,
                retry_after=_retry_after(exc.response.headers),
                quota_exhausted=quota,
            )
        if status == 404:
            return LLMInvalidRequestError(
                f"Groq returned HTTP 404: model '{self.model}' may not exist or may not be "
                f"available to this key. Set GROQ_MODEL to a model from your Groq console.{suffix}",
                status_code=status,
            )
        if status == 408:
            return LLMTimeoutError(f"Groq reported a request timeout (HTTP 408).{suffix}", status_code=status)
        if status >= 500:
            return LLMServerError(f"Groq server error (HTTP {status}).{suffix}", status_code=status)

        if code == "json_validate_failed":
            failed = exc.body.get("error", {}).get("failed_generation") if isinstance(exc.body, Mapping) else None
            return LLMStructuredOutputError(
                "The model failed to produce valid JSON in JSON mode (Groq json_validate_failed).",
                status_code=status,
                raw_content=failed if isinstance(failed, str) else None,
            )
        if json_mode and any(marker in detail.lower() for marker in _JSON_MODE_MARKERS):
            return LLMUnsupportedFeatureError(
                f"Model '{self.model}' rejected JSON mode (response_format=json_object). "
                "Set GROQ_MODEL to a model that supports JSON mode; AutoPatch does not "
                f"switch models automatically.{suffix}",
                status_code=status,
            )
        return LLMInvalidRequestError(f"Groq rejected the request (HTTP {status}).{suffix}", status_code=status)


def _retry_after(headers: Mapping[str, str] | Iterable[Any]) -> float | None:
    """Parse a Retry-After header given in seconds or as an HTTP date."""
    try:
        raw = headers.get("retry-after")  # type: ignore[union-attr]
    except AttributeError:
        return None
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    return max(0.0, when.timestamp() - time.time())
