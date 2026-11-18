"""Request/response types for the LLM client (provider-neutral, no secrets)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, Field

from autopatch.models.common import CodeStr, StrictModel

MAX_PROMPT_CHARS = 60_000  # guard against sending whole files/repositories


def _non_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("message content must not be empty")
    return value


class ChatMessage(StrictModel):
    role: Literal["system", "user", "assistant"]
    content: Annotated[str, Field(max_length=MAX_PROMPT_CHARS), AfterValidator(_non_blank)]


class TokenUsage(StrictModel):
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)


class ChatResult(StrictModel):
    content: CodeStr
    model: str
    finish_reason: str | None = None
    usage: TokenUsage = Field(default_factory=TokenUsage)
    attempts: int = Field(ge=1)
    latency_seconds: float = Field(ge=0.0)
    response_id: str | None = None

    @property
    def truncated(self) -> bool:
        return self.finish_reason == "length"
