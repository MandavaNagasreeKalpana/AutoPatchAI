"""Groq LLM integration (M3A). Not yet connected to any agent."""

from autopatch.config import MissingLLMConfigError

from .client import GroqClient, StructuredResult
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

__all__ = [
    "MAX_PROMPT_CHARS",
    "ChatMessage",
    "ChatResult",
    "GroqClient",
    "LLMAuthenticationError",
    "LLMConnectionError",
    "LLMEmptyResponseError",
    "LLMError",
    "LLMInvalidRequestError",
    "LLMRateLimitError",
    "LLMResponseError",
    "LLMServerError",
    "LLMStructuredOutputError",
    "LLMTimeoutError",
    "LLMUnsupportedFeatureError",
    "MissingLLMConfigError",
    "StructuredResult",
    "TokenUsage",
    "parse_json_object",
    "validate_json",
]
