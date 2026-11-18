"""Strict parsing of JSON model output. Independent of any patch format."""

from __future__ import annotations

import json
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from .errors import LLMEmptyResponseError, LLMStructuredOutputError

T = TypeVar("T", bound=BaseModel)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def parse_json_object(content: str | None) -> dict[str, Any]:
    """Parse ``content`` as a single JSON object.

    Strict on purpose: no markdown-fence stripping, no NaN/Infinity, no
    duplicate keys, and the top level must be an object.
    """
    if content is None or not content.strip():
        raise LLMEmptyResponseError("The model returned an empty response; expected a JSON object.")
    try:
        value = json.loads(
            content,
            parse_constant=_reject_constant,
            object_pairs_hook=_no_duplicate_keys,
        )
    except json.JSONDecodeError as exc:
        raise LLMStructuredOutputError(
            f"The model response is not valid JSON (line {exc.lineno}, column {exc.colno}: {exc.msg}).",
            raw_content=content,
        ) from None
    except ValueError as exc:
        raise LLMStructuredOutputError(
            f"The model response is not acceptable JSON: {exc}.", raw_content=content
        ) from None
    if not isinstance(value, dict):
        raise LLMStructuredOutputError(
            f"Expected a JSON object at the top level, got {type(value).__name__}.",
            raw_content=content,
        )
    return value


def validate_json(data: dict[str, Any], schema: type[T], *, raw_content: str | None = None) -> T:
    """Validate parsed JSON against a Pydantic model. Error messages list
    field locations and problems but never echo the offending values."""
    try:
        return schema.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors(include_url=False, include_input=False)[:10]
        )
        raise LLMStructuredOutputError(
            f"The JSON response does not match {schema.__name__}: {problems}.",
            raw_content=raw_content,
        ) from None
