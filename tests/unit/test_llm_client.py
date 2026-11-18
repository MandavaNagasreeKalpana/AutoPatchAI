"""GroqClient with mocked Groq responses. No real API key, no network.

Two kinds of mocks:
* ``FakeSDK`` stands in for ``groq.Groq`` and raises real ``groq`` exception
  objects, to test translation and retry policy precisely.
* ``httpx.MockTransport`` plugged into the *real* ``groq.Groq`` checks the
  SDK wiring end to end, with HTTP intercepted in-process.

An autouse fixture disables httpx's real transport, so any accidental network
call fails the test instead of reaching Groq.
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace

import groq
import httpx
import pytest
from pydantic import BaseModel

from autopatch.config import MissingLLMConfigError, Settings
from autopatch.llm import (
    MAX_PROMPT_CHARS,
    ChatMessage,
    GroqClient,
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

# Obviously fake placeholder, never a real key.
FAKE_KEY = "test-api-key-not-real-0000"
MODEL = "test-model"
URL = "https://api.groq.com/openai/v1/chat/completions"
REQUEST = httpx.Request("POST", URL, headers={"Authorization": f"Bearer {FAKE_KEY}"})
USER = [{"role": "user", "content": "Say hello."}]
JSON_USER = [{"role": "user", "content": "Reply with a JSON object."}]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(self, request):
        raise RuntimeError(f"real network access attempted in a unit test: {request.url}")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", blocked)


def settings(**overrides):
    values = {"groq_api_key": FAKE_KEY, "groq_model": MODEL, "llm_timeout": 30, "llm_max_retries": 2}
    values.update(overrides)
    return Settings(**values)


def completion(content="Hello!", finish_reason="stop", model=MODEL, usage=(12, 3, 15), choices=True):
    choice = SimpleNamespace(message=SimpleNamespace(content=content), finish_reason=finish_reason)
    return SimpleNamespace(
        id="chatcmpl-test",
        model=model,
        choices=[choice] if choices else [],
        usage=SimpleNamespace(prompt_tokens=usage[0], completion_tokens=usage[1], total_tokens=usage[2]),
    )


def status_error(cls, status, message="error", code=None, headers=None, extra=None):
    body = {"error": {"message": message, "type": "test", **({"code": code} if code else {}), **(extra or {})}}
    response = httpx.Response(status, request=REQUEST, headers=headers or {}, json=body)
    return cls(f"Error code: {status} - {body}", response=response, body=body)


class FakeSDK:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def make(*outcomes, sleeps=None, **settings_overrides):
    sdk = FakeSDK(*outcomes)
    recorded = [] if sleeps is None else sleeps
    client = GroqClient(settings(**settings_overrides), sdk_client=sdk, sleep=recorded.append, rng=lambda: 1.0)
    return client, sdk, recorded


# --- initialization ---------------------------------------------------------


def test_initializes_real_sdk_without_network_and_without_sdk_retries():
    client = GroqClient(settings())
    sdk = client._sdk
    assert isinstance(sdk, groq.Groq)
    assert sdk.max_retries == 0  # our wrapper owns retries
    assert sdk.timeout == 30.0
    assert client.model == MODEL and client.max_retries == 2


@pytest.mark.parametrize(
    ("overrides", "missing"),
    [({"groq_api_key": None}, "GROQ_API_KEY"), ({"groq_model": None}, "GROQ_MODEL"),
     ({"groq_api_key": None, "groq_model": None}, "GROQ_API_KEY, GROQ_MODEL")],
)
def test_missing_configuration_fails_before_any_request(overrides, missing):
    sdk = FakeSDK()
    with pytest.raises(MissingLLMConfigError, match=missing):
        GroqClient(settings(**overrides), sdk_client=sdk)
    assert sdk.calls == []


def test_from_env_reads_local_env_file(tmp_path, monkeypatch):
    for name in ("GROQ_API_KEY", "GROQ_MODEL", "AUTOPATCH_LLM_TIMEOUT", "AUTOPATCH_LLM_MAX_RETRIES"):
        monkeypatch.delenv(name, raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"GROQ_API_KEY={FAKE_KEY}\nGROQ_MODEL=file-model\nAUTOPATCH_LLM_TIMEOUT=15\n", encoding="utf-8"
    )
    client = GroqClient.from_env(env_file, sdk_client=FakeSDK())
    assert client.model == "file-model" and client.timeout == 15


def test_repr_and_attributes_hide_key():
    client, _, _ = make()
    assert FAKE_KEY not in repr(client) and FAKE_KEY not in str(client)
    assert "api_key=<set>" in repr(client)
    assert not any(FAKE_KEY == v for k, v in vars(client).items() if not k.startswith("_GroqClient__"))


# --- chat --------------------------------------------------------------------


def test_successful_chat_completion():
    client, sdk, sleeps = make(completion("Hello there"))
    result = client.chat(USER, temperature=0.2, max_tokens=50)

    assert result.content == "Hello there"
    assert result.model == MODEL and result.finish_reason == "stop"
    assert (result.usage.prompt_tokens, result.usage.completion_tokens, result.usage.total_tokens) == (12, 3, 15)
    assert result.attempts == 1 and result.response_id == "chatcmpl-test"
    assert sdk.calls == [
        {"model": MODEL, "messages": USER, "temperature": 0.2, "max_tokens": 50}
    ]
    assert sleeps == []


def test_accepts_chat_message_objects():
    client, sdk, _ = make(completion())
    client.chat([ChatMessage(role="system", content="Be brief."), ChatMessage(role="user", content="Hi")])
    assert [m["role"] for m in sdk.calls[0]["messages"]] == ["system", "user"]


@pytest.mark.parametrize(
    "messages",
    [[], "hello", [{"role": "tool", "content": "x"}], [{"role": "user", "content": "   "}],
     [{"role": "user"}], [{"role": "user", "content": "x", "extra": 1}]],
)
def test_invalid_messages_rejected_locally(messages):
    client, sdk, _ = make()
    with pytest.raises(LLMInvalidRequestError):
        client.chat(messages)
    assert sdk.calls == []


def test_oversized_prompt_rejected_locally():
    client, sdk, _ = make()
    half = "x" * (MAX_PROMPT_CHARS // 2 + 1)
    with pytest.raises(LLMInvalidRequestError, match="too large"):
        client.chat([{"role": "system", "content": half}, {"role": "user", "content": half}])
    assert sdk.calls == []


@pytest.mark.parametrize("content", ["", "   \n", None])
def test_empty_response(content):
    client, _, _ = make(completion(content))
    with pytest.raises(LLMEmptyResponseError, match="empty"):
        client.chat(USER)


def test_response_without_choices():
    client, _, _ = make(completion(choices=False))
    with pytest.raises(LLMResponseError, match="no choices"):
        client.chat(USER)


def test_truncated_chat_is_reported_not_hidden():
    client, _, _ = make(completion("partial", finish_reason="length"))
    assert client.chat(USER).truncated is True


# --- JSON mode -----------------------------------------------------------------


class Verdict(BaseModel):
    vulnerable: bool
    reason: str


def test_successful_json_response_with_schema():
    payload = {"vulnerable": True, "reason": "string-built SQL"}
    client, sdk, _ = make(completion(json.dumps(payload)))
    result = client.chat_json(JSON_USER, schema=Verdict)

    assert result.data == payload
    assert result.parsed == Verdict(**payload)
    assert result.raw.attempts == 1
    assert sdk.calls[0]["response_format"] == {"type": "json_object"}
    assert sdk.calls[0]["model"] == MODEL


def test_json_without_schema_returns_dict():
    client, _, _ = make(completion('{"a": 1}'))
    result = client.chat_json(JSON_USER)
    assert result.data == {"a": 1} and result.parsed is None


@pytest.mark.parametrize(
    ("content", "match"),
    [
        ("not json at all", "not valid JSON"),
        ('{"a": 1', "not valid JSON"),
        ('```json\n{"a": 1}\n```', "not valid JSON"),
        ("[1, 2, 3]", "JSON object"),
        ('"just a string"', "JSON object"),
        ('{"a": NaN}', "NaN"),
        ('{"a": 1, "a": 2}', "duplicate key"),
    ],
)
def test_invalid_json_is_rejected(content, match):
    client, _, _ = make(completion(content))
    with pytest.raises(LLMStructuredOutputError, match=match) as exc_info:
        client.chat_json(JSON_USER)
    assert exc_info.value.raw_content == content  # kept for debugging, not in str(exc)


def test_schema_mismatch_lists_fields_without_values():
    client, _, _ = make(completion('{"vulnerable": "SECRET-ish-value", "extra": 1}'))
    with pytest.raises(LLMStructuredOutputError, match="does not match Verdict") as exc_info:
        client.chat_json(JSON_USER, schema=Verdict)
    message = str(exc_info.value)
    assert "vulnerable" in message and "reason" in message
    assert "SECRET-ish-value" not in message


def test_empty_json_response():
    client, _, _ = make(completion("  "))
    with pytest.raises(LLMEmptyResponseError):
        client.chat_json(JSON_USER)


def test_truncated_json_response_rejected():
    client, _, _ = make(completion('{"a": 1}', finish_reason="length"))
    with pytest.raises(LLMStructuredOutputError, match="cut off"):
        client.chat_json(JSON_USER)


def test_json_mode_requires_prompt_to_mention_json():
    client, sdk, _ = make()
    with pytest.raises(LLMInvalidRequestError, match="mention 'JSON'"):
        client.chat_json(USER)
    assert sdk.calls == []


def test_model_without_json_mode_is_reported_and_not_switched():
    err = status_error(
        groq.BadRequestError, 400, "response_format `json_object` is not supported with this model"
    )
    client, sdk, sleeps = make(err)
    with pytest.raises(LLMUnsupportedFeatureError, match="does not switch models") as exc_info:
        client.chat_json(JSON_USER)
    assert MODEL in str(exc_info.value)
    assert len(sdk.calls) == 1 and sdk.calls[0]["model"] == MODEL
    assert sleeps == []


def test_groq_json_validate_failed_is_structured_error():
    err = status_error(
        groq.BadRequestError, 400, "Failed to generate JSON", code="json_validate_failed",
        extra={"failed_generation": '{"broken": '},
    )
    client, sdk, _ = make(err)
    with pytest.raises(LLMStructuredOutputError, match="json_validate_failed") as exc_info:
        client.chat_json(JSON_USER)
    assert exc_info.value.raw_content == '{"broken": '
    assert len(sdk.calls) == 1


# --- error translation and retries ---------------------------------------------


def test_authentication_failure_not_retried():
    client, sdk, sleeps = make(status_error(groq.AuthenticationError, 401, "Invalid API Key"))
    with pytest.raises(LLMAuthenticationError, match="GROQ_API_KEY") as exc_info:
        client.chat(USER)
    assert exc_info.value.status_code == 401
    assert len(sdk.calls) == 1 and sleeps == []


def test_permission_denied_not_retried():
    client, sdk, _ = make(status_error(groq.PermissionDeniedError, 403, "model access denied"))
    with pytest.raises(LLMAuthenticationError, match="HTTP 403"):
        client.chat(USER)
    assert len(sdk.calls) == 1


def test_unknown_model_not_retried():
    client, sdk, _ = make(status_error(groq.NotFoundError, 404, "The model `x` does not exist"))
    with pytest.raises(LLMInvalidRequestError, match="GROQ_MODEL"):
        client.chat(USER)
    assert len(sdk.calls) == 1


def test_bad_request_not_retried():
    client, sdk, sleeps = make(status_error(groq.BadRequestError, 400, "max_tokens too large"))
    with pytest.raises(LLMInvalidRequestError, match="max_tokens too large"):
        client.chat(USER)
    assert len(sdk.calls) == 1 and sleeps == []


def test_rate_limit_retried_using_retry_after():
    err = status_error(groq.RateLimitError, 429, "Rate limit reached ... requests per minute (RPM)",
                       headers={"retry-after": "2"})
    client, sdk, sleeps = make(err, completion("ok"))
    result = client.chat(USER)
    assert result.content == "ok" and result.attempts == 2
    assert sleeps == [2.0]


def test_rate_limit_with_long_retry_after_stops_immediately():
    err = status_error(groq.RateLimitError, 429, "Rate limit reached (RPM)", headers={"retry-after": "120"})
    client, sdk, sleeps = make(err, completion("never reached"))
    with pytest.raises(LLMRateLimitError, match="stopping") as exc_info:
        client.chat(USER)
    assert exc_info.value.retry_after == 120.0
    assert len(sdk.calls) == 1 and sleeps == []


def test_daily_quota_exhausted_stops_without_retry():
    err = status_error(
        groq.RateLimitError, 429,
        "Rate limit reached for model `test-model` on tokens per day (TPD): Limit 100000, Used 100000",
        headers={"retry-after": "1"},
    )
    client, sdk, sleeps = make(err, completion("never reached"))
    with pytest.raises(LLMRateLimitError, match="quota appears to be exhausted") as exc_info:
        client.chat(USER)
    assert exc_info.value.quota_exhausted is True
    assert "no other model or provider is used" in str(exc_info.value)
    assert len(sdk.calls) == 1 and sleeps == []


def test_rate_limit_retries_are_bounded():
    errs = [status_error(groq.RateLimitError, 429, "slow down", headers={"retry-after": "1"}) for _ in range(5)]
    client, sdk, sleeps = make(*errs, llm_max_retries=2)
    with pytest.raises(LLMRateLimitError, match="Gave up after 3 attempt") as exc_info:
        client.chat(USER)
    assert exc_info.value.attempts == 3
    assert len(sdk.calls) == 3 and sleeps == [1.0, 1.0]


def test_timeout_retried_then_reported():
    client, sdk, sleeps = make(*[groq.APITimeoutError(request=REQUEST) for _ in range(3)])
    with pytest.raises(LLMTimeoutError, match="timed out after 30s"):
        client.chat(USER)
    assert len(sdk.calls) == 3
    assert sleeps == [1.0, 2.0]  # exponential backoff (jitter pinned by rng=1.0)


def test_connection_error_retried_then_succeeds():
    client, sdk, sleeps = make(groq.APIConnectionError(request=REQUEST), completion("back"))
    assert client.chat(USER).content == "back"
    assert len(sdk.calls) == 2 and sleeps == [1.0]


def test_connection_error_reported_after_retries():
    client, _, _ = make(*[groq.APIConnectionError(request=REQUEST) for _ in range(3)])
    with pytest.raises(LLMConnectionError, match="network error"):
        client.chat(USER)


@pytest.mark.parametrize("status", [500, 502, 503])
def test_server_error_retried(status):
    client, sdk, _ = make(status_error(groq.InternalServerError, status, "upstream failure"), completion("ok"))
    assert client.chat(USER).content == "ok"
    assert len(sdk.calls) == 2


def test_server_error_reported_after_retries():
    errs = [status_error(groq.InternalServerError, 503, "unavailable") for _ in range(3)]
    client, sdk, _ = make(*errs)
    with pytest.raises(LLMServerError, match="HTTP 503"):
        client.chat(USER)
    assert len(sdk.calls) == 3


def test_zero_retries_means_single_attempt():
    client, sdk, sleeps = make(status_error(groq.InternalServerError, 500, "x"), llm_max_retries=0)
    with pytest.raises(LLMServerError):
        client.chat(USER)
    assert len(sdk.calls) == 1 and sleeps == []


def test_backoff_is_capped_by_max_retry_wait():
    errs = [groq.APIConnectionError(request=REQUEST) for _ in range(6)]
    sdk = FakeSDK(*errs)
    sleeps: list[float] = []
    client = GroqClient(settings(llm_max_retries=5), sdk_client=sdk, sleep=sleeps.append,
                        rng=lambda: 1.0, max_retry_wait=3.0)
    with pytest.raises(LLMConnectionError):
        client.chat(USER)
    assert sleeps == [1.0, 2.0, 3.0, 3.0, 3.0]


def test_unexpected_exception_is_wrapped_not_retried():
    client, sdk, sleeps = make(ValueError("something odd"))
    with pytest.raises(LLMError, match="Unexpected error") as exc_info:
        client.chat(USER)
    assert type(exc_info.value) is LLMError
    assert len(sdk.calls) == 1 and sleeps == []


def test_original_sdk_exception_is_not_chained():
    """The SDK exception holds the request (with the Authorization header)."""
    client, _, _ = make(status_error(groq.AuthenticationError, 401, "Invalid API Key"))
    with pytest.raises(LLMAuthenticationError) as exc_info:
        client.chat(USER)
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True
    assert exc_info.value.__context__ is None  # SDK exception not retained at all


# --- secret redaction ----------------------------------------------------------


def test_server_message_echoing_the_key_is_redacted():
    err = status_error(groq.BadRequestError, 400, f"bad header Authorization: Bearer {FAKE_KEY}")
    client, _, _ = make(err)
    with pytest.raises(LLMInvalidRequestError) as exc_info:
        client.chat(USER)
    assert FAKE_KEY not in str(exc_info.value)
    assert "***REDACTED***" in str(exc_info.value)


def test_unexpected_exception_text_is_redacted():
    client, _, _ = make(RuntimeError(f"failed with key {FAKE_KEY}"))
    with pytest.raises(LLMError) as exc_info:
        client.chat(USER)
    assert FAKE_KEY not in str(exc_info.value)


def test_retry_logs_contain_no_secrets_or_content(caplog):
    caplog.set_level(logging.DEBUG)
    client, _, _ = make(status_error(groq.InternalServerError, 500, f"oops {FAKE_KEY}"), completion("secret answer"))
    client.chat([{"role": "user", "content": "private prompt text"}])
    assert "retrying" in caplog.text
    for forbidden in (FAKE_KEY, "Authorization", "Bearer", "private prompt text", "secret answer"):
        assert forbidden not in caplog.text


# --- real SDK over an in-process mock transport ----------------------------------


def transport_client(handler, **overrides):
    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    sdk = groq.Groq(api_key=FAKE_KEY, http_client=http_client, max_retries=0)
    sleeps: list[float] = []
    return GroqClient(settings(**overrides), sdk_client=sdk, sleep=sleeps.append, rng=lambda: 1.0), sleeps


def completion_json(content='{"ok": true}'):
    return {
        "id": "chatcmpl-mock",
        "object": "chat.completion",
        "created": 0,
        "model": MODEL,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 4, "total_tokens": 9},
    }


def test_real_sdk_request_shape_via_mock_transport():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=completion_json())

    client, _ = transport_client(handler)
    result = client.chat_json(JSON_USER)
    assert result.data == {"ok": True}
    assert result.raw.usage.total_tokens == 9
    assert seen["auth"] == f"Bearer {FAKE_KEY}"
    assert seen["body"]["model"] == MODEL
    assert seen["body"]["response_format"] == {"type": "json_object"}


def test_real_sdk_status_codes_map_correctly_via_mock_transport():
    responses = iter([
        httpx.Response(429, headers={"retry-after": "0"}, json={"error": {"message": "slow down"}}),
        httpx.Response(503, json={"error": {"message": "busy"}}),
        httpx.Response(200, json=completion_json()),
    ])
    client, sleeps = transport_client(lambda request: next(responses))
    assert client.chat(USER).content == '{"ok": true}'
    assert sleeps == [0.0, 2.0]


def test_real_sdk_auth_failure_via_mock_transport():
    client, _ = transport_client(
        lambda r: httpx.Response(401, json={"error": {"message": "Invalid API Key", "code": "invalid_api_key"}})
    )
    with pytest.raises(LLMAuthenticationError) as exc_info:
        client.chat(USER)
    assert FAKE_KEY not in str(exc_info.value)


@pytest.mark.parametrize(
    ("exc", "expected"),
    [(httpx.ConnectTimeout("t"), LLMTimeoutError), (httpx.ReadTimeout("t"), LLMTimeoutError),
     (httpx.ConnectError("c"), LLMConnectionError)],
)
def test_real_sdk_transport_failures_via_mock_transport(exc, expected):
    def handler(request):
        raise exc

    client, sleeps = transport_client(handler, llm_max_retries=1)
    with pytest.raises(expected):
        client.chat(USER)
    assert sleeps == [1.0]


def test_no_network_guard_is_active():
    with pytest.raises(RuntimeError, match="real network access"):
        httpx.Client().get("https://api.groq.com/")
