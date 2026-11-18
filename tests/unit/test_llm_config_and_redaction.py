"""New LLM settings (M3A) and the shared redaction helper."""

from __future__ import annotations

import pytest

from autopatch import config, redaction
from autopatch.config import ConfigError, load_settings
from autopatch.llm import parse_json_object
from autopatch.scanner import errors as scanner_errors

FAKE_KEY = "test-api-key-not-real-0000"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for name in (config.ENV_LLM_TIMEOUT, config.ENV_LLM_MAX_RETRIES, config.ENV_GROQ_API_KEY):
        monkeypatch.delenv(name, raising=False)


def test_llm_defaults():
    settings = load_settings(env={})
    assert settings.llm_timeout == 60
    assert settings.llm_max_retries == 2


def test_llm_values_loaded():
    settings = load_settings(env={"AUTOPATCH_LLM_TIMEOUT": "15", "AUTOPATCH_LLM_MAX_RETRIES": "0"})
    assert (settings.llm_timeout, settings.llm_max_retries) == (15, 0)


@pytest.mark.parametrize("raw", ["0", "601", "abc", "1.5"])
def test_invalid_llm_timeout(raw):
    with pytest.raises(ConfigError, match="AUTOPATCH_LLM_TIMEOUT"):
        load_settings(env={"AUTOPATCH_LLM_TIMEOUT": raw})


@pytest.mark.parametrize("raw", ["-1", "6", "x"])
def test_invalid_llm_max_retries(raw):
    with pytest.raises(ConfigError, match="AUTOPATCH_LLM_MAX_RETRIES"):
        load_settings(env={"AUTOPATCH_LLM_MAX_RETRIES": raw})


def test_safe_dict_includes_llm_settings_but_not_key():
    settings = load_settings(env={"GROQ_API_KEY": FAKE_KEY, "AUTOPATCH_LLM_TIMEOUT": "20"})
    safe = settings.safe_dict()
    assert safe["llm_timeout"] == 20 and safe["llm_max_retries"] == 2
    assert FAKE_KEY not in repr(settings) and FAKE_KEY not in str(safe)


def test_patch_retries_and_llm_retries_are_independent():
    settings = load_settings(env={"AUTOPATCH_MAX_RETRIES": "7", "AUTOPATCH_LLM_MAX_RETRIES": "1"})
    assert (settings.max_retries, settings.llm_max_retries) == (7, 1)


# --- redaction -------------------------------------------------------------------


def test_extra_secrets_are_redacted():
    out = redaction.redact_secrets(f"key is {FAKE_KEY}", environ={}, extra_secrets=[FAKE_KEY, None])
    assert FAKE_KEY not in out and redaction.REDACTED in out


@pytest.mark.parametrize(
    "text",
    ["Authorization: Bearer abc.def-123", "authorization=xyz123", "{'Authorization': 'Bearer t0k3n'}"],
)
def test_authorization_headers_are_redacted(text):
    out = redaction.redact_secrets(text, environ={})
    assert "abc.def-123" not in out and "xyz123" not in out and "t0k3n" not in out


def test_groq_style_key_pattern_redacted():
    fake = "gsk" + "_" + "Z" * 20  # assembled so secret scanners don't flag the repo
    assert fake not in redaction.redact_secrets(f"x {fake} y", environ={})


def test_scanner_reexports_shared_helpers():
    assert scanner_errors.redact_secrets is redaction.redact_secrets
    assert scanner_errors.safe_error_message is redaction.safe_error_message


def test_safe_error_message_with_extra_secret():
    message = redaction.safe_error_message(RuntimeError(f"boom {FAKE_KEY}"), extra_secrets=[FAKE_KEY])
    assert FAKE_KEY not in message and message.startswith("RuntimeError")


def test_parse_json_object_accepts_nested_object():
    assert parse_json_object('{"a": {"b": [1, 2]}}') == {"a": {"b": [1, 2]}}
