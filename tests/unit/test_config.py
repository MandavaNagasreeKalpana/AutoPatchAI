"""Unit tests for autopatch.config. No real Groq key or network access needed."""

from __future__ import annotations

import pytest

from autopatch import config
from autopatch.config import (
    ConfigError,
    MissingLLMConfigError,
    Settings,
    load_settings,
)

FAKE_KEY = "gsk_test_FAKE_KEY_DO_NOT_LEAK_1234567890"

ALL_VARS = (
    config.ENV_GROQ_API_KEY,
    config.ENV_GROQ_MODEL,
    config.ENV_MAX_RETRIES,
    config.ENV_SANDBOX_IMAGE,
    config.ENV_SANDBOX_TIMEOUT,
    config.ENV_ALLOW_HOST_EXEC,
)


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    """Run every test in an empty directory with no AutoPatch variables set,
    so a developer's real .env or shell variables can never leak in."""
    monkeypatch.chdir(tmp_path)
    for name in ALL_VARS:
        monkeypatch.delenv(name, raising=False)


# --- defaults ---------------------------------------------------------------


def test_defaults_when_nothing_configured():
    settings = load_settings(env={})

    assert settings.groq_api_key is None
    assert settings.groq_model is None
    assert settings.max_retries == config.DEFAULT_MAX_RETRIES == 3
    assert settings.sandbox_image == config.DEFAULT_SANDBOX_IMAGE
    assert settings.sandbox_timeout == config.DEFAULT_SANDBOX_TIMEOUT == 120
    assert settings.allow_host_exec is False
    assert settings.has_llm_credentials is False


def test_no_model_is_hardcoded():
    assert load_settings(env={}).groq_model is None


def test_settings_are_immutable():
    settings = load_settings(env={})
    with pytest.raises(AttributeError):
        settings.max_retries = 5  # type: ignore[misc]


# --- environment loading ----------------------------------------------------


def test_loads_all_values_from_env_mapping():
    settings = load_settings(
        env={
            "GROQ_API_KEY": FAKE_KEY,
            "GROQ_MODEL": "example-model",
            "AUTOPATCH_MAX_RETRIES": "5",
            "AUTOPATCH_SANDBOX_IMAGE": "my-sandbox:1.0",
            "AUTOPATCH_SANDBOX_TIMEOUT": "300",
            "AUTOPATCH_ALLOW_HOST_EXEC": "true",
        }
    )

    assert settings.groq_api_key == FAKE_KEY
    assert settings.groq_model == "example-model"
    assert settings.max_retries == 5
    assert settings.sandbox_image == "my-sandbox:1.0"
    assert settings.sandbox_timeout == 300
    assert settings.allow_host_exec is True
    assert settings.has_llm_credentials is True


def test_reads_process_environment_by_default(monkeypatch):
    monkeypatch.setenv("GROQ_MODEL", "from-os-environ")
    monkeypatch.setenv("AUTOPATCH_MAX_RETRIES", "2")

    settings = load_settings()

    assert settings.groq_model == "from-os-environ"
    assert settings.max_retries == 2


def test_loads_default_dotenv_file_from_current_directory(tmp_path):
    (tmp_path / ".env").write_text(
        "GROQ_MODEL=model-from-file\nAUTOPATCH_SANDBOX_TIMEOUT=45\n", encoding="utf-8"
    )

    settings = load_settings(env={})

    assert settings.groq_model == "model-from-file"
    assert settings.sandbox_timeout == 45


def test_environment_overrides_dotenv_file(tmp_path):
    env_file = tmp_path / "custom.env"
    env_file.write_text("GROQ_MODEL=model-from-file\n", encoding="utf-8")

    settings = load_settings(env={"GROQ_MODEL": "model-from-env"}, env_file=env_file)

    assert settings.groq_model == "model-from-env"


def test_loading_does_not_modify_process_environment(tmp_path):
    import os

    (tmp_path / ".env").write_text("GROQ_MODEL=model-from-file\n", encoding="utf-8")
    load_settings()
    assert "GROQ_MODEL" not in os.environ


def test_missing_default_dotenv_file_is_fine():
    assert load_settings(env={}).max_retries == 3


def test_explicit_missing_env_file_raises(tmp_path):
    with pytest.raises(ConfigError, match="Environment file not found"):
        load_settings(env={}, env_file=tmp_path / "does-not-exist.env")


def test_env_file_can_be_disabled(tmp_path):
    (tmp_path / ".env").write_text("GROQ_MODEL=model-from-file\n", encoding="utf-8")
    assert load_settings(env={}, env_file=None).groq_model is None


def test_blank_values_are_treated_as_unset():
    settings = load_settings(
        env={"GROQ_API_KEY": "   ", "GROQ_MODEL": "", "AUTOPATCH_MAX_RETRIES": " "}
    )
    assert settings.groq_api_key is None
    assert settings.groq_model is None
    assert settings.max_retries == 3


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("1", True), ("YES", True), ("On", True), ("0", False), ("false", False), ("off", False)],
)
def test_allow_host_exec_boolean_parsing(raw, expected):
    assert load_settings(env={"AUTOPATCH_ALLOW_HOST_EXEC": raw}).allow_host_exec is expected


# --- missing Groq key -------------------------------------------------------


def test_scanner_usage_does_not_need_groq_key():
    """Loading settings must succeed without any Groq configuration."""
    settings = load_settings(env={})
    assert settings.has_llm_credentials is False


def test_require_llm_raises_when_key_missing():
    settings = load_settings(env={"GROQ_MODEL": "example-model"})

    with pytest.raises(MissingLLMConfigError) as exc_info:
        settings.require_llm()

    message = str(exc_info.value)
    assert "GROQ_API_KEY" in message
    assert "GROQ_MODEL" not in message


def test_require_llm_raises_when_model_missing():
    settings = load_settings(env={"GROQ_API_KEY": FAKE_KEY})

    with pytest.raises(MissingLLMConfigError) as exc_info:
        settings.require_llm()

    message = str(exc_info.value)
    assert "GROQ_MODEL" in message
    assert FAKE_KEY not in message


def test_require_llm_lists_both_when_both_missing():
    with pytest.raises(MissingLLMConfigError, match="GROQ_API_KEY, GROQ_MODEL"):
        load_settings(env={}).require_llm()


def test_missing_llm_error_is_a_config_error():
    assert issubclass(MissingLLMConfigError, ConfigError)


def test_require_llm_returns_credentials_when_configured():
    settings = load_settings(env={"GROQ_API_KEY": FAKE_KEY, "GROQ_MODEL": "example-model"})
    assert settings.require_llm() == (FAKE_KEY, "example-model")


# --- invalid retry count ----------------------------------------------------


@pytest.mark.parametrize("raw", ["abc", "2.5", "-1", "11", "1e3"])
def test_invalid_retry_count_raises(raw):
    with pytest.raises(ConfigError, match="AUTOPATCH_MAX_RETRIES"):
        load_settings(env={"AUTOPATCH_MAX_RETRIES": raw})


@pytest.mark.parametrize("raw", ["0", "10"])
def test_retry_count_boundaries_are_accepted(raw):
    assert load_settings(env={"AUTOPATCH_MAX_RETRIES": raw}).max_retries == int(raw)


# --- invalid sandbox timeout ------------------------------------------------


@pytest.mark.parametrize("raw", ["abc", "0", "-5", "3601", "12.5"])
def test_invalid_sandbox_timeout_raises(raw):
    with pytest.raises(ConfigError, match="AUTOPATCH_SANDBOX_TIMEOUT"):
        load_settings(env={"AUTOPATCH_SANDBOX_TIMEOUT": raw})


@pytest.mark.parametrize("raw", ["1", "3600"])
def test_sandbox_timeout_boundaries_are_accepted(raw):
    assert load_settings(env={"AUTOPATCH_SANDBOX_TIMEOUT": raw}).sandbox_timeout == int(raw)


# --- other invalid values ---------------------------------------------------


def test_invalid_boolean_raises():
    with pytest.raises(ConfigError, match="AUTOPATCH_ALLOW_HOST_EXEC"):
        load_settings(env={"AUTOPATCH_ALLOW_HOST_EXEC": "maybe"})


def test_sandbox_image_with_whitespace_raises():
    with pytest.raises(ConfigError, match="AUTOPATCH_SANDBOX_IMAGE"):
        load_settings(env={"AUTOPATCH_SANDBOX_IMAGE": "bad image"})


def test_validation_error_never_contains_api_key():
    with pytest.raises(ConfigError) as exc_info:
        load_settings(env={"GROQ_API_KEY": FAKE_KEY, "AUTOPATCH_MAX_RETRIES": "nope"})
    assert FAKE_KEY not in str(exc_info.value)


# --- secret-safe representation ---------------------------------------------


def test_repr_and_str_hide_api_key():
    settings = load_settings(env={"GROQ_API_KEY": FAKE_KEY, "GROQ_MODEL": "example-model"})

    for text in (repr(settings), str(settings), f"{settings}", f"{settings!r}"):
        assert FAKE_KEY not in text
        assert "<set>" in text
        assert "example-model" in text


def test_safe_dict_hides_api_key():
    with_key = load_settings(env={"GROQ_API_KEY": FAKE_KEY}).safe_dict()
    without_key = load_settings(env={}).safe_dict()

    assert FAKE_KEY not in str(with_key)
    assert with_key["groq_api_key"] == "<set>"
    assert without_key["groq_api_key"] == "<not set>"


def test_direct_construction_also_hides_key():
    assert FAKE_KEY not in repr(Settings(groq_api_key=FAKE_KEY))
