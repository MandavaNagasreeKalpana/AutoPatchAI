"""Runtime configuration for AutoPatch AI.

Settings are read from environment variables, optionally supplemented by a
local ``.env`` file. Real environment variables always take precedence over
values in the file.

Design rules:
* Loading configuration never makes a network request.
* The Groq API key is optional at load time; it is only required when an LLM
  operation calls :meth:`Settings.require_llm`. Scanner-only workflows work
  without it.
* The API key is never included in ``repr``/``str`` output, in
  :meth:`Settings.safe_dict`, or in any error message raised here.
* The Groq model is never hardcoded; it must come from ``GROQ_MODEL``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

ENV_GROQ_API_KEY = "GROQ_API_KEY"
ENV_GROQ_MODEL = "GROQ_MODEL"
ENV_MAX_RETRIES = "AUTOPATCH_MAX_RETRIES"
ENV_SANDBOX_IMAGE = "AUTOPATCH_SANDBOX_IMAGE"
ENV_SANDBOX_TIMEOUT = "AUTOPATCH_SANDBOX_TIMEOUT"
ENV_ALLOW_HOST_EXEC = "AUTOPATCH_ALLOW_HOST_EXEC"
ENV_LLM_TIMEOUT = "AUTOPATCH_LLM_TIMEOUT"
ENV_LLM_MAX_RETRIES = "AUTOPATCH_LLM_MAX_RETRIES"

DEFAULT_MAX_RETRIES = 3
MIN_MAX_RETRIES = 0
MAX_MAX_RETRIES = 10

DEFAULT_SANDBOX_IMAGE = "autopatch-sandbox:latest"

DEFAULT_SANDBOX_TIMEOUT = 120  # seconds
MIN_SANDBOX_TIMEOUT = 1
MAX_SANDBOX_TIMEOUT = 3600

# Groq request timeout and retries for *transient* API failures (rate limits,
# timeouts, connection and 5xx errors). Separate from AUTOPATCH_MAX_RETRIES,
# which bounds patch-refinement attempts.
DEFAULT_LLM_TIMEOUT = 60  # seconds
MIN_LLM_TIMEOUT = 1
MAX_LLM_TIMEOUT = 600

DEFAULT_LLM_MAX_RETRIES = 2
MIN_LLM_MAX_RETRIES = 0
MAX_LLM_MAX_RETRIES = 5

DEFAULT_ENV_FILE = ".env"

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


class ConfigError(ValueError):
    """Raised when a configuration value is invalid."""


class MissingLLMConfigError(ConfigError):
    """Raised when an LLM operation is requested but Groq settings are missing."""


@dataclass(frozen=True)
class Settings:
    """Validated AutoPatch AI settings. Instances are immutable."""

    groq_api_key: str | None = field(default=None, repr=False)
    groq_model: str | None = None
    max_retries: int = DEFAULT_MAX_RETRIES
    sandbox_image: str = DEFAULT_SANDBOX_IMAGE
    sandbox_timeout: int = DEFAULT_SANDBOX_TIMEOUT
    allow_host_exec: bool = False
    llm_timeout: int = DEFAULT_LLM_TIMEOUT
    llm_max_retries: int = DEFAULT_LLM_MAX_RETRIES

    @property
    def has_llm_credentials(self) -> bool:
        """True when both the Groq API key and model are configured."""
        return bool(self.groq_api_key) and bool(self.groq_model)

    def require_llm(self) -> tuple[str, str]:
        """Return ``(api_key, model)`` or raise if either is missing.

        Call this immediately before an LLM operation, never at import or
        configuration-load time.
        """
        missing = [
            name
            for name, value in (
                (ENV_GROQ_API_KEY, self.groq_api_key),
                (ENV_GROQ_MODEL, self.groq_model),
            )
            if not value
        ]
        if missing:
            raise MissingLLMConfigError(
                "LLM operation requested but required configuration is missing: "
                + ", ".join(missing)
                + ". Set these in the environment or in a local .env file "
                "(see .env.example)."
            )
        assert self.groq_api_key is not None and self.groq_model is not None
        return self.groq_api_key, self.groq_model

    def safe_dict(self) -> dict[str, object]:
        """Return settings suitable for display or logging (no secrets)."""
        return {
            "groq_api_key": "<set>" if self.groq_api_key else "<not set>",
            "groq_model": self.groq_model,
            "max_retries": self.max_retries,
            "sandbox_image": self.sandbox_image,
            "sandbox_timeout": self.sandbox_timeout,
            "allow_host_exec": self.allow_host_exec,
            "llm_timeout": self.llm_timeout,
            "llm_max_retries": self.llm_max_retries,
        }

    def __repr__(self) -> str:
        fields = ", ".join(f"{k}={v!r}" for k, v in self.safe_dict().items())
        return f"Settings({fields})"

    __str__ = __repr__


def load_settings(
    env: Mapping[str, str] | None = None,
    env_file: str | os.PathLike[str] | None = DEFAULT_ENV_FILE,
) -> Settings:
    """Load and validate settings.

    Args:
        env: Variables to read. Defaults to ``os.environ``. Tests pass a dict.
        env_file: Path to a ``.env`` file. The default ``.env`` (relative to
            the current directory) is optional; an explicitly given path that
            does not exist raises :class:`ConfigError`. ``None`` disables
            file loading.

    The process environment is never modified.
    """
    values: dict[str, str] = {}
    if env_file is not None:
        values.update(_read_env_file(Path(env_file), explicit=env_file != DEFAULT_ENV_FILE))
    values.update(os.environ if env is None else env)

    return Settings(
        groq_api_key=_optional_str(values.get(ENV_GROQ_API_KEY)),
        groq_model=_optional_str(values.get(ENV_GROQ_MODEL)),
        max_retries=_parse_int(
            values, ENV_MAX_RETRIES, DEFAULT_MAX_RETRIES, MIN_MAX_RETRIES, MAX_MAX_RETRIES
        ),
        sandbox_image=_parse_image(values),
        sandbox_timeout=_parse_int(
            values,
            ENV_SANDBOX_TIMEOUT,
            DEFAULT_SANDBOX_TIMEOUT,
            MIN_SANDBOX_TIMEOUT,
            MAX_SANDBOX_TIMEOUT,
        ),
        allow_host_exec=_parse_bool(values, ENV_ALLOW_HOST_EXEC, default=False),
        llm_timeout=_parse_int(
            values, ENV_LLM_TIMEOUT, DEFAULT_LLM_TIMEOUT, MIN_LLM_TIMEOUT, MAX_LLM_TIMEOUT
        ),
        llm_max_retries=_parse_int(
            values,
            ENV_LLM_MAX_RETRIES,
            DEFAULT_LLM_MAX_RETRIES,
            MIN_LLM_MAX_RETRIES,
            MAX_LLM_MAX_RETRIES,
        ),
    )


def _read_env_file(path: Path, *, explicit: bool) -> dict[str, str]:
    if not path.is_file():
        if explicit:
            raise ConfigError(f"Environment file not found: {path}")
        return {}
    return {k: v for k, v in dotenv_values(path).items() if v is not None}


def _optional_str(raw: str | None) -> str | None:
    if raw is None:
        return None
    stripped = raw.strip()
    return stripped or None


def _parse_int(
    values: Mapping[str, str], name: str, default: int, minimum: int, maximum: int
) -> int:
    raw = _optional_str(values.get(name))
    if raw is None:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        raise ConfigError(
            f"{name} must be an integer between {minimum} and {maximum}; got {raw!r}."
        ) from None
    if not minimum <= parsed <= maximum:
        raise ConfigError(
            f"{name} must be between {minimum} and {maximum}; got {parsed}."
        )
    return parsed


def _parse_bool(values: Mapping[str, str], name: str, *, default: bool) -> bool:
    raw = _optional_str(values.get(name))
    if raw is None:
        return default
    lowered = raw.lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    raise ConfigError(
        f"{name} must be a boolean (true/false, 1/0, yes/no, on/off); got {raw!r}."
    )


def _parse_image(values: Mapping[str, str]) -> str:
    raw = _optional_str(values.get(ENV_SANDBOX_IMAGE))
    if raw is None:
        return DEFAULT_SANDBOX_IMAGE
    if any(ch.isspace() for ch in raw):
        raise ConfigError(f"{ENV_SANDBOX_IMAGE} must not contain whitespace; got {raw!r}.")
    return raw
