# AutoPatch AI: Stage Log

A record of each development stage: what was built, how it was verified, and what is still open.

---

## Day 1 (2026-11-18): Repository audit

- No AutoPatch AI code existed. The only material was the project abstract (PDF).
- Agreed architecture: four agents (Scanner, Patch Generator, Verification, Documentation) plus a central orchestrator; FastAPI backend; Streamlit UI.
- Target categories: SQL injection, hardcoded credentials, insecure deserialization.
- The project lives in its own repository at `E:\Projects\autopatch-ai`.

## M0 (2026-11-18): Project scaffold and configuration

**Goal:** a clean, tested foundation with safe configuration handling. No agents.

**Built**
- `pyproject.toml`: Python ≥ 3.11, hatchling build, runtime dependency `python-dotenv`, dev group `pytest`. Exact versions locked in `uv.lock`.
- `autopatch/config.py`:
  - `load_settings()` reads environment variables plus an optional `.env` file. Real environment variables win, and the process environment is never modified.
  - Validation with clear `ConfigError` messages: retries are an integer 0–10, the sandbox timeout is an integer 1–3600 seconds, booleans accept true/false/1/0/yes/no/on/off, and the image name may not contain whitespace.
  - The Groq key is optional at load time. `Settings.require_llm()` raises `MissingLLMConfigError` only when an LLM operation needs the key.
  - No model is hardcoded, and no network calls are made.
  - The API key is hidden from `repr`/`str`/`safe_dict()` and from all error messages.
- `.env.example` (empty secrets) and a `.gitignore` covering `.env*`, `.venv`, caches, coverage files and `reports/`.
- `README.md` with setup steps and an honest status table.

**Verified**
- `uv run pytest`: 44 passed (Python 3.11.9, pytest 9.2.0).
- Git checks: the repository root is `E:\Projects\autopatch-ai`, and `.env` and `.venv` are confirmed ignored with `git check-ignore`.

**Open items**
- The Docker engine was not running on the development machine. It is needed from M4.
- No GitHub remote yet. Pushing waits for approval.
