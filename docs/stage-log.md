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

## M1 (2026-11-18): Core data models and benchmark foundation

**Goal:** shared, validated data models for all four agents, plus a small benchmark of vulnerable fixtures. No agents and no Groq calls.

**Dependency added:** `pydantic>=2.7,<3`. It resolved to 2.14.3 (pydantic-core 2.50.4) on Python 3.11.9, installed only in the project `.venv`.

**Built**
- `autopatch/models/`:
  - `enums.py`: case-insensitive string enums. A test fails if a category is added without its entry in `CATEGORY_INFO`.
  - `common.py`: checked types for project paths, identifiers, confidence, line numbers and timezone-aware datetimes, plus a frozen, extra-forbid base model.
  - `finding.py`, `patch.py`, `verification.py`, `report.py`: the four main models.
  - `benchmark.py`: the manifest schema.
- Validation highlights:
  - Path traversal and absolute paths are rejected, including inside diff headers.
  - A patch must actually change the code.
  - Overall verification status is worked out from the checks and must agree with them.
  - The report checks links between findings, patches and verifications.
- `autopatch/benchmark.py`: loads and validates the manifest, and checks sample files by reading them as text and parsing with `ast.parse`. Nothing is imported or executed.
- `benchmarks/`: 9 intentionally vulnerable samples (sqli-001..003, creds-001..003, deser-001..003), `manifest.json` and a README. All credentials are fake (`fake-benchmark-*`).
- 155 new unit tests in 6 files, plus shared factories in `tests/unit/conftest.py`.

**Verified**
- `uv run pytest`: 199 passed. That is the 44 original M0 config tests plus 155 new ones.
- One test runs a sample whose code would write a marker file if executed, and confirms the file is never created.

**Open items**
- The expected Bandit rule IDs and lines in `manifest.json` have not yet been checked against Bandit. M2 does this.
- The benchmark has no safe ("negative") samples yet, so false positives can't be measured. Planned for M7.
- Patches currently record the replaced code (`original_code`) but not its line span. The span comes from the finding's `AstContext`. M3 may add an explicit span if applying patches needs it.
