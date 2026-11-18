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

## M2 (2026-11-18): Scanner Agent

**Goal:** turn Bandit + AST analysis into validated M1 `Finding` objects, safely and read-only. No patching, Groq, API or UI.

**Dependency added:** `bandit>=1.8,<2`, locked at 1.9.4, which brings in PyYAML, stevedore and rich. It is installed only in `.venv`.

**Built**
- `autopatch/scanner/`:
  - `file_discovery.py`: recursive `*.py` discovery with default generated-directory exclusions and glob `--exclude` patterns. It never follows symlinked directories, skips symlinked files, and refuses anything that resolves outside the root (including Windows junctions).
  - `bandit_runner.py`: runs Bandit in-process through `BanditManager` on exactly the discovered files, with no subprocess and no Bandit file discovery. Every result is validated (`parse_issue`), and malformed results are collected instead of crashing. A missing Bandit raises `BanditNotInstalledError`. Bandit crashes are wrapped with secret-redacted messages.
  - `rule_mapping.py`: the single rule→category table, plus the related rule B403, the excluded rules with reasons, confidence scores and category explanations.
  - `ast_context.py`: decodes source per PEP 263 and parses it with `ast.parse` only. It finds the innermost function or class of at most 150 lines (otherwise the innermost statement), qualified names, decorators, imports and bounded snippets, and handles syntax errors and NUL bytes. It also redacts string literals for credential findings.
  - `scanner.py`: `ScannerAgent` builds `Finding`s with deterministic IDs, puts B403 in `related_findings` and other rules in `ignored_issues`, and rejects results for files that weren't selected.
- `autopatch/models/scan.py`: `ScanResult`, `IgnoredIssue`, `SkippedFile`.
- `autopatch/benchmark.py`: `compare_scan_to_manifest()` gives per-sample detection outcomes.
- `autopatch/cli.py` + `[project.scripts]`: `autopatch scan <dir> [-o file.json] [-e GLOB] [--ignore-nosec] [--fail-on-findings]`. Exit codes: 0 completed, 1 findings with `--fail-on-findings`, 2 operational error.

**Decision: B303–B306 are not mapped.** The M2 spec listed them under insecure deserialization. In Bandit 1.9.4 they are `md5`, `ciphers`, `cipher_modes` and `mktemp_q`, so mapping them would misclassify unrelated findings. `test_b303_to_b306_are_not_deserialization` records this against the installed Bandit. B614 (`pytorch_load`) is a real deserialization rule in Bandit 1.9.4 and is a candidate to add later with approval.

**Benchmark validation (real Bandit 1.9.4)**
- All 9 samples were detected with the expected rule and line, with no unexpected supported findings and no unsupported rules firing.
- B403 was reported as related for deser-001 line 6.
- No manifest expectations changed. Only the manifest's description sentence was updated to say the expectations are confirmed.

**Verified**
- `uv run pytest`: 341 passed, 3 skipped. The 3 skips are real-symlink tests that need privileges this Windows account lacks. Junction and mocked tests cover the same protection.
- Read-only: benchmark file hashes and mtimes were unchanged after the scan, and the scan opened no file in a write mode. No `__pycache__` appeared, no sample was imported, and a file with marker-writing top-level code was scanned without running.
- No `fake-benchmark-*` credential appears in any scan output.

**Open items**
- `AstContext.source` is redacted for credential findings, so M3 must read the original span from disk to build `Patch.original_code`.
- There is no data-flow analysis, and Bandit's credential name patterns miss names like `api_key`.

## M3A (2026-11-18): Groq API integration (standalone client)

**Goal:** a safe, tested Groq chat-completion client for the future Patch Generator. It is not connected to the scanner or any agent, and generates no patches.

**Dependency added:** `groq>=1.0,<2`, the official SDK, locked at 1.7.0. It brings in httpx 0.28.1, anyio, distro and certifi, and is installed only in `.venv`.

**Built**
- `autopatch/config.py`: new `AUTOPATCH_LLM_TIMEOUT` (default 60, range 1–600 s) and `AUTOPATCH_LLM_MAX_RETRIES` (default 2, range 0–5), also shown in `safe_dict()`. Existing settings and behaviour are unchanged.
- `autopatch/redaction.py`: one shared redaction helper, now used by both the scanner and the LLM integration. `scanner/errors.py` re-exports the same function objects (`redact_secrets`, `safe_error_message`, `REDACTED`), so existing scanner imports and call signatures still work.
  - **Preserved:** all M2 redaction (secret-looking environment values, and Groq/OpenAI/AWS/GitHub token formats). `safe_error_message` output is identical for the same input.
  - **Stricter:** `Authorization` header values are now also masked, including quoted dict/JSON forms such as `{'Authorization': 'Bearer …'}`. This applies to scanner error messages too, so scanner redaction changed in this one additive way: it masks more, never less. A side-by-side check of the M2 and M3A helpers on the same inputs matched in every case except the two `Authorization` examples.
  - **New:** an `extra_secrets` parameter, so the LLM client can remove the configured key even when it came from `.env` rather than the process environment.
- `autopatch/llm/`:
  - `errors.py`: the `LLMError` hierarchy, each class with a `retryable` flag.
  - `types.py`: `ChatMessage`, `ChatResult` (content, model, finish reason, token usage, attempts, latency) and `TokenUsage`, plus a 60,000-character prompt limit.
  - `structured.py`: `parse_json_object` (strict: no fences, NaN or duplicate keys; the top level must be an object) and `validate_json`, which validates against a Pydantic schema and never echoes values in errors.
  - `client.py`: `GroqClient` with `chat()` and `chat_json()`.
    - The SDK's own retries are off (`max_retries=0`), and the wrapper owns a bounded retry loop.
    - Retry-After is honoured, up to a 30 s maximum wait.
    - Backoff is exponential with jitter.
    - An exhausted daily quota stops at once.
    - Errors are translated without chaining the SDK exception.
    - AutoPatch's own `autopatch.llm` logger records only metadata. The Groq SDK's logger can write prompt messages when DEBUG or `GROQ_LOG=debug` is enabled (see the README).

**Verified**
- `uv run pytest`: 424 passed, 3 skipped (the 341 earlier tests plus 83 new ones). The 3 skips are the same Windows symlink-privilege tests as in M2.
- All Groq tests are mocked. A fake SDK raises real `groq` exception objects, and the real `groq.Groq` runs over `httpx.MockTransport`. An autouse fixture makes the real `httpx.HTTPTransport` raise, and a test confirms the guard is active. No API key was needed, and no `.env` exists in the repository.
- Secret checks on all changed and new files found no key patterns. The fake token in a test is assembled at runtime.

**Open items**
- No live Groq call has been made. Real-model behaviour still needs a manual check with your own key:
  - which models support JSON mode
  - the exact 429 and quota messages
- Quota detection is heuristic, based on Groq's message text ("per day", TPD/RPD, "quota"). An unrecognised wording would be treated as an ordinary rate limit, so it is still bounded by retries and the 30 s wait limit.
- There is no streaming, tool calling or async client, because they aren't needed yet.
