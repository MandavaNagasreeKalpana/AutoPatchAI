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

## M3B (2026-11-19): Patch Generator Agent

**Goal:** turn one validated scanner `Finding` plus the file's source text into one **unverified candidate patch**, using the M3A `GroqClient`. Patches are never applied, nothing is written to disk, and generated code is never executed.

**Design decisions**
- **No existing model changed.**
  - A new `PatchProposal` model describes the LLM's JSON contract (summary, rationale, diff, improvements, assumptions, limitations, declared dependencies, self-estimated confidence). This is untrusted output that must be checked before building our own M1 `Patch`.
  - A new `PatchCandidate` dataclass returns the `Patch` together with the proposal, warnings, token usage and the in-memory patched file.
- **Report-safe vs real content.**
  - The model sees a redacted, line-preserving view of the file.
  - Diffs are matched against that view, and every unchanged line is copied from the real file.
  - `Patch` (code, diff) holds the redacted view, so it is safe for reports. `PatchCandidate.proposed_source` held the real patched file in memory. *(Superseded by the audit fixes below: the real file now lives in the execution-only `PatchedSource`.)*
- **No second Groq integration.** The agent accepts any client with `chat_json`. `from_settings()` builds the existing `GroqClient`.

**Built (`autopatch/patcher/`)**
- **`context.py`:**
  - **Input checks:** invalid finding, missing source, unparseable source, missing AST span, finding beyond the end of the file, and a stale source (the snippet doesn't match).
  - **Bounds:** the context is the import header plus the AST span ±3 lines. It may be at most 200 lines and 24,000 characters, and the whole file at most 500,000 characters. Anything larger is rejected, never truncated.
  - **Redaction:** all literals on flagged credential lines, literals bound to secret-looking names, and token formats. If the flagged credential can't be masked, or a masked value survives, it fails closed.
- **`prompts.py`:**
  - System rules covering prompt injection, minimal changes, category-specific remediation, forbidden constructs, dependencies, no verification claims and JSON-only output.
  - Untrusted source and guidance blocks delimited with a per-request random nonce, regenerated if the source contains it.
  - Guidance is limited to 2,000 characters and redacted.
- **`diff.py`:**
  - A strict single-file unified-diff parser covering paths, hunk headers and counts, ordering, empty and no-op diffs, multiple files, and file-level operations.
  - In-memory application with exact matching (trailing whitespace aside), a unique match within 20 lines of the declared position, and line-scope enforcement.
- **`safety.py`:** `ast.parse`-only syntax check, an alias-aware deny-list of dangerous calls (counts may only stay the same or fall), and enforcement that new non-standard-library imports are declared.
- **`agent.py`:** `PatchGeneratorAgent.generate()`.
  - LLM errors are mapped to `PatchLLMError` (retryable and quota flags) and malformed output to `MalformedPatchResponseError`.
  - These errors are raised outside the `except` block, so there is no `__context__`.
  - `LLMStructuredOutputError.raw_content` is never copied.
  - The canonical diff is regenerated with `difflib`, and `Patch.status` is always `generated`.
- **`errors.py`:** 20 domain errors under `PatchGenerationError`.

**Verified**
- `uv run pytest -v`: 582 passed, 3 skipped (424 earlier tests plus 158 new ones). The 3 skips are the usual Windows symlink-privilege tests.
- **New tests:**
  - context: 25
  - prompts: 28
  - diff: 47
  - safety: 19
  - agent: 36
  - benchmark integration: 3 (sqli-001, creds-001, deser-002, using real scanner findings and a mocked LLM)
- **Mocked only:** every Groq interaction uses the real `GroqClient` with a fake SDK, and real httpx transport is blocked.
- **Safety tests:**
  - No file is opened for writing, and no rename, remove, temp-file or `os.system` call happens during generation.
  - `exec` and `eval` are never called, and `compile` is only used AST-only.
  - A patch containing a marker-writing `open(...)` is produced as text and never executed.
- **Secrets:** they never appear in prompts, `Patch` JSON, reprs, logs or error messages, and the raw model output never appears in logs or errors.
- **Scope:** no tracked M0–M3A file and no benchmark sample changed. `git diff --check` and `uv lock --check` passed, and there are no new dependencies.

**Limitations and open items**
- **Not verified:** candidates are not tested or rescanned (M4). A syntactically valid patch can still be functionally wrong or incomplete.
- **Deny-list gaps:** indirect calls such as `getattr`, string-built names or new helper modules are not detected.
- **Redaction is heuristic:** an unusual secret format elsewhere in the shown code could still be sent.
- **Only shown lines can change:** this can reject legitimate fixes that need edits outside the shown context (for example an import below a module header longer than 40 lines).
- **No live Groq run yet:** prompt quality, JSON-mode support and real diff accuracy still need testing with your own key.
- **No refinement loop yet:** `generate()` accepts `guidance` and `attempt`, which the M5 orchestrator will use for retries.

### M3B audit fixes (2026-11-19)

An independent read-only audit returned **APPROVE AFTER SPECIFIC FIXES**. The fixes below are not yet committed.

1. **[High] Credential over-redaction.**
   - **Problem:** on a flagged credential line, every literal was treated as a secret and then replaced anywhere in the shown code, including inside identifiers. For B107 / creds-003, `"admin"` collided with the `admin_login` metadata, so generation always failed. In creds-002, the base URL was treated as a secret.
   - **Fix:**
     - A new `patcher/secrets.py` picks the credential literal by rule: B105 assigned value, B106 keyword value, B107 parameter default.
     - All literals on the flagged lines are masked only as a fallback, which carries a warning.
     - Masking works on AST nodes and on string and comment tokens only, using character offsets, so identifiers are never rewritten and line positions and endings are preserved.
     - The leak check matches standalone values only, never parts of identifiers.
     - Comments and docstrings that state a credential are hidden, and short secrets are masked wherever they appear as a literal.
2. **[Medium] Real source exposed by serialization.**
   - **Problem:** `PatchCandidate.proposed_source` was exposed by `asdict`, pickle, `TypeAdapter` and `vars`.
   - **Fix:**
     - `PatchCandidate` is now purely report-safe.
     - The real file lives in the new `PatchedSource`: `__slots__`, immutable, a repr with counts only, and an explicit `reveal_for_verification()`. Copying, pickling and Pydantic serialization raise `SourceSerializationError`.
     - `generate()` now returns `PatchGeneration(candidate, patched_source)`.
3. **[Medium] Source-derived metadata outside the untrusted block.**
   - **Problem:** the file path, scope, description and rule ID were placed outside the nonce-delimited block.
   - **Fix:**
     - They are now inside the block, each reduced to one line, with control characters and U+2028/2029/0085 removed and a length limit.
     - The nonce-collision check covers the whole block.
     - A path containing line separators is rejected.
     - The diff rules refer to `<FILE>`, and validation still enforces the exact path.
4. **[Medium] Deny-list bypasses and missing category checks.**
   - **Fix:**
     - The check now counts dangerous *references* with alias resolution: `f = eval`, `pickle.loads` held as a value, `__builtins__`, `builtins.__dict__`.
     - It also covers star imports from dangerous modules, `getattr` with dangerous or computed names, `importlib.import_module`, `runpy.*`, `os.startfile`, and `asyncio.create_subprocess_*`.
     - `yaml.load` with a safe Loader is no longer treated as dangerous.
     - New category checks:
       - no new hardcoded string bound to a secret-looking name, in any category
       - credential findings must remove the flagged value
       - deserialization findings must reduce the flagged unsafe call's count, without penalising unrelated calls
5. **[Low] Smaller issues.**
   - **End-of-file newline:** the original end-of-file state is now kept.
   - **`repr(candidate)`:** shows identifiers and status only.
   - **Documentation:** now states that `+NEW_START` is not checked, that hunks may match within 20 lines of their declared position, the deny-list and redaction limitations, and that `PatchedSource` must stay in the same process.

**Verified:** `uv run pytest -v` gives 659 passed and 3 skipped. That is the 424 M0–M3A tests unchanged, plus 235 patcher tests (previously 158).
- **Integration:** all 9 benchmark samples now patch successfully using real scanner findings. For creds-001/002/003, context building succeeds, no `fake-benchmark-*` value reaches the prompt, and ordinary identifiers and values stay visible.
- **Checks:** `git diff --check` and `uv lock --check` passed. No dependencies were added, and no M0–M3A file or benchmark sample changed.
