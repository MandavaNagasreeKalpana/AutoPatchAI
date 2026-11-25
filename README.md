# AutoPatch AI

**An AST-aware multi-agent framework for automated security vulnerability remediation in Python projects.**

> **Status: early development (Milestone M3B complete).**
> Implemented so far: configuration, shared data models, a small seed benchmark,
> the **Scanner Agent** with its `autopatch scan` CLI, the **Groq client**
> (`autopatch/llm/`), and the **Patch Generator Agent** (`autopatch/patch_generator/`),
> which produces **unverified candidate patches only**. The Verification and
> Documentation agents, the orchestrator, the API and the UI are not implemented
> yet. See [Development status](#development-status).

## Overview

AutoPatch AI aims to:

1. Scan Python source code for security vulnerabilities with a SAST tool (Bandit).
2. Locate the affected code and gather context with Python's `ast` module.
3. Give that context to an LLM (via the Groq API) to generate a minimal, secure candidate patch.
4. Verify each patch with syntax checks, the project's tests (inside an isolated Docker sandbox) and a repeat security scan.
5. Feed failures back to the generator for refinement, up to a bounded number of retries.
6. Produce a reviewable report and patch file.

Patches are **never applied or merged automatically**. A human reviews every change.

Initial vulnerability categories: **SQL injection**, **hardcoded credentials** and
**insecure deserialization**. The design keeps categories in a registry so more can be added.

## Architecture (planned)

```
Streamlit UI ──HTTP──> FastAPI ──> Orchestrator
                                      │
     ┌──────────────┬─────────────────┼─────────────────┬──────────────────┐
  Scanner Agent   Patch Generator    Verification Agent   Documentation Agent
  Bandit + AST    Groq LLM           syntax, Docker tests, report + .patch file
  context                            security rescan
                        ▲                    │
                        └── failure feedback ┘  (bounded retries)
```

| Agent | Responsibility | Status |
|---|---|---|
| Scanner | Run Bandit, map findings to categories, extract AST context | **Implemented (M2)** |
| Patch Generator | Build prompts, call Groq, validate the returned patch | **Implemented (M3B)**: unverified candidates only |
| Verification | Syntax check, sandboxed tests, Bandit rescan | Not implemented |
| Documentation | Explain the vulnerability, the patch and verification results | Not implemented |
| Orchestrator | Coordinate agents and the retry loop | Not implemented |

## Technology stack

| Purpose | Technology | In use yet? |
|---|---|---|
| Language | Python ≥ 3.11 | Yes |
| Environment / dependencies | [uv](https://docs.astral.sh/uv/) | Yes |
| Configuration | python-dotenv | Yes |
| Data models / validation | Pydantic v2 | Yes |
| Tests | pytest | Yes |
| Static security analysis | Bandit (Python API) | Yes |
| LLM | Groq API (official `groq` SDK) | Yes, used by the Patch Generator (M3B) |
| Isolated verification | Docker | Planned (M4) |
| Backend API | FastAPI | Planned (M6) |
| User interface | Streamlit | Planned (M6) |

## Setup

Requirements: Python 3.11+, [uv](https://docs.astral.sh/uv/getting-started/installation/), Git.
Docker Desktop will be needed from Milestone M4.

```powershell
git clone <repo-url> autopatch-ai
cd autopatch-ai
uv sync
```

`uv sync` creates a project-local virtual environment in `.venv/` and installs the
exact versions recorded in `uv.lock` (runtime plus the `dev` group), including
Bandit and the `autopatch` command. Nothing is installed into your global Python.

## Configuration

Copy the template and edit it locally. `.env` is git-ignored.

```powershell
Copy-Item .env.example .env
```

| Variable | Default | Valid values | Notes |
|---|---|---|---|
| `GROQ_API_KEY` | *(unset)* | any | Only required when an LLM operation runs. Never printed or logged. |
| `GROQ_MODEL` | *(unset)* | a Groq model ID | No model is hardcoded; required for LLM operations. |
| `AUTOPATCH_LLM_TIMEOUT` | `60` | integer 1–600 (seconds) | Timeout for each Groq request. |
| `AUTOPATCH_LLM_MAX_RETRIES` | `2` | integer 0–5 | Retries for transient Groq failures only. |
| `AUTOPATCH_MAX_RETRIES` | `3` | integer 0–10 | Extra patch attempts after a failed verification. |
| `AUTOPATCH_SANDBOX_IMAGE` | `autopatch-sandbox:latest` | image name, no spaces | Docker image for running tests. |
| `AUTOPATCH_SANDBOX_TIMEOUT` | `120` | integer 1–3600 (seconds) | Per-run sandbox timeout. |
| `AUTOPATCH_ALLOW_HOST_EXEC` | `false` | true/false, 1/0, yes/no, on/off | Keep `false`. Allows running untrusted code on the host. |

Real environment variables take precedence over `.env`. Invalid values raise a
`ConfigError` that names the variable and the allowed range.

```python
from autopatch.config import load_settings

settings = load_settings()        # never makes a network request
print(settings)                   # API key shown only as <set> / <not set>
api_key, model = settings.require_llm()  # raises MissingLLMConfigError if unset
```

## Groq LLM client (M3A)

`autopatch/llm/` holds a small Groq chat-completion client. The Patch Generator
(M3B) uses it. The scanner does not.

### Local setup (your own key, never committed)

1. Create a Groq account and an API key in your own Groq console.
2. Create your **own local** `.env` file from the template. `.env` is
   git-ignored and must never be committed.
   ```powershell
   Copy-Item .env.example .env
   ```
3. Open `.env` in your editor and set `GROQ_API_KEY` and `GROQ_MODEL` (a model
   available to your account; for JSON output, one that supports JSON mode).
   Don't paste the key anywhere else: not in code, docs, issues or chat.
4. Check the configuration without printing the key:
   ```powershell
   uv run python -c "from autopatch.config import load_settings; print(load_settings())"
   ```
   The key is shown only as `<set>` or `<not set>`.

### Usage

```python
from autopatch.llm import GroqClient

client = GroqClient.from_env()  # reads .env; raises MissingLLMConfigError if unset
reply = client.chat([{"role": "user", "content": "Say hello."}])
print(reply.content, reply.usage.total_tokens)

result = client.chat_json(
    [{"role": "user", "content": "Return a JSON object with a 'status' field."}],
    schema=MyPydanticModel,  # optional
)
print(result.data, result.parsed)
```

### Behaviour

- **Configuration:**
  - `GROQ_API_KEY` and `GROQ_MODEL` are required only when a client is created,
    and nothing contacts Groq until you call `chat` or `chat_json`.
  - The model always comes from `GROQ_MODEL`. The client **never switches
    model or provider**.
- **JSON mode:**
  - `chat_json` sends `response_format={"type": "json_object"}`, and the prompt
    must mention JSON.
  - The reply must be one valid JSON object: no markdown fences, no NaN, no
    duplicate keys. With `schema`, it is also validated.
  - Invalid, empty or truncated output raises an error. It is never accepted
    silently.
  - If the model rejects JSON mode, `LLMUnsupportedFeatureError` says so and
    nothing else is tried.
- **Errors:** each failure raises its own exception class, listed in the table
  below.
- **Retries:**
  - At most `AUTOPATCH_LLM_MAX_RETRIES` retries, with exponential backoff and
    jitter (capped at 30 s).
  - Rate-limit retries honour `Retry-After`.
  - The SDK's own retries are disabled, so attempts are never doubled.
- **Stops immediately when:** the server asks to wait more than 30 s, or the
  error looks like an exhausted daily quota.
- **No paid fallback.**
- **Safety:**
  - Error messages are length-limited and redacted: the configured key, secret
    env values, token formats and `Authorization` headers are removed.
  - The original SDK exception, which holds the request headers, is not
    chained.
  - **AutoPatch's own logger** (`autopatch.llm`) records only metadata: the
    error type, HTTP status, retry wait and attempt number. It never logs
    prompts, model responses, request headers or API keys.
  - **The Groq SDK's own logging is separate.** When DEBUG logging is enabled
    (for example `logging.basicConfig(level=logging.DEBUG)`, or the
    environment variable `GROQ_LOG=debug`), the SDK's `groq._base_client`
    logger writes request options, **including the prompt messages**. An
    audit with DEBUG enabled found no API key or `Authorization` header in
    those logs, but prompt content was present.
  - Don't enable DEBUG or `GROQ_LOG=debug` when handling sensitive source code,
    and keep the default logging level (INFO or higher) for real projects.
    AutoPatch does not claim that every log is free of prompt content.
  - Prompts over 60,000 characters are refused locally, so whole files or
    repositories can't be sent by accident.

| Exception | When | Retried? |
|---|---|---|
| `MissingLLMConfigError` | key or model not configured | – (raised before any request) |
| `LLMAuthenticationError` | HTTP 401 / 403 | No |
| `LLMRateLimitError` | HTTP 429 (`quota_exhausted=True` for daily limits) | Short waits only |
| `LLMTimeoutError` | request timed out / HTTP 408 | Yes |
| `LLMConnectionError` | network failure | Yes |
| `LLMServerError` | HTTP 5xx | Yes |
| `LLMInvalidRequestError` | HTTP 400/404/422, oversized or invalid prompt | No |
| `LLMUnsupportedFeatureError` | model rejected JSON mode | No |
| `LLMEmptyResponseError` / `LLMResponseError` | empty or malformed response | No |
| `LLMStructuredOutputError` | invalid/truncated JSON, schema mismatch | No |

## Code layout: one folder per agent

Each agent's code lives only in its own folder, so it can be developed and
debugged on its own. Code used by more than one agent lives outside them, and
an agent never imports from another agent's folder.

```
autopatch/
├─ scanner/           Agent 1: Scanner Agent (Bandit + AST)
├─ patch_generator/   Agent 2: Patch Generator Agent (Groq)
├─ verification/      Agent 3: Verification Agent (planned)
├─ documentation/     Agent 4: Documentation Agent (planned)
├─ common/            shared: source parsing (source.py), secret redaction (sensitive.py)
├─ models/            shared data models (Finding, Patch, ScanResult, ...)
├─ llm/               shared Groq client
├─ config.py, redaction.py, benchmark.py, cli.py
```

Tests follow the same names: `tests/unit/test_scanner_*.py`,
`tests/unit/test_patch_generator_*.py`, and
`tests/integration/test_scanner_to_patch_generator_*.py` for the hand-off
between the two agents.

## Patch Generator Agent (M3B)

> ⚠️ **Generated patches are UNVERIFIED candidates.** They are never applied to
> your project, never written to disk, and never executed. A later Verification
> Agent (M4) and a human reviewer must check every patch before it is used.

```
autopatch/patch_generator/
├─ context.py  validate inputs; bounded, redacted, line-numbered source context
├─ prompts.py  system rules + untrusted-data prompt with a random delimiter
├─ secrets.py  finds hardcoded credential literals by rule (B105/B106/B107), AST only
├─ schema.py   PatchProposal (LLM JSON contract), PatchCandidate (report-safe),
│              PatchedSource (execution-only), PatchGeneration (the pair)
├─ diff.py     strict single-file unified-diff parser; in-memory application
├─ safety.py   AST-only checks: syntax, dangerous references, dependencies, category checks
├─ agent.py    PatchGeneratorAgent: context -> prompt -> Groq -> diff -> checks -> Patch
└─ errors.py   PatchGenerationError and its subclasses
```

### Usage

```python
from pathlib import Path
from autopatch.config import load_settings
from autopatch.patch_generator import PatchGeneratorAgent
from autopatch.scanner import ScannerAgent

scan = ScannerAgent().scan("path/to/project")
finding = scan.findings[0]
source = (Path(scan.project_root) / finding.file_path).read_text(encoding="utf-8")

agent = PatchGeneratorAgent.from_settings(load_settings())  # reuses the M3A GroqClient
result = agent.generate(finding, source)                     # nothing is written or run

candidate = result.candidate          # REPORT-SAFE: may be serialized and stored
print(candidate.patch.unified_diff)   # M1 Patch, status "generated" (redacted view)
print(candidate.verified)             # always False at this stage

holder = result.patched_source        # EXECUTION-ONLY: real patched file, in memory
```

The agent receives the finding and the file's text from the caller and never
reads or writes files itself.

**Two outputs, kept apart on purpose:**

- **`result.candidate`** (`PatchCandidate`) is report-safe.
  - It contains the M1 `Patch`, the validated proposal, warnings and token usage.
  - For credential findings, the `Patch` code and diff show the **redacted** view
    the model saw.
  - It contains no real source, so `dataclasses.asdict`, `pickle` and Pydantic
    serialization are safe. Its `repr` shows identifiers and status only.
- **`result.patched_source`** (`PatchedSource`) holds the **real** patched file:
  unchanged lines are restored, so it may include other real secrets from the
  file.
  - It is meant only for the in-memory hand-off to the Verification Agent (M4),
    which will read it with `holder.reveal_for_verification()` and place it in
    its isolated sandbox.
  - It has no `__dict__`, cannot be changed, and its `repr` shows only the patch
    ID, the file and a character count.
  - Copying it, pickling it, or Pydantic serialization raises
    `SourceSerializationError`.
  - The whole `PatchGeneration` therefore also refuses `dataclasses.asdict` and
    pickling. Only persist `result.candidate`.

### How a candidate is produced

1. **Context:**
   - The finding and source are validated.
   - A stale source is detected by comparing the finding's snippet with the file.
   - The model sees only the finding's AST span (plus 3 lines on each side) and
     the module's import header, with real line numbers. Nothing else in the
     repository is sent.
   - Context over 200 lines or 24,000 characters is **rejected, never truncated**.
2. **Redaction before sending** (positions and line endings preserved; only
   string literals and comments are ever rewritten, never identifiers):
   - **Credential findings:** the actual credential literal is chosen by rule:
     - B105: the value assigned to the secret-looking variable
     - B106: the value of the secret-looking keyword argument
     - B107: the default value of the secret-looking parameter

     Ordinary values on the same line, such as `username="admin"` or a base
     URL, stay visible.
   - **Fallback:** only if the credential can't be identified is every literal
     on the flagged lines masked. The candidate then carries a warning, and
     removal of the credential is not checked locally.
   - **Any category:**
     - literals bound to secret-looking names (`password`, `token`, `api_key`,
       …) anywhere in the file
     - any other literal equal to a masked secret
     - known token formats and secret environment values inside strings and
       comments
     - comments and docstrings that state a credential (`password: …`)
   - **Fails closed:** if a credential finding has nothing to mask, or a masked
     value still appears as a standalone value in the prompt, the request is
     refused.
3. **Prompt:**
   - Source code, reviewer guidance **and all source-derived metadata** go inside
     delimiters carrying a random per-request nonce. That metadata is the file
     path, rule ID, enclosing scope and scanner description, each reduced to a
     single line with control and line-separator characters removed and a
     length limit.
   - The nonce is regenerated if any of that text contains it.
   - Outside the blocks are only the validated finding ID, the category enum and
     line numbers.
   - The model must copy the file path from the block into the diff headers.
     Validation enforces the exact path.
   - The system rules tell the model to ignore instructions in the code, fix
     only this finding, keep unrelated behaviour, follow the category guidance
     (parameterized SQL, environment-based secrets, safe deserialization), never
     add `eval`/`exec`/shell calls, declare any new dependency, never claim the
     patch is verified, and return JSON only.
4. **Structured output:** the model must return a `PatchProposal`: finding ID,
   category, vulnerability summary, rationale, unified diff, security
   improvements, assumptions, limitations, new dependencies and a self-estimated
   confidence. Unknown keys, a wrong finding or category, and empty or invalid
   JSON are all rejected.
5. **Diff validation (in memory):**
   - It must be exactly one file, and the path must equal the finding's file.
     Absolute paths, `..`, `/dev/null`, and create/delete/rename/mode/binary
     changes are rejected.
   - Hunk headers must be well formed and their line counts must match.
   - Hunks must be ordered and non-overlapping.
   - Empty and no-op diffs are rejected.
   - Every hunk's context and removed lines must match the source exactly,
     ignoring only trailing whitespace.
   - **Tolerances** (deliberate):
     - The hunk is looked for at its declared `-OLD_START` line, otherwise at the
       nearest unique position within **20 lines**.
     - `+NEW_START` is **not checked**.
     - A bare empty line inside a hunk counts as an empty context line.
     - The original end-of-file state is kept, so a file without a final newline
       still has none.
   - Only lines shown to the model may change.
   - The redaction placeholder may not appear in added lines.
6. **Static checks** (`ast.parse` only, never executed). These are defence in
   depth, not proof of safety. Counts are compared before and after, so existing
   code elsewhere in the file is not blamed on the patch.
   - The patched file must be valid Python.
   - **No new dangerous references.** These are references, not only calls, and
     aliases count:
     - `eval`, `exec`, `compile`, `__import__`, `__builtins__`,
       `builtins.__dict__`
     - `os.system`, `popen`, `startfile`, `exec*`, `spawn*`
     - `subprocess.*`, `asyncio.create_subprocess_*`
     - `importlib.import_module`, `runpy.*`
     - pickle, dill, marshal and shelve loaders, and `yaml.load` with an unsafe
       Loader
     - `getattr` with a dangerous or computed attribute name
     - `shell=True`
     - star imports from dangerous modules
   - New third-party imports must be declared in `new_dependencies`.
   - **Credentials (any category):** no new hardcoded string bound to a
     secret-looking variable, keyword argument or parameter default.
   - **Credential findings:** the flagged credential value must be gone.
   - **Deserialization findings:** the flagged unsafe call's count must drop.
     Unrelated unsafe calls elsewhere in the file are not penalised.
7. **Result:**
   - A `PatchGeneration`: a report-safe `candidate` whose `Patch` has status
     `generated` and a locally regenerated canonical diff, plus the
     execution-only `patched_source`.
   - Text where the model claims the patch is verified or guaranteed safe is
     reported as a warning and ignored.

**Errors** are subclasses of `PatchGenerationError`:
- **Inputs:** `InvalidFindingError`, `InsufficientContextError`,
  `SourceMismatchError`, `ContextTooLargeError`, `RedactionError`
- **LLM:**
  - `PatchLLMError` carries `llm_error`, `retryable`, `quota_exhausted` and
    `status_code`. There is no fallback model or provider.
  - `MalformedPatchResponseError`
- **Diff:** `DiffFormatError`, `DiffPathError`, `MultiFileDiffError`,
  `EmptyDiffError`, `NoOpDiffError`, `DiffHunkError`, `DiffApplyError`,
  `DiffScopeError`
- **Patched code:** `PatchSyntaxError`, `UnsafePatchError`

Error messages contain no source code, raw model output or secrets, and no
library exception is chained. Logs (`autopatch.patch_generator`) record only IDs, rule,
line counts and error types.

### Limitations

- **Not checked yet:** the generator does not run tests or rescan with Bandit.
  That is the Verification Agent's job (M4). A candidate can be syntactically
  valid and still wrong.
- **The dangerous-reference deny-list is defence in depth, not proof of safety.**
  - It catches the common patterns and aliases above.
  - Deeper dynamic tricks are not caught, for example
    `globals()["ev" + "al"]`, `type(x).__subclasses__()`, `ctypes`, or code
    hidden in a new helper module.
  - Some safe code is also rejected (false positives):
    - `getattr` with a computed name
    - a new absolute import of a project-local module, which is treated as an
      undeclared dependency
    - a new keyword such as `secret_name="db/password"`, which is treated as a
      hardcoded credential
- **Category checks are partial.**
  - A literal hidden in an expression, such as `os.getenv("X") or "fallback"`,
    is not seen as a new hardcoded credential.
  - SQL injection has no local category check; the M4 rescan must confirm that
    fix.
- **Redaction is heuristic.** It covers:
  - rule-specific credential literals
  - literals bound to secret-looking names
  - known token formats and secret environment values in strings and comments
  - comments and docstrings that state a credential (`password: …`)

  An unusual secret elsewhere in the shown code, such as a free-form comment
  without a keyword, could still be sent. Secrets shorter than 4 characters are
  masked wherever they appear as a literal, but are not checked by substring
  search.
- **A real secret that also appears as an identifier or in the prompt text** (for
  example a password equal to a function name) makes the leak check fail closed.
- **Only lines shown to the model may change.** A fix that needs an import far
  below a long module header (over 40 lines), or changes elsewhere in the file,
  is rejected.
- **`PatchedSource` refuses copying and pickling**, so it cannot be sent to
  another process. M4 must use it in-process.
- **Confidence** is the model's own estimate, not a measurement.
- **No live check yet:** real model behaviour has not been tested against Groq.
  All tests use mocked responses.

## Data models

All agents exchange immutable, validated Pydantic models (`autopatch/models/`).
Unknown fields are rejected, and validation never touches the filesystem or
runs code.

| Module | Models | Purpose |
|---|---|---|
| `enums.py` | `VulnerabilityCategory`, `Severity`, `PatchStatus`, `VerificationStatus`, `CATEGORY_INFO` | Shared vocabularies. Values are case-insensitive (Bandit's `HIGH` becomes `high`). Each category has a display name and CWE IDs. |
| `common.py` | `ProjectPath`, `Identifier`, `Confidence`, … | Reusable checked types (see the rules below) |
| `finding.py` | `Finding`, `AstContext` | A vulnerability found by the scanner, plus the code span a patch may replace |
| `patch.py` | `Patch` | A proposed fix: original and proposed code, unified diff, model name, timestamp, confidence, assumptions, status, attempt number |
| `verification.py` | `VerificationResult`, `CheckResult`, `RescanResult` | Results of the syntax check, unit tests and security rescan, plus an overall status |
| `report.py` | `RemediationReport` | Findings, patches and verifications for one project, with links between them checked |
| `benchmark.py` | `BenchmarkManifest`, `BenchmarkSample` | Schema for `benchmarks/manifest.json` |
| `scan.py` | `ScanResult`, `IgnoredIssue`, `SkippedFile` | Output of one Scanner Agent run (M2) |

Validation rules:
- **Project paths** must be relative to the project. Absolute paths (POSIX or
  Windows), drive letters, UNC paths, `..` components, `:` and control
  characters are all rejected. `\` is converted to `/`.
- **Identifiers** are 1–128 characters from `[A-Za-z0-9._:-]` and must start
  with a letter or digit. They are generated automatically when omitted.
- **Confidence** is between 0 and 1 inclusive. NaN and infinity are rejected.
- **Line numbers** start at 1, `end_line` must be at least `line`, and a
  finding's `ast_context` span must contain its lines.
- **Timestamps** must include a timezone (UTC by default).
- **Patches** must actually change the code. Every `---`/`+++` path in the diff
  must be safe and equal to `target_file`.
- **Verification:**
  - If `overall_status` is omitted, it is worked out from the three checks:
    `failed` if any check failed, otherwise `error` if any errored, otherwise
    `unverified` if any was skipped, otherwise `passed`.
  - A given `overall_status` that contradicts the checks is rejected.
  - A failure or error must come with `failure_details`.
  - A `passed` rescan needs `target_finding_resolved=True` and no new findings.
- **Reports** reject:
  - duplicate IDs
  - patches that point to an unknown finding or a different file than their finding
  - verifications that point to an unknown patch
  - patches marked `verified` without a passed verification

## Scanner Agent

```
autopatch/scanner/
├─ file_discovery.py  find *.py files inside the root (skip generated dirs, exclusions, links leaving the root)
├─ bandit_runner.py   run Bandit in-process via its Python API; validate every result
├─ rule_mapping.py    the ONLY place Bandit rule IDs are mapped to categories
├─ ast_context.py     ast.parse -> enclosing function/class span, imports, AST context
├─ scanner.py         ScannerAgent: discovery -> Bandit -> classify -> Finding models -> ScanResult
└─ errors.py          ScannerError types + secret redaction for error messages
```

`ScannerAgent().scan(path)` returns a `ScanResult` (`autopatch/models/scan.py`).
The result holds `findings` (validated M1 `Finding` objects), `related_findings`,
`ignored_issues`, `skipped_files` and `errors`.

### Supported categories and rules

| Category | Bandit rules (Bandit check name) |
|---|---|
| SQL Injection | B608 `hardcoded_sql_expressions` |
| Hardcoded Credentials | B105 `hardcoded_password_string`, B106 `hardcoded_password_funcarg`, B107 `hardcoded_password_default` |
| Insecure Deserialization | B301 `pickle` (pickle/dill), B302 `marshal`, B506 `yaml_load` |
| *Related (informational, never patched)* | B403 `import_pickle` |

Every other Bandit rule is listed under `ignored_issues` and never given one of
these categories. **B303–B306 are deliberately not mapped.** In Bandit they are
`md5` (weak hashes), `ciphers`, `cipher_modes` (ECB) and `mktemp_q` (temporary
files), none of which is deserialization. A test checks every mapped ID against
the installed Bandit.

Each finding includes:
- a stable ID (a hash of path, rule, line and column)
- category, severity (Bandit's level, lower-cased)
- confidence: Bandit's LOW/MEDIUM/HIGH mapped to 0.3/0.6/0.9
- project-relative path and line range
- the Bandit description, plus a category explanation
- a code snippet (at most 20 lines)
- `AstContext`: the innermost enclosing function or class of at most 150 lines
  (otherwise the innermost statement), its qualified name, the enclosing class,
  and the module imports

### Safety

- **Read-only.** Files are only read as bytes. They are never written, imported,
  compiled to bytecode or executed. Bandit and `ast.parse` only build syntax
  trees. No subprocess is used.
- **Stays inside the root.**
  - Default generated directories are skipped: `.git`, `.venv`, `__pycache__`,
    `.pytest_cache`, `node_modules`, `build`, `dist`, `*.egg-info` and similar.
  - Symlinked directories are not followed.
  - Symlinked files are skipped.
  - Anything that resolves outside the root, including Windows junctions, is
    refused.
  - Bandit results for files that weren't selected for scanning are rejected.
- **Secrets.**
  - For credential findings, string literals on the flagged lines are replaced
    with `"***REDACTED***"` in the snippet and context.
  - Bandit's message, which quotes the secret, is shortened to its prefix.
  - Error messages are length-limited and scrubbed of secret-looking
    environment variable values and token formats.

### CLI

```powershell
uv run autopatch scan benchmarks --output reports/findings.json
uv run autopatch scan path\to\project --exclude tests --exclude "legacy/*"
uv run autopatch scan path\to\project --fail-on-findings
```

| Exit code | Meaning |
|---|---|
| 0 | Scan completed: zero findings, or findings without `--fail-on-findings` |
| 1 | Scan completed with supported findings and `--fail-on-findings` was given |
| 2 | Operational error: missing directory, Bandit missing or crashing, malformed results, or the report couldn't be written |

The summary always prints `Supported findings: N`. A clean scan ends with
`Result: no supported vulnerabilities found. The scan completed successfully.`,
while failures print `ERROR: ...` to stderr and exit with 2. `--output` must be a
`.json` file and can never overwrite a scanned source file.

### Limitations

- **Bandit's patterns only.**
  - Detection is limited to what Bandit's syntax patterns catch. There is no
    data-flow or taint analysis, so B608 flags string-built SQL whether or not
    the input is attacker-controlled.
  - Credential checks depend on Bandit's variable-name patterns, so a name
    like `api_key = "..."` is **not** flagged.
- **Confidence numbers** are fixed placeholders, not calibrated probabilities.
- **Redaction is broad and partial.**
  - It masks every string literal on the flagged lines, including harmless ones
    like a username or URL.
  - Credentials elsewhere in the file are not redacted.
  - Because of the masking, `AstContext.source` for credential findings is not
    the exact file text. The Patch Generator will need to read the original
    span from disk.
- **Unparseable files.** Files with syntax errors are reported as skipped. A
  finding in a file that `ast` can't parse has no `ast_context`.
- **`# nosec`.** Lines marked `# nosec` are respected unless `--ignore-nosec` is
  given.
- **Symlink tests.** On Windows without symlink privilege, the real symlink
  tests are skipped. Junction and mocked tests cover the same protection.

## Benchmark

`benchmarks/` holds a **small, hand-written seed set** of 9 intentionally
vulnerable snippets (3 per category), used as test fixtures. It is not a
comprehensive or real-world dataset. See [benchmarks/README.md](benchmarks/README.md).

```
benchmarks/
├─ manifest.json        # sample ID, category, description, file, expected CWE / rule IDs / lines
└─ samples/<category>/<sample>/app.py
```

`autopatch.benchmark.load_manifest()` validates the manifest, and
`check_sample_files()` checks that each file exists, parses with `ast.parse`, and
has the expected lines. Sample files are never imported or executed.

## Running tests

```powershell
uv run pytest
```

Tests need no Groq key and no network access, and never run benchmark samples.
The Groq tests use mocked responses (a fake SDK, or the real SDK over
`httpx.MockTransport`). Real HTTP transport is blocked during those tests.
`tests/unit/` mocks Bandit where useful. `tests/integration/` runs the real
Bandit on the benchmark fixtures and the CLI.

## Development status

| Milestone | Scope | Status |
|---|---|---|
| M0 | Project scaffold, configuration, tests | Done |
| M1 | Data models + seed benchmark | Done |
| M2 | Scanner Agent + `autopatch scan` CLI | Done |
| M3A | Groq client (standalone) | Done |
| M3B | Patch Generator Agent (unverified candidates) | Done |
| M4 | Verification Agent (Docker) | Not started |
| M5 | Orchestrator, Documentation Agent, CLI | Not started |
| M6 | FastAPI backend + Streamlit UI | Not started |
| M7 | Evaluation and baselines | Not started |
| M8 | Final documentation | Not started |

See [docs/stage-log.md](docs/stage-log.md) for a record of each stage.
