# AutoPatch AI

**An AST-aware multi-agent framework for automated security vulnerability remediation in Python projects.**

> **Status: early development (Milestone M3A complete).**
> Implemented so far: configuration, shared data models, a small seed benchmark,
> the **Scanner Agent** with its `autopatch scan` CLI, and a standalone **Groq
> client** (`autopatch/llm/`). The Groq client is not connected to any agent yet.
> The Patch Generator, Verification and Documentation agents, the orchestrator,
> the API and the UI are not implemented yet. See
> [Development status](#development-status).

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
| Patch Generator | Build prompts, call Groq, validate the returned patch | Not implemented |
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
| LLM | Groq API (official `groq` SDK) | Client only (M3A); not yet used by an agent |
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

`autopatch/llm/` holds a small Groq chat-completion client. It is a standalone
building block for the upcoming Patch Generator and is **not connected to the
scanner or any agent yet**.

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
├─ ast_context.py     ast.parse -> enclosing function/class span, imports, snippet, literal redaction
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
| M3B | Patch Generator Agent | Not started |
| M4 | Verification Agent (Docker) | Not started |
| M5 | Orchestrator, Documentation Agent, CLI | Not started |
| M6 | FastAPI backend + Streamlit UI | Not started |
| M7 | Evaluation and baselines | Not started |
| M8 | Final documentation | Not started |

See [docs/stage-log.md](docs/stage-log.md) for a record of each stage.
