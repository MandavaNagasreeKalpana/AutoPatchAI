# AutoPatch AI

**An AST-aware multi-agent framework for automated security vulnerability remediation in Python projects.**

> **Status: early development (Milestone M0, project scaffold).**
> Only the configuration module and its tests exist so far. None of the agents,
> the orchestrator, the API or the UI are implemented yet. See
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
| Scanner | Run Bandit, map findings to categories, extract AST context | Not implemented |
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
| Tests | pytest | Yes |
| Static security analysis | Bandit | Planned (M2) |
| LLM | Groq API | Planned (M3) |
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
exact versions recorded in `uv.lock` (runtime plus the `dev` group). Nothing is
installed into your global Python.

## Configuration

Copy the template and edit it locally. `.env` is git-ignored.

```powershell
Copy-Item .env.example .env
```

| Variable | Default | Valid values | Notes |
|---|---|---|---|
| `GROQ_API_KEY` | *(unset)* | any | Only required when an LLM operation runs. Never printed or logged. |
| `GROQ_MODEL` | *(unset)* | a Groq model ID | No model is hardcoded; required for LLM operations. |
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

## Running tests

```powershell
uv run pytest
```

Tests need no Groq key and no network access.

## Development status

| Milestone | Scope | Status |
|---|---|---|
| M0 | Project scaffold, configuration, tests | Done |
| M1 | Data models + vulnerable test set | Not started |
| M2 | Scanner Agent | Not started |
| M3 | Patch Generator Agent | Not started |
| M4 | Verification Agent (Docker) | Not started |
| M5 | Orchestrator, Documentation Agent, CLI | Not started |
| M6 | FastAPI backend + Streamlit UI | Not started |
| M7 | Evaluation and baselines | Not started |
| M8 | Final documentation | Not started |

See [docs/stage-log.md](docs/stage-log.md) for a record of each stage.
