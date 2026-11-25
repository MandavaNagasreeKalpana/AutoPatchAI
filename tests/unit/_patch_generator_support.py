"""Shared helpers for Patch Generator tests (fake data only, no network)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx

from autopatch.config import Settings
from autopatch.llm import GroqClient
from autopatch.models import Finding, VulnerabilityCategory
from autopatch.common.source import (
    extract_snippet,
    parse_source,
    redact_string_literals,
)
from autopatch.scanner.ast_context import build_context
from autopatch.common.sensitive import REDACT_LITERALS

FAKE_KEY = "test-api-key-not-real-0000"
MODEL = "test-model"
REQUEST = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")

# --- SQL injection -------------------------------------------------------------
SQL_PATH = "app/db.py"
SQL_SOURCE = (
    "import sqlite3\n"
    "\n"
    "\n"
    "def find_user(conn, name):\n"
    "    cursor = conn.cursor()\n"
    "    query = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
    "    cursor.execute(query)\n"
    "    return cursor.fetchone()\n"
)
SQL_DIFF = (
    "--- a/app/db.py\n"
    "+++ b/app/db.py\n"
    "@@ -5,4 +5,4 @@\n"
    "     cursor = conn.cursor()\n"
    "-    query = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
    "-    cursor.execute(query)\n"
    "+    query = \"SELECT * FROM users WHERE name = ?\"\n"
    "+    cursor.execute(query, (name,))\n"
    "     return cursor.fetchone()\n"
)

# --- Hardcoded credentials (fake values) ------------------------------------------
CREDS_PATH = "app/mail.py"
SECRET = "Sup3r-Secret-Value-42"
OTHER_SECRET = "Backup-Token-Value-77"
CREDS_SOURCE = (
    "import smtplib\n"
    "\n"
    f'BACKUP_TOKEN = "{OTHER_SECRET}"\n'
    f'SMTP_PASSWORD = "{SECRET}"\n'
    "\n"
    "\n"
    "def send(body):\n"
    '    with smtplib.SMTP("smtp.example.invalid") as server:\n'
    '        server.login("alerts", SMTP_PASSWORD)\n'
)
CREDS_DIFF = (
    "--- a/app/mail.py\n"
    "+++ b/app/mail.py\n"
    "@@ -1,4 +1,5 @@\n"
    "+import os\n"
    " import smtplib\n"
    " \n"
    ' BACKUP_TOKEN = "***REDACTED***"\n'
    '-SMTP_PASSWORD = "***REDACTED***"\n'
    '+SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]\n'
)

# --- Insecure deserialization -------------------------------------------------------
DESER_PATH = "app/session.py"
DESER_SOURCE = (
    "import base64\n"
    "import pickle\n"
    "\n"
    "\n"
    "def load_session(cookie):\n"
    "    raw = base64.b64decode(cookie)\n"
    "    return pickle.loads(raw)\n"
)
DESER_DIFF = (
    "--- a/app/session.py\n"
    "+++ b/app/session.py\n"
    "@@ -1,7 +1,7 @@\n"
    " import base64\n"
    "-import pickle\n"
    "+import json\n"
    " \n"
    " \n"
    " def load_session(cookie):\n"
    "     raw = base64.b64decode(cookie)\n"
    "-    return pickle.loads(raw)\n"
    "+    return json.loads(raw)\n"
)

CASES = {
    "sql_injection": (SQL_SOURCE, 6, "B608", SQL_PATH, SQL_DIFF),
    "hardcoded_credentials": (CREDS_SOURCE, 4, "B105", CREDS_PATH, CREDS_DIFF),
    "insecure_deserialization": (DESER_SOURCE, 7, "B301", DESER_PATH, DESER_DIFF),
}


def make_finding(
    source: str,
    line: int,
    *,
    category: str = "sql_injection",
    rule_id: str = "B608",
    path: str = SQL_PATH,
    end_line: int | None = None,
    finding_id: str = "finding-test-1",
    with_context: bool = True,
    snippet: str | None = None,
) -> Finding:
    """Build a Finding the same way the scanner does (parse only)."""
    cat = VulnerabilityCategory(category)
    parsed = parse_source(source)
    end = end_line or line
    view = parsed.lines
    if cat in REDACT_LITERALS:
        view, _ = redact_string_literals(parsed, line, end)
    context = build_context(parsed, line, end, view) if with_context else None
    return Finding(
        finding_id=finding_id,
        category=cat,
        severity="medium",
        file_path=path,
        line=line,
        end_line=end,
        rule_id=rule_id,
        description="Test finding.",
        code_snippet=extract_snippet(view, line, end) if snippet is None else snippet,
        ast_context=context,
        confidence=0.6,
    )


def case_finding(category: str) -> tuple[Finding, str, str]:
    source, line, rule, path, diff = CASES[category]
    return make_finding(source, line, category=category, rule_id=rule, path=path), source, diff


def proposal(finding: Finding, diff: str, **overrides) -> dict:
    data = {
        "finding_id": finding.finding_id,
        "category": finding.category.value,
        "vulnerability_summary": "User-controlled data reaches a dangerous sink.",
        "remediation_rationale": "The change removes the unsafe construct.",
        "unified_diff": diff,
        "security_improvements": ["Removes the vulnerable construct."],
        "assumptions": ["Callers pass the same argument types."],
        "limitations": ["Behaviour for malformed input may differ."],
        "new_dependencies": [],
        "confidence": 0.7,
    }
    data.update(overrides)
    return data


def completion(content: str | None, finish_reason: str = "stop"):
    choice = SimpleNamespace(message=SimpleNamespace(content=content), finish_reason=finish_reason)
    usage = SimpleNamespace(prompt_tokens=100, completion_tokens=50, total_tokens=150)
    return SimpleNamespace(id="chatcmpl-test", model=MODEL, choices=[choice], usage=usage)


class FakeSDK:
    """Stands in for groq.Groq; records every request."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def sent_text(self) -> str:
        return "\n".join(m["content"] for call in self.calls for m in call["messages"])


def groq_client(*outcomes, retries: int = 0) -> tuple[GroqClient, FakeSDK]:
    """The real M3A GroqClient wired to a fake SDK (no network)."""
    sdk = FakeSDK(*outcomes)
    settings = Settings(groq_api_key=FAKE_KEY, groq_model=MODEL, llm_max_retries=retries)
    return GroqClient(settings, sdk_client=sdk, sleep=lambda _: None, rng=lambda: 1.0), sdk


def json_reply(data: dict):
    return completion(json.dumps(data))


def status_error(cls, status: int, message: str, headers: dict | None = None):
    body = {"error": {"message": message}}
    response = httpx.Response(status, request=REQUEST, headers=headers or {}, json=body)
    return cls(f"Error code: {status} - {body}", response=response, body=body)
