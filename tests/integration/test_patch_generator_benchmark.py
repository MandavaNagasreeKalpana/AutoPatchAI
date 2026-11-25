"""Patch Generator on real scanner findings for all nine benchmark samples.

Benchmark files are only read. The LLM is a fake that returns a hand-written
correct diff (in the redacted view the model would see), so this checks the
scanner -> patcher hand-off, rule-specific credential redaction, in-memory
application and the static checks on realistic fixtures. Generated code is
never executed and nothing is written.
"""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from autopatch.benchmark import DEFAULT_BENCHMARK_DIR, load_manifest
from autopatch.config import Settings
from autopatch.llm import GroqClient
from autopatch.patch_generator import PatchGeneratorAgent, build_messages, build_patch_context
from autopatch.scanner import ScannerAgent
from autopatch.common.source import parse_source

R = '"***REDACTED***"'


def _header(path: str) -> str:
    return f"--- a/{path}\n+++ b/{path}\n"


DIFFS = {
    "sqli-001": (
        "@@ -9,4 +9,4 @@\n"
        "     cursor = conn.cursor()\n"
        "-    query = f\"SELECT id, username, email FROM users WHERE username = '{username}'\"\n"
        "-    cursor.execute(query)\n"
        "+    query = \"SELECT id, username, email FROM users WHERE username = ?\"\n"
        "+    cursor.execute(query, (username,))\n"
        "     return cursor.fetchone()\n"
    ),
    "sqli-002": (
        "@@ -9,1 +9,1 @@\n"
        "-    conn.execute(\"DELETE FROM orders WHERE id = %s\" % order_id)\n"
        "+    conn.execute(\"DELETE FROM orders WHERE id = ?\", (order_id,))\n"
    ),
    "sqli-003": (
        "@@ -11,2 +11,4 @@\n"
        "-    sql = \"SELECT name, price FROM products WHERE category = '{}' ORDER BY {}\".format(category, sort_column)\n"
        "-    return conn.execute(sql).fetchall()\n"
        "+    if sort_column not in {\"name\", \"price\"}:\n"
        "+        raise ValueError(\"unsupported sort column\")\n"
        "+    sql = \"SELECT name, price FROM products WHERE category = ? ORDER BY \" + sort_column\n"
        "+    return conn.execute(sql, (category,)).fetchall()\n"
    ),
    "creds-001": (
        "@@ -2,8 +2,9 @@\n"
        " # Do not import, execute or reuse this code. The credential below is fake.\n"
        ' """Mail sender with a password hardcoded in a module-level constant."""\n'
        " \n"
        "+import os\n"
        " import smtplib\n"
        " \n"
        ' SMTP_HOST = "smtp.example.invalid"\n'
        ' SMTP_USER = "notifications"\n'
        f"-SMTP_PASSWORD = {R}\n"
        '+SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]\n'
    ),
    "creds-002": (
        "@@ -5,1 +5,2 @@\n"
        " from dataclasses import dataclass\n"
        "+import os\n"
        "@@ -15,1 +16,1 @@\n"
        f'-    return ApiClient(base_url="https://api.example.invalid", token={R})\n'
        '+    return ApiClient(base_url="https://api.example.invalid", token=os.environ["API_TOKEN"])\n'
    ),
    "creds-003": (
        "@@ -5,3 +5,8 @@\n"
        " \n"
        f'-def admin_login(host: str, username: str = "admin", password: str = {R}) -> dict:\n'
        "+import os\n"
        "+\n"
        "+\n"
        '+def admin_login(host: str, username: str = "admin", password: str | None = None) -> dict:\n'
        "+    if password is None:\n"
        '+        password = os.environ["ADMIN_PASSWORD"]\n'
        '     return {"host": host, "username": username, "password_length": len(password)}\n'
    ),
    "deser-001": (
        "@@ -5,7 +5,7 @@\n"
        " import base64\n"
        "-import pickle\n"
        "+import json\n"
        " \n"
        " \n"
        " def load_session(cookie_value: str) -> dict:\n"
        "     raw = base64.b64decode(cookie_value)\n"
        "-    return pickle.loads(raw)\n"
        "+    return json.loads(raw)\n"
    ),
    "deser-002": (
        "@@ -8,2 +8,2 @@\n"
        " def parse_config(text: str) -> dict:\n"
        "-    return yaml.load(text, Loader=yaml.Loader)\n"
        "+    return yaml.safe_load(text)\n"
    ),
    "deser-003": (
        "@@ -5,7 +5,7 @@\n"
        "-import marshal\n"
        "+import json\n"
        " from pathlib import Path\n"
        " \n"
        " \n"
        " def read_cache(path: str):\n"
        "     data = Path(path).read_bytes()\n"
        "-    return marshal.loads(data)\n"
        "+    return json.loads(data)\n"
    ),
}

MANIFEST = load_manifest()
SAMPLES = {s.sample_id: s for s in MANIFEST.samples}


class FakeSDK:
    def __init__(self, content: str):
        self.content = content
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        choice = SimpleNamespace(message=SimpleNamespace(content=self.content), finish_reason="stop")
        usage = SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2)
        return SimpleNamespace(id="x", model="test-model", choices=[choice], usage=usage)


def _hashes() -> dict[str, str]:
    return {p.as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in DEFAULT_BENCHMARK_DIR.rglob("*") if p.is_file()}


@pytest.fixture(scope="module")
def scan():
    return ScannerAgent().scan(DEFAULT_BENCHMARK_DIR)


def _finding_and_source(scan, sample_id):
    sample = SAMPLES[sample_id]
    finding = next(f for f in scan.findings if f.file_path == sample.vulnerable_file)
    return finding, (DEFAULT_BENCHMARK_DIR / sample.vulnerable_file).read_text(encoding="utf-8")


def test_every_benchmark_sample_has_a_diff():
    assert set(DIFFS) == set(SAMPLES)


@pytest.mark.parametrize("sample_id", sorted(DIFFS))
def test_benchmark_finding_to_candidate(scan, sample_id):
    finding, source = _finding_and_source(scan, sample_id)
    before = _hashes()
    reply = {
        "finding_id": finding.finding_id,
        "category": finding.category.value,
        "vulnerability_summary": "Benchmark vulnerability.",
        "remediation_rationale": "Minimal safe replacement.",
        "unified_diff": _header(finding.file_path) + DIFFS[sample_id],
        "security_improvements": ["Removes the unsafe construct."],
        "assumptions": [],
        "limitations": [],
        "new_dependencies": [],
        "confidence": 0.8,
    }
    sdk = FakeSDK(json.dumps(reply))
    client = GroqClient(Settings(groq_api_key="test-api-key-not-real-0000", groq_model="test-model"), sdk_client=sdk)
    result = PatchGeneratorAgent(client).generate(finding, source)

    candidate = result.candidate
    real = result.patched_source.reveal_for_verification()
    assert candidate.patch.target_file == SAMPLES[sample_id].vulnerable_file
    assert candidate.verified is False
    assert parse_source(real).tree is not None
    assert _hashes() == before  # benchmark files untouched
    sent = "\n".join(m["content"] for m in sdk.calls[0]["messages"])
    for text in (sent, candidate.patch.model_dump_json(), real, repr(result)):
        assert "fake-benchmark-" not in text


# --- credential samples: context construction and what the model sees -----------------------

EXPECTED_VISIBLE = {
    "creds-001": ['SMTP_HOST = "smtp.example.invalid"', 'SMTP_USER = "notifications"', f"SMTP_PASSWORD = {R}"],
    "creds-002": ['base_url="https://api.example.invalid"', f"token={R}", "def build_client() -> ApiClient:"],
    "creds-003": [
        f'def admin_login(host: str, username: str = "admin", password: str = {R}) -> dict:',
        '{"host": host, "username": username, "password_length": len(password)}',
    ],
}


@pytest.mark.parametrize("sample_id", sorted(EXPECTED_VISIBLE))
def test_credential_sample_context_and_prompt(scan, sample_id):
    finding, source = _finding_and_source(scan, sample_id)
    context = build_patch_context(finding, source)
    messages = build_messages(context)
    prompt = "\n".join(m.content for m in messages)

    assert context.fallback_redaction is False
    assert len(context.flagged_values) == 1 and context.flagged_values[0].startswith("fake-benchmark-")
    assert "fake-benchmark-" not in prompt
    for visible in EXPECTED_VISIBLE[sample_id]:
        assert visible in prompt, visible
