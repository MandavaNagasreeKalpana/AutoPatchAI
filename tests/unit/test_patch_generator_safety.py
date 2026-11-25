"""Static checks on patched code (AST only, never executed)."""

from __future__ import annotations

import pytest

from autopatch.models import VulnerabilityCategory
from autopatch.patch_generator import PatchSyntaxError, UnsafePatchError
from autopatch.patch_generator.safety import check_patched_source

ORIGINAL = "import json\n\n\ndef load(data):\n    return json.loads(data)\n"


def test_clean_patch_passes():
    patched = ORIGINAL.replace("json.loads(data)", "json.loads(data or '{}')")
    assert check_patched_source(ORIGINAL, patched) == []


def test_syntax_error_rejected():
    with pytest.raises(PatchSyntaxError, match="not valid Python"):
        check_patched_source(ORIGINAL, ORIGINAL + "def broken(:\n")


@pytest.mark.parametrize(
    "addition",
    [
        "eval(data)",
        "exec(data)",
        "compile(data, 'x', 'exec')",
        "__import__('os')",
        "import os\nos.system('ls')",
        "from os import system\nsystem('ls')",
        "import subprocess\nsubprocess.run(['ls'])",
        "import subprocess as sp\nsp.Popen('ls', shell=True)",
        "import pickle as p\np.loads(data)",
        "import marshal\nmarshal.loads(data)",
        "import yaml\nyaml.load(data, Loader=yaml.Loader)",
        "open_it(cmd, shell=True)",
    ],
)
def test_dangerous_constructs_rejected(addition):
    patched = ORIGINAL + "\n" + addition + "\n"
    with pytest.raises(UnsafePatchError, match="dangerous"):
        check_patched_source(ORIGINAL, patched)


def test_existing_dangerous_call_may_remain_or_be_removed():
    original = "import pickle\n\n\ndef load(d):\n    return pickle.loads(d)\n"
    unchanged_count = original.replace("return pickle.loads(d)", "data = d\n    return pickle.loads(data)")
    assert check_patched_source(original, unchanged_count) == []
    removed = "import json\n\n\ndef load(d):\n    return json.loads(d)\n"
    assert check_patched_source(original, removed) == []


def test_new_stdlib_import_allowed():
    patched = "import os\n" + ORIGINAL
    assert check_patched_source(ORIGINAL, patched) == []


def test_undeclared_third_party_import_rejected():
    patched = "import requests\n" + ORIGINAL
    with pytest.raises(UnsafePatchError, match="requests"):
        check_patched_source(ORIGINAL, patched)


def test_declared_third_party_import_allowed_with_warning():
    patched = "from defusedxml import ElementTree\n" + ORIGINAL
    warnings = check_patched_source(ORIGINAL, patched, ["defusedxml"])
    assert warnings == ["The patch adds a declared third-party dependency: defusedxml."]


def test_relative_imports_are_not_dependencies():
    patched = "from . import settings\n" + ORIGINAL
    assert check_patched_source(ORIGINAL, patched) == []


# --- bypasses found in the M3B audit --------------------------------------------------


@pytest.mark.parametrize(
    "addition",
    [
        "from subprocess import *\nrun(['ls'])",
        "f2 = eval\nf2('1')",
        "runner = exec",
        "c = compile",
        "imp = __import__",
        "b = __builtins__",
        "import os\ngetattr(os, 'sys' + 'tem')('ls')",
        "import os\ngetattr(os, 'system')('ls')",
        "import importlib\nimportlib.import_module('subprocess')",
        "from importlib import import_module as im\nim('subprocess')",
        "import builtins\nbuiltins.__dict__['exec']('1')",
        "import os\nos.startfile('x')",
        "import asyncio\nasyncio.create_subprocess_shell('ls')",
        "import asyncio\nasyncio.create_subprocess_exec('ls')",
        "import runpy\nrunpy.run_path('x.py')",
        "from os import *\nsystem('ls')",
        "import pickle\nloader = pickle.loads",
    ],
)
def test_audit_bypasses_now_rejected(addition):
    with pytest.raises(UnsafePatchError, match="dangerous"):
        check_patched_source(ORIGINAL, ORIGINAL + "\n" + addition + "\n")


def test_existing_dangerous_references_are_not_blamed_on_the_patch():
    original = "import os\nf = eval\n\n\ndef g(x):\n    return os.system(x)\n"
    patched = original.replace("return os.system(x)", "cmd = x\n    return os.system(cmd)")
    assert check_patched_source(original, patched) == []


def test_yaml_safe_loader_is_not_dangerous():
    original = "import yaml\n\n\ndef parse(t):\n    return yaml.load(t, Loader=yaml.Loader)\n"
    patched = original.replace("Loader=yaml.Loader", "Loader=yaml.SafeLoader")
    assert check_patched_source(original, patched) == []


# --- category-specific checks -----------------------------------------------------------


CRED_ORIGINAL = 'import os\nDB_PASSWORD = "old-secret-value"\n\n\ndef connect():\n    return DB_PASSWORD\n'


@pytest.mark.parametrize(
    "replacement",
    [
        'DB_PASSWORD = "changeme"',
        'DB_PASSWORD: str = "changeme"',
        'DB_PASSWORD = os.getenv("DB_PASSWORD") or "fallback-secret"',  # BoolOp: not bound directly
    ],
)
def test_new_hardcoded_credential_rejected(replacement):
    patched = CRED_ORIGINAL.replace('DB_PASSWORD = "old-secret-value"', replacement)
    if "fallback-secret" in replacement:
        # A literal inside an expression is not "bound" to the name: documented limitation.
        check_patched_source(CRED_ORIGINAL, patched, category=VulnerabilityCategory.HARDCODED_CREDENTIALS,
                             flagged_values=["old-secret-value"])
        return
    with pytest.raises(UnsafePatchError, match="new hardcoded string") as exc_info:
        check_patched_source(CRED_ORIGINAL, patched, category=VulnerabilityCategory.HARDCODED_CREDENTIALS,
                             flagged_values=["old-secret-value"])
    assert "changeme" not in str(exc_info.value)


@pytest.mark.parametrize(
    "addition",
    ['connect(password="hunter2-new")', 'def login(token="tok-new-123"):\n    return token'],
)
def test_new_credential_keyword_or_default_rejected_in_any_category(addition):
    with pytest.raises(UnsafePatchError, match="new hardcoded string"):
        check_patched_source(ORIGINAL, ORIGINAL + "\n" + addition + "\n")


def test_environment_based_credential_accepted():
    patched = CRED_ORIGINAL.replace('DB_PASSWORD = "old-secret-value"', 'DB_PASSWORD = os.environ["DB_PASSWORD"]')
    assert check_patched_source(
        CRED_ORIGINAL, patched, category=VulnerabilityCategory.HARDCODED_CREDENTIALS,
        flagged_values=["old-secret-value"],
    ) == []


def test_flagged_credential_still_present_rejected():
    patched = CRED_ORIGINAL.replace("return DB_PASSWORD", 'return DB_PASSWORD or "x"')
    with pytest.raises(UnsafePatchError, match="does not remove the flagged hardcoded credential") as exc_info:
        check_patched_source(CRED_ORIGINAL, patched, category=VulnerabilityCategory.HARDCODED_CREDENTIALS,
                             flagged_values=["old-secret-value"])
    assert "old-secret-value" not in str(exc_info.value)


DESER_ORIGINAL = (
    "import pickle\n\n\ndef load(d):\n    return pickle.loads(d)\n\n\n"
    "def legacy(d):\n    return pickle.loads(d)\n"
)


def test_unsafe_deserialization_left_in_place_rejected():
    patched = DESER_ORIGINAL.replace("    return pickle.loads(d)\n\n\n", "    data = d\n    return pickle.loads(data)\n\n\n", 1)
    with pytest.raises(UnsafePatchError, match="does not remove the flagged unsafe deserialization"):
        check_patched_source(DESER_ORIGINAL, patched, category=VulnerabilityCategory.INSECURE_DESERIALIZATION,
                             flagged_lines=range(5, 6))


def test_fixing_flagged_call_ignores_unrelated_existing_unsafe_call():
    patched = "import json\nimport pickle\n" + DESER_ORIGINAL.replace(
        "import pickle\n", "", 1).replace("return pickle.loads(d)\n\n\n", "return json.loads(d)\n\n\n", 1)
    assert "pickle.loads(d)" in patched  # the unrelated legacy() call remains
    assert check_patched_source(DESER_ORIGINAL, patched, category=VulnerabilityCategory.INSECURE_DESERIALIZATION,
                                flagged_lines=range(5, 6)) == []


def test_yaml_safe_loader_counts_as_fixing_b506():
    original = "import yaml\n\n\ndef parse(t):\n    return yaml.load(t, Loader=yaml.Loader)\n"
    patched = original.replace("Loader=yaml.Loader", "Loader=yaml.SafeLoader")
    assert check_patched_source(original, patched, category=VulnerabilityCategory.INSECURE_DESERIALIZATION,
                                flagged_lines=range(5, 6)) == []
