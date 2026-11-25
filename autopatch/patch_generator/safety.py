"""Static (non-executing) checks on a patched file.

The patched source is only parsed with ``ast.parse``. It is never compiled
to bytecode, imported, or run.

This is **defence in depth, not a proof of safety**: a static deny-list
cannot catch every dynamic Python trick. Candidates stay UNVERIFIED until
the Verification Agent (M4) tests and rescans them, and a human reviews them.

Checks (counts are compared before vs after, so dangerous code that already
existed elsewhere in the file is not blamed on the patch):
* syntax: the patched file must parse;
* dangerous references (not only calls): ``eval``/``exec``/``compile``/
  ``__import__``/``__builtins__``, ``os.system``/``popen``/``startfile``/
  ``exec*``/``spawn*``, ``subprocess.*``, ``asyncio.create_subprocess_*``,
  ``importlib.import_module``, ``runpy.*``, unsafe deserializers, aliases of
  all of these, ``getattr`` with a dangerous or computed attribute name,
  ``shell=True``, and star imports from dangerous modules;
* dependencies: new non-standard-library imports must be declared;
* credentials (any category): no new hardcoded string bound to a
  secret-looking name; for credential findings the flagged value must be gone;
* insecure deserialization findings: the flagged unsafe call must be removed
  (its count must drop).
"""

from __future__ import annotations

import ast
import sys
from collections import Counter
from collections.abc import Iterable

from autopatch.models import VulnerabilityCategory
from autopatch.common.source import parse_source
from autopatch.common.sensitive import key_literal_ids, name_like_values

from .errors import PatchSyntaxError, UnsafePatchError
from .secrets import credential_literals, is_str_literal, literal_value

UNSAFE_DESERIALIZATION = frozenset(
    {
        "pickle.load", "pickle.loads", "pickle.Unpickler", "_pickle.loads", "cPickle.loads",
        "dill.load", "dill.loads", "marshal.load", "marshal.loads", "shelve.open",
        "yaml.load", "yaml.unsafe_load", "yaml.full_load", "yaml.load_all", "yaml.unsafe_load_all",
        "jsonpickle.decode",
    }
)
DANGEROUS_NAMES = UNSAFE_DESERIALIZATION | frozenset(
    {
        "eval", "exec", "compile", "__import__", "__builtins__", "breakpoint",
        "builtins.eval", "builtins.exec", "builtins.compile", "builtins.__import__", "builtins.__dict__",
        "os.system", "os.popen", "os.startfile", "pty.spawn", "code.interact",
        "importlib.import_module", "importlib.__import__",
    }
)
DANGEROUS_PREFIXES = (
    "subprocess.", "os.exec", "os.spawn", "os.posix_spawn",
    "asyncio.create_subprocess_", "runpy.", "importlib.util.",
)
STAR_RISKY_MODULES = frozenset(
    {"os", "subprocess", "pickle", "marshal", "dill", "shelve", "yaml", "builtins",
     "importlib", "runpy", "pty", "asyncio", "code", "jsonpickle"}
)
DANGEROUS_ATTRIBUTES = frozenset(
    {"system", "popen", "startfile", "spawn", "eval", "exec", "compile", "__import__",
     "import_module", "run_path", "run_module", "loads", "load", "Unpickler", "Popen", "run",
     "call", "check_call", "check_output", "getoutput", "getstatusoutput",
     "create_subprocess_shell", "create_subprocess_exec", "__dict__", "__builtins__"}
)
SAFE_YAML_LOADERS = frozenset({"yaml.SafeLoader", "yaml.CSafeLoader", "yaml.BaseLoader"})
_STDLIB = frozenset(sys.stdlib_module_names) | {"__future__"}


def _aliases(tree: ast.AST) -> dict[str, str]:
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                names[alias.asname or root] = alias.name if alias.asname else root
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name != "*":
                    names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _dotted(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value, aliases)
        return f"{base}.{node.attr}" if base else None
    return None


def _is_dangerous(name: str) -> bool:
    return name in DANGEROUS_NAMES or name.startswith(DANGEROUS_PREFIXES)


def _safe_yaml_calls(tree: ast.AST, aliases: dict[str, str]) -> set[int]:
    """ids of ``yaml.load`` references used with a safe Loader."""
    safe: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _dotted(node.func, aliases) in ("yaml.load", "yaml.load_all"):
            loader = next((k.value for k in node.keywords if k.arg == "Loader"), None)
            if loader is None and len(node.args) > 1:
                loader = node.args[1]
            if loader is not None and _dotted(loader, aliases) in SAFE_YAML_LOADERS:
                safe.add(id(node.func))
    return safe


def dangerous_references(tree: ast.AST) -> list[tuple[str, int]]:
    """``(construct, line)`` for every dangerous reference in ``tree``."""
    aliases = _aliases(tree)
    safe_yaml = _safe_yaml_calls(tree, aliases)
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if any(a.name == "*" for a in node.names) and node.module.split(".")[0] in STAR_RISKY_MODULES:
                found.append((f"from {node.module} import *", node.lineno))
        elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
            name = _dotted(node, aliases)
            if name and _is_dangerous(name) and id(node) not in safe_yaml:
                found.append((name, node.lineno))
        elif isinstance(node, ast.Call):
            if _dotted(node.func, aliases) == "getattr" and len(node.args) >= 2:
                attr = node.args[1]
                if not (isinstance(attr, ast.Constant) and isinstance(attr.value, str)):
                    found.append(("getattr(<computed name>)", node.lineno))
                elif attr.value in DANGEROUS_ATTRIBUTES:
                    found.append((f"getattr(..., {attr.value!r})", node.lineno))
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    found.append(("shell=True", node.lineno))
    return found


def dangerous_constructs(tree: ast.AST) -> Counter[str]:
    return Counter(name for name, _ in dangerous_references(tree))


def imported_modules(tree: ast.AST) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module.split(".")[0])
    return modules


def _credential_values(tree: ast.AST) -> set[str]:
    return {literal_value(n) for n in credential_literals(tree)}


def check_patched_source(
    original: str,
    patched: str,
    declared_dependencies: Iterable[str] = (),
    *,
    category: VulnerabilityCategory | None = None,
    flagged_lines: range | None = None,
    flagged_values: Iterable[str] = (),
) -> list[str]:
    """Validate the patched file statically. Returns informational warnings.

    Raises :class:`PatchSyntaxError` or :class:`UnsafePatchError`. Error
    messages name constructs and modules, never secret values or code.
    """
    before = parse_source(original).tree
    after_parsed = parse_source(patched)
    if after_parsed.tree is None:
        raise PatchSyntaxError(f"The patched file is not valid Python ({after_parsed.error}).")
    if before is None:
        raise PatchSyntaxError("The original file could not be parsed for comparison.")
    after = after_parsed.tree

    refs_before = dangerous_references(before)
    counts_before = Counter(name for name, _ in refs_before)
    counts_after = dangerous_constructs(after)
    added = counts_after - counts_before
    if added:
        raise UnsafePatchError(
            "The patch introduces dangerous constructs: " + ", ".join(sorted(added)) + "."
        )

    declared = {name.split(".")[0] for name in declared_dependencies}
    new_third_party = imported_modules(after) - imported_modules(before) - _STDLIB
    undeclared = sorted(new_third_party - declared)
    if undeclared:
        raise UnsafePatchError(
            "The patch imports new non-standard-library modules without declaring them in "
            "new_dependencies: " + ", ".join(undeclared) + "."
        )

    new_credentials = {v for v in _credential_values(after) if v} - _credential_values(before)
    if new_credentials:
        raise UnsafePatchError(
            "The patch introduces a new hardcoded string bound to a secret-looking name "
            "(variable, keyword argument or parameter default)."
        )

    if category is VulnerabilityCategory.HARDCODED_CREDENTIALS:
        remaining = {v for v in flagged_values if v}
        # A name-like value (``"password"``) may legitimately stay as a key,
        # e.g. ``form["password"]``; anywhere else it still counts.
        name_like = name_like_values(after, remaining)
        keys = key_literal_ids(after)
        if remaining and any(
            is_str_literal(node)
            and literal_value(node) in remaining  # type: ignore[arg-type]
            and not (literal_value(node) in name_like and id(node) in keys)  # type: ignore[arg-type]
            for node in ast.walk(after)
        ):
            raise UnsafePatchError("The patch does not remove the flagged hardcoded credential.")

    if category is VulnerabilityCategory.INSECURE_DESERIALIZATION and flagged_lines is not None:
        flagged_calls = {
            name for name, line in refs_before if name in UNSAFE_DESERIALIZATION and line in flagged_lines
        }
        if flagged_calls:
            before_count = sum(counts_before[n] for n in flagged_calls)
            after_count = sum(counts_after[n] for n in flagged_calls)
            if after_count >= before_count:
                raise UnsafePatchError(
                    "The patch does not remove the flagged unsafe deserialization call ("
                    + ", ".join(sorted(flagged_calls)) + ")."
                )

    return [
        f"The patch adds a declared third-party dependency: {name}."
        for name in sorted(new_third_party & declared)
    ]
