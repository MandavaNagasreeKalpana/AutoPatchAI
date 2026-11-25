"""The single place where Bandit rules are mapped to AutoPatch categories.

* ``SUPPORTED_RULES`` become :class:`~autopatch.models.Finding` objects.
* ``RELATED_RULES`` are reported separately as informational findings. They
  point at a risky capability (e.g. ``import pickle``) but not at a specific
  vulnerable call, so they are not sent for patching.
* Every other Bandit rule is *unsupported*. It is listed as ignored and never
  assigned one of our categories.

``bandit_name`` is Bandit's own plugin/blacklist name. A test checks every
entry against the installed Bandit so a wrong ID cannot slip in.

To support a new rule, add a ``RuleSpec`` here (and a category in
``autopatch/models/enums.py`` if it is a new category).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from autopatch.common.sensitive import REDACT_LITERALS  # noqa: F401  (re-exported)
from autopatch.models import VulnerabilityCategory

_SQLI = VulnerabilityCategory.SQL_INJECTION
_CREDS = VulnerabilityCategory.HARDCODED_CREDENTIALS
_DESER = VulnerabilityCategory.INSECURE_DESERIALIZATION


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    bandit_name: str
    category: VulnerabilityCategory
    title: str


def _index(*specs: RuleSpec) -> MappingProxyType[str, RuleSpec]:
    return MappingProxyType({s.rule_id: s for s in specs})


SUPPORTED_RULES = _index(
    RuleSpec("B608", "hardcoded_sql_expressions", _SQLI, "SQL built from string formatting"),
    RuleSpec("B105", "hardcoded_password_string", _CREDS, "Hardcoded password string"),
    RuleSpec("B106", "hardcoded_password_funcarg", _CREDS, "Hardcoded password function argument"),
    RuleSpec("B107", "hardcoded_password_default", _CREDS, "Hardcoded password default argument"),
    RuleSpec("B301", "pickle", _DESER, "pickle/dill deserialization of untrusted data"),
    RuleSpec("B302", "marshal", _DESER, "marshal deserialization of untrusted data"),
    RuleSpec("B506", "yaml_load", _DESER, "yaml.load with an unsafe loader"),
)

RELATED_RULES = _index(
    RuleSpec("B403", "import_pickle", _DESER, "Import of a pickle-family module"),
)

# Requested in the M2 spec but deliberately NOT mapped. In Bandit these IDs are
# not deserialization checks (verified against Bandit 1.9.4):
EXCLUDED_RULE_NOTES = MappingProxyType(
    {
        "B303": "md5: insecure hash functions (MD2/MD4/MD5/SHA1), not deserialization",
        "B304": "ciphers: insecure ciphers (ARC2/ARC4/Blowfish/DES/XOR), not deserialization",
        "B305": "cipher_modes: insecure cipher mode (ECB), not deserialization",
        "B306": "mktemp_q: insecure temporary file (tempfile.mktemp), not deserialization",
    }
)


class RuleKind(StrEnum):
    SUPPORTED = "supported"
    RELATED = "related"
    UNSUPPORTED = "unsupported"


def classify_rule(rule_id: str) -> RuleKind:
    if rule_id in SUPPORTED_RULES:
        return RuleKind.SUPPORTED
    if rule_id in RELATED_RULES:
        return RuleKind.RELATED
    return RuleKind.UNSUPPORTED


def rule_spec(rule_id: str) -> RuleSpec | None:
    return SUPPORTED_RULES.get(rule_id) or RELATED_RULES.get(rule_id)


# Bandit's ordinal confidence mapped to the 0..1 scale used by Finding.
# These are fixed placeholders, not calibrated probabilities.
CONFIDENCE_SCORES = MappingProxyType({"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.9, "UNDEFINED": 0.3})

CATEGORY_EXPLANATIONS = MappingProxyType(
    {
        _SQLI: (
            "The SQL statement is assembled with string formatting or concatenation. "
            "If any interpolated value is attacker-controlled, it can change the "
            "query's meaning (SQL injection). Use bound parameters, and allow-lists "
            "for identifiers such as column names."
        ),
        _CREDS: (
            "A credential appears to be written directly in source code, where anyone "
            "with access to the code or its history can read it. Load secrets from the "
            "environment or a secrets manager instead. Literal values on the flagged "
            "lines are redacted in this report."
        ),
        _DESER: (
            "Data is deserialized with a format that can construct arbitrary objects "
            "or run code while loading. Deserializing untrusted input this way can "
            "lead to remote code execution. Use a data-only format (e.g. JSON) or a "
            "safe loader."
        ),
    }
)

# Categories whose flagged lines may contain secret literals.
