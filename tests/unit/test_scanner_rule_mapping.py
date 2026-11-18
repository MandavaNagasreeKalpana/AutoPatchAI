"""Rule-to-category mapping, checked against the installed Bandit."""

from __future__ import annotations

import pytest

from autopatch.models import VulnerabilityCategory
from autopatch.scanner import RELATED_RULES, SUPPORTED_RULES, RuleKind, classify_rule
from autopatch.scanner.rule_mapping import (
    CATEGORY_EXPLANATIONS,
    CONFIDENCE_SCORES,
    EXCLUDED_RULE_NOTES,
    rule_spec,
)

C = VulnerabilityCategory


def _bandit_name(rule_id: str) -> str:
    from bandit.core import extension_loader

    manager = extension_loader.MANAGER
    if rule_id in manager.plugins_by_id:
        return manager.plugins_by_id[rule_id].name
    return manager.blacklist_by_id[rule_id]["name"]


def test_supported_rule_set():
    assert {rid: spec.category for rid, spec in SUPPORTED_RULES.items()} == {
        "B608": C.SQL_INJECTION,
        "B105": C.HARDCODED_CREDENTIALS,
        "B106": C.HARDCODED_CREDENTIALS,
        "B107": C.HARDCODED_CREDENTIALS,
        "B301": C.INSECURE_DESERIALIZATION,
        "B302": C.INSECURE_DESERIALIZATION,
        "B506": C.INSECURE_DESERIALIZATION,
    }


def test_related_rules_are_separate():
    assert set(RELATED_RULES) == {"B403"}
    assert not set(RELATED_RULES) & set(SUPPORTED_RULES)


@pytest.mark.parametrize("rule_id", sorted({*SUPPORTED_RULES, *RELATED_RULES}))
def test_mapping_matches_installed_bandit(rule_id):
    """Each mapped ID must be the Bandit check we think it is."""
    assert _bandit_name(rule_id) == rule_spec(rule_id).bandit_name


@pytest.mark.parametrize(
    ("rule_id", "bandit_name"),
    [("B303", "md5"), ("B304", "ciphers"), ("B305", "cipher_modes"), ("B306", "mktemp_q")],
)
def test_b303_to_b306_are_not_deserialization(rule_id, bandit_name):
    """Documents why these spec-requested IDs are not mapped."""
    assert _bandit_name(rule_id) == bandit_name
    assert classify_rule(rule_id) is RuleKind.UNSUPPORTED
    assert bandit_name in EXCLUDED_RULE_NOTES[rule_id]


@pytest.mark.parametrize(
    ("rule_id", "kind"),
    [("B608", RuleKind.SUPPORTED), ("B403", RuleKind.RELATED), ("B311", RuleKind.UNSUPPORTED),
     ("B999", RuleKind.UNSUPPORTED), ("", RuleKind.UNSUPPORTED)],
)
def test_classify_rule(rule_id, kind):
    assert classify_rule(rule_id) is kind


def test_every_category_has_rules_and_explanation():
    for category in VulnerabilityCategory:
        assert any(s.category is category for s in SUPPORTED_RULES.values()), category
        assert CATEGORY_EXPLANATIONS[category]


def test_confidence_scores_are_ordered_and_in_range():
    assert CONFIDENCE_SCORES["LOW"] < CONFIDENCE_SCORES["MEDIUM"] < CONFIDENCE_SCORES["HIGH"]
    assert all(0 <= v <= 1 for v in CONFIDENCE_SCORES.values())


def test_mapping_is_read_only():
    with pytest.raises(TypeError):
        SUPPORTED_RULES["B999"] = SUPPORTED_RULES["B608"]  # type: ignore[index]
