"""Tests for src/local_analyzer.py — the offline, deterministic scoring engine."""

import pytest

from src import local_analyzer as la
from src import compliance_engine as ce


@pytest.fixture(scope="module")
def pci_data():
    return ce.load_pci_data()


def test_raises_on_empty_text(pci_data):
    with pytest.raises(la.LocalAnalyzerError):
        la.analyze_evidence("   ", pci_data)


def test_exact_keyword_match_scores_highly(pci_data):
    text = ("Network Security Policy: firewall policy, roles and responsibilities, "
            "policy review date.")
    result = la.analyze_evidence(text, pci_data, target_sub_requirement="1.1")
    match = next(a for a in result["assessments"] if a["sub_requirement_id"] == "1.1")
    assert match["sufficiency_score"] > 70
    assert "exact match" in match["rationale"]


def test_irrelevant_text_yields_no_assessments(pci_data):
    result = la.analyze_evidence("The quick brown fox jumps over the lazy dog.", pci_data)
    assert result["assessments"] == []


def test_targeted_subrequirement_always_included_even_at_zero(pci_data):
    result = la.analyze_evidence("completely unrelated filler content here", pci_data,
                                  target_sub_requirement="1.1")
    ids = [a["sub_requirement_id"] for a in result["assessments"]]
    assert "1.1" in ids


def test_fuzzy_match_catches_typo(pci_data):
    # 'firewal' (missing an 'l') instead of 'firewall'
    text = "This is our firewal policy and roles and responsibilities document."
    result = la.analyze_evidence(text, pci_data, target_sub_requirement="1.1")
    match = next(a for a in result["assessments"] if a["sub_requirement_id"] == "1.1")
    assert "fuzzy" in match["rationale"].lower()
    assert match["sufficiency_score"] > 0


def test_fuzzy_match_is_worth_less_than_exact(pci_data):
    exact_text = "firewall policy roles and responsibilities policy review date"
    fuzzy_text = "firewal policy roles and responsibilities policy review date"
    exact_result = la.analyze_evidence(exact_text, pci_data, target_sub_requirement="1.1")
    fuzzy_result = la.analyze_evidence(fuzzy_text, pci_data, target_sub_requirement="1.1")
    exact_score = next(a for a in exact_result["assessments"] if a["sub_requirement_id"] == "1.1")["sufficiency_score"]
    fuzzy_score = next(a for a in fuzzy_result["assessments"] if a["sub_requirement_id"] == "1.1")["sufficiency_score"]
    assert exact_score >= fuzzy_score


def test_filename_bonus_only_when_corroborated(pci_data):
    text = "firewall policy roles and responsibilities policy review date"
    with_good_name = la.analyze_evidence(text, pci_data, target_sub_requirement="1.1",
                                          filename="network_security_policy.txt")
    with_generic_name = la.analyze_evidence(text, pci_data, target_sub_requirement="1.1",
                                             filename="scan_004.txt")
    good = next(a for a in with_good_name["assessments"] if a["sub_requirement_id"] == "1.1")
    generic = next(a for a in with_generic_name["assessments"] if a["sub_requirement_id"] == "1.1")
    assert good["sufficiency_score"] >= generic["sufficiency_score"]


def test_misleading_filename_alone_earns_nothing(pci_data):
    # Filename suggests firewall policy, but content is about something else entirely —
    # the filename bonus must require content corroboration, not just say-so.
    text = "completely unrelated filler content about lunch orders"
    result = la.analyze_evidence(text, pci_data, target_sub_requirement="1.1",
                                  filename="network_security_policy.txt")
    match = next(a for a in result["assessments"] if a["sub_requirement_id"] == "1.1")
    assert "corroborates" not in match["rationale"]


def test_custom_weights_change_the_score(pci_data):
    text = "network security policy firewall policy roles and responsibilities policy review date"
    default_result = la.analyze_evidence(text, pci_data, target_sub_requirement="1.1")
    kw_heavy_result = la.analyze_evidence(
        text, pci_data, target_sub_requirement="1.1",
        weights={"keyword": 0.9, "title": 0.05, "example": 0.05},
    )
    default_score = next(a for a in default_result["assessments"] if a["sub_requirement_id"] == "1.1")["sufficiency_score"]
    kw_heavy_score = next(a for a in kw_heavy_result["assessments"] if a["sub_requirement_id"] == "1.1")["sufficiency_score"]
    assert kw_heavy_score != default_score


def test_scores_always_within_bounds(pci_data):
    text = "network security policy firewall policy roles and responsibilities policy review date " * 5
    result = la.analyze_evidence(text, pci_data, filename="network_security_policy.txt")
    for a in result["assessments"]:
        assert 0 <= a["sufficiency_score"] <= 100


def test_deterministic_same_input_same_output(pci_data):
    text = "firewall policy roles and responsibilities policy review date"
    r1 = la.analyze_evidence(text, pci_data, target_sub_requirement="1.1")
    r2 = la.analyze_evidence(text, pci_data, target_sub_requirement="1.1")
    s1 = next(a for a in r1["assessments"] if a["sub_requirement_id"] == "1.1")["sufficiency_score"]
    s2 = next(a for a in r2["assessments"] if a["sub_requirement_id"] == "1.1")["sufficiency_score"]
    assert s1 == s2


def test_every_subrequirement_has_evidence_keywords(pci_data):
    """Guards against a future data-file edit silently dropping evidence_keywords
    for a sub-requirement (which would make it invisible to this engine)."""
    for req in pci_data["requirements"]:
        for sub in req["sub_requirements"]:
            assert sub.get("evidence_keywords"), f"{sub['id']} has no evidence_keywords"
