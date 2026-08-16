"""
risk_engine.py
----------------
Risk scoring + risk register layer for VerifAI 360.

This sits alongside compliance_engine.py: where the compliance engine
answers "how sufficient is our evidence for sub-requirement X?", this
module answers "if that gap stays open, how much business/security risk
does it represent, and who owns closing it?".

Approach
--------
Risk score = Likelihood (1-5) x Impact (1-5), a standard 5x5 qualitative
risk matrix (range 1-25), bucketed into Low / Medium / High / Critical.

  - Likelihood is derived from the current compliance sufficiency score
    for that sub-requirement (lower evidence sufficiency -> higher
    likelihood that the control fails when actually needed / tested).
  - Impact is derived from a fixed criticality weight per PCI DSS
    top-level requirement, reflecting how directly that requirement
    protects cardholder data if it fails (e.g. "Protect stored account
    data" is weighted higher than "Maintain a policy that addresses
    information security").

These weights are a reasonable, documented default for a self-assessment
tool -- NOT an official PCI SSC risk-weighting scheme. Users can freely
override likelihood/impact when editing a risk, and can add fully manual
risks unrelated to any gap (e.g. a vendor risk, a project risk).

Auto-generation
---------------
`sync_auto_risks_from_gaps()` is called on demand (button in the UI). For
every open gap (score < compliant threshold) it creates or refreshes a
single 'auto-gap' sourced risk-register row per sub-requirement, without
touching any risk a user has manually edited into a different status.
"""

import datetime
from . import database as db

# Impact weight (1-5) per top-level PCI DSS requirement. Reflects how
# directly a failure of that requirement domain endangers cardholder data.
REQUIREMENT_IMPACT_WEIGHTS = {
    "1": 4,   # Network security controls
    "2": 3,   # Secure configurations
    "3": 5,   # Protect stored account data
    "4": 5,   # Encrypt transmission of account data
    "5": 4,   # Protect against malware
    "6": 4,   # Secure systems and software
    "7": 4,   # Restrict access by business need-to-know
    "8": 4,   # Identify users and authenticate access
    "9": 3,   # Restrict physical access
    "10": 4,  # Log and monitor all access
    "11": 4,  # Test security of systems and networks regularly
    "12": 3,  # Organizational policy and program support
}

RISK_LEVELS = [
    (1, 4, "Low"),
    (5, 9, "Medium"),
    (10, 14, "High"),
    (15, 25, "Critical"),
]

STATUS_OPTIONS = ["Open", "Mitigating", "Accepted", "Closed"]


def risk_level_for_score(risk_score: int) -> str:
    for lo, hi, label in RISK_LEVELS:
        if lo <= risk_score <= hi:
            return label
    return "Low"


def likelihood_from_compliance_score(score: int) -> int:
    """
    Maps a 0-100 sufficiency score to a 1-5 likelihood-of-control-failure
    rating. No evidence at all (score 0) is treated as most likely to fail
    (5); a fully sufficient, mature control (score >= 90) is least likely (1).
    """
    if score >= 90:
        return 1
    if score >= 70:
        return 2
    if score >= 40:
        return 3
    if score > 0:
        return 4
    return 5


def impact_for_requirement(requirement_id: str) -> int:
    return REQUIREMENT_IMPACT_WEIGHTS.get(str(requirement_id), 3)


def compute_risk_score(likelihood: int, impact: int) -> int:
    likelihood = max(1, min(5, int(likelihood)))
    impact = max(1, min(5, int(impact)))
    return likelihood * impact


def sync_auto_risks_from_gaps(gaps: list) -> dict:
    """
    Upserts one 'auto-gap' risk per open gap from compliance_engine.build_gap_report().
    Never overwrites a risk a user has manually moved to 'Mitigating', 'Accepted',
    or 'Closed', or manually edited (source stays 'auto-gap' only while untouched).
    Returns {'created': n, 'updated': n, 'skipped': n}.
    """
    created = updated = skipped = 0
    for g in gaps:
        sub_id = g["sub_requirement_id"]
        req_id = g["requirement_id"]
        likelihood = likelihood_from_compliance_score(g["current_score"])
        impact = impact_for_requirement(req_id)
        score = compute_risk_score(likelihood, impact)
        level = risk_level_for_score(score)
        title = f"Insufficient / missing control evidence — {sub_id} {g['sub_requirement_title']}"
        description = (
            f"Compliance gap for sub-requirement {sub_id} (current sufficiency score "
            f"{g['current_score']}/100). " + (" ".join(g["gaps"]) if g["gaps"] else "")
        )
        mitigation = "\n".join(f"- {r}" for r in g["recommendations"]) if g["recommendations"] else ""

        existing = db.get_auto_risk_for_subreq(sub_id)
        if existing is None:
            db.insert_risk(
                requirement_id=req_id, sub_requirement_id=sub_id, title=title, description=description,
                likelihood=likelihood, impact=impact, risk_score=score, risk_level=level,
                owner=None, status="Open", mitigation_plan=mitigation, due_date=None, source="auto-gap",
            )
            created += 1
        elif existing["status"] == "Open":
            db.update_risk(
                existing["id"], title=title, description=description, likelihood=likelihood,
                impact=impact, risk_score=score, risk_level=level, mitigation_plan=mitigation,
            )
            updated += 1
        else:
            # User has already started managing this risk (Mitigating/Accepted/Closed) — leave it alone.
            skipped += 1

    return {"created": created, "updated": updated, "skipped": skipped}


def get_register(status_filter=None, level_filter=None):
    risks = db.get_all_risks()
    if status_filter and status_filter != "All":
        risks = [r for r in risks if r["status"] == status_filter]
    if level_filter and level_filter != "All":
        risks = [r for r in risks if r["risk_level"] == level_filter]
    return risks


def risk_exposure_summary(risks=None):
    """
    Aggregate risk posture:
      - total open risk score (sum of risk_score for Open/Mitigating risks)
      - count per level
      - count per status
    """
    risks = risks if risks is not None else db.get_all_risks()
    open_like = [r for r in risks if r["status"] in ("Open", "Mitigating")]
    by_level = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    by_status = {s: 0 for s in STATUS_OPTIONS}
    for r in risks:
        by_level[r["risk_level"]] = by_level.get(r["risk_level"], 0) + 1
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    return {
        "total_open_exposure": sum(r["risk_score"] for r in open_like),
        "open_count": len(open_like),
        "critical_open": sum(1 for r in open_like if r["risk_level"] == "Critical"),
        "by_level": by_level,
        "by_status": by_status,
    }


def heatmap_matrix(risks=None):
    """5x5 matrix (rows=impact 5->1, cols=likelihood 1->5) of open-risk counts, for a plotly heatmap."""
    risks = risks if risks is not None else db.get_all_risks()
    matrix = [[0] * 5 for _ in range(5)]
    for r in risks:
        if r["status"] not in ("Open", "Mitigating"):
            continue
        li = max(1, min(5, r["likelihood"])) - 1
        im = max(1, min(5, r["impact"])) - 1
        matrix[4 - im][li] += 1  # row 0 = impact 5 (top), row 4 = impact 1 (bottom)
    return matrix
