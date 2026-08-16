"""
compliance_engine.py
----------------------
Aggregation layer sitting between the AI analyzer / database and the UI.

Responsibilities:
  - Load the PCI DSS catalog.
  - Run the full pipeline for one uploaded evidence file (extract -> AI
    analyze -> persist).
  - Compute compliance % per sub-requirement, per top-level requirement,
    and overall.
  - Build the gap report (sub-requirements with no evidence, or with
    evidence below a "compliant" threshold).
"""

import os
import re
import json
import shutil
import datetime

from . import database as db
from . import evidence_processor as ep
from . import ai_analyzer as ai

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
EVIDENCE_STORE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence_store")
COMPLIANT_THRESHOLD = 70  # score >= this is treated as "met" for the gap report
MAX_EVIDENCE_FILE_BYTES = 25 * 1024 * 1024  # 25 MB — prevents resource-exhaustion via giant OCR/PDF uploads


class EvidenceUploadError(Exception):
    """Raised for security/validation problems with an incoming upload, before any processing happens."""
    pass


def _safe_stored_filename(original_filename: str, stamp: str) -> str:
    """
    Builds a filename to write inside EVIDENCE_STORE that can never escape
    that directory, regardless of what a client sends as the "filename".

    os.path.basename() strips any directory components (so "../../etc/passwd"
    becomes "passwd"), and we additionally strip characters that aren't
    safe across filesystems, keeping only the extension from the original
    name for readability.
    """
    base = os.path.basename(original_filename or "evidence")
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    if not base or base in (".", ".."):
        base = "evidence"
    return f"{stamp}_{base}"


def load_pci_data() -> dict:
    with open(os.path.join(DATA_DIR, "pci_dss_data.json")) as f:
        return json.load(f)


def all_sub_requirements(pci_data: dict):
    for req in pci_data["requirements"]:
        for sub in req["sub_requirements"]:
            yield req, sub


def process_uploaded_evidence(source_filepath: str, original_filename: str, target_sub_requirement: str = None):
    """
    Full pipeline for one evidence upload:
      1. Copy file into evidence_store/
      2. Extract text
      3. Build 'prior context' string from previously-submitted evidence
         near the target sub-requirement (helps the AI reason about
         cumulative maturity, not just this one file in isolation)
      4. Call the AI analyzer
      5. Persist evidence + every returned assessment (this is where
         cross-requirement spanning actually gets recorded)

    Returns the parsed AI response dict.
    """
    os.makedirs(EVIDENCE_STORE, exist_ok=True)

    file_size = os.path.getsize(source_filepath)
    if file_size > MAX_EVIDENCE_FILE_BYTES:
        raise EvidenceUploadError(
            f"File is {file_size / (1024*1024):.1f} MB, which exceeds the "
            f"{MAX_EVIDENCE_FILE_BYTES // (1024*1024)} MB limit for evidence uploads."
        )

    stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    stored_name = _safe_stored_filename(original_filename, stamp)
    stored_path = os.path.join(EVIDENCE_STORE, stored_name)

    # Defense in depth: even with a sanitized filename, confirm the
    # resolved path still lands inside EVIDENCE_STORE before writing.
    if os.path.commonpath([os.path.abspath(stored_path), EVIDENCE_STORE]) != EVIDENCE_STORE:
        raise EvidenceUploadError("Rejected upload: resolved file path escaped the evidence store directory.")

    shutil.copyfile(source_filepath, stored_path)

    evidence_type = ep.detect_evidence_type(original_filename)
    text = ep.extract_text(stored_path)

    pci_data = load_pci_data()
    prior_context = _build_prior_context(target_sub_requirement)

    result = ai.analyze_evidence(
        evidence_text=text,
        pci_data=pci_data,
        target_sub_requirement=target_sub_requirement,
        prior_context=prior_context,
    )

    evidence_id = db.insert_evidence(
        filename=original_filename,
        stored_path=stored_path,
        evidence_type=evidence_type,
        target_sub_requirement=target_sub_requirement,
        raw_text_excerpt=text,
    )

    for a in result["assessments"]:
        db.insert_assessment(
            evidence_id=evidence_id,
            sub_requirement_id=a["sub_requirement_id"],
            is_primary_target=(a["sub_requirement_id"] == target_sub_requirement),
            sufficiency_score=a["sufficiency_score"],
            maturity_level=a["maturity_level"],
            rationale=a["rationale"],
            gaps=a["gaps"],
            recommendations=a["recommendations"],
        )

    result["evidence_id"] = evidence_id
    result["evidence_type"] = evidence_type
    return result


def _build_prior_context(target_sub_requirement, max_items=5):
    if not target_sub_requirement:
        return ""
    history = db.get_assessments_for_subreq(target_sub_requirement)[:max_items]
    if not history:
        return ""
    lines = [f"For sub-requirement {target_sub_requirement}, prior evidence on file:"]
    for h in history:
        lines.append(
            f"- '{h['filename']}': score {h['sufficiency_score']}, maturity {h['maturity_level']}"
        )
    return "\n".join(lines)


def compute_compliance_summary():
    """
    Returns:
      {
        "overall_pct": float,
        "requirements": [
           {"id": "...", "title": "...", "pct": float,
            "sub_requirements": [{"id","title","score","status","has_evidence"}]}
        ]
      }
    score for a sub-requirement with no evidence = 0.
    """
    pci_data = load_pci_data()
    best_scores = db.get_best_score_per_subreq()

    requirements_out = []
    all_scores = []

    for req in pci_data["requirements"]:
        sub_out = []
        for sub in req["sub_requirements"]:
            score = best_scores.get(sub["id"], 0)
            all_scores.append(score)
            sub_out.append(
                {
                    "id": sub["id"],
                    "title": sub["title"],
                    "score": score,
                    "has_evidence": sub["id"] in best_scores,
                    "status": _status_for_score(score),
                }
            )
        req_pct = round(sum(s["score"] for s in sub_out) / len(sub_out), 1) if sub_out else 0.0
        requirements_out.append(
            {"id": req["id"], "title": req["title"], "pct": req_pct, "sub_requirements": sub_out}
        )

    overall_pct = round(sum(all_scores) / len(all_scores), 1) if all_scores else 0.0
    return {"overall_pct": overall_pct, "requirements": requirements_out}


def _status_for_score(score: int) -> str:
    if score == 0:
        return "No evidence"
    if score < COMPLIANT_THRESHOLD:
        return "Partial / Gap"
    return "Compliant"


def build_gap_report():
    """Flat list of every sub-requirement below the compliant threshold, with recommendations."""
    pci_data = load_pci_data()
    latest = db.get_latest_assessment_per_subreq()
    best_scores = db.get_best_score_per_subreq()

    gaps = []
    for req, sub in all_sub_requirements(pci_data):
        score = best_scores.get(sub["id"], 0)
        if score < COMPLIANT_THRESHOLD:
            latest_a = latest.get(sub["id"])
            recs = json.loads(latest_a["recommendations"]) if latest_a else []
            gap_notes = json.loads(latest_a["gaps"]) if latest_a else []
            if not latest_a:
                recs = [f"Upload evidence for '{sub['title']}' — e.g. {', '.join(sub['example_evidence'])}."]
                gap_notes = ["No evidence submitted yet."]
            gaps.append(
                {
                    "requirement_id": req["id"],
                    "requirement_title": req["title"],
                    "sub_requirement_id": sub["id"],
                    "sub_requirement_title": sub["title"],
                    "current_score": score,
                    "gaps": gap_notes,
                    "recommendations": recs,
                }
            )
    gaps.sort(key=lambda g: g["current_score"])
    return gaps
