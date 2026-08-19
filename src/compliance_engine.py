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
import hashlib
import datetime

from . import database as db
from . import evidence_processor as ep
from . import ai_analyzer as ai
from . import local_analyzer as la
from . import scoping_data as sd

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


def _sha256_of_file(path: str) -> str:
    """Real per-file SHA-256 integrity hash, computed from the stored bytes on disk (streamed, not
    loaded fully into memory, so it stays cheap even near the 25 MB upload cap)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_pci_data() -> dict:
    with open(os.path.join(DATA_DIR, "pci_dss_data.json")) as f:
        return json.load(f)


def all_sub_requirements(pci_data: dict):
    for req in pci_data["requirements"]:
        for sub in req["sub_requirements"]:
            yield req, sub


ANALYSIS_ENGINES = {"ai": "AI-powered (Gemini)", "local": "Local rule-based (offline)"}


def process_uploaded_evidence(source_filepath: str, original_filename: str, target_sub_requirement: str = None,
                               analysis_mode: str = "ai"):
    """
    Full pipeline for one evidence upload:
      1. Copy file into evidence_store/
      2. Extract text
      3. Build 'prior context' string from previously-submitted evidence
         near the target sub-requirement (helps the AI reason about
         cumulative maturity, not just this one file in isolation)
      4. Call the analysis engine — either the AI analyzer (ai_analyzer.py,
         calls Gemini) or the local analyzer (local_analyzer.py, offline
         keyword matching against data/pci_dss_data.json), selected via
         `analysis_mode` ("ai" or "local"). Both return the same schema.
      5. Persist evidence + every returned assessment, tagged with which
         engine produced it (this is where cross-requirement spanning
         actually gets recorded)

    Returns the parsed analyzer response dict, plus 'analysis_mode'.
    """
    if analysis_mode not in ANALYSIS_ENGINES:
        raise ValueError(f"Unknown analysis_mode: {analysis_mode!r}. Expected one of {list(ANALYSIS_ENGINES)}.")

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
    file_hash = _sha256_of_file(stored_path)

    evidence_type = ep.detect_evidence_type(original_filename)
    text = ep.extract_text(stored_path)

    pci_data = load_pci_data()
    prior_context = _build_prior_context(target_sub_requirement)

    if analysis_mode == "local":
        result = la.analyze_evidence(
            evidence_text=text,
            pci_data=pci_data,
            target_sub_requirement=target_sub_requirement,
            prior_context=prior_context,
            filename=original_filename,
        )
    else:
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
        sha256=file_hash,
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
            analysis_source=analysis_mode,
        )

    result["evidence_id"] = evidence_id
    result["evidence_type"] = evidence_type
    result["analysis_mode"] = analysis_mode
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


def get_current_saq_type() -> str:
    return db.get_setting("saq_type", sd.DEFAULT_SAQ_TYPE)


def set_current_saq_type(saq_type: str):
    if saq_type not in sd.SAQ_TYPES:
        raise ValueError(f"Unknown SAQ type: {saq_type}")
    db.set_setting("saq_type", saq_type)


def compute_compliance_summary(saq_type: str = None):
    """
    Returns:
      {
        "overall_pct": float,
        "saq_type": "...",
        "in_scope_requirement_ids": [...],
        "requirements": [
           {"id": "...", "title": "...", "pct": float, "in_scope": bool,
            "sub_requirements": [{"id","title","score","status","has_evidence"}]}
        ]
      }
    score for a sub-requirement with no evidence = 0.

    SAQ-aware scoping: requirements not applicable to the currently-selected
    SAQ type (see scoping_data.py) are still listed (so the user can see
    what's excluded and why) but are marked "in_scope": False and are
    EXCLUDED from the overall_pct / req_pct averages, so the headline
    compliance % reflects only what the chosen SAQ type actually requires.
    """
    if saq_type is None:
        saq_type = get_current_saq_type()
    in_scope_ids = sd.applicable_requirement_ids(saq_type)

    pci_data = load_pci_data()
    best_scores = db.get_best_score_per_subreq()

    requirements_out = []
    all_scores = []

    for req in pci_data["requirements"]:
        req_in_scope = req["id"] in in_scope_ids
        sub_out = []
        for sub in req["sub_requirements"]:
            score = best_scores.get(sub["id"], 0)
            if req_in_scope:
                all_scores.append(score)
            sub_out.append(
                {
                    "id": sub["id"],
                    "title": sub["title"],
                    "score": score,
                    "has_evidence": sub["id"] in best_scores,
                    "status": _status_for_score(score) if req_in_scope else "Not applicable (SAQ scope)",
                }
            )
        scored_subs = sub_out if req_in_scope else []
        req_pct = round(sum(s["score"] for s in scored_subs) / len(scored_subs), 1) if scored_subs else None
        requirements_out.append(
            {
                "id": req["id"],
                "title": req["title"],
                "pct": req_pct if req_pct is not None else 0.0,
                "in_scope": req_in_scope,
                "sub_requirements": sub_out,
            }
        )

    overall_pct = round(sum(all_scores) / len(all_scores), 1) if all_scores else 0.0
    return {
        "overall_pct": overall_pct,
        "saq_type": saq_type,
        "in_scope_requirement_ids": sorted(in_scope_ids, key=int),
        "requirements": requirements_out,
    }


def _status_for_score(score: int) -> str:
    if score == 0:
        return "No evidence"
    if score < COMPLIANT_THRESHOLD:
        return "Partial / Gap"
    return "Compliant"


def build_gap_report(saq_type: str = None):
    """Flat list of every in-scope sub-requirement below the compliant threshold, with
    recommendations. Sub-requirements belonging to a top-level requirement that's not
    applicable under the current SAQ type (see scoping_data.py) are excluded."""
    if saq_type is None:
        saq_type = get_current_saq_type()
    in_scope_ids = sd.applicable_requirement_ids(saq_type)

    pci_data = load_pci_data()
    latest = db.get_latest_assessment_per_subreq()
    best_scores = db.get_best_score_per_subreq()

    gaps = []
    for req, sub in all_sub_requirements(pci_data):
        if req["id"] not in in_scope_ids:
            continue
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


# ---------------------------------------------------------------------------
# Recurring testing tracker (Requirement 11) — due-date status helper
# ---------------------------------------------------------------------------

TEST_FREQUENCY_DAYS = {
    "Quarterly": 90,
    "Semi-Annual": 182,
    "Annual": 365,
    "After significant change": None,  # event-driven, not calendar-driven
}


def suggest_next_due_date(last_performed_date: str, frequency: str):
    """Given an ISO date string (YYYY-MM-DD) and a frequency, suggest the next due date.
    Returns None if there's no last-performed date or the frequency is event-driven."""
    days = TEST_FREQUENCY_DAYS.get(frequency)
    if not last_performed_date or not days:
        return None
    try:
        last = datetime.datetime.strptime(last_performed_date, "%Y-%m-%d").date()
    except ValueError:
        return None
    return (last + datetime.timedelta(days=days)).isoformat()


def testing_tracker_status(next_due_date: str, result_status: str = None) -> str:
    """Overdue / Due soon (<=14 days) / On track, based on today's date vs next_due_date."""
    if not next_due_date:
        return "No due date set"
    try:
        due = datetime.datetime.strptime(next_due_date, "%Y-%m-%d").date()
    except ValueError:
        return "No due date set"
    today = datetime.date.today()
    delta = (due - today).days
    if delta < 0:
        return "Overdue"
    if delta <= 14:
        return "Due soon"
    return "On track"


def testing_tracker_summary(items=None):
    """Counts of Overdue / Due soon / On track across the recurring testing tracker."""
    items = items if items is not None else db.get_all_test_items()
    counts = {"Overdue": 0, "Due soon": 0, "On track": 0, "No due date set": 0}
    for it in items:
        counts[testing_tracker_status(it.get("next_due_date"))] += 1
    return counts
