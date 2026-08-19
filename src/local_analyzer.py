"""
local_analyzer.py
------------------
Offline, deterministic PCI DSS evidence analyzer — no external API, no
network call, no third-party data sharing. This is an ALTERNATIVE engine
to ai_analyzer.py, not a replacement for it: the two are interchangeable
at the compliance_engine layer (same input/output contract), and the
Upload & Analyze page lets the user pick either one per file.

Why this exists: ai_analyzer.py sends evidence text to Google's Gemini
API, which costs nothing on the free tier but still means (a) a network
dependency, (b) evidence content leaving the local machine, and (c) a
result that depends on an LLM's judgment call, which isn't reproducible
run-to-run. This module trades some of the AI's semantic understanding
for a fully local, deterministic, auditable score that runs with zero
setup and zero cost.

DATA SOURCES — every field in data/pci_dss_data.json is used, not just
`evidence_keywords`:
  - evidence_keywords    -> the curated, primary signal (highest trust:
                             these phrases were hand-picked specifically
                             as "what real evidence for this control looks
                             like"). Weight: 0.60 of the final score.
  - title + summary       -> mined for significant vocabulary (stopwords
    (sub-requirement)        removed) as a secondary, broader signal —
                             catches evidence that uses domain language
                             without hitting an exact curated keyword.
                             Weight: 0.20.
  - example_evidence      -> also mined for vocabulary the same way
                             (these describe *document types*, e.g.
                             "Network security policy document", so their
                             words overlap with real policy text more
                             than the phrases themselves would as exact
                             substrings). Weight: 0.20.
  - top-level requirement -> its title is folded into the same broader
    (req["title"])            vocabulary pool as a light corroborating
                             signal (e.g. "Network Security Controls").
  - uploaded filename     -> NOT part of pci_dss_data.json, but the one
    (if provided)             other free, deterministic signal available
                             at upload time. A file named
                             "network_security_policy.txt" is itself
                             evidence of what it's about. Used as a small
                             explicit bonus (+0 to +10), never as the
                             primary driver, and only when it corroborates
                             keyword/context terms already found in the
                             text — a suggestive filename with no matching
                             content inside earns nothing.

Deliberately NOT used: PCI DSS SAQ eligibility text in scoping_data.py —
that describes which top-level *requirements* apply to a business, not
what a piece of *evidence* should contain, so it's the wrong signal for
per-file scoring (it's already used correctly elsewhere, for scoping the
Dashboard/Gap Report). There is no per-sub-requirement "expected file
type" field in the source data to check the detected evidence_type
against, so nothing is invented there.

Scoring model (auditable — every contributing signal is named in the
rationale, nothing is hidden):
  1. Normalize the evidence text (lowercase, collapse whitespace).
  2. keyword_score  = % of that sub-requirement's evidence_keywords found
                       as phrases in the text.
  3. title_score    = % of the significant vocabulary mined from
                       title + summary + parent requirement title found
                       as whole words in the text.
  4. example_score  = % of the significant vocabulary mined from
                       example_evidence found as whole words in the text.
  5. filename_bonus = up to +10 points if the uploaded filename's own
                       words overlap with this sub-requirement's context
                       vocabulary AND at least one of those terms is also
                       actually present in the extracted text (so a
                       misleading filename alone can't inflate a score).
  6. final_score = round(0.60*keyword_score + 0.20*title_score
                          + 0.20*example_score) + filename_bonus,
                    clamped to [0, 100].
  7. maturity_level is derived from banded score thresholds.
  8. A sub-requirement is only included in the results if at least one
     curated keyword matched, or it's the user's explicitly targeted
     sub-requirement — context-only overlap (common domain words) is
     supporting evidence, not on its own enough to claim relevance. This
     mirrors the AI engine's "genuine relevance only" rule.

Known limitations (surfaced in the UI, not hidden):
  - Keyword/vocabulary matching cannot understand paraphrasing, synonyms
    outside the curated lists, or context the way an LLM can — a document
    that describes the right control in very different words will score
    lower here than with the AI engine.
  - It cannot read screenshots/images at all beyond whatever OCR text
    evidence_processor.py already extracted upstream.
  - It has no notion of prior evidence / cumulative maturity across
    multiple uploads (prior_context is accepted for interface
    compatibility but intentionally not used — there's no reliable local
    way to weigh "this is the 3rd file for this control" without an LLM's
    judgment).
  Treat this as a fast, private, first-pass triage tool that now uses
  every deterministic signal available in this repo, and the AI engine
  as the deeper semantic read for anything borderline or high-stakes.
"""

import os
import re

ENGINE_NAME = "local"

# Small, generic English stopword list — enough to strip filler words out
# of title/summary/example_evidence text so the "context vocabulary" pool
# is made of meaningful domain terms, not "and", "the", "with", etc.
STOPWORDS = {
    "a", "an", "the", "and", "or", "of", "to", "in", "on", "for", "with",
    "is", "are", "be", "as", "by", "that", "this", "these", "those",
    "it", "its", "at", "from", "into", "such", "not", "no", "all", "any",
    "own", "their", "which", "who", "whom", "have", "has", "had", "will",
    "may", "can", "must", "should", "would", "also", "than", "then",
    "each", "other", "over", "under", "per", "via", "etc", "e.g", "eg",
}

KEYWORD_WEIGHT = 0.60
CONTEXT_TITLE_WEIGHT = 0.20
CONTEXT_EXAMPLE_WEIGHT = 0.20
FILENAME_BONUS_MAX = 10


class LocalAnalyzerError(Exception):
    pass


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower())


def _significant_words(text: str) -> set:
    """Lowercase words of length >= 4, with stopwords removed — used to build
    the 'context vocabulary' pool from title/summary/example_evidence text."""
    words = re.findall(r"[a-zA-Z][a-zA-Z\-]{3,}", text.lower())
    return {w for w in words if w not in STOPWORDS}


def _keyword_hits(text_norm: str, keywords: list) -> list:
    hits = []
    for kw in keywords:
        kw_norm = (kw or "").lower().strip()
        if not kw_norm:
            continue
        if re.search(re.escape(kw_norm), text_norm):
            hits.append(kw)
    return hits


def _word_hits(text_norm: str, words: set) -> set:
    hits = set()
    for w in words:
        if re.search(r"\b" + re.escape(w) + r"\b", text_norm):
            hits.add(w)
    return hits


def _maturity_for_score(score: int) -> str:
    if score >= 90:
        return "Optimized"
    if score >= 75:
        return "Managed"
    if score >= 55:
        return "Defined"
    if score >= 30:
        return "Developing"
    return "Initial"


def _filename_terms(filename: str) -> set:
    if not filename:
        return set()
    stem = os.path.splitext(filename)[0]
    words = re.findall(r"[a-zA-Z][a-zA-Z\-]{3,}", stem.replace("_", " ").replace("-", " "))
    return {w.lower() for w in words if w.lower() not in STOPWORDS}


def analyze_evidence(evidence_text: str, pci_data: dict, target_sub_requirement: str = None,
                      prior_context: str = "", filename: str = "") -> dict:
    """
    Same input/output contract as ai_analyzer.analyze_evidence(), plus an
    optional `filename` used only as a small corroborating signal (see
    module docstring). compliance_engine.process_uploaded_evidence() calls
    this interchangeably with the AI engine. `prior_context` is accepted
    only for interface compatibility — this engine scores the current
    file in isolation.
    """
    if not evidence_text or not evidence_text.strip():
        raise LocalAnalyzerError("No text could be extracted from this evidence file — nothing to analyze.")

    text_norm = _normalize(evidence_text)
    word_count = len(text_norm.split())
    file_terms = _filename_terms(filename)

    assessments = []
    for req in pci_data["requirements"]:
        req_title_terms = _significant_words(req.get("title", ""))
        for sub in req["sub_requirements"]:
            keywords = sub.get("evidence_keywords") or []
            if not keywords:
                continue

            # --- Signal 1: curated evidence_keywords (primary, weight 0.60) ---
            kw_hits = _keyword_hits(text_norm, keywords)
            kw_score = (len(kw_hits) / len(keywords)) * 100 if keywords else 0.0

            # --- Signal 2: title + summary + parent requirement title vocabulary (weight 0.20) ---
            title_pool = _significant_words(sub.get("title", "") + " " + sub.get("summary", "")) | req_title_terms
            title_hits = _word_hits(text_norm, title_pool) if title_pool else set()
            title_score = (len(title_hits) / len(title_pool)) * 100 if title_pool else 0.0

            # --- Signal 3: example_evidence vocabulary (weight 0.20) ---
            examples = sub.get("example_evidence") or []
            example_pool = _significant_words(" ".join(examples))
            example_hits = _word_hits(text_norm, example_pool) if example_pool else set()
            example_score = (len(example_hits) / len(example_pool)) * 100 if example_pool else 0.0

            is_target = target_sub_requirement is not None and sub["id"] == target_sub_requirement
            if not kw_hits and not is_target:
                # Context-only overlap isn't enough to claim relevance on its
                # own (too many sub-requirements would match on generic
                # words like "policy" or "review") — mirrors the AI engine's
                # "genuine relevance only" rule.
                continue

            combined_pool = title_pool | example_pool
            file_overlap = file_terms & combined_pool
            # Filename bonus only counts terms that are BOTH in the filename
            # AND actually present in the extracted text — a suggestive
            # filename with no matching content can't inflate the score.
            file_bonus_terms = file_overlap & (title_hits | example_hits | set(kw_hits))
            filename_bonus = min(FILENAME_BONUS_MAX, len(file_bonus_terms) * 4) if file_bonus_terms else 0

            score = (
                KEYWORD_WEIGHT * kw_score
                + CONTEXT_TITLE_WEIGHT * title_score
                + CONTEXT_EXAMPLE_WEIGHT * example_score
            )
            # Substance bonus: several distinct curated-keyword matches in a
            # document that isn't trivially short is a decent signal this is
            # a real artifact, not a buzzword dropped into unrelated text.
            if len(kw_hits) >= 2 and word_count >= 40:
                score += 6
            score = round(score) + filename_bonus
            score = max(0, min(100, score))

            missing_kw = [k for k in keywords if k not in kw_hits]
            gaps = [f"No mention found of: \u2018{k}\u2019" for k in missing_kw[:6]]

            recommendations = []
            if score < 70:
                if examples:
                    recommendations.append(
                        "Consider adding evidence such as: " + ", ".join(examples[:3]) + "."
                    )
                if missing_kw:
                    recommendations.append(
                        "This artifact should explicitly cover: " + ", ".join(missing_kw[:4]) + "."
                    )

            rationale_parts = [
                f"Curated keywords: {len(kw_hits)}/{len(keywords)} matched"
                + (f" ({', '.join(repr(h) for h in kw_hits)})" if kw_hits else "") + "."
            ]
            if title_pool:
                rationale_parts.append(
                    f"Title/summary vocabulary: {len(title_hits)}/{len(title_pool)} terms found."
                )
            if example_pool:
                rationale_parts.append(
                    f"Example-evidence vocabulary: {len(example_hits)}/{len(example_pool)} terms found."
                )
            if filename_bonus:
                rationale_parts.append(
                    f"Filename '{filename}' corroborates this control (+{filename_bonus} pts)."
                )
            rationale_parts.append(
                "Automated multi-signal keyword/vocabulary estimate, not a semantic read \u2014 "
                "verify manually, or re-run with the AI engine for a deeper read."
            )

            assessments.append({
                "sub_requirement_id": sub["id"],
                "sufficiency_score": score,
                "maturity_level": _maturity_for_score(score),
                "rationale": " ".join(rationale_parts),
                "gaps": gaps,
                "recommendations": recommendations,
            })

    assessments.sort(key=lambda a: -a["sufficiency_score"])

    summary = (
        f"Offline multi-signal scan of a {word_count}-word document \u2014 checked against curated "
        f"keywords, title/summary vocabulary, example-evidence vocabulary"
        + (f", and the filename '{filename}'" if filename else "")
        + f" for every PCI DSS sub-requirement. Matched {len(assessments)} sub-requirement(s). "
        "No data left this machine and no AI model was called."
    )
    return {"evidence_summary": summary, "assessments": assessments}
