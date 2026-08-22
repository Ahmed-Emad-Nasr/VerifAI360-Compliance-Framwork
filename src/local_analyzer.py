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
from difflib import SequenceMatcher

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

# Every tunable number the scoring model uses lives in one dict, so the
# Settings page can override any of them (persisted via
# database.get_settings_json("local_engine_weights")) without touching
# code. Values here are the defaults used when nothing is overridden.
DEFAULT_WEIGHTS = {
    "keyword": 0.60,          # curated evidence_keywords — primary signal
    "title": 0.20,            # sub-requirement title/summary + parent req title vocabulary
    "example": 0.20,          # example_evidence vocabulary
    "fuzzy_credit": 0.70,     # a fuzzy (typo-tolerant) keyword match counts as this fraction of an exact one
    "fuzzy_threshold": 0.84,   # SequenceMatcher similarity ratio (0-1) required to count as a fuzzy match
    "filename_bonus_max": 10,  # cap on points added when the filename corroborates matched content
    "substance_bonus": 6,      # small bonus when >=2 distinct keywords matched in a non-trivial document
}


class LocalAnalyzerError(Exception):
    pass


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower())


def _significant_words(text: str) -> set:
    """Lowercase words of length >= 4, with stopwords removed — used to build
    the 'context vocabulary' pool from title/summary/example_evidence text."""
    words = re.findall(r"[a-zA-Z][a-zA-Z\-]{3,}", text.lower())
    return {w for w in words if w not in STOPWORDS}


def _fuzzy_ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


# Improvement: negation-awareness. Without this, a document that literally
# says "we do NOT have a documented firewall policy" would score a hit for
# the keyword "firewall policy" — exactly backwards, since the sentence is
# reporting the *absence* of the control, not evidence of it.
NEGATION_CUES = {
    "no", "not", "without", "lacks", "lacking", "missing", "none", "never",
    "isn't", "isnt", "doesn't", "doesnt", "don't", "dont", "didn't", "didnt",
    "hasn't", "hasnt", "haven't", "havent", "wasn't", "wasnt", "weren't", "werent",
    "insufficient", "unable", "fails", "failed", "absence", "lacked",
}


def _is_negated(text_norm: str, match_start: int, window_chars: int = 45) -> bool:
    """Checks the short span of text immediately before a keyword match for a
    negation cue ('no firewall policy', 'does not have a firewall policy'),
    within the SAME sentence only — a negation cue from an earlier, unrelated
    sentence doesn't carry over."""
    if match_start <= 0:
        return False
    start = max(0, match_start - window_chars)
    preceding = text_norm[start:match_start]
    last_boundary = max(preceding.rfind(". "), preceding.rfind("! "),
                         preceding.rfind("? "), preceding.rfind("\n"))
    if last_boundary != -1:
        preceding = preceding[last_boundary + 1:]
    preceding_words = re.findall(r"[a-z']+", preceding)
    return any(w in NEGATION_CUES or w.endswith("n't") for w in preceding_words)


def _word_offsets(text_words: list) -> list:
    """Character offset of each word within the normalized text. Computed once
    per document and reused for every keyword — the previous implementation
    re-walked the whole word list for each keyword just to know where a match
    landed."""
    offsets = []
    pos = 0
    for word in text_words:
        offsets.append(pos)
        pos += len(word) + 1  # +1 for the single space _normalize() guarantees
    return offsets


# Float slack for the length band below. Without it a window sitting exactly
# on the boundary (e.g. a 2-character window against a 3-character keyword at
# threshold 0.80, whose true ratio is exactly 0.80) gets rejected, because the
# bound computes as 2.0000000000000004 rather than 2.0. That silently dropped
# real matches, so the band is widened by an amount far below one character.
_BAND_EPSILON = 1e-9


def _length_band(keyword_len: int, threshold: float):
    """
    The range of window lengths that could still clear `threshold`, so
    everything outside it can be rejected without any comparison at all.

    difflib's ratio is 2*M/T, where M is the number of matched characters and
    T is the combined length of both strings. M can never exceed the shorter
    string's length, so a window shorter than
    `keyword_len * threshold / (2 - threshold)` — or longer than its
    reciprocal — cannot reach the threshold no matter what its characters
    are. This is an exact bound, not a heuristic: nothing that could have
    matched is ever skipped.
    """
    return (keyword_len * threshold / (2 - threshold) - _BAND_EPSILON,
            keyword_len * (2 - threshold) / threshold + _BAND_EPSILON)


def _keyword_hits(text_norm: str, keywords: list, fuzzy_threshold: float):
    """Returns (exact_hits, fuzzy_hits, negated_hits). Exact hits are literal
    substring matches (full credit). Fuzzy hits are near-misses — e.g. a typo
    like 'firewal policy' instead of 'firewall policy' — found by sliding a
    same-length word-window across the text and comparing it to the keyword
    phrase with difflib's similarity ratio. Fuzzy hits get partial credit
    (see DEFAULT_WEIGHTS['fuzzy_credit']) and are always labeled as fuzzy in
    the rationale, never silently treated as an exact match. A match (exact
    or fuzzy) found immediately after a negation cue in the same sentence is
    routed to negated_hits instead — it's evidence the control is MISSING,
    not evidence it exists, so it must never count toward the score."""
    text_words = text_norm.split()
    n_words = len(text_words)
    offsets = _word_offsets(text_words)

    # Windows of a given word-count are shared by every keyword of that length,
    # and the same phrase usually recurs many times in one document, so each
    # set is built once and DEDUPLICATED. Comparing 'access control' against
    # the same window text forty times cannot produce forty different answers.
    # First appearance wins, which preserves the original "earliest window with
    # a strictly better ratio" tie-break exactly.
    window_cache = {}

    def windows_of(size):
        if size not in window_cache:
            first_seen = {}
            for i in range(0, max(0, n_words - size + 1)):
                window = text_words[i] if size == 1 else " ".join(text_words[i:i + size])
                if window not in first_seen:
                    first_seen[window] = offsets[i]
            window_cache[size] = list(first_seen.items())
        return window_cache[size]

    exact_hits, fuzzy_hits, negated_hits = [], [], []

    # One reusable matcher instead of constructing a fresh SequenceMatcher per
    # window. Note the argument order: the keyword must be sequence *a* and the
    # window sequence *b*, matching the original implementation — difflib's
    # ratio() is not symmetric, and swapping them changes borderline results.
    matcher = SequenceMatcher(None)

    for kw in keywords:
        kw_norm = (kw or "").lower().strip()
        if not kw_norm:
            continue

        m = re.search(re.escape(kw_norm), text_norm)
        if m:
            (negated_hits if _is_negated(text_norm, m.start()) else exact_hits).append(kw)
            continue

        # No exact match — fall back to the fuzzy scan. This previously ran
        # difflib's full ratio() against every window position in the document
        # for every keyword. On a real policy PDF (tens of thousands of words
        # against ~200 curated keywords) that took over a minute with the UI
        # frozen. Two exact upper-bound filters now reject the overwhelming
        # majority of candidates before any real comparison happens:
        #   1. length band  — pure arithmetic, no character comparison at all
        #   2. quick_ratio  — difflib's own documented upper bound on ratio()
        # Because both are upper bounds, anything they reject provably could
        # not have cleared the threshold. The hits this returns are identical
        # to the previous implementation's at every threshold; the work that
        # disappeared was arithmetic whose outcome was already decided.
        kw_word_count = len(kw_norm.split())
        min_len, max_len = _length_band(len(kw_norm), fuzzy_threshold)
        matcher.set_seq1(kw_norm)

        best = 0.0
        best_char_pos = None
        for window, char_pos in windows_of(kw_word_count):
            window_len = len(window)
            if window_len < min_len or window_len > max_len:
                continue
            matcher.set_seq2(window)
            if matcher.quick_ratio() < fuzzy_threshold:
                continue
            ratio = matcher.ratio()
            if ratio > best:
                best = ratio
                best_char_pos = char_pos
                if best >= 0.999:
                    break

        if best >= fuzzy_threshold:
            is_neg = best_char_pos is not None and _is_negated(text_norm, best_char_pos)
            (negated_hits if is_neg else fuzzy_hits).append(kw)

    return exact_hits, fuzzy_hits, negated_hits


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
                      prior_context: str = "", filename: str = "", weights: dict = None) -> dict:
    """
    Same input/output contract as ai_analyzer.analyze_evidence(), plus two
    local-only extras: `filename` (a small corroborating signal — see
    module docstring) and `weights` (overrides for DEFAULT_WEIGHTS, e.g.
    from the Settings page via database.get_settings_json("local_engine_weights")).
    compliance_engine.process_uploaded_evidence() calls this interchangeably
    with the AI engine. `prior_context` is accepted only for interface
    compatibility — this engine scores the current file in isolation.
    """
    if not evidence_text or not evidence_text.strip():
        raise LocalAnalyzerError("No text could be extracted from this evidence file — nothing to analyze.")

    w = {**DEFAULT_WEIGHTS, **(weights or {})}

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

            # --- Signal 1: curated evidence_keywords, exact + fuzzy (primary) ---
            exact_hits, fuzzy_hits, negated_hits = _keyword_hits(text_norm, keywords, w["fuzzy_threshold"])
            weighted_hit_count = len(exact_hits) + w["fuzzy_credit"] * len(fuzzy_hits)
            kw_score = (weighted_hit_count / len(keywords)) * 100 if keywords else 0.0

            # --- Signal 2: title + summary + parent requirement title vocabulary ---
            title_pool = _significant_words(sub.get("title", "") + " " + sub.get("summary", "")) | req_title_terms
            title_hits = _word_hits(text_norm, title_pool) if title_pool else set()
            title_score = (len(title_hits) / len(title_pool)) * 100 if title_pool else 0.0

            # --- Signal 3: example_evidence vocabulary ---
            examples = sub.get("example_evidence") or []
            example_pool = _significant_words(" ".join(examples))
            example_hits = _word_hits(text_norm, example_pool) if example_pool else set()
            example_score = (len(example_hits) / len(example_pool)) * 100 if example_pool else 0.0

            is_target = target_sub_requirement is not None and sub["id"] == target_sub_requirement
            if not exact_hits and not fuzzy_hits and not is_target:
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
            file_bonus_terms = file_overlap & (title_hits | example_hits | set(exact_hits) | set(fuzzy_hits))
            filename_bonus = min(w["filename_bonus_max"], len(file_bonus_terms) * 4) if file_bonus_terms else 0

            score = w["keyword"] * kw_score + w["title"] * title_score + w["example"] * example_score
            # Substance bonus: several distinct curated-keyword matches in a
            # document that isn't trivially short is a decent signal this is
            # a real artifact, not a buzzword dropped into unrelated text.
            if (len(exact_hits) + len(fuzzy_hits)) >= 2 and word_count >= 40:
                score += w["substance_bonus"]
            score = round(score) + filename_bonus
            score = max(0, min(100, score))

            found_kw = set(exact_hits) | set(fuzzy_hits)
            missing_kw = [k for k in keywords if k not in found_kw and k not in negated_hits]
            gaps = [f"No mention found of: \u2018{k}\u2019" for k in missing_kw[:6]]
            if negated_hits:
                gaps = [
                    f"Document explicitly states this is MISSING/absent: \u2018{k}\u2019"
                    for k in negated_hits[:4]
                ] + gaps

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
                f"Curated keywords: {len(exact_hits)}/{len(keywords)} exact match"
                + (f" ({', '.join(repr(h) for h in exact_hits)})" if exact_hits else "") + "."
            ]
            if fuzzy_hits:
                rationale_parts.append(
                    f"+{len(fuzzy_hits)} fuzzy/typo-tolerant match"
                    f"{'es' if len(fuzzy_hits) != 1 else ''} ({', '.join(repr(h) for h in fuzzy_hits)}), "
                    f"counted at {int(w['fuzzy_credit'] * 100)}% credit."
                )
            if negated_hits:
                rationale_parts.append(
                    f"{len(negated_hits)} mention{'s' if len(negated_hits) != 1 else ''} of "
                    f"({', '.join(repr(h) for h in negated_hits)}) appeared in a negative context "
                    "(e.g. 'no ...', 'does not have ...') and was correctly excluded, not counted as a match."
                )
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
        f"keywords (with typo-tolerant fuzzy matching), title/summary vocabulary, example-evidence "
        f"vocabulary"
        + (f", and the filename '{filename}'" if filename else "")
        + f" for every PCI DSS sub-requirement. Matched {len(assessments)} sub-requirement(s). "
        "No data left this machine and no AI model was called."
    )
    return {"evidence_summary": summary, "assessments": assessments}
