"""
app.py — VerifAI 360 Streamlit application entry point (the whole UI lives here).

Run with:
    streamlit run app.py

Requires GOOGLE_API_KEY to be set (see .env.example) for the
"Upload & Analyze" page. All other pages work purely off the local
SQLite database and need no API key.

HOW THIS FILE IS ORGANIZED (read this first — it's ~1250 lines, but the shape is simple)
------------------------------------------------------------------------------------------
Streamlit re-runs this ENTIRE script from top to bottom every time the user
clicks something. There is no separate "backend" process — this script IS
the backend and the frontend at once. To keep that manageable, the file is
split into three parts:

  1. SETUP (top of the file): imports, theme/CSS, small reusable helper
     functions like page_header(), and the sidebar navigation menu that
     decides which page name is currently selected (the `page` variable).

  2. PAGES (the big `if / elif` chain that makes up most of the file): each
     `elif page == "...":` block is one screen of the app. Only ONE of
     these blocks actually runs on any given script execution — Streamlit
     "navigating" to a different page just means the user picked a
     different sidebar option, so on the next re-run a different `elif`
     branch executes instead. Each page block only talks to the `src/`
     modules (database, compliance_engine, risk_engine, ai_analyzer,
     report_generator, scoping_data) to get/save data — this file itself
     contains almost no business logic, only "ask src/ for data, then
     draw it with Streamlit widgets".

  3. Nothing runs "at the end" in the traditional sense — whichever page
     block matched `page` is the last code that executed for this run.

If you're looking for where a specific number/calculation comes from,
it is NOT computed in this file — search inside `src/` instead (this file
only displays what `src/` returns).
"""

import os
import tempfile
import secrets
import datetime
import json
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv

load_dotenv()

from src import database as db
from src import compliance_engine as ce
from src import risk_engine as re_
from src import report_generator as rg
from src import ai_analyzer as ai
from src import scoping_data as sd
from src import local_analyzer as la
from src.ai_analyzer import AIAnalyzerError
from src.local_analyzer import LocalAnalyzerError
from src.evidence_processor import EvidenceExtractionError
from src.compliance_engine import EvidenceUploadError, DuplicateEvidenceError
from src import security as sec
from src import data_portability as dp
from src import theme

st.set_page_config(page_title="VerifAI 360 — PCI DSS Compliance", page_icon="🛡️", layout="wide")
db.init_db()

# ----------------------------------------------------------------------------
# Theme / global styling
#
# The stylesheet used to live here as a ~300-line string literal. It now
# lives in src/theme.py, which also exports the design tokens the Plotly
# charts on this page use — so a colour is defined in exactly one place
# instead of being duplicated between the CSS and every chart call.
# ----------------------------------------------------------------------------
theme.inject()

# ----------------------------------------------------------------------------
# App-level passcode gate (see src/security.py for the full design rationale).
# One shared passcode, entered once per browser session, required before any
# page renders. If APP_PASSCODE was never configured, one is auto-generated
# and written to .env on first run — auth is never silently disabled.
# ----------------------------------------------------------------------------
if not st.session_state.get("authenticated", False):
    sec.get_or_create_passcode()  # auto-generates + persists to .env on first run if missing

    # Brute-force throttling: identify the caller by IP when Streamlit exposes
    # it, falling back to a per-session identity (still throttles a single
    # browser/session hammering the form even when IP isn't available — see
    # src/security.py for the full scope note on this control's limits).
    _client_key = getattr(st.context, "ip_address", None) or st.session_state.get("_client_fallback_id")
    if not _client_key:
        _client_key = secrets.token_hex(8)
        st.session_state["_client_fallback_id"] = _client_key

    st.markdown('<div class="vf-login-wrap">', unsafe_allow_html=True)
    st.markdown(
        '<div class="vf-icon-big">🛡️</div>'
        '<h1>VerifAI 360</h1>'
        '<p class="vf-login-tag">RESTRICTED ACCESS — ENTER PASSCODE TO CONTINUE</p>',
        unsafe_allow_html=True,
    )

    _locked, _remaining = sec.check_lockout(_client_key)
    if _locked:
        st.error(
            f"Too many incorrect attempts. Try again in {int(_remaining) + 1} seconds."
        )
        entered = st.text_input("Passcode", type="password", label_visibility="collapsed",
                                 placeholder="Enter passcode", disabled=True)
        st.button("🔓 Unlock", type="primary", width='stretch', disabled=True)
    else:
        entered = st.text_input("Passcode", type="password", label_visibility="collapsed",
                                 placeholder="Enter passcode")
        if st.button("🔓 Unlock", type="primary", width='stretch'):
            if sec.check_passcode(entered):
                sec.record_successful_attempt(_client_key)
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                sec.record_failed_attempt(_client_key)
                st.error("Incorrect passcode.")

    with st.expander("First time here? / أول مرة تفتح التطبيق؟"):
        st.caption(
            "No passcode was configured, so one was generated automatically and saved to your "
            "`.env` file as `APP_PASSCODE`. Open that file to find it, or set your own value there "
            "and restart the app. Anyone with this passcode can see and edit all data in this app — "
            "share it only with people who should have that access."
        )
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()


def page_header(icon: str, title: str, subtitle: str = "", about: str = ""):
    """Consistent icon + title (+ optional subtitle) header used at the top of every page.

    `about`, when provided, renders a collapsed "What is this page & why does it exist?"
    expander right under the header — meant for walking someone else through the app
    (a mentor, a client, an interviewer) without having to explain each screen from memory.
    """
    sub_html = f'<div class="vf-subtitle">{subtitle}</div>' if subtitle else ""
    st.markdown(
        f"""
        <div class="vf-page-header">
            <div class="vf-icon">{icon}</div>
            <div><h1>{title}</h1>{sub_html}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if about:
        with st.expander("🛈 What this page does, and why it exists", expanded=False):
            st.markdown(about)
    st.write("")  # small breathing room below the header



# ----------------------------------------------------------------------------
# Cached report builders
#
# st.download_button needs its bytes up front, so calling
# rg.generate_pdf_report() inline meant the whole PDF was rebuilt on EVERY
# rerun of the page — every filter change, every expander click. These
# wrappers are keyed on db.data_fingerprint(), so a report is built once and
# then reused until the underlying data actually changes.
# ----------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def cached_full_report(_fingerprint: str) -> bytes:
    return rg.generate_pdf_report()


@st.cache_data(show_spinner=False)
def cached_executive_summary(_fingerprint: str) -> bytes:
    return rg.generate_executive_summary_pdf()


@st.cache_data(show_spinner=False)
def cached_data_export(_fingerprint: str) -> str:
    return dp.export_all_data_json()


def risk_badge(level: str) -> str:
    cls = {"Critical": "vf-badge-critical", "High": "vf-badge-high",
           "Medium": "vf-badge-medium", "Low": "vf-badge-low"}.get(level, "vf-badge-low")
    return f'<span class="vf-badge {cls}">{level}</span>'


def risk_badge_emoji(level: str) -> str:
    return {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(level, "⚪")


def demo_banner(text: str):
    st.markdown(f'<div class="vf-demo-banner">🧪 <b>Simulated data —</b> {text}</div>', unsafe_allow_html=True)


# ----------------------------------------------------------------------------
# Sidebar navigation
# ----------------------------------------------------------------------------
LANG = st.session_state.get("lang", "en")


def t(en: str, ar: str) -> str:
    """Tiny translation helper — returns the Arabic string when the sidebar
    language toggle is set to Arabic, English otherwise. Currently covers
    navigation labels, page titles/subtitles, and the sidebar chrome — the
    highest-traffic strings for walking someone through a demo. Full-page
    body text (About boxes, form fields) stays English-only for now."""
    return ar if LANG == "ar" else en


st.sidebar.markdown(
    """
    <div class="vf-brand">
        <span style="font-size:1.55rem;">🛡️</span>
        <span class="vf-brand-title">VerifAI 360<span class="vf-brand-cursor"></span></span>
    </div>
    """,
    unsafe_allow_html=True,
)
st.sidebar.caption(t("AI-driven PCI DSS self-assessment", "تقييم ذاتي لمعيار PCI DSS مدعوم بالذكاء الاصطناعي"))

_tt_counts = ce.testing_tracker_summary()
_overdue_suffix = f" ({_tt_counts['Overdue']} overdue)" if _tt_counts["Overdue"] else ""

_core_labels_en = [
    "🎯 SAQ Scoping",
    "📤 Upload & Analyze",
    "📊 Compliance Dashboard",
    "🗺️ CDE Scope",
    "🛡️ Compensating Controls",
    f"🧪 Testing Tracker (Req 11){_overdue_suffix}",
    "🤝 Vendor / TPSP Register",
    "⚠️ Identified Risks",
    "🕳️ Gap Report",
    "📚 Requirement Explorer",
    "🗂️ Evidence Log",
]
_core_labels_ar = [
    "🎯 نطاق SAQ",
    "📤 رفع وتحليل الأدلة",
    "📊 لوحة الامتثال",
    "🗺️ نطاق CDE",
    "🛡️ الضوابط التعويضية",
    f"🧪 متابعة الاختبارات (متطلب 11){_overdue_suffix}",
    "🤝 سجل الموردين",
    "⚠️ المخاطر المرصودة",
    "🕳️ تقرير الفجوات",
    "📚 دليل متطلبات PCI DSS",
    "🗂️ سجل الأدلة",
]
# Pair the two labels each page has so the language toggle can swap one
# for the other without losing track of which page the user is on.
_LANG_TWIN = {}
for _en, _ar in zip(_core_labels_en, _core_labels_ar):
    _pair = {"en": _en, "ar": _ar}
    _LANG_TWIN[_en] = _pair
    _LANG_TWIN[_ar] = _pair

lang_col, review_col = st.sidebar.columns(2)
with lang_col:
    if st.button("🇬🇧 EN" if LANG == "ar" else "🇪🇬 AR", key="_lang_toggle", width='stretch'):
        new_lang = "en" if LANG == "ar" else "ar"
        # Carry the currently-open page across the switch. The nav radio's
        # options are rebuilt in the new language on the next run, so its
        # stored value would otherwise no longer be one of them and the
        # highlight would silently snap back to the first item while a
        # different page stayed on screen.
        _active = st.session_state.get("_active_page")
        if _active in _LANG_TWIN:
            twin = _LANG_TWIN[_active][new_lang]
            st.session_state["_active_page"] = twin
            st.session_state["_core_radio"] = twin
        st.session_state["lang"] = new_lang
        st.rerun()
with review_col:
    reviewer_mode = st.toggle("🔒 " + t("Reviewer", "مراجعة فقط"), key="reviewer_mode",
                               help=t(
                                   "Read-only mode: hides/disables every button that adds, edits, "
                                   "deletes, or analyzes data. Safe to hand this session to someone "
                                   "you're demoing the app to.",
                                   "وضع القراءة فقط: بيعطّل كل زرار بيضيف أو يعدّل أو يحلل بيانات — "
                                   "مناسب لما تسيب حد يتصفح التطبيق من غير ما يقدر يغيّر حاجة."
                               ))
if reviewer_mode:
    st.sidebar.markdown(
        f'<div class="vf-readonly-banner">🔒 {t("Reviewer mode is ON — editing disabled", "وضع المراجعة شغّال — التعديل متوقف")}</div>',
        unsafe_allow_html=True,
    )

st.sidebar.markdown(f'<div class="vf-nav-caption">{t("Workspace", "مساحة العمل")}</div>', unsafe_allow_html=True)


def _activate_core():
    st.session_state["_active_page"] = st.session_state["_core_radio"]


def _activate_demo():
    st.session_state["_active_page"] = st.session_state["_demo_radio"]


def _activate_settings():
    st.session_state["_active_page"] = st.session_state["_settings_radio"]


_core_labels = _core_labels_ar if LANG == "ar" else _core_labels_en
# Map BOTH language's labels back to the stable English id, not just the
# currently-displayed one. `_active_page` below persists across reruns, so
# right after a language toggle it still holds the label from the PREVIOUS
# language — if that label isn't in this map, page-matching falls through
# every `elif` and the user gets a blank screen.
_core_id_by_label = {
    **dict(zip(_core_labels_ar, _core_labels_en)),
    **dict(zip(_core_labels_en, _core_labels_en)),
}

core_page = st.sidebar.radio(
    "Navigate", _core_labels, label_visibility="collapsed", key="_core_radio", on_change=_activate_core,
)
st.sidebar.markdown(f'<div class="vf-nav-caption">{t("Settings", "الإعدادات")}</div>', unsafe_allow_html=True)
settings_page = st.sidebar.radio(
    "Settings", ["⚙️ Settings & Security"], label_visibility="collapsed",
    index=None, key="_settings_radio", on_change=_activate_settings,
)
st.sidebar.markdown(f'<div class="vf-nav-caption">{t("Roadmap · Demo", "خارطة الطريق · تجريبي")}</div>', unsafe_allow_html=True)
demo_page = st.sidebar.radio(
    "Demo pages",
    [
        "🔌 Automated Connectors (demo)",
        "📡 Alerts & Drift (demo)",
        "🧾 QSA Audit View (demo)",
    ],
    label_visibility="collapsed",
    index=None,
    key="_demo_radio",
    on_change=_activate_demo,
)
# on_change only fires on the widget the user actually just touched, so this
# correctly survives unrelated reruns (e.g. clicking a button on a demo page)
# without silently snapping back to the workspace radio's stale selection.
if "_active_page" not in st.session_state:
    st.session_state["_active_page"] = core_page
page_raw = st.session_state["_active_page"]
# Translate an Arabic-selected core label back to its stable English id
# before stripping the emoji, so the rest of the app's page-matching logic
# (which all compares against English strings) doesn't need to know about i18n.
page_raw = _core_id_by_label.get(page_raw, page_raw)
# Strip the leading emoji + space for internal page-matching logic below.
page = page_raw.split(" ", 1)[1] if page_raw and " " in page_raw else page_raw
# Testing Tracker's label carries a dynamic "(N overdue)" suffix — strip it
# back to the stable page id too.
if page.startswith("Testing Tracker (Req 11)"):
    page = "Testing Tracker (Req 11)"

st.sidebar.divider()
_n_keys = ai.get_key_count()
if _n_keys == 0:
    st.sidebar.warning(
        "GOOGLE_API_KEY is not set. Get a free key at aistudio.google.com/apikey "
        "and set it in a `.env` file to enable AI analysis. The Local engine works with no key."
    )
elif _n_keys == 1:
    st.sidebar.markdown(
        '<div style="display:flex;align-items:center;gap:6px;color:#71e6ab;font-size:0.85rem;">'
        '🟢 Gemini API key detected</div>',
        unsafe_allow_html=True,
    )
    st.sidebar.caption(
        "💡 Add `GOOGLE_API_KEY_2` (a second free key from another Google account) to your `.env` "
        "for automatic failover if this key's quota runs out."
    )
else:
    st.sidebar.markdown(
        f'<div style="display:flex;align-items:center;gap:6px;color:#71e6ab;font-size:0.85rem;">'
        f'🟢 {_n_keys} Gemini API keys detected — automatic failover enabled</div>',
        unsafe_allow_html=True,
    )
if st.sidebar.button("⚠️ Reset all demo data", disabled=reviewer_mode):
    _removed = db.reset_all()
    st.cache_data.clear()  # the cached PDFs describe data that no longer exists
    st.sidebar.success(
        f"All evidence, scores, and risks cleared ({_removed} stored evidence file(s) deleted)."
    )
    st.rerun()

st.sidebar.markdown(
    f"""
    <div class="vf-status-ticker">
        <span class="vf-status-dot"></span> SYSTEM ONLINE
        <span style="margin-left:auto;">🔒 ENCRYPTED</span>
    </div>
    <div class="vf-status-ticker">
        <span class="vf-status-dot {'vf-status-amber' if reviewer_mode else ''}"></span>
        {'READ-ONLY' if reviewer_mode else 'READ/WRITE'}
        <span style="margin-left:auto;">v1.1</span>
    </div>
    """,
    unsafe_allow_html=True,
)

pci_data = ce.load_pci_data()


def sub_req_options():
    opts = ["(let the AI decide — no specific target)"]
    id_map = {}
    for req in pci_data["requirements"]:
        for sub in req["sub_requirements"]:
            label = f"{sub['id']} — {sub['title']}"
            opts.append(label)
            id_map[label] = sub["id"]
    return opts, id_map


def requirement_id_for_sub(sub_id):
    return sub_id.split(".")[0] if sub_id else None


# ----------------------------------------------------------------------------
# PAGE: Upload & Analyze
#
# Plain-English summary: this is the "front door" of the app. The user picks
# a file (a policy doc, a screenshot, a scan report...) and, optionally, the
# specific PCI DSS sub-requirement it's meant to prove. Clicking "Analyze"
# saves the file to disk, sends its text to the AI (see src/ai_analyzer.py),
# and shows the AI's opinion: a 0-100 score, a maturity label, gaps, and
# recommendations. Everything the AI returns gets saved to the database by
# src/compliance_engine.process_uploaded_evidence().
# ----------------------------------------------------------------------------
if page == "Upload & Analyze":
    page_header("📤", t("Upload evidence for AI assessment", "رفع الأدلة للتقييم"),
                "Sufficiency scoring, cross-requirement mapping, and gap detection in one pass",
                about=(
                    "**This is the front door of the app.** You upload one or more artifacts — a "
                    "policy doc, a config screenshot, a scan report, anything — and optionally tell "
                    "it which PCI DSS sub-requirement it's meant to prove.\n\n"
                    "**Two analysis engines, your choice:** the **AI engine** sends the extracted text "
                    "to Google Gemini for a semantic read — best accuracy, needs an API key and network "
                    "access. The **Local engine** scores it against four fully offline signals mined "
                    "from `data/pci_dss_data.json` and the filename itself — curated evidence keywords "
                    "(with typo-tolerant fuzzy matching), title/summary vocabulary, example-evidence "
                    "vocabulary, and a filename cross-check, all weighted per **Settings → Local Engine** "
                    "— free, deterministic, and nothing leaves your machine, at the cost of not "
                    "understanding paraphrased or novel wording the way an LLM can. You can also run "
                    "**both engines side by side** on the same file to compare them directly.\n\n"
                    "**Either way you get:** a 0–100 sufficiency score, a maturity label, gaps, and "
                    "recommendations — sometimes mapping one file to *several* sub-requirements at once. "
                    "Re-uploading a file you've already submitted (same bytes, detected via SHA-256) "
                    "is flagged before it's re-analyzed, so you don't burn a second AI call by accident.\n\n"
                    "**Why it exists:** manually cross-checking each piece of evidence against 12 "
                    "requirements and dozens of sub-requirements is the slowest part of a real PCI DSS "
                    "self-assessment. This page automates that first read so a human only needs to "
                    "review and confirm, not start from a blank page."
                ))
    st.write(
        "Upload one or more policy documents, configuration screenshots, scan reports, or similar "
        "artifacts. The selected engine(s) will assess **sufficiency**, assign a **compliance/"
        "maturity score**, check for **cross-requirement spanning**, and generate **gap-remediation "
        "recommendations**."
    )

    n_keys = ai.get_key_count()
    compare_mode = st.checkbox(
        "🔬 Compare AI vs Local side by side (single file only)",
        help="Runs both engines on the same file and shows their results next to each other — useful "
             "for sanity-checking the Local engine's scores against the AI's deeper read. Nothing is "
             "saved in this mode: pick an engine and run it normally to record a score.",
    )

    if compare_mode:
        analysis_mode = None
        if n_keys == 0:
            st.warning("Compare mode needs a Gemini API key for the AI half — add `GOOGLE_API_KEY` "
                       "to your `.env`, or turn off Compare mode to use the Local engine alone.")
    else:
        engine_choice = st.radio(
            "Analysis engine",
            ["🤖 AI-powered (Gemini)", "🧩 Local rule-based (offline, no API needed)"],
            horizontal=True,
            index=0 if n_keys > 0 else 1,
            help=(
                "AI engine: deeper, context-aware read via Google Gemini — needs GOOGLE_API_KEY and "
                "network access. Local engine: instant, offline multi-signal scoring against the "
                "bundled PCI DSS catalog — no API key, no network call, no data leaves this machine."
            ),
        )
        analysis_mode = "local" if engine_choice.startswith("🧩") else "ai"
        if analysis_mode == "ai" and n_keys == 0:
            st.warning(
                "No Gemini API key detected — the AI engine will fail. Switch to **Local rule-based** "
                "above, or add `GOOGLE_API_KEY` to your `.env` file."
            )
        elif analysis_mode == "local":
            st.caption(
                "🧩 Local engine selected — scoring is multi-signal keyword/vocabulary based "
                "(transparent, tunable in Settings, but less nuanced than the AI read). Good for a "
                "fast first pass or when working offline."
            )

    opts, id_map = sub_req_options()
    col1, col2 = st.columns([2, 1])
    with col1:
        uploaded_files = st.file_uploader(
            "Evidence file(s)",
            type=["txt", "log", "csv", "json", "md", "conf", "cfg", "yaml", "yml",
                  "pdf", "docx", "png", "jpg", "jpeg", "bmp", "tiff"],
            accept_multiple_files=True,
            disabled=reviewer_mode,
        )
    with col2:
        target_label = st.selectbox("Primary target sub-requirement (optional)", opts)
        target_id = id_map.get(target_label)

    if compare_mode and uploaded_files and len(uploaded_files) > 1:
        st.warning("Compare mode only processes the **first** file when multiple are selected.")
        uploaded_files = uploaded_files[:1]


    def _run_one_engine(tmp_path, filename, mode, allow_dup, persist=True):
        """Runs process_uploaded_evidence for one file+engine, translating every known exception into
        a (result, error_message, duplicate_error) tuple instead of raising, so the caller can render
        results for whichever files/engines succeeded even if others in the same batch failed."""
        try:
            result = ce.process_uploaded_evidence(tmp_path, filename, target_id,
                                                    analysis_mode=mode, allow_duplicate=allow_dup,
                                                    persist=persist)
            return result, None, None
        except DuplicateEvidenceError as e:
            return None, None, e
        except EvidenceUploadError as e:
            return None, f"Upload rejected: {e}", None
        except EvidenceExtractionError as e:
            return None, f"Could not read this file: {e}", None
        except AIAnalyzerError as e:
            return None, f"AI analysis failed: {e}", None
        except LocalAnalyzerError as e:
            return None, f"Local analysis failed: {e}", None


    def _render_assessments(result):
        engine_label = ce.ANALYSIS_ENGINES.get(result.get("analysis_mode"), "")
        st.success(f"Analysis complete via **{engine_label}** — evidence recognized as: "
                   f"**{result['evidence_type']}**")
        st.info(result.get("evidence_summary", ""))
        dropped = result.get("dropped_sub_requirement_ids")
        if dropped:
            st.warning(
                "The AI referenced sub-requirement(s) that aren't in the bundled PCI DSS catalog: "
                + ", ".join(dropped)
                + ". They were discarded rather than saved, because a score filed against an "
                "unknown id would never appear on the dashboard."
            )
        assessments = sorted(result["assessments"], key=lambda a: -a["sufficiency_score"])
        if not assessments:
            st.warning("No relevant PCI DSS sub-requirement was found for this evidence in the catalog.")
            return
        st.caption(f"Mapped to {len(assessments)} sub-requirement(s)"
                   + (" — ✨ cross-requirement spanning detected" if len(assessments) > 1 else ""))
        for a in assessments:
            is_primary = a["sub_requirement_id"] == target_id
            title_prefix = "🎯 " if is_primary else "🔗 "
            with st.expander(
                f"{title_prefix}{a['sub_requirement_id']} — score {a['sufficiency_score']}/100 "
                f"({a['maturity_level']})",
                expanded=is_primary,
            ):
                st.progress(a["sufficiency_score"] / 100)
                st.write(a["rationale"])
                if a["gaps"]:
                    st.markdown("**Gaps identified:**")
                    for g in a["gaps"]:
                        st.markdown(f"- {g}")
                if a["recommendations"]:
                    st.markdown("**Recommendations:**")
                    for r in a["recommendations"]:
                        st.markdown(f"- {r}")


    if uploaded_files and st.button("🔍 Analyze evidence", type="primary", disabled=reviewer_mode):
        any_success = False
        for uploaded in uploaded_files:
            suffix = os.path.splitext(uploaded.name)[1]
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(uploaded.getbuffer())
                tmp_path = tmp.name
            file_hash = ce.sha256_of_file(tmp_path)
            allow_dup = st.session_state.get(f"_allow_dup_{file_hash}", False)

            st.divider()
            st.markdown(f"#### 📄 {uploaded.name}")

            if compare_mode:
                # Compare mode is a read-only side-by-side: both engines run with
                # persist=False. Previously the AI half saved an evidence row and
                # then the Local half saved a SECOND one for the same bytes, so a
                # single comparison counted the file twice on the dashboard and
                # left two scores in the register. Nothing is committed here — the
                # user picks an engine and re-runs to record a result.
                with st.spinner("Running both engines (comparison only — nothing is saved)..."):
                    r_ai, err_ai, _ = _run_one_engine(tmp_path, uploaded.name, "ai", True, persist=False)
                    r_local, err_local, _ = _run_one_engine(tmp_path, uploaded.name, "local", True, persist=False)

                ccol1, ccol2 = st.columns(2)
                with ccol1:
                    st.markdown("**🤖 AI (Gemini)**")
                    if err_ai:
                        st.error(err_ai)
                    elif r_ai:
                        _render_assessments(r_ai)
                with ccol2:
                    st.markdown("**🧩 Local (offline)**")
                    if err_local:
                        st.error(err_local)
                    elif r_local:
                        _render_assessments(r_local)

                if r_ai or r_local:
                    st.info(
                        "Comparison only — neither result was saved. Turn off Compare mode and run "
                        "the engine you want to keep to record a score against these sub-requirements."
                    )
            else:
                spinner_text = (
                    "Extracting evidence and running AI compliance analysis..."
                    if analysis_mode == "ai" else
                    "Extracting evidence and running local multi-signal analysis..."
                )
                with st.spinner(spinner_text):
                    result, err, dup = _run_one_engine(tmp_path, uploaded.name, analysis_mode, allow_dup)
                if dup:
                    st.warning(f"⚠️ {dup}")
                    if st.button("Analyze anyway", key=f"dup_{file_hash}", disabled=reviewer_mode):
                        st.session_state[f"_allow_dup_{file_hash}"] = True
                        st.rerun()
                elif err:
                    st.error(err)
                elif result:
                    _render_assessments(result)
                    any_success = True

            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        if any_success:
            st.divider()
            st.caption(
                "💡 Head to **Identified Risks** and click *Sync risks from gap report* to turn any "
                "unresolved gaps above into tracked risk items."
            )

# ----------------------------------------------------------------------------
# PAGE: Compliance Dashboard
#
# Plain-English summary: the "big picture" page. It calls
# compliance_engine.compute_compliance_summary() to turn every stored score
# into one overall percentage, a percentage per top-level requirement
# (1-12), and charts (bar chart per requirement, trend line of scores over
# time, risk heatmap). Nothing is computed here — this page only asks the
# compliance_engine / risk_engine for numbers and draws them with Plotly.
# ----------------------------------------------------------------------------
elif page == "Compliance Dashboard":
    page_header("📊", t("Compliance Dashboard", "لوحة الامتثال"),
                t("Overall PCI DSS posture, scoped to your selected SAQ type",
                  "الوضع العام للامتثال، محدد حسب نوع SAQ المختار"),
                about=(
                    "**This is the big-picture page.** It takes every score stored so far and rolls it "
                    "up into one overall compliance percentage, plus a percentage per top-level "
                    "requirement (1–12), a trend line of scores over time, and a risk heatmap.\n\n"
                    "**Nothing is calculated here** — this page only asks `compliance_engine` / "
                    "`risk_engine` for numbers and draws them with Plotly. The real math lives in `src/`.\n\n"
                    "**Why it exists:** it's the single screen you'd show a manager or a QSA to answer "
                    "\"where do we stand right now, and scoped to what actually applies to us?\""
                ))
    summary = ce.compute_compliance_summary()
    saq_def = sd.get_saq_definition(summary["saq_type"])
    risks = db.get_all_risks()
    exposure = re_.risk_exposure_summary(risks)

    if summary["saq_type"] == "Not yet determined":
        st.warning(
            "No SAQ type selected yet — showing all 12 requirements. Compliance % may be misleading "
            "for anyone using a smaller SAQ than D. Pick your SAQ type on the **SAQ Scoping** page."
        )
    else:
        st.info(
            f"Scoped to **{saq_def['label']}** — in-scope requirements: "
            f"{', '.join(summary['in_scope_requirement_ids'])}. Change this on the **SAQ Scoping** page."
        )

    st.download_button(
        "📄 Executive summary (1-page PDF)",
        cached_executive_summary(db.data_fingerprint()),
        file_name=f"verifai360_executive_summary_{datetime.date.today().isoformat()}.pdf",
        mime="application/pdf",
        help="A short, manager-facing PDF: headline %, SAQ scope, and per-requirement breakdown — "
             "no detailed evidence/vendor/testing tables. For the full audit trail, use "
             "'Generate audit PDF' on the QSA Audit View page.",
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Overall PCI DSS compliance", f"{summary['overall_pct']}%")
    n_evidence = len(db.get_all_evidence())
    c2.metric("Evidence artifacts submitted", n_evidence)
    n_compliant = sum(
        1 for r in summary["requirements"] for s in r["sub_requirements"] if s["status"] == "Compliant"
    )
    n_total = sum(len(r["sub_requirements"]) for r in summary["requirements"])
    c3.metric("Sub-requirements compliant", f"{n_compliant} / {n_total}")
    c4.metric("Open risk exposure", exposure["total_open_exposure"],
              help="Sum of (likelihood x impact) across every Open/Mitigating item in Identified Risks.")

    in_scope_reqs = [r for r in summary["requirements"] if r["in_scope"]]
    out_scope_reqs = [r for r in summary["requirements"] if not r["in_scope"]]
    df = pd.DataFrame(
        [{"Requirement": f"{r['id']}. {r['title']}", "Compliance %": r["pct"]} for r in in_scope_reqs]
    )
    fig = px.bar(df, x="Compliance %", y="Requirement", orientation="h", range_x=[0, 100],
                 color="Compliance %", color_continuous_scale=theme.CHART_SCALE)
    fig.update_layout(**theme.plotly_layout(
        height=max(180, 60 * len(in_scope_reqs)),
        yaxis={"categoryorder": "total ascending"},
    ))
    st.plotly_chart(fig, width='stretch')
    if out_scope_reqs:
        st.caption(
            "Not applicable under the current SAQ type: " +
            ", ".join(f"Req {r['id']}" for r in out_scope_reqs)
        )

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Historical Trend (Maturity vs Time)")
        history = db.get_score_history()
        if history:
            hdf = pd.DataFrame(history)
            hdf["recorded_at"] = pd.to_datetime(hdf["recorded_at"])
            trend = hdf.groupby(hdf["recorded_at"].dt.floor("min"))["score"].mean().reset_index()
            trend["cumulative_avg"] = trend["score"].expanding().mean()
            fig2 = go.Figure()
            fig2.add_trace(go.Scatter(x=trend["recorded_at"], y=trend["cumulative_avg"],
                                       mode="lines+markers", name="Running average score",
                                       line=dict(color=theme.CHART_LINE, width=3)))
            fig2.update_layout(**theme.plotly_layout(
                height=340, yaxis_title="Avg sufficiency score", xaxis_title="Time",
            ))
            st.plotly_chart(fig2, width='stretch')
        else:
            st.caption("No assessments yet — upload evidence to start building the maturity trend.")

    with col_b:
        st.subheader("Risk Heatmap (Open + Mitigating)")
        matrix = re_.heatmap_matrix(risks)
        fig3 = go.Figure(data=go.Heatmap(
            z=matrix,
            x=["1", "2", "3", "4", "5"],
            y=["5", "4", "3", "2", "1"],
            colorscale=theme.HEATMAP_SCALE,
            showscale=False,
            hovertemplate="Likelihood %{x}, Impact %{y}<br>Risks: %{z}<extra></extra>",
        ))
        fig3.update_layout(**theme.plotly_layout(
            height=340, xaxis_title="Likelihood", yaxis_title="Impact",
        ))
        st.plotly_chart(fig3, width='stretch')
        if exposure["critical_open"]:
            st.caption(f"⚠️ {exposure['critical_open']} Critical risk(s) currently open.")
        else:
            st.caption("No Critical risks currently open.")

    st.subheader("Detail by requirement")
    for r in summary["requirements"]:
        pct_label = f"{r['pct']}%" if r["in_scope"] else "N/A (out of SAQ scope)"
        label = f"{r['id']}. {r['title']} — {pct_label}"
        with st.expander(label):
            if not r["in_scope"]:
                st.caption("Not applicable to the currently-selected SAQ type — excluded from compliance %.")
            sdf = pd.DataFrame(r["sub_requirements"])
            st.dataframe(sdf[["id", "title", "score", "status"]], width='stretch', hide_index=True)

    st.divider()
    rep_col1, rep_col2 = st.columns([3, 1])
    with rep_col1:
        st.subheader("📄 Full compliance report")
        st.caption(
            "One PDF: executive summary, SAQ scope, per-requirement scores, CDE scope, compensating "
            "controls, recurring testing tracker, vendor register, gap report with remediation, "
            "the identified-risks register, and the evidence log with SHA-256 integrity hashes."
        )
    with rep_col2:
        st.write("")
        st.download_button(
            "⬇️ Download PDF report",
            cached_full_report(db.data_fingerprint()),
            file_name=f"verifai360_compliance_report_{datetime.date.today().isoformat()}.pdf",
            mime="application/pdf",
            type="primary",
            width='stretch',
        )

    st.divider()
    st.subheader("✍️ Attestation of Compliance (AOC)")
    st.caption(
        "Generates a signature-ready AOC *summary* document from this tool's own scores — not the "
        "official PCI SSC AOC template. Use the official template for any real submission."
    )
    with st.form("aoc_form"):
        ac1, ac2 = st.columns(2)
        with ac1:
            org_name = st.text_input("Organization (merchant/service provider) name",
                                      value=db.get_setting("aoc_org_name", ""))
            dba_name = st.text_input("DBA name", value=db.get_setting("aoc_dba_name", ""))
            exec_name = st.text_input("Executive signer name", value=db.get_setting("aoc_exec_name", ""))
            exec_title = st.text_input("Executive signer title", value=db.get_setting("aoc_exec_title", ""))
        with ac2:
            assessor_company = st.text_input("Assessor company (if QSA-assisted)",
                                               value=db.get_setting("aoc_assessor_company", ""))
            assessor_name = st.text_input("Assessor name (if QSA-assisted)",
                                           value=db.get_setting("aoc_assessor_name", ""))
            contact_email = st.text_input("Contact email", value=db.get_setting("aoc_contact_email", ""))
            assessment_date = st.date_input("Assessment date", value=datetime.date.today())
        generate_aoc = st.form_submit_button("Generate AOC PDF", type="primary")
        if generate_aoc:
            for key, val in [("aoc_org_name", org_name), ("aoc_dba_name", dba_name),
                              ("aoc_exec_name", exec_name), ("aoc_exec_title", exec_title),
                              ("aoc_assessor_company", assessor_company),
                              ("aoc_assessor_name", assessor_name),
                              ("aoc_contact_email", contact_email)]:
                db.set_setting(key, val)
            st.session_state["_aoc_bytes"] = rg.generate_aoc_pdf({
                "organization_name": org_name, "dba_name": dba_name,
                "executive_name": exec_name, "executive_title": exec_title,
                "assessor_company": assessor_company, "assessor_name": assessor_name,
                "contact_email": contact_email, "assessment_date": str(assessment_date),
            })
    if st.session_state.get("_aoc_bytes"):
        st.download_button(
            "⬇️ Download AOC PDF",
            st.session_state["_aoc_bytes"],
            file_name=f"verifai360_aoc_{datetime.date.today().isoformat()}.pdf",
            mime="application/pdf",
        )


# ----------------------------------------------------------------------------
# PAGE: SAQ Type Selection & Scoping
#
# Plain-English summary: usually the FIRST page a new user should visit.
# The user tells the app which SAQ type applies to them (see
# src/scoping_data.py for what each type means), and the app remembers that
# choice (db.set_setting). Every other page then uses that choice to decide
# which of the 12 top-level requirements are actually "in scope" — so the
# headline compliance % only reflects what the user's business actually
# needs to satisfy.
# ----------------------------------------------------------------------------
elif page == "SAQ Scoping":
    page_header("🎯", t("SAQ Type Selection & Scoping", "اختيار نوع ونطاق SAQ"),
                "Pick the SAQ type that matches how you handle cardholder data — this determines "
                "which of the 12 requirements are actually in scope",
                about=(
                    "**This should usually be the first page a new user visits.** You tell the app "
                    "which Self-Assessment Questionnaire (SAQ) type describes your business — that "
                    "choice is saved and remembered.\n\n"
                    "**Why it matters:** every other page then uses this setting to decide which of "
                    "the 12 top-level PCI DSS requirements are actually *in scope* for you. A business "
                    "that only uses a hosted payment page (SAQ A) has a much smaller in-scope surface "
                    "than one that stores cardholder data directly (SAQ D) — so the headline compliance "
                    "% you see on the Dashboard only reflects what your business actually needs to "
                    "satisfy, not the full standard."
                ))
    current_saq = ce.get_current_saq_type()
    st.warning(
        "**Accuracy note:** the mapping below is a simplified approximation at the level of the 12 "
        "top-level PCI DSS requirements, not the official question-by-question SAQ text. Confirm the "
        "exact applicable requirements using the official SAQ document for your type at "
        "pcisecuritystandards.org, and validate the correct SAQ type with your acquirer/QSA."
    )

    labels = {k: v["label"] for k, v in sd.SAQ_TYPES.items()}
    options = list(sd.SAQ_TYPES.keys())
    chosen = st.selectbox(
        "SAQ type", options,
        index=options.index(current_saq) if current_saq in options else 0,
        format_func=lambda k: labels[k],
    )
    saq_def = sd.get_saq_definition(chosen)
    st.markdown(f"**{saq_def['label']}**")
    st.write(saq_def["description"])
    st.caption(saq_def["notes"])
    st.markdown(
        "**In-scope requirements:** " +
        ", ".join(f"Req {i}" for i in saq_def["applicable_requirements"])
    )
    not_applicable = [str(i) for i in range(1, 13) if str(i) not in saq_def["applicable_requirements"]]
    if not_applicable:
        st.markdown("**Not applicable for this SAQ type:** " + ", ".join(f"Req {i}" for i in not_applicable))

    if st.button("💾 Save SAQ type", type="primary", disabled=reviewer_mode):
        ce.set_current_saq_type(chosen)
        st.success(f"SAQ type set to {saq_def['label']}. The Compliance Dashboard and PDF report now "
                   f"reflect this scope.")
        st.rerun()

    st.divider()
    st.subheader("All SAQ types at a glance")
    overview_rows = [
        {"SAQ type": v["label"], "In-scope requirements": ", ".join(v["applicable_requirements"])}
        for k, v in sd.SAQ_TYPES.items() if k != "Not yet determined"
    ]
    st.dataframe(pd.DataFrame(overview_rows), width='stretch', hide_index=True)

# ----------------------------------------------------------------------------
# PAGE: CDE Scope Definition
#
# Plain-English summary: a simple form + table (backed by the cde_scope
# table in database.py) where the user lists every system that is inside,
# or connected to, the Cardholder Data Environment (CDE) — the part of the
# network that actually touches card data. This is bookkeeping only: no AI
# or scoring is involved, it just records what the user tells it.
# ----------------------------------------------------------------------------
elif page == "CDE Scope":
    page_header("🗺️", t("Cardholder Data Environment (CDE) Scope", "نطاق بيئة بيانات حاملي البطاقات (CDE)"),
                "Document what's in scope, what's out of scope, and what's connected-to/security-"
                "impacting the CDE",
                about=(
                    "**A form + table for listing every system that is inside, or connected to, the "
                    "CDE** — the part of your network that actually touches card data.\n\n"
                    "**This is pure bookkeeping:** no AI, no scoring. It just records what you tell it, "
                    "so anyone reviewing the assessment can see exactly where the perimeter was drawn "
                    "and why — a required artifact for any real PCI DSS assessment."
                ))
    st.caption(
        "PCI DSS v4.0 Requirement 1.2.4 expects a current, accurate inventory of in-scope systems "
        "plus network and data-flow diagrams. This page tracks the system inventory; keep your "
        "actual network/data-flow diagrams as evidence uploads or external documents."
    )

    with st.expander("➕ Add a system / component"):
        with st.form("add_cde_form", clear_on_submit=True):
            cc1, cc2 = st.columns(2)
            with cc1:
                sys_name = st.text_input("System / component name*")
                comp_type = st.selectbox(
                    "Component type",
                    ["Server", "Application", "Network device", "Endpoint", "Storage", "Cloud service", "Other"],
                )
                owner = st.text_input("Owner")
            with cc2:
                in_scope = st.selectbox("In CDE scope?", ["In scope", "Out of scope"]) == "In scope"
                connected = st.selectbox(
                    "Connected-to / security-impacting the CDE?", ["No", "Yes"]
                ) == "Yes"
            description = st.text_area("Description")
            flow_notes = st.text_area("Data flow notes (how cardholder data enters/exits/moves through this system)")
            submitted = st.form_submit_button("Add system", disabled=reviewer_mode)
            if submitted:
                if not sys_name.strip():
                    st.error("System / component name is required.")
                else:
                    db.insert_cde_system(sys_name.strip(), comp_type, description, in_scope, connected,
                                          flow_notes, owner or None)
                    st.success("Added.")
                    st.rerun()

    items = db.get_all_cde_systems()
    if not items:
        st.info("No systems documented yet.")
    else:
        n_in = sum(1 for i in items if i["in_scope"])
        n_conn = sum(1 for i in items if i["connected_to_cde"])
        m1, m2, m3 = st.columns(3)
        m1.metric("Total systems documented", len(items))
        m2.metric("In CDE scope", n_in)
        m3.metric("Connected-to / impacting", n_conn)

        for it in items:
            tag = "🔴 In scope" if it["in_scope"] else "⚪ Out of scope"
            with st.expander(f"{tag} — {it['system_name']} ({it.get('component_type') or 'Other'})"):
                st.write(it.get("description") or "_No description._")
                if it.get("data_flow_notes"):
                    st.markdown("**Data flow notes:**")
                    st.write(it["data_flow_notes"])
                st.caption(f"Owner: {it.get('owner') or '—'}  |  "
                           f"Connected-to/impacting: {'Yes' if it['connected_to_cde'] else 'No'}")
                bcol1, bcol2 = st.columns([1, 5])
                with bcol1:
                    if st.button("🗑️ Delete", key=f"del_cde_{it['id']}", disabled=reviewer_mode):
                        db.delete_cde_system(it["id"])
                        st.rerun()

        cdf = pd.DataFrame(items)[
            ["id", "system_name", "component_type", "in_scope", "connected_to_cde", "owner"]
        ]
        st.download_button(
            "⬇️ Export CDE scope as CSV",
            cdf.to_csv(index=False).encode("utf-8"),
            file_name="verifai360_cde_scope.csv",
            mime="text/csv",
        )

# ----------------------------------------------------------------------------
# PAGE: Compensating Controls Worksheet
#
# Plain-English summary: sometimes a company can't implement a control
# exactly as PCI DSS describes it, so they document an equivalent
# "compensating control" instead. This page is a structured form (backed by
# the compensating_controls table) for writing that justification down:
# why the standard control doesn't fit, what alternative meets the same
# goal, and who signed off on it. Again, pure record-keeping — no AI here.
# ----------------------------------------------------------------------------
elif page == "Compensating Controls":
    page_header("🛡️", t("Compensating Controls Worksheet", "ورقة عمل الضوابط التعويضية"),
                "Document an alternative control when a standard requirement can't be implemented as written",
                about=(
                    "**Sometimes a company can't implement a control exactly as PCI DSS describes it,** "
                    "so it documents an equivalent \"compensating control\" instead — same risk reduction, "
                    "different mechanism.\n\n"
                    "**This page is a structured form** for writing that justification down: why the "
                    "standard control doesn't fit, what alternative meets the same goal, and who signed "
                    "off. Pure record-keeping, no AI involved — but it's the exact artifact a QSA will "
                    "ask for during a real audit."
                ))
    st.caption(
        "Modeled on PCI DSS Appendix B/C guidance: a compensating control must meet the intent and "
        "rigor of the original requirement, provide a similar level of defense, be above and beyond "
        "other requirements, and be commensurate with the additional risk from not using the standard "
        "control."
    )

    with st.expander("➕ Add a compensating control"):
        opts, id_map = sub_req_options()
        with st.form("add_cc_form", clear_on_submit=True):
            sub_label = st.selectbox("Sub-requirement this applies to*", opts)
            constraint_reason = st.text_area("Why can't the standard control be implemented as written?")
            objective_met = st.text_area("Control objective this compensating control meets")
            cc_description = st.text_area("Compensating control description*")
            additional_risk = st.text_area("Additional risk introduced")
            validation_evidence = st.text_input("Validation evidence reference (evidence log filename/ID)")
            vc1, vc2, vc3 = st.columns(3)
            with vc1:
                reviewed_by = st.text_input("Reviewed by")
            with vc2:
                review_date = st.date_input("Review date", value=datetime.date.today())
            with vc3:
                next_review = st.date_input("Next review date", value=None)
            status = st.selectbox("Status", ["Draft", "Approved", "Expired", "Retired"])
            submitted = st.form_submit_button("Add compensating control", disabled=reviewer_mode)
            if submitted:
                sub_id = id_map.get(sub_label)
                if not sub_id:
                    st.error("Pick a specific sub-requirement (not 'let the AI decide').")
                elif not cc_description.strip():
                    st.error("Compensating control description is required.")
                else:
                    orig_text = None
                    for r_ in pci_data["requirements"]:
                        for s_ in r_["sub_requirements"]:
                            if s_["id"] == sub_id:
                                orig_text = s_["summary"]
                    db.insert_compensating_control(
                        sub_id, orig_text, constraint_reason, objective_met, cc_description.strip(),
                        additional_risk, validation_evidence, reviewed_by or None,
                        str(review_date) if review_date else None,
                        str(next_review) if next_review else None, status,
                    )
                    st.success("Compensating control added.")
                    st.rerun()

    items = db.get_all_compensating_controls()
    if not items:
        st.info("No compensating controls documented yet.")
    else:
        for it in items:
            with st.expander(f"[{it['sub_requirement_id']}] — {it['status']}"):
                if it.get("original_requirement_text"):
                    st.caption("Original requirement: " + it["original_requirement_text"])
                if it.get("constraint_reason"):
                    st.markdown("**Why the standard control can't be used:**")
                    st.write(it["constraint_reason"])
                st.markdown("**Compensating control:**")
                st.write(it["compensating_control_description"])
                if it.get("additional_risk"):
                    st.markdown("**Additional risk:**")
                    st.write(it["additional_risk"])
                st.caption(
                    f"Reviewed by {it.get('reviewed_by') or '—'} on {it.get('review_date') or '—'}  |  "
                    f"Next review: {it.get('next_review_date') or '—'}"
                )
                bcol1, bcol2 = st.columns([1, 5])
                with bcol1:
                    if st.button("🗑️ Delete", key=f"del_cc_{it['id']}", disabled=reviewer_mode):
                        db.delete_compensating_control(it["id"])
                        st.rerun()

# ----------------------------------------------------------------------------
# PAGE: Recurring Testing Tracker (Requirement 11)
#
# Plain-English summary: PCI DSS Requirement 11 requires things like
# vulnerability scans and penetration tests on a recurring schedule
# (quarterly, annual, etc.), not just once. This page lets the user log
# each test and its result, and automatically works out (via
# compliance_engine.suggest_next_due_date / testing_tracker_status) whether
# the next one is "On track", "Due soon", or "Overdue".
# ----------------------------------------------------------------------------
elif page == "Testing Tracker (Req 11)":
    page_header("🧪", t("Recurring Testing Tracker", "متابعة الاختبارات الدورية"),
                "Requirement 11: ASV quarterly external scans, internal scans, annual penetration "
                "tests, and segmentation testing — with due dates, not one-time evidence",
                about=(
                    "**PCI DSS Requirement 11 needs proof of recurring testing, not a one-off scan.** "
                    "Vulnerability scans, penetration tests, and segmentation checks all run on a "
                    "schedule (quarterly, annual, etc.).\n\n"
                    "**This page logs each test and its result**, and automatically works out — via "
                    "`compliance_engine.suggest_next_due_date()` / `testing_tracker_status()` — whether "
                    "the *next* one is On track, Due soon, or Overdue. It turns a compliance requirement "
                    "that's easy to forget about into something with a visible clock on it."
                ))
    tt_summary = ce.testing_tracker_summary()
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🔴 Overdue", tt_summary["Overdue"])
    m2.metric("🟡 Due soon (≤14 days)", tt_summary["Due soon"])
    m3.metric("🟢 On track", tt_summary["On track"])
    m4.metric("No due date set", tt_summary["No due date set"])

    with st.expander("➕ Add a recurring test"):
        with st.form("add_test_form", clear_on_submit=True):
            tc1, tc2 = st.columns(2)
            with tc1:
                test_type = st.selectbox(
                    "Test type",
                    ["ASV External Scan", "Internal Vulnerability Scan", "Penetration Test",
                     "Segmentation Test", "Other"],
                )
                related_req = st.text_input("Related requirement (e.g. 11.3.1, 11.4.3)")
                frequency = st.selectbox("Frequency", list(ce.TEST_FREQUENCY_DAYS.keys()))
            with tc2:
                owner = st.text_input("Owner")
                last_performed = st.date_input("Last performed", value=None)
                result_status = st.selectbox("Result status", ["Not yet run", "Pass", "Pass with exceptions", "Fail"])
            scope_description = st.text_area("Scope description")
            suggested = ce.suggest_next_due_date(str(last_performed) if last_performed else None, frequency)
            next_due = st.date_input(
                "Next due date*",
                value=datetime.date.fromisoformat(suggested) if suggested else None,
                help="Auto-suggested from last performed + frequency where possible; override as needed.",
            )
            result_summary = st.text_area("Result summary")
            submitted = st.form_submit_button("Add test", disabled=reviewer_mode)
            if submitted:
                if not next_due:
                    st.error("Next due date is required.")
                else:
                    db.insert_test_item(
                        test_type, related_req or None, scope_description, frequency,
                        str(last_performed) if last_performed else None, str(next_due),
                        result_summary, result_status, None, owner or None,
                    )
                    st.success("Test added.")
                    st.rerun()

    items = db.get_all_test_items()
    if not items:
        st.info("No recurring tests tracked yet.")
    else:
        status_icon = {"Overdue": "🔴", "Due soon": "🟡", "On track": "🟢", "No due date set": "⚪"}
        for it in items:
            status = ce.testing_tracker_status(it.get("next_due_date"))
            with st.expander(f"{status_icon[status]} {it['test_type']} — due {it.get('next_due_date') or '—'} ({status})"):
                st.caption(
                    f"Related requirement: {it.get('related_requirement') or '—'}  |  "
                    f"Frequency: {it['frequency']}  |  Owner: {it.get('owner') or '—'}"
                )
                if it.get("scope_description"):
                    st.write(it["scope_description"])
                st.markdown(
                    f"**Last performed:** {it.get('last_performed_date') or '—'}  ·  "
                    f"**Result:** {it.get('result_status') or '—'}"
                )
                if it.get("result_summary"):
                    st.write(it["result_summary"])

                ec1, ec2 = st.columns(2)
                new_last = ec1.date_input(
                    "Update last performed", value=None, key=f"last_{it['id']}"
                )
                # next_due_date is required at insert time, but a restored
                # backup can still contain a null or malformed value — don't
                # let one bad row take down the page.
                try:
                    _cur_due = datetime.date.fromisoformat(it["next_due_date"])
                except (TypeError, ValueError):
                    _cur_due = None
                new_next = ec2.date_input(
                    "Update next due", value=_cur_due, key=f"next_{it['id']}"
                )
                bc1, bc2, bc3 = st.columns([1, 1, 4])
                with bc1:
                    if st.button("💾 Save", key=f"save_test_{it['id']}", disabled=reviewer_mode):
                        db.update_test_item(
                            it["id"],
                            last_performed_date=str(new_last) if new_last else it.get("last_performed_date"),
                            next_due_date=str(new_next),
                        )
                        st.success("Updated.")
                        st.rerun()
                with bc2:
                    if st.button("🗑️ Delete", key=f"del_test_{it['id']}", disabled=reviewer_mode):
                        db.delete_test_item(it["id"])
                        st.rerun()

        tdf = pd.DataFrame(items)[
            ["id", "test_type", "related_requirement", "frequency", "last_performed_date",
             "next_due_date", "result_status"]
        ]
        st.download_button(
            "⬇️ Export testing tracker as CSV",
            tdf.to_csv(index=False).encode("utf-8"),
            file_name="verifai360_testing_tracker.csv",
            mime="text/csv",
        )

# ----------------------------------------------------------------------------
# PAGE: Vendor / TPSP Management Register
#
# Plain-English summary: a simple CRM-style table (backed by the
# vendor_register table) for tracking every third-party service provider
# (TPSP) that touches the cardholder data environment: what they do, how
# they connect, and whether their own PCI DSS attestation (AOC/SAQ/ROC) is
# current. No AI or scoring involved — just structured record-keeping.
# ----------------------------------------------------------------------------
elif page == "Vendor / TPSP Register":
    page_header("🤝", t("Vendor / TPSP Management Register", "سجل إدارة الموردين وأطراف الخدمة"),
                "Requirements 12.8 & 12.9 — third-party service providers, tracked separately from "
                "general evidence",
                about=(
                    "**A CRM-style table for every third-party service provider (TPSP)** that touches "
                    "your cardholder data environment: payment processors, cloud hosts, MSSPs, etc.\n\n"
                    "**For each vendor it tracks** what they do, how they connect, and whether their "
                    "own PCI DSS attestation (AOC / SAQ / ROC) is still current. No AI or scoring — "
                    "just structured record-keeping for Requirements 12.8 & 12.9, which specifically "
                    "require you to manage vendor compliance, not just your own."
                ))

    with st.expander("➕ Add a vendor / TPSP"):
        with st.form("add_vendor_form", clear_on_submit=True):
            vc1, vc2 = st.columns(2)
            with vc1:
                vendor_name = st.text_input("Vendor name*")
                service = st.text_input("Service provided")
                responsibility = st.selectbox(
                    "PCI DSS responsibility",
                    ["Vendor-managed", "Shared", "Merchant-managed"],
                )
                compliance_status = st.selectbox(
                    "Compliance status", ["Compliant", "Non-Compliant", "Unknown", "Expired"]
                )
            with vc2:
                attestation_type = st.selectbox(
                    "Attestation on file", ["AOC on file", "SAQ on file", "ROC on file", "None"]
                )
                attestation_expiry = st.date_input("Attestation expiry", value=None)
                last_reviewed = st.date_input("Last reviewed", value=None)
                next_review = st.date_input("Next review due", value=None)
            cde_connection = st.text_area("How does this vendor connect to / affect the CDE?")
            contract_ref = st.text_input("Contract reference")
            notes = st.text_area("Notes")
            submitted = st.form_submit_button("Add vendor", disabled=reviewer_mode)
            if submitted:
                if not vendor_name.strip():
                    st.error("Vendor name is required.")
                else:
                    db.insert_vendor(
                        vendor_name.strip(), service, responsibility, cde_connection, compliance_status,
                        attestation_type, str(attestation_expiry) if attestation_expiry else None,
                        str(last_reviewed) if last_reviewed else None,
                        str(next_review) if next_review else None, contract_ref or None, notes,
                    )
                    st.success("Vendor added.")
                    st.rerun()

    vendors = db.get_all_vendors()
    if not vendors:
        st.info("No vendors documented yet.")
    else:
        status_color_map = {"Compliant": "🟢", "Non-Compliant": "🔴", "Unknown": "⚪", "Expired": "🟠"}
        m1, m2, m3 = st.columns(3)
        m1.metric("Total vendors", len(vendors))
        m2.metric("Compliant", sum(1 for v in vendors if v["compliance_status"] == "Compliant"))
        m3.metric("Needs attention", sum(1 for v in vendors if v["compliance_status"] in ("Non-Compliant", "Unknown", "Expired")))

        for v in vendors:
            icon = status_color_map.get(v["compliance_status"], "⚪")
            with st.expander(f"{icon} {v['vendor_name']} — {v['compliance_status']}"):
                st.caption(f"Service: {v.get('service_provided') or '—'}  |  "
                           f"Responsibility: {v.get('pci_dss_responsibility') or '—'}  |  "
                           f"Attestation: {v.get('attestation_type') or '—'}")
                if v.get("cde_connection"):
                    st.markdown("**CDE connection:**")
                    st.write(v["cde_connection"])
                if v.get("notes"):
                    st.markdown("**Notes:**")
                    st.write(v["notes"])
                st.caption(
                    f"Last reviewed: {v.get('last_reviewed_date') or '—'}  |  "
                    f"Next review due: {v.get('next_review_due') or '—'}  |  "
                    f"Contract ref: {v.get('contract_reference') or '—'}"
                )
                bcol1, bcol2 = st.columns([1, 5])
                with bcol1:
                    if st.button("🗑️ Delete", key=f"del_vendor_{v['id']}", disabled=reviewer_mode):
                        db.delete_vendor(v["id"])
                        st.rerun()

        vdf = pd.DataFrame(vendors)[
            ["id", "vendor_name", "service_provided", "pci_dss_responsibility", "compliance_status",
             "attestation_type", "next_review_due"]
        ]
        st.download_button(
            "⬇️ Export vendor register as CSV",
            vdf.to_csv(index=False).encode("utf-8"),
            file_name="verifai360_vendor_register.csv",
            mime="text/csv",
        )

elif page == "Identified Risks":
    page_header("⚠️", t("Identified Risks", "المخاطر المرصودة"),
                "Internal risk items tracked from this tool — not your organization's official risk register",
                about=(
                    "**A lightweight risk register**, scored on a standard 5×5 Likelihood × Impact "
                    "matrix (1–25) — the same model used across GRC and SOC risk-triage work.\n\n"
                    "**Risks get added two ways:** manually, or auto-generated by syncing unresolved "
                    "gaps from the Gap Report. This turns \"the AI found a weak control\" into a "
                    "trackable item with a severity, an owner, and a status — the bridge between "
                    "an assessment finding and an actual remediation plan."
                ))
    st.write(
        "Tracked risks, scored on a standard 5×5 **Likelihood × Impact** matrix (1–25). "
        "Items are either added manually or generated automatically from open compliance gaps."
    )

    top1, top2 = st.columns([1, 3])
    with top1:
        if st.button("🔄 Sync risks from gap report", type="primary", disabled=reviewer_mode):
            gaps = ce.build_gap_report()
            result = re_.sync_auto_risks_from_gaps(gaps)
            st.success(
                f"Sync complete — {result['created']} new risk(s) created, "
                f"{result['updated']} refreshed, {result['skipped']} left untouched "
                "(already being managed)."
            )
            st.rerun()
    with top2:
        st.caption(
            "Auto-generated risks (source = *auto-gap*) are refreshed each sync as long as they're "
            "still 'Open'. Once you move one to Mitigating / Accepted / Closed, syncing will leave it alone."
        )

    with st.expander("➕ Add a manual risk"):
        opts, id_map = sub_req_options()
        with st.form("add_risk_form", clear_on_submit=True):
            rc1, rc2 = st.columns(2)
            with rc1:
                title = st.text_input("Risk title*")
                sub_label = st.selectbox("Related sub-requirement (optional)", opts)
                owner = st.text_input("Owner")
                due_date = st.date_input("Due date", value=None)
            with rc2:
                likelihood = st.slider("Likelihood (1=rare, 5=almost certain)", 1, 5, 3)
                impact = st.slider("Impact (1=minor, 5=severe)", 1, 5, 3)
                status = st.selectbox("Status", re_.STATUS_OPTIONS)
            description = st.text_area("Description")
            mitigation = st.text_area("Mitigation plan")
            submitted = st.form_submit_button("Add risk", disabled=reviewer_mode)
            if submitted:
                if not title.strip():
                    st.error("Risk title is required.")
                else:
                    sub_id = id_map.get(sub_label)
                    req_id = requirement_id_for_sub(sub_id)
                    score = re_.compute_risk_score(likelihood, impact)
                    level = re_.risk_level_for_score(score)
                    db.insert_risk(
                        requirement_id=req_id, sub_requirement_id=sub_id, title=title.strip(),
                        description=description, likelihood=likelihood, impact=impact,
                        risk_score=score, risk_level=level, owner=owner or None, status=status,
                        mitigation_plan=mitigation, due_date=str(due_date) if due_date else None,
                        source="manual",
                    )
                    st.success("Risk added.")
                    st.rerun()

    risks = db.get_all_risks()
    exposure = re_.risk_exposure_summary(risks)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total risks", len(risks))
    m2.metric("Open / Mitigating", exposure["open_count"])
    m3.metric("Critical (open)", exposure["critical_open"])
    m4.metric("Total open exposure", exposure["total_open_exposure"])

    st.divider()
    f1, f2 = st.columns(2)
    with f1:
        status_filter = st.selectbox("Filter by status", ["All"] + re_.STATUS_OPTIONS)
    with f2:
        level_filter = st.selectbox("Filter by risk level", ["All", "Critical", "High", "Medium", "Low"])

    filtered = re_.get_register(status_filter, level_filter)
    if not filtered:
        st.info("No risks match this filter yet.")
    else:
        for r in filtered:
            header = f"{risk_badge_emoji(r['risk_level'])} {r['title']}  ·  score {r['risk_score']}"
            with st.expander(header):
                st.markdown(risk_badge(r["risk_level"]), unsafe_allow_html=True)
                st.caption(
                    f"Linked to: {r['sub_requirement_id'] or '—'}  |  Source: {r['source']}  |  "
                    f"Created: {r['created_at'][:10]}"
                )
                if r["description"]:
                    st.write(r["description"])
                if r["mitigation_plan"]:
                    st.markdown("**Mitigation plan:**")
                    st.markdown(r["mitigation_plan"])

                ec1, ec2, ec3, ec4 = st.columns(4)
                # A restored backup (or a hand-edited DB) can carry a status
                # string that isn't one of ours; .index() raised ValueError and
                # took the whole page down. Fall back to the first option.
                _status_index = (re_.STATUS_OPTIONS.index(r["status"])
                                 if r["status"] in re_.STATUS_OPTIONS else 0)
                new_status = ec1.selectbox("Status", re_.STATUS_OPTIONS,
                                            index=_status_index,
                                            key=f"status_{r['id']}")
                new_owner = ec2.text_input("Owner", value=r["owner"] or "", key=f"owner_{r['id']}")
                new_likelihood = ec3.slider("Likelihood", 1, 5, r["likelihood"], key=f"like_{r['id']}")
                new_impact = ec4.slider("Impact", 1, 5, r["impact"], key=f"impact_{r['id']}")

                bc1, bc2 = st.columns([1, 5])
                with bc1:
                    if st.button("💾 Save", key=f"save_{r['id']}", disabled=reviewer_mode):
                        new_score = re_.compute_risk_score(new_likelihood, new_impact)
                        new_level = re_.risk_level_for_score(new_score)
                        db.update_risk(
                            r["id"], status=new_status, owner=new_owner or None,
                            likelihood=new_likelihood, impact=new_impact,
                            risk_score=new_score, risk_level=new_level,
                        )
                        st.success("Updated.")
                        st.rerun()
                with bc2:
                    if st.button("🗑️ Delete", key=f"del_{r['id']}", disabled=reviewer_mode):
                        db.delete_risk(r["id"])
                        st.rerun()

        rdf = pd.DataFrame(filtered)[["id", "title", "sub_requirement_id", "likelihood", "impact",
                                       "risk_score", "risk_level", "status", "owner"]]
        st.download_button(
            "⬇️ Export identified risks as CSV",
            rdf.to_csv(index=False).encode("utf-8"),
            file_name="verifai360_identified_risks.csv",
            mime="text/csv",
        )

# ----------------------------------------------------------------------------
# PAGE: Gap Report
#
# Plain-English summary: shows exactly which sub-requirements are still
# below the "compliant" score threshold, sorted worst-first, with the
# specific gaps and recommendations the AI (or the default message, if no
# evidence exists yet) attached to each one. All the data comes straight
# from compliance_engine.build_gap_report() — this page just displays it
# and offers a "sync these gaps into the Identified Risks register" button.
# ----------------------------------------------------------------------------
elif page == "Gap Report":
    page_header("🕳️", t("Gap Report & Remediation Plan", "تقرير الفجوات وخطة المعالجة"),
                f"Sub-requirements below the compliant threshold ({ce.COMPLIANT_THRESHOLD}/100)",
                about=(
                    "**Shows exactly which sub-requirements are still below the compliant score "
                    "threshold**, worst-first, along with the specific gaps and recommendations "
                    "attached to each one — either from the AI's last assessment, or a default "
                    "message if no evidence has been uploaded for it yet.\n\n"
                    "**All the data comes straight from** `compliance_engine.build_gap_report()`; this "
                    "page only displays it and offers a one-click *sync these gaps into Identified "
                    "Risks* button. It's the action list version of the Dashboard's percentages."
                ))
    gaps = ce.build_gap_report()

    if not gaps:
        st.success("No gaps — every sub-requirement is at or above the compliant threshold.")
    else:
        st.metric("Open gaps", len(gaps))
        for g in gaps:
            with st.expander(
                f"[{g['sub_requirement_id']}] {g['sub_requirement_title']} "
                f"— score {g['current_score']}/100 (Req {g['requirement_id']}: {g['requirement_title']})"
            ):
                st.markdown("**Gaps:**")
                for x in g["gaps"]:
                    st.markdown(f"- {x}")
                st.markdown("**Recommended remediation:**")
                for x in g["recommendations"]:
                    st.markdown(f"- {x}")

        gdf = pd.DataFrame(gaps)[["sub_requirement_id", "sub_requirement_title", "current_score"]]
        st.download_button(
            "⬇️ Export gap list as CSV",
            gdf.to_csv(index=False).encode("utf-8"),
            file_name="verifai360_gap_report.csv",
            mime="text/csv",
        )
        st.caption("💡 Visit **Identified Risks** and sync to turn these gaps into tracked, ownable risk items.")

# ----------------------------------------------------------------------------
# PAGE: Requirement Explorer
#
# Plain-English summary: a read-only, browsable view of the entire PCI DSS
# catalog loaded from data/pci_dss_data.json, with the current score/status
# for each sub-requirement shown next to it. Useful for understanding what
# a requirement actually asks for, independent of the dashboard's summary
# numbers.
# ----------------------------------------------------------------------------
elif page == "Requirement Explorer":
    page_header("📚", t("PCI DSS Requirement Explorer", "دليل متطلبات PCI DSS"),
                t("Browse the full catalog and current evidence status", "تصفح الدليل الكامل وحالة الأدلة الحالية"),
                about=(
                    "**A read-only, browsable view of the entire PCI DSS catalog**, loaded from "
                    "`data/pci_dss_data.json`, with the current score/status shown next to each "
                    "sub-requirement.\n\n"
                    "**Why it exists:** the Dashboard tells you *how well* you're doing; this page "
                    "tells you *what a requirement actually asks for* — useful for understanding "
                    "context, independent of any score."
                ))
    st.caption(
        "Condensed, paraphrased reference data bundled with this demo — for real assessments always "
        "consult the official PCI DSS standard from the PCI Security Standards Council."
    )
    best_scores = db.get_best_score_per_subreq()
    for req in pci_data["requirements"]:
        with st.expander(f"Requirement {req['id']}: {req['title']}"):
            for sub in req["sub_requirements"]:
                score = best_scores.get(sub["id"])
                badge = f"— current score: {score}/100" if score is not None else "— no evidence yet"
                st.markdown(f"**[{sub['id']}] {sub['title']}** {badge}")
                st.markdown(sub["summary"])
                st.caption("Typical evidence: " + ", ".join(sub["example_evidence"]))
                if score is not None:
                    history = db.get_assessments_for_subreq(sub["id"])
                    for h in history:
                        st.markdown(f"  - `{h['filename']}` → {h['sufficiency_score']}/100 ({h['maturity_level']})")
                st.divider()

# ----------------------------------------------------------------------------
# PAGE: Evidence Log
#
# Plain-English summary: a simple chronological table of every file ever
# uploaded (from the evidence table), including its SHA-256 hash — a
# fingerprint that changes if the file's bytes ever change, so it can be
# used later to prove a stored file hasn't been tampered with.
# ----------------------------------------------------------------------------
elif page == "Evidence Log":
    page_header("🗂️", t("Evidence Log", "سجل الأدلة"),
                t("Every artifact submitted so far, in one place", "كل الأدلة المرفوعة في مكان واحد"),
                about=(
                    "**A chronological table of every file ever uploaded**, pulled straight from the "
                    "`evidence` table, including each file's **SHA-256 hash** — a fingerprint that "
                    "changes the instant the file's bytes change — and which **analysis engine** "
                    "(AI or Local) scored it.\n\n"
                    "**Why the hash matters:** it lets you (or an auditor) later prove a stored piece "
                    "of evidence hasn't been silently swapped or edited since it was submitted — the "
                    "same integrity-verification idea used in digital forensics chain-of-custody."
                ))
    evidence = db.get_all_evidence()
    if not evidence:
        st.info("No evidence submitted yet.")
    else:
        edf = pd.DataFrame(evidence)[
            ["id", "filename", "evidence_type", "target_sub_requirement", "uploaded_at",
             "analysis_source", "sha256"]
        ]
        edf["sha256"] = edf["sha256"].fillna("— (uploaded before integrity hashing was enabled)")
        edf["analysis_source"] = edf["analysis_source"].map(
            {"ai": "🤖 AI (Gemini)", "local": "🧩 Local (offline)"}
        ).fillna("—")
        edf = edf.rename(columns={"sha256": "SHA-256 (integrity hash)", "analysis_source": "Engine"})
        st.dataframe(edf, width='stretch', hide_index=True)
        st.caption(
            "SHA-256 is computed from the stored file's actual bytes at upload time — a real "
            "integrity hash you can use to verify a file on disk hasn't been altered since. "
            "**Engine** shows whether that file's score came from the AI (Gemini) or the Local "
            "(offline keyword-matching) analysis engine."
        )

    with st.expander(t("🧾 Analysis call log (audit trail)", "🧾 سجل استدعاءات التحليل (سجل تدقيق)")):
        st.caption(
            t(
                "Every call to an analysis engine — AI (Gemini) or Local — is logged here, "
                "success or failure, with the engine/model used and how many sub-requirements "
                "it returned scores for. This is the audit trail for accountability and for "
                "spotting repeated failures or unexpected scoring activity.",
                "يتم تسجيل كل استدعاء لمحرك التحليل هنا، سواء نجح أو فشل، مع المحرك/النموذج "
                "المستخدم وعدد المتطلبات الفرعية التي تم تقييمها. هذا سجل تدقيق للمساءلة."
            )
        )
        call_log = db.get_all_call_log()
        if not call_log:
            st.info(t("No analysis calls logged yet.", "لا يوجد سجل استدعاءات بعد."))
        else:
            ldf = pd.DataFrame(call_log)[
                ["called_at", "filename", "engine", "model_used", "target_sub_requirement",
                 "success", "assessments_count", "error_message"]
            ]
            ldf["engine"] = ldf["engine"].map({"ai": "🤖 AI (Gemini)", "local": "🧩 Local"}).fillna(ldf["engine"])
            ldf["success"] = ldf["success"].map({1: "✅", 0: "❌"})
            ldf = ldf.rename(columns={
                "called_at": "When", "filename": "File", "engine": "Engine",
                "model_used": "Model", "target_sub_requirement": "Target sub-req",
                "success": "OK?", "assessments_count": "# scored", "error_message": "Error",
            })
            st.dataframe(ldf, width='stretch', hide_index=True)

# ----------------------------------------------------------------------------
# PAGE: Automated Connectors (demo / roadmap mockup)
#
# Plain-English summary: NOT a real feature yet. This page only shows what
# it would look like to auto-pull evidence from tools like AWS Config or a
# vulnerability scanner, using hardcoded sample data. It's a mockup for
# planning future work, clearly labeled with demo_banner() so it's never
# mistaken for live functionality.
# ----------------------------------------------------------------------------
elif page == "Automated Connectors (demo)":
    page_header("🔌", t("Automated Evidence Ingestion", "استيراد الأدلة تلقائيًا"),
                t("Roadmap concept — not a live integration", "فكرة مستقبلية — مش شغالة فعليًا"),
                about=(
                    "**Not a real feature yet.** This page only shows what it would look like to "
                    "auto-pull evidence from tools like AWS Config, Wazuh, or a vulnerability scanner, "
                    "using hardcoded sample data.\n\n"
                    "**Why it's here:** it's a UI mockup for planning future work — clearly labeled "
                    "with the demo banner below so it's never mistaken for something actually wired up. "
                    "No connector on this page reads real data or credentials."
                ))
    demo_banner(
        "this page is a UI mockup of a planned feature. No connector below is actually wired up to "
        "Wazuh, Splunk, or Nessus — nothing here reads real data or credentials."
    )
    st.write(
        "Concept: connect VerifAI 360 directly to your security stack so evidence (FIM alerts, auth logs, "
        "scan results) is pulled in automatically instead of uploaded by hand."
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        st.info("🟢 **Wazuh EDR** (mock)")
        st.caption("Example: would sync FIM/auth alerts")
    with col2:
        st.warning("🟡 **Splunk SIEM** (mock)")
        st.caption("Example: would sync firewall/config exports")
    with col3:
        st.error("🔴 **Nessus Scanner** (mock)")
        st.caption("Example: would sync vulnerability scan results")

    st.divider()
    st.subheader("Example connector log (illustrative only)")
    log_data = pd.DataFrame({
        "Timestamp": [datetime.datetime.now() - datetime.timedelta(minutes=i * 15) for i in range(5)],
        "Source": ["Wazuh", "Wazuh", "Splunk", "Wazuh", "Splunk"],
        "Event": ["Pulled FIM alerts", "Pulled Auth logs", "Analyzed firewall configs",
                   "Checked agent status", "Exported audit trail"],
        "Would map to": ["Req 11.5", "Req 10.2", "Req 1.2", "Req 1.1", "Req 10.3"],
    })
    st.dataframe(log_data, width='stretch', hide_index=True)

# ----------------------------------------------------------------------------
# PAGE: Alerts & Drift (demo / roadmap mockup)
#
# Plain-English summary: also NOT a real feature yet — a mockup of what
# alerts would look like if the app could detect that a previously-compliant
# control had "drifted" out of compliance (e.g. a firewall rule changed).
# Uses sample/illustrative data only.
# ----------------------------------------------------------------------------
elif page == "Alerts & Drift (demo)":
    page_header("📡", t("Compliance Drift Alerts", "تنبيهات انحراف الامتثال"),
                t("Roadmap concept — not a live integration", "فكرة مستقبلية — مش شغالة فعليًا"),
                about=(
                    "**Also not a real feature yet.** A mockup of what alerts would look like if the "
                    "app could detect that a previously-compliant control had *drifted* out of "
                    "compliance — e.g. a firewall rule changed, an S3 bucket went public.\n\n"
                    "**Why it's here:** it illustrates a planned direction (continuous monitoring, not "
                    "just point-in-time assessment). The alerts and score changes shown are sample/"
                    "illustrative data only, not derived from your real evidence."
                ))
    demo_banner(
        "the alerts and score changes below are illustrative sample data, not derived from your "
        "actual uploaded evidence. A real version would compare successive AI assessments per "
        "sub-requirement and flag regressions automatically."
    )

    st.error("🚨 Example alert (Req 8.3.1): a newly uploaded password policy contradicts a previously "
             "recorded MFA requirement — sample score drop from 95 to 60.")
    st.warning("⚠️ Example alert (Req 11.2.1): quarterly vulnerability scan shown as 5 days overdue.")
    st.info("ℹ️ Example notice: a hypothetical scanner integration mapped new findings to Req 6.1.")

    st.subheader("Example score changes")
    drift_data = pd.DataFrame({
        "Sub-Requirement": ["8.3.1", "11.2.1", "6.1", "10.2.1"],
        "Previous Score": [95, 100, 75, 80],
        "New Score": [60, 85, 75, 82],
        "Trend": ["📉 Down", "📉 Down", "➖ Stable", "📈 Up"],
    })
    st.dataframe(drift_data, width='stretch', hide_index=True)

# ----------------------------------------------------------------------------
# PAGE: QSA Audit View (demo / roadmap mockup)
#
# Plain-English summary: mostly REAL, partly mockup. The compliance %,
# per-file SHA-256 hashes, and the "Generate audit PDF" button are wired to
# real data. What's still a mockup is the rest of a full auditor workflow
# (reviewer sign-off, sampling notes, a separate read-only auditor login).
# ----------------------------------------------------------------------------
elif page == "QSA Audit View (demo)":
    page_header("🧾", t("QSA Audit View", "واجهة المدقق (QSA)"),
                t("Roadmap concept — not a live integration", "فكرة مستقبلية — مش شغالة فعليًا"),
                about=(
                    "**Mostly real, partly mockup.** The compliance %, per-file SHA-256 hashes, and "
                    "the *Generate audit PDF* button below are wired to your real data.\n\n"
                    "**What's still just a sketch** is the rest of a full auditor workflow: reviewer "
                    "sign-off, sampling notes, and a separate read-only auditor login. This page shows "
                    "what handing the assessment off to a QSA (Qualified Security Assessor) could look "
                    "like once that part is built."
                ))
    demo_banner(
        "this is a UI concept for a future read-only auditor view. The compliance %, evidence "
        "hashes, and PDF export below are all real (pulled from your actual data). What's still "
        "just a roadmap sketch is the rest of a proper QSA workflow — reviewer sign-off, sampling "
        "notes, interview logs, and a locked-down read-only auditor login."
    )

    summary = ce.compute_compliance_summary()
    st.metric("Current compliance score", f"{summary['overall_pct']}%")

    st.download_button(
        "📄 Generate audit PDF",
        cached_full_report(db.data_fingerprint()),
        file_name=f"verifai360_audit_report_{datetime.date.today().isoformat()}.pdf",
        mime="application/pdf",
        type="primary",
    )

    st.divider()
    st.subheader("Evidence submitted so far")
    evidence = db.get_all_evidence()
    if not evidence:
        st.caption("No artifacts found.")
    else:
        edf = pd.DataFrame(evidence)[["id", "filename", "uploaded_at", "target_sub_requirement", "sha256"]]
        edf["sha256"] = edf["sha256"].fillna("— (uploaded before integrity hashing was enabled)")
        edf = edf.rename(columns={"sha256": "SHA-256 (integrity hash)"})
        st.dataframe(edf, width='stretch', hide_index=True)
        st.caption(
            "SHA-256 is computed from each stored file's actual bytes at upload time — a real, "
            "per-file integrity hash (no longer a placeholder)."
        )

# ----------------------------------------------------------------------------
# PAGE: Settings & Security
# ----------------------------------------------------------------------------
# Not part of the roadmap/demo group — this is real, live configuration:
# the Local engine's scoring weights, encryption/passcode status, and full
# data export/import. Kept off the main "Workspace" nav group since it's
# infrastructure, not assessment work.
# ----------------------------------------------------------------------------
elif page == "Settings & Security":
    page_header("⚙️", t("Settings & Security", "الإعدادات والأمان"),
                "Local engine tuning, encryption status, and full data backup/restore",
                about=(
                    "**Everything on this page is real and live** — nothing here is a roadmap mockup.\n\n"
                    "- **Local engine weights:** the four numbers driving `local_analyzer.py`'s scoring "
                    "(keyword / title / example-evidence weights, plus the fuzzy-match threshold). "
                    "Changing them here affects every future Local-engine analysis immediately.\n"
                    "- **Security status:** confirms the passcode gate and encryption-at-rest are active, "
                    "without ever displaying the actual secrets on screen.\n"
                    "- **Backup & restore:** exports every table in the database as one JSON file, or "
                    "restores from one — a full **replace**, not a merge, so restoring asks for "
                    "confirmation first."
                ))

    tab_engine, tab_security, tab_data = st.tabs(["🧩 Local Engine", "🔐 Security", "💾 Backup & Restore"])

    with tab_engine:
        st.markdown("##### Scoring weights")
        st.caption(
            "These four numbers control how `local_analyzer.py` scores evidence. The three main "
            "weights should add up to roughly 1.0 (they're re-normalized if they don't). Reset to "
            "defaults any time — nothing here is destructive to past scores already saved."
        )
        current_weights = db.get_settings_json("local_engine_weights", default={}) or {}
        w = {**la.DEFAULT_WEIGHTS, **current_weights}

        c1, c2, c3 = st.columns(3)
        with c1:
            w_kw = st.slider("Keyword weight", 0.0, 1.0, float(w["keyword"]), 0.05,
                              disabled=reviewer_mode,
                              help="Weight given to curated evidence_keywords matches — the primary, "
                                   "highest-trust signal.")
        with c2:
            w_title = st.slider("Title/summary weight", 0.0, 1.0, float(w["title"]), 0.05,
                                 disabled=reviewer_mode,
                                 help="Weight given to vocabulary mined from the sub-requirement's "
                                      "title/summary and its parent requirement's title.")
        with c3:
            w_example = st.slider("Example-evidence weight", 0.0, 1.0, float(w["example"]), 0.05,
                                   disabled=reviewer_mode,
                                   help="Weight given to vocabulary mined from example_evidence entries.")

        c4, c5, c6 = st.columns(3)
        with c4:
            w_fuzzy_credit = st.slider("Fuzzy-match credit", 0.0, 1.0, float(w["fuzzy_credit"]), 0.05,
                                        disabled=reviewer_mode,
                                        help="How much credit a typo-tolerant fuzzy keyword match gets, "
                                             "relative to an exact match.")
        with c5:
            w_fuzzy_threshold = st.slider("Fuzzy-match threshold", 0.5, 1.0, float(w["fuzzy_threshold"]), 0.01,
                                           disabled=reviewer_mode,
                                           help="Minimum similarity ratio (difflib) required to count as "
                                                "a fuzzy match. Higher = stricter (fewer false positives).")
        with c6:
            w_filename_bonus = st.slider("Filename bonus (max pts)", 0, 20, int(w["filename_bonus_max"]), 1,
                                          disabled=reviewer_mode,
                                          help="Cap on the small bonus applied when the uploaded filename "
                                               "corroborates content already found in the text.")

        total = w_kw + w_title + w_example
        if total > 0 and abs(total - 1.0) > 0.01:
            st.caption(f"⚠️ Keyword + title + example weights sum to {total:.2f}, not 1.00 — they'll be "
                       "proportionally re-normalized when used, but consider adjusting them to sum to 1.0.")

        bcol1, bcol2 = st.columns(2)
        with bcol1:
            if st.button("💾 Save weights", type="primary", disabled=reviewer_mode, width='stretch'):
                db.set_settings_json("local_engine_weights", {
                    "keyword": w_kw, "title": w_title, "example": w_example,
                    "fuzzy_credit": w_fuzzy_credit, "fuzzy_threshold": w_fuzzy_threshold,
                    "filename_bonus_max": w_filename_bonus,
                    "substance_bonus": w.get("substance_bonus", la.DEFAULT_WEIGHTS["substance_bonus"]),
                })
                st.success("Saved — future Local-engine analyses will use these weights.")
        with bcol2:
            if st.button("↺ Reset to defaults", disabled=reviewer_mode, width='stretch'):
                db.set_settings_json("local_engine_weights", {})
                st.rerun()  # so the sliders redraw at their defaults immediately

    with tab_security:
        st.markdown("##### Passcode gate")
        st.markdown(
            '<span class="vf-secure-badge">🔒 ACTIVE</span> App-level passcode is required for every '
            "session.", unsafe_allow_html=True,
        )
        st.caption("The current passcode is never displayed here. It lives in `APP_PASSCODE` in `.env`.")
        with st.form("change_passcode_form"):
            new_pc = st.text_input("Set a new passcode", type="password", disabled=reviewer_mode)
            if st.form_submit_button("Update passcode", disabled=reviewer_mode):
                try:
                    sec.set_passcode(new_pc)
                    st.success("Passcode updated. New logins use it immediately. Sessions that are "
                               "already unlocked stay open until the app is restarted.")
                except sec.PasscodeError as e:
                    st.error(str(e))

        st.divider()
        st.markdown("##### Encryption at rest")
        st.markdown(
            '<span class="vf-secure-badge">🔒 ACTIVE</span> Evidence files and extracted text are '
            "Fernet-encrypted before they touch disk.", unsafe_allow_html=True,
        )
        st.caption(
            "The encryption key lives in `ENCRYPTION_KEY` in `.env` — never shown here. **Back up "
            "`.env` separately from `verifai360.db` and `evidence_store/`**: losing the key makes "
            "encrypted evidence permanently unrecoverable by design. Scores, dates, filenames, and "
            "sub-requirement IDs remain in plain SQLite columns (needed for querying/sorting); the "
            "evidence *content* is what's encrypted."
        )

    with tab_data:
        st.markdown("##### Export everything")
        st.caption(
            "Downloads one JSON file with every row from every table (evidence metadata, "
            "assessments, risks, CDE scope, compensating controls, testing tracker, vendor "
            "register, settings). Encrypted text fields stay encrypted in the export. The actual "
            "evidence files in `evidence_store/` are **not** included — copy that folder alongside "
            "this JSON for a complete backup."
        )
        st.download_button(
            "⬇️ Export all data as JSON",
            cached_data_export(db.data_fingerprint()),
            file_name=f"verifai360_export_{datetime.date.today().isoformat()}.json",
            mime="application/json",
            width='stretch',
        )

        st.divider()
        st.markdown("##### Restore from a backup")
        st.warning(
            "⚠️ Restoring **replaces** everything currently in the database — it is not a merge. "
            "Export a backup of the current state first if you're not sure."
        )
        restore_file = st.file_uploader("Choose a VerifAI 360 export JSON file", type=["json"],
                                         disabled=reviewer_mode)
        if restore_file:
            try:
                payload = json.loads(restore_file.getvalue().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                st.error("This doesn't look like a valid JSON file.")
                payload = None
            if payload:
                n_evidence = len(payload.get("tables", {}).get("evidence", []))
                st.info(f"This file contains {n_evidence} evidence record(s) and its own assessments, "
                        "risks, and settings.")
                confirm = st.checkbox("I understand this will replace all current data", disabled=reviewer_mode)
                if st.button("♻️ Restore now", type="primary", disabled=(reviewer_mode or not confirm)):
                    try:
                        summary = dp.import_all_data(payload)
                        st.success(f"Restored: {summary}")
                        st.rerun()
                    except dp.ImportError_ as e:
                        st.error(f"Restore failed: {e}")
