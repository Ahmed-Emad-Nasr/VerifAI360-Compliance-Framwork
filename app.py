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
import datetime
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
from src.ai_analyzer import AIAnalyzerError
from src.evidence_processor import EvidenceExtractionError
from src.compliance_engine import EvidenceUploadError

st.set_page_config(page_title="VerifAI 360 — PCI DSS Compliance", page_icon="🛡️", layout="wide")
db.init_db()

# ----------------------------------------------------------------------------
# Theme / global styling
# ----------------------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&display=swap');

    :root {
        --vf-bg: #0b1018;
        --vf-bg-alt: #0e1420;
        --vf-panel: #141c2b;
        --vf-panel-raised: #182337;
        --vf-border: #263049;
        --vf-border-soft: #1d2740;
        --vf-accent: #35d0c0;
        --vf-accent-soft: rgba(53,208,192,0.12);
        --vf-accent-dim: #1f8a80;
        --vf-text: #e7ecf5;
        --vf-muted: #8fa0bd;
        --vf-red: #e5484d;
        --vf-amber: #e0a72e;
        --vf-green: #3ecf8e;
    }

    html, body, .stApp { background: var(--vf-bg); color: var(--vf-text); font-family: 'Inter', sans-serif; }
    h1, h2, h3, h4 { font-family: 'Space Grotesk', sans-serif; letter-spacing: 0.2px; }
    p, span, div, label { font-family: 'Inter', sans-serif; }

    /* remove default streamlit top padding for a tighter, more app-like feel */
    .block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1200px; }

    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, var(--vf-panel) 0%, var(--vf-bg-alt) 100%);
        border-right: 1px solid var(--vf-border);
    }
    section[data-testid="stSidebar"] .block-container { padding-top: 1.2rem; }

    /* ---- Page header component (see page_header() helper) ---- */
    .vf-page-header {
        display: flex; align-items: center; gap: 14px;
        padding-bottom: 6px; margin-bottom: 4px;
        border-bottom: 1px solid var(--vf-border-soft);
    }
    .vf-page-header .vf-icon {
        font-size: 1.7rem; width: 46px; height: 46px; min-width: 46px;
        display: flex; align-items: center; justify-content: center;
        background: var(--vf-accent-soft); border: 1px solid rgba(53,208,192,0.3);
        border-radius: 12px;
    }
    .vf-page-header h1 { font-size: 1.6rem; margin: 0; line-height: 1.15; font-weight: 700; }
    .vf-page-header .vf-subtitle { color: var(--vf-muted); font-size: 0.92rem; margin-top: 2px; }

    /* ---- Metrics ---- */
    [data-testid="stMetric"] {
        background: var(--vf-panel);
        border: 1px solid var(--vf-border);
        border-radius: 12px;
        padding: 16px 18px 12px 18px;
        transition: border-color 0.15s ease;
    }
    [data-testid="stMetric"]:hover { border-color: var(--vf-accent-dim); }
    [data-testid="stMetricLabel"] { color: var(--vf-muted) !important; font-size: 0.85rem !important; }
    [data-testid="stMetricValue"] { font-family: 'Space Grotesk', sans-serif; }

    /* ---- Expanders (used as cards throughout) ---- */
    div[data-testid="stExpander"] {
        background: var(--vf-panel);
        border: 1px solid var(--vf-border);
        border-radius: 12px;
        margin-bottom: 10px;
        overflow: hidden;
    }
    div[data-testid="stExpander"] summary { padding: 4px 2px; }
    div[data-testid="stExpander"]:hover { border-color: var(--vf-border-soft); }

    /* ---- Buttons ---- */
    .stButton > button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        border: 1px solid var(--vf-border) !important;
    }
    .stButton > button[kind="primary"] {
        background: var(--vf-accent) !important;
        color: #0b1018 !important;
        border: none !important;
    }
    .stDownloadButton > button { border-radius: 8px !important; font-weight: 600 !important; }

    /* ---- Badges (risk level chips) ---- */
    .vf-badge {
        display: inline-block; padding: 3px 11px; border-radius: 999px;
        font-size: 0.72rem; font-weight: 700; letter-spacing: 0.4px; text-transform: uppercase;
    }
    .vf-badge-critical { background: rgba(229,72,77,0.15); color: #ff8b8f; border: 1px solid rgba(229,72,77,0.4); }
    .vf-badge-high { background: rgba(224,167,46,0.15); color: #f0c15e; border: 1px solid rgba(224,167,46,0.4); }
    .vf-badge-medium { background: rgba(224,167,46,0.1); color: #d8c78a; border: 1px solid rgba(224,167,46,0.25); }
    .vf-badge-low { background: rgba(62,207,142,0.15); color: #71e6ab; border: 1px solid rgba(62,207,142,0.4); }

    /* ---- Demo banner ---- */
    .vf-demo-banner {
        background: rgba(224,167,46,0.08);
        border: 1px solid rgba(224,167,46,0.3);
        border-radius: 10px;
        padding: 12px 16px;
        margin-bottom: 16px;
        color: #f0c15e;
        font-size: 0.88rem;
    }

    /* ---- Sidebar nav section captions ---- */
    .vf-nav-caption {
        color: var(--vf-muted); font-size: 0.72rem; font-weight: 700;
        text-transform: uppercase; letter-spacing: 0.8px;
        margin: 14px 0 2px 4px;
    }

    /* tighten default streamlit radio spacing in sidebar for a nav-menu feel */
    section[data-testid="stSidebar"] div[role="radiogroup"] label {
        padding: 3px 6px; border-radius: 6px;
    }

    hr { border-color: var(--vf-border-soft) !important; }
    </style>
    """,
    unsafe_allow_html=True,
)


def page_header(icon: str, title: str, subtitle: str = ""):
    """Consistent icon + title (+ optional subtitle) header used at the top of every page."""
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
    st.write("")  # small breathing room below the header


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
st.sidebar.markdown(
    """
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:2px;">
        <span style="font-size:1.6rem;">🛡️</span>
        <span style="font-family:'Space Grotesk',sans-serif;font-weight:700;font-size:1.25rem;color:#e7ecf5;">
            VerifAI 360
        </span>
    </div>
    """,
    unsafe_allow_html=True,
)
st.sidebar.caption("AI-driven PCI DSS self-assessment")
st.sidebar.markdown('<div class="vf-nav-caption">Workspace</div>', unsafe_allow_html=True)


def _activate_core():
    st.session_state["_active_page"] = st.session_state["_core_radio"]


def _activate_demo():
    st.session_state["_active_page"] = st.session_state["_demo_radio"]


core_page = st.sidebar.radio(
    "Navigate",
    [
        "🎯 SAQ Scoping",
        "📤 Upload & Analyze",
        "📊 Compliance Dashboard",
        "🗺️ CDE Scope",
        "🛡️ Compensating Controls",
        "🧪 Testing Tracker (Req 11)",
        "🤝 Vendor / TPSP Register",
        "⚠️ Identified Risks",
        "🕳️ Gap Report",
        "📚 Requirement Explorer",
        "🗂️ Evidence Log",
    ],
    label_visibility="collapsed",
    key="_core_radio",
    on_change=_activate_core,
)
st.sidebar.markdown('<div class="vf-nav-caption">Roadmap · Demo</div>', unsafe_allow_html=True)
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
# Strip the leading emoji + space for internal page-matching logic below.
page = page_raw.split(" ", 1)[1] if page_raw and " " in page_raw else page_raw

st.sidebar.divider()
_n_keys = ai.get_key_count()
if _n_keys == 0:
    st.sidebar.warning(
        "GOOGLE_API_KEY is not set. Get a free key at aistudio.google.com/apikey "
        "and set it in a `.env` file to enable AI analysis."
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
if st.sidebar.button("⚠️ Reset all demo data"):
    db.reset_all()
    st.sidebar.success("All evidence, scores, and risks cleared.")
    st.rerun()

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
    page_header("📤", "Upload evidence for AI assessment",
                "Sufficiency scoring, cross-requirement mapping, and gap detection in one pass")
    st.write(
        "Upload a policy document, configuration screenshot, scan report, or similar artifact. "
        "The AI will assess its **sufficiency**, assign a **compliance/maturity score**, check whether "
        "it also **spans other sub-requirements**, and generate **gap-remediation recommendations**."
    )

    opts, id_map = sub_req_options()
    col1, col2 = st.columns([2, 1])
    with col1:
        uploaded = st.file_uploader(
            "Evidence file",
            type=["txt", "log", "csv", "json", "md", "conf", "cfg", "yaml", "yml",
                  "pdf", "docx", "png", "jpg", "jpeg", "bmp", "tiff"],
        )
    with col2:
        target_label = st.selectbox("Primary target sub-requirement (optional)", opts)
        target_id = id_map.get(target_label)

    if uploaded and st.button("🔍 Analyze evidence", type="primary"):
        with st.spinner("Extracting evidence and running AI compliance analysis..."):
            try:
                suffix = os.path.splitext(uploaded.name)[1]
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(uploaded.getbuffer())
                    tmp_path = tmp.name

                result = ce.process_uploaded_evidence(tmp_path, uploaded.name, target_id)
                os.unlink(tmp_path)
            except EvidenceUploadError as e:
                st.error(f"Upload rejected: {e}")
                st.stop()
            except EvidenceExtractionError as e:
                st.error(f"Could not read this file: {e}")
                st.stop()
            except AIAnalyzerError as e:
                st.error(f"AI analysis failed: {e}")
                st.stop()

        st.success(f"Analysis complete — evidence recognized as: **{result['evidence_type']}**")
        st.info(result.get("evidence_summary", ""))

        assessments = sorted(result["assessments"], key=lambda a: -a["sufficiency_score"])
        if not assessments:
            st.warning("The AI did not find this evidence relevant to any PCI DSS sub-requirement in the catalog.")
        else:
            st.subheader(f"Mapped to {len(assessments)} sub-requirement(s)")
            if len(assessments) > 1:
                st.caption(
                    "✨ Cross-requirement spanning detected: this single piece of evidence "
                    "contributes to more than one sub-requirement."
                )
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
    page_header("📊", "Compliance Dashboard", "Overall PCI DSS posture, scoped to your selected SAQ type")
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
                 color="Compliance %", color_continuous_scale=["#e5484d", "#e0a72e", "#3ecf8e"])
    fig.update_layout(height=max(180, 60 * len(in_scope_reqs)), yaxis={"categoryorder": "total ascending"},
                       paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                       font_color="#e7ecf5")
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
                                       line=dict(color="#35d0c0", width=3)))
            fig2.update_layout(height=340, yaxis_title="Avg sufficiency score", xaxis_title="Time",
                                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                font_color="#e7ecf5")
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
            colorscale=[[0, "#141c2b"], [0.5, "#e0a72e"], [1, "#e5484d"]],
            showscale=False,
            hovertemplate="Likelihood %{x}, Impact %{y}<br>Risks: %{z}<extra></extra>",
        ))
        fig3.update_layout(height=340, xaxis_title="Likelihood", yaxis_title="Impact",
                            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                            font_color="#e7ecf5")
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
            rg.generate_pdf_report(),
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
# NOTE: "Identified Risks" is rendered as a section further up inside the
# Compliance Dashboard block above (it shares that page's sidebar entry),
# not as its own separate "elif" branch — that's why there's no
# `elif page == "Identified Risks":` here.
# ----------------------------------------------------------------------------

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
    page_header("🎯", "SAQ Type Selection & Scoping",
                "Pick the SAQ type that matches how you handle cardholder data — this determines "
                "which of the 12 requirements are actually in scope")
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

    if st.button("💾 Save SAQ type", type="primary"):
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
    page_header("🗺️", "Cardholder Data Environment (CDE) Scope",
                "Document what's in scope, what's out of scope, and what's connected-to/security-"
                "impacting the CDE")
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
            submitted = st.form_submit_button("Add system")
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
                    if st.button("🗑️ Delete", key=f"del_cde_{it['id']}"):
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
    page_header("🛡️", "Compensating Controls Worksheet",
                "Document an alternative control when a standard requirement can't be implemented as written")
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
            submitted = st.form_submit_button("Add compensating control")
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
                    if st.button("🗑️ Delete", key=f"del_cc_{it['id']}"):
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
    page_header("🧪", "Recurring Testing Tracker",
                "Requirement 11: ASV quarterly external scans, internal scans, annual penetration "
                "tests, and segmentation testing — with due dates, not one-time evidence")
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
            submitted = st.form_submit_button("Add test")
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
                new_next = ec2.date_input(
                    "Update next due", value=datetime.date.fromisoformat(it["next_due_date"]),
                    key=f"next_{it['id']}"
                )
                bc1, bc2, bc3 = st.columns([1, 1, 4])
                with bc1:
                    if st.button("💾 Save", key=f"save_test_{it['id']}"):
                        db.update_test_item(
                            it["id"],
                            last_performed_date=str(new_last) if new_last else it.get("last_performed_date"),
                            next_due_date=str(new_next),
                        )
                        st.success("Updated.")
                        st.rerun()
                with bc2:
                    if st.button("🗑️ Delete", key=f"del_test_{it['id']}"):
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
    page_header("🤝", "Vendor / TPSP Management Register",
                "Requirements 12.8 & 12.9 — third-party service providers, tracked separately from "
                "general evidence")

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
            submitted = st.form_submit_button("Add vendor")
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
                    if st.button("🗑️ Delete", key=f"del_vendor_{v['id']}"):
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
    page_header("⚠️", "Identified Risks",
                "Internal risk items tracked from this tool — not your organization's official risk register")
    st.write(
        "Tracked risks, scored on a standard 5×5 **Likelihood × Impact** matrix (1–25). "
        "Items are either added manually or generated automatically from open compliance gaps."
    )

    top1, top2 = st.columns([1, 3])
    with top1:
        if st.button("🔄 Sync risks from gap report", type="primary"):
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
            submitted = st.form_submit_button("Add risk")
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
                new_status = ec1.selectbox("Status", re_.STATUS_OPTIONS,
                                            index=re_.STATUS_OPTIONS.index(r["status"]),
                                            key=f"status_{r['id']}")
                new_owner = ec2.text_input("Owner", value=r["owner"] or "", key=f"owner_{r['id']}")
                new_likelihood = ec3.slider("Likelihood", 1, 5, r["likelihood"], key=f"like_{r['id']}")
                new_impact = ec4.slider("Impact", 1, 5, r["impact"], key=f"impact_{r['id']}")

                bc1, bc2 = st.columns([1, 5])
                with bc1:
                    if st.button("💾 Save", key=f"save_{r['id']}"):
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
                    if st.button("🗑️ Delete", key=f"del_{r['id']}"):
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
    page_header("🕳️", "Gap Report & Remediation Plan",
                f"Sub-requirements below the compliant threshold ({ce.COMPLIANT_THRESHOLD}/100)")
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
    page_header("📚", "PCI DSS Requirement Explorer", "Browse the full catalog and current evidence status")
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
    page_header("🗂️", "Evidence Log", "Every artifact submitted so far, in one place")
    evidence = db.get_all_evidence()
    if not evidence:
        st.info("No evidence submitted yet.")
    else:
        edf = pd.DataFrame(evidence)[
            ["id", "filename", "evidence_type", "target_sub_requirement", "uploaded_at", "sha256"]
        ]
        edf["sha256"] = edf["sha256"].fillna("— (uploaded before integrity hashing was enabled)")
        edf = edf.rename(columns={"sha256": "SHA-256 (integrity hash)"})
        st.dataframe(edf, width='stretch', hide_index=True)
        st.caption(
            "SHA-256 is computed from the stored file's actual bytes at upload time — a real "
            "integrity hash you can use to verify a file on disk hasn't been altered since."
        )

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
    page_header("🔌", "Automated Evidence Ingestion", "Roadmap concept — not a live integration")
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
    page_header("📡", "Compliance Drift Alerts", "Roadmap concept — not a live integration")
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
    page_header("🧾", "QSA Audit View", "Roadmap concept — not a live integration")
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
        rg.generate_pdf_report(),
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
