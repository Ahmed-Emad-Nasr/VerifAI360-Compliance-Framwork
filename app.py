"""
VerifAI 360 — Streamlit application entry point.

Run with:
    streamlit run app.py

Requires GOOGLE_API_KEY to be set (see .env.example) for the
"Upload & Analyze" page. All other pages work purely off the local
SQLite database and need no API key.
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
        "📤 Upload & Analyze",
        "📊 Compliance Dashboard",
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
if not os.environ.get("GOOGLE_API_KEY"):
    st.sidebar.warning(
        "GOOGLE_API_KEY is not set. Get a free key at aistudio.google.com/apikey "
        "and set it in a `.env` file to enable AI analysis."
    )
else:
    st.sidebar.markdown(
        '<div style="display:flex;align-items:center;gap:6px;color:#71e6ab;font-size:0.85rem;">'
        '🟢 Gemini API key detected</div>',
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
# ----------------------------------------------------------------------------
elif page == "Compliance Dashboard":
    page_header("📊", "Compliance Dashboard", "Overall PCI DSS posture across all 12 requirements")
    summary = ce.compute_compliance_summary()
    risks = db.get_all_risks()
    exposure = re_.risk_exposure_summary(risks)

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

    df = pd.DataFrame(
        [{"Requirement": f"{r['id']}. {r['title']}", "Compliance %": r["pct"]} for r in summary["requirements"]]
    )
    fig = px.bar(df, x="Compliance %", y="Requirement", orientation="h", range_x=[0, 100],
                 color="Compliance %", color_continuous_scale=["#e5484d", "#e0a72e", "#3ecf8e"])
    fig.update_layout(height=500, yaxis={"categoryorder": "total ascending"},
                       paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                       font_color="#e7ecf5")
    st.plotly_chart(fig, width='stretch')

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
        with st.expander(f"{r['id']}. {r['title']} — {r['pct']}%"):
            sdf = pd.DataFrame(r["sub_requirements"])
            st.dataframe(sdf[["id", "title", "score", "status"]], width='stretch', hide_index=True)

# ----------------------------------------------------------------------------
# PAGE: Identified Risks
# ----------------------------------------------------------------------------
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
# ----------------------------------------------------------------------------
elif page == "Evidence Log":
    page_header("🗂️", "Evidence Log", "Every artifact submitted so far, in one place")
    evidence = db.get_all_evidence()
    if not evidence:
        st.info("No evidence submitted yet.")
    else:
        edf = pd.DataFrame(evidence)[["id", "filename", "evidence_type", "target_sub_requirement", "uploaded_at"]]
        st.dataframe(edf, width='stretch', hide_index=True)

# ----------------------------------------------------------------------------
# PAGE: Automated Connectors (demo / roadmap mockup)
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
# ----------------------------------------------------------------------------
elif page == "QSA Audit View (demo)":
    page_header("🧾", "QSA Audit View", "Roadmap concept — not a live integration")
    demo_banner(
        "this is a UI concept for a future read-only auditor view. The compliance % below is real "
        "(pulled from your actual data), but the file hashes and PDF export are placeholders — no "
        "real hashing or PDF generation happens yet."
    )

    summary = ce.compute_compliance_summary()
    st.metric("Current compliance score", f"{summary['overall_pct']}%")

    if st.button("📄 Generate audit PDF (not yet implemented)"):
        st.info(
            "PDF export isn't implemented yet. The `pdf` authoring skill/toolchain referenced in the "
            "README would need to be wired up to render a real report from the data below."
        )

    st.divider()
    st.subheader("Evidence submitted so far")
    evidence = db.get_all_evidence()
    if not evidence:
        st.caption("No artifacts found.")
    else:
        edf = pd.DataFrame(evidence)[["id", "filename", "uploaded_at", "target_sub_requirement"]]
        st.dataframe(edf, width='stretch', hide_index=True)
        st.caption(
            "Note: a real 'immutable evidence chain' would need per-file SHA-256 hashes computed at "
            "upload time and stored alongside each record — not shown here since that isn't built yet."
        )
