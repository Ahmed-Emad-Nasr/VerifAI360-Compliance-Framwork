"""
report_generator.py
---------------------
Builds one complete, downloadable PDF compliance report for VerifAI 360.

The report pulls together everything the Streamlit dashboard shows across
several pages into a single QSA-style document:

  1. Cover page — overall compliance %, generation timestamp, disclaimer.
  2. Executive summary — headline metrics (evidence count, sub-requirements
     compliant, open risk exposure).
  3. Compliance by requirement — one table per top-level PCI DSS
     requirement, with every sub-requirement's score/status.
  4. Gap report — every sub-requirement below the compliant threshold,
     with its concrete gaps and recommended remediation.
  5. Identified risks register — Likelihood x Impact scored risks, with
     level, status, owner.
  6. Evidence log — every uploaded artifact with its real SHA-256
     integrity hash (see compliance_engine._sha256_of_file), so the report
     can be used to verify a file on disk hasn't been altered since upload.

Built with reportlab (Platypus), so it renders identically regardless of
what's installed on the machine running the app — no external renderer or
headless browser needed.

NOTE ON ACCURACY: like every page in the app itself, this report is an
automated, preliminary self-assessment aid. It is NOT a Qualified Security
Assessor (QSA) opinion and does not constitute formal PCI DSS validation.
That disclaimer is printed on every page of the report, not just here.
"""

import io
import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)

from . import database as db
from . import compliance_engine as ce
from . import risk_engine as re_
from . import ai_analyzer as ai
from . import scoping_data as sd

# ----------------------------------------------------------------------------
# Palette — echoes the app's teal/dark theme, but tuned for print-on-white
# legibility rather than the dark Streamlit UI.
# ----------------------------------------------------------------------------
ACCENT = colors.HexColor("#0f8a80")
ACCENT_DARK = colors.HexColor("#0b2a3d")
COVER_BG = colors.HexColor("#0b1018")
RED = colors.HexColor("#c0392b")
AMBER = colors.HexColor("#b8860b")
GREEN = colors.HexColor("#1e8449")
GREY = colors.HexColor("#5a6472")
LIGHT_BG = colors.HexColor("#eef4f3")
HEADER_TEXT = colors.white

PAGE_SIZE = letter
MARGIN = 2 * cm


def _status_color(status: str):
    return {"Compliant": GREEN, "Partial / Gap": AMBER, "No evidence": RED}.get(status, GREY)


def _risk_color(level: str):
    return {
        "Critical": RED,
        "High": colors.HexColor("#d35400"),
        "Medium": AMBER,
        "Low": GREEN,
    }.get(level, GREY)


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="VFTitle", fontName="Helvetica-Bold", fontSize=26, leading=30,
        textColor=colors.white, alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="VFSubtitle", fontName="Helvetica", fontSize=13, leading=18,
        textColor=colors.HexColor("#9fb3c8"), alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="VFCoverMetric", fontName="Helvetica-Bold", fontSize=44, leading=48,
        textColor=ACCENT, alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="VFCoverMetricLabel", fontName="Helvetica", fontSize=11, leading=14,
        textColor=colors.HexColor("#9fb3c8"), alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="VFH1", fontName="Helvetica-Bold", fontSize=17, leading=21,
        textColor=ACCENT_DARK, spaceBefore=6, spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="VFH2", fontName="Helvetica-Bold", fontSize=12.5, leading=16,
        textColor=ACCENT_DARK, spaceBefore=10, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="VFBody", fontName="Helvetica", fontSize=9.5, leading=13,
        textColor=colors.HexColor("#20262f"),
    ))
    styles.add(ParagraphStyle(
        name="VFBodySmall", fontName="Helvetica", fontSize=8.3, leading=11.5,
        textColor=colors.HexColor("#20262f"),
    ))
    styles.add(ParagraphStyle(
        name="VFCaption", fontName="Helvetica-Oblique", fontSize=8.3, leading=11,
        textColor=GREY,
    ))
    styles.add(ParagraphStyle(
        name="VFCellHeader", fontName="Helvetica-Bold", fontSize=8.6, leading=11,
        textColor=colors.white,
    ))
    styles.add(ParagraphStyle(
        name="VFCell", fontName="Helvetica", fontSize=8.3, leading=11,
        textColor=colors.HexColor("#20262f"),
    ))
    return styles


def _disclaimer_banner(styles):
    text = (
        "<b>Automated self-assessment output — not a QSA opinion.</b> Scores and recommendations "
        "in this report were generated by an AI model against a condensed, paraphrased PCI DSS "
        "v4.0-style requirement catalog. They are a preliminary starting point to verify, not a "
        "formal PCI DSS validation. For any real assessment, consult a Qualified Security Assessor "
        "and the official PCI DSS v4.0.1 standard (pcisecuritystandards.org)."
    )
    p = Paragraph(text, ParagraphStyle(
        "VFDisclaimer", fontName="Helvetica", fontSize=8, leading=11,
        textColor=colors.HexColor("#5a3d00"),
    ))
    t = Table([[p]], colWidths=[PAGE_SIZE[0] - 2 * MARGIN])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fdf3d8")),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#e0c168")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return t


def _cover_page(story, styles, summary, exposure, n_evidence):
    generated = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    story.append(Spacer(1, 3.2 * cm))
    story.append(Paragraph("VerifAI 360", styles["VFTitle"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph("AI-Driven PCI DSS Self-Assessment — Compliance Report", styles["VFSubtitle"]))
    story.append(Spacer(1, 1.4 * cm))

    metric_cells = [
        [Paragraph(f"{summary['overall_pct']}%", styles["VFCoverMetric"]),
         Paragraph(str(n_evidence), styles["VFCoverMetric"]),
         Paragraph(str(exposure["total_open_exposure"]), styles["VFCoverMetric"])],
        [Paragraph("OVERALL COMPLIANCE", styles["VFCoverMetricLabel"]),
         Paragraph("EVIDENCE ARTIFACTS", styles["VFCoverMetricLabel"]),
         Paragraph("OPEN RISK EXPOSURE", styles["VFCoverMetricLabel"])],
    ]
    t = Table(metric_cells, colWidths=[(PAGE_SIZE[0] - 2 * MARGIN) / 3] * 3)
    t.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, 0), 4),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 2.2 * cm))
    story.append(Paragraph(f"Generated {generated}", styles["VFSubtitle"]))
    story.append(Spacer(1, 4 * cm))
    story.append(_disclaimer_banner_dark(styles))
    story.append(PageBreak())


def _disclaimer_banner_dark(styles):
    text = (
        "This report is an automated, preliminary self-assessment aid — it is NOT a Qualified "
        "Security Assessor (QSA) opinion and does not constitute formal PCI DSS validation."
    )
    p = Paragraph(text, ParagraphStyle(
        "VFDiscDark", fontName="Helvetica-Oblique", fontSize=9, leading=13,
        textColor=colors.HexColor("#9fb3c8"), alignment=TA_CENTER,
    ))
    return p


def _executive_summary(story, styles, summary, exposure, n_evidence, n_compliant, n_total, n_keys):
    story.append(Paragraph("Executive Summary", styles["VFH1"]))
    story.append(_disclaimer_banner(styles))
    story.append(Spacer(1, 10))

    rows = [
        ["Overall PCI DSS compliance", f"{summary['overall_pct']}%"],
        ["Sub-requirements compliant", f"{n_compliant} / {n_total}"],
        ["Evidence artifacts submitted", str(n_evidence)],
        ["Open gaps (below compliant threshold)", str(n_total - n_compliant)],
        ["Open risk exposure (sum of Likelihood x Impact, Open/Mitigating)", str(exposure["total_open_exposure"])],
        ["Critical risks currently open", str(exposure["critical_open"])],
        ["Gemini API keys configured (analysis redundancy)", str(n_keys)],
    ]
    t = Table([["Metric", "Value"]] + rows, colWidths=[10.5 * cm, 5.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5dee0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t)
    story.append(PageBreak())


def _compliance_by_requirement(story, styles, summary):
    story.append(Paragraph("Compliance by Requirement", styles["VFH1"]))
    story.append(Paragraph(
        "Score per sub-requirement is the best (highest) sufficiency score across every piece of "
        "evidence ever submitted for it. A requirement with no evidence on file scores 0.",
        styles["VFCaption"],
    ))
    story.append(Spacer(1, 8))

    for req in summary["requirements"]:
        block = [Paragraph(f"Requirement {req['id']}: {req['title']} — {req['pct']}%", styles["VFH2"])]
        header = ["ID", "Sub-requirement", "Score", "Status"]
        data = [header]
        for s in req["sub_requirements"]:
            data.append([s["id"], Paragraph(s["title"], styles["VFCell"]), f"{s['score']}/100", s["status"]])
        t = Table(data, colWidths=[1.6 * cm, 9.4 * cm, 1.8 * cm, 3.2 * cm], repeatRows=1)
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.3),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dee0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        for i, s in enumerate(req["sub_requirements"], start=1):
            style_cmds.append(("TEXTCOLOR", (3, i), (3, i), _status_color(s["status"])))
            style_cmds.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))
        t.setStyle(TableStyle(style_cmds))
        block.append(t)
        block.append(Spacer(1, 12))
        story.append(KeepTogether(block))
    story.append(PageBreak())


def _simple_table_section(story, styles, title, caption, header, rows, col_widths, empty_msg):
    """Shared helper for the small register-style sections (CDE scope, compensating controls,
    testing tracker, vendor register) so each one doesn't reinvent table styling."""
    story.append(Paragraph(title, styles["VFH1"]))
    if caption:
        story.append(Paragraph(caption, styles["VFCaption"]))
    story.append(Spacer(1, 8))
    if not rows:
        story.append(Paragraph(empty_msg, styles["VFBody"]))
        story.append(PageBreak())
        return
    data = [header] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.6),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dee0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t)
    story.append(PageBreak())


def _saq_scope_summary(story, styles, summary):
    saq_def = sd.get_saq_definition(summary["saq_type"])
    story.append(Paragraph("SAQ Type & Scope", styles["VFH1"]))
    story.append(Paragraph(
        f"<b>Selected SAQ type:</b> {saq_def['label']}", styles["VFBody"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(saq_def["description"], styles["VFBodySmall"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "In-scope requirements for this SAQ type: " +
        ", ".join(summary["in_scope_requirement_ids"]) + ". "
        "Requirements outside this list are reported as Not Applicable and excluded from the "
        "compliance % on this page and throughout this report.",
        styles["VFBodySmall"],
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>Accuracy note:</b> this requirement-level SAQ mapping is a simplified approximation. "
        "Confirm the official, question-level applicability using the current SAQ document at "
        "pcisecuritystandards.org and validate the correct SAQ type with your acquirer/QSA.",
        styles["VFCaption"],
    ))
    story.append(Spacer(1, 10))
    story.append(_disclaimer_banner(styles))
    story.append(PageBreak())


def _cde_scope_section(story, styles):
    items = db.get_all_cde_systems()
    header = ["System / Component", "Type", "In CDE scope?", "Connected-to/Impacting?", "Data flow notes"]
    rows = []
    for it in items:
        rows.append([
            Paragraph(it["system_name"], styles["VFCell"]),
            it.get("component_type") or "—",
            "Yes" if it["in_scope"] else "No",
            "Yes" if it["connected_to_cde"] else "No",
            Paragraph((it.get("data_flow_notes") or "—")[:200], styles["VFCell"]),
        ])
    _simple_table_section(
        story, styles,
        "Cardholder Data Environment (CDE) Scope",
        "Systems and components documented as in-scope, out-of-scope, or connected-to/security-"
        "impacting the CDE (PCI DSS v4.0 Requirement 1.2.4 calls for this documentation, along with "
        "network and data-flow diagrams maintained outside this tool).",
        header, rows,
        [4.5 * cm, 2.4 * cm, 2.2 * cm, 3 * cm, 4.9 * cm],
        "No CDE scope items documented yet — add them on the CDE Scope page.",
    )


def _compensating_controls_section(story, styles):
    items = db.get_all_compensating_controls()
    header = ["Sub-req", "Constraint", "Compensating control", "Additional risk", "Status", "Next review"]
    rows = []
    for it in items:
        rows.append([
            it["sub_requirement_id"],
            Paragraph((it.get("constraint_reason") or "—")[:150], styles["VFCell"]),
            Paragraph((it.get("compensating_control_description") or "—")[:220], styles["VFCell"]),
            Paragraph((it.get("additional_risk") or "—")[:120], styles["VFCell"]),
            it.get("status") or "Draft",
            it.get("next_review_date") or "—",
        ])
    _simple_table_section(
        story, styles,
        "Compensating Controls Worksheet",
        "Documented per PCI DSS Appendix B/C guidance for cases where a standard requirement "
        "cannot be met as written and an alternative control is used instead.",
        header, rows,
        [1.6 * cm, 3.4 * cm, 5.2 * cm, 2.8 * cm, 1.6 * cm, 2 * cm],
        "No compensating controls documented — add them on the Compensating Controls page.",
    )


def _testing_tracker_section(story, styles):
    items = db.get_all_test_items()
    header = ["Test type", "Related req", "Frequency", "Last performed", "Next due", "Status", "Result"]
    rows = []
    for it in items:
        status = ce.testing_tracker_status(it.get("next_due_date"))
        rows.append([
            Paragraph(it["test_type"], styles["VFCell"]),
            it.get("related_requirement") or "—",
            it.get("frequency") or "—",
            it.get("last_performed_date") or "—",
            it.get("next_due_date") or "—",
            status,
            it.get("result_status") or "—",
        ])
    _simple_table_section(
        story, styles,
        "Recurring Testing Tracker (Requirement 11)",
        "ASV quarterly external scans, internal vulnerability scans, annual penetration tests, and "
        "segmentation testing are recurring obligations under Requirement 11, not one-time evidence "
        "uploads. This tracker records due dates and status for each.",
        header, rows,
        [3.2 * cm, 2 * cm, 2.2 * cm, 2.2 * cm, 2 * cm, 1.8 * cm, 2.1 * cm],
        "No recurring tests tracked yet — add them on the Testing Tracker page.",
    )


def _vendor_register_section(story, styles):
    items = db.get_all_vendors()
    header = ["Vendor", "Service", "Responsibility", "Compliance status", "Attestation", "Next review"]
    rows = []
    for it in items:
        rows.append([
            Paragraph(it["vendor_name"], styles["VFCell"]),
            Paragraph((it.get("service_provided") or "—")[:120], styles["VFCell"]),
            it.get("pci_dss_responsibility") or "—",
            it.get("compliance_status") or "Unknown",
            it.get("attestation_type") or "—",
            it.get("next_review_due") or "—",
        ])
    _simple_table_section(
        story, styles,
        "Vendor / TPSP Management Register",
        "Third-party service providers (TPSPs) engaged by the organization, tracked separately from "
        "general evidence per Requirements 12.8 (TPSP due diligence) and 12.9 (written acknowledgment "
        "of PCI DSS responsibilities).",
        header, rows,
        [3 * cm, 4 * cm, 2.6 * cm, 2.6 * cm, 2.4 * cm, 1.9 * cm],
        "No vendors documented yet — add them on the Vendor Register page.",
    )


def _gap_report(story, styles):
    gaps = ce.build_gap_report()
    story.append(Paragraph("Gap Report & Remediation Plan", styles["VFH1"]))
    story.append(Paragraph(
        f"Sub-requirements scoring below the compliant threshold ({ce.COMPLIANT_THRESHOLD}/100).",
        styles["VFCaption"],
    ))
    story.append(Spacer(1, 8))

    if not gaps:
        story.append(Paragraph("No gaps — every sub-requirement is at or above the compliant threshold.",
                                styles["VFBody"]))
    else:
        for g in gaps:
            title = (f"[{g['sub_requirement_id']}] {g['sub_requirement_title']} — "
                     f"score {g['current_score']}/100 (Req {g['requirement_id']}: {g['requirement_title']})")
            block = [Paragraph(title, styles["VFH2"])]
            if g["gaps"]:
                block.append(Paragraph("<b>Gaps:</b> " + "; ".join(g["gaps"]), styles["VFBodySmall"]))
            if g["recommendations"]:
                block.append(Paragraph("<b>Recommended remediation:</b> " + "; ".join(g["recommendations"]),
                                        styles["VFBodySmall"]))
            block.append(Spacer(1, 8))
            story.append(KeepTogether(block))
    story.append(PageBreak())


def _identified_risks(story, styles):
    risks = db.get_all_risks()
    exposure = re_.risk_exposure_summary(risks)
    story.append(Paragraph("Identified Risks Register", styles["VFH1"]))
    story.append(Paragraph(
        "Internal risk items tracked by this tool (Likelihood x Impact, 1-25) — not the "
        "organization's official risk register.",
        styles["VFCaption"],
    ))
    story.append(Spacer(1, 8))

    if not risks:
        story.append(Paragraph("No risks tracked yet.", styles["VFBody"]))
        story.append(PageBreak())
        return

    summary_rows = [[k, str(v)] for k, v in exposure["by_level"].items()]
    st_ = Table([["Risk level", "Open + Mitigating count"]] + summary_rows, colWidths=[6 * cm, 6 * cm])
    st_.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dee0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(st_)
    story.append(Spacer(1, 12))

    header = ["Sub-req", "Title", "L", "I", "Score", "Level", "Status", "Owner"]
    data = [header]
    for r in risks:
        data.append([
            r.get("sub_requirement_id") or "—",
            Paragraph((r["title"] or "")[:70], styles["VFCell"]),
            str(r["likelihood"]), str(r["impact"]), str(r["risk_score"]),
            r["risk_level"], r["status"], r.get("owner") or "—",
        ])
    t = Table(data, colWidths=[1.6 * cm, 6.5 * cm, 0.8 * cm, 0.8 * cm, 1.3 * cm, 2 * cm, 2 * cm, 2 * cm],
              repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.6),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dee0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i, r in enumerate(risks, start=1):
        style_cmds.append(("TEXTCOLOR", (5, i), (5, i), _risk_color(r["risk_level"])))
        style_cmds.append(("FONTNAME", (5, i), (5, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style_cmds))
    story.append(t)
    story.append(PageBreak())


def _evidence_log(story, styles):
    evidence = db.get_all_evidence()
    story.append(Paragraph("Evidence Log & Integrity Hashes", styles["VFH1"]))
    story.append(Paragraph(
        "Every artifact submitted so far. SHA-256 is computed from the stored file's bytes at "
        "upload time and can be used to verify the file on disk hasn't been altered since.",
        styles["VFCaption"],
    ))
    story.append(Spacer(1, 8))

    if not evidence:
        story.append(Paragraph("No evidence submitted yet.", styles["VFBody"]))
        return

    header = ["ID", "Filename", "Type", "Target sub-req", "Uploaded (UTC)", "SHA-256"]
    data = [header]
    for e in evidence:
        sha = e.get("sha256") or "not available (uploaded before integrity hashing was enabled)"
        data.append([
            str(e["id"]),
            Paragraph(e["filename"], styles["VFCell"]),
            e.get("evidence_type") or "—",
            e.get("target_sub_requirement") or "—",
            (e["uploaded_at"] or "")[:19].replace("T", " "),
            Paragraph(f"<font face='Courier' size=6.6>{sha}</font>", styles["VFCell"]),
        ])
    t = Table(data, colWidths=[1 * cm, 3.4 * cm, 1.8 * cm, 2.2 * cm, 2.6 * cm, 4.6 * cm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.4),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dee0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t)


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(ACCENT)
    canvas.setLineWidth(0.6)
    canvas.line(MARGIN, 1.55 * cm, PAGE_SIZE[0] - MARGIN, 1.55 * cm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(GREY)
    canvas.drawString(MARGIN, 1.2 * cm,
                       "VerifAI 360 - Automated PCI DSS self-assessment output. NOT a QSA opinion.")
    canvas.drawRightString(PAGE_SIZE[0] - MARGIN, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()


def _cover_page_background(canvas, doc):
    """Only paints the dark cover background on page 1; later pages stay white for printing."""
    if doc.page == 1:
        canvas.saveState()
        canvas.setFillColor(COVER_BG)
        canvas.rect(0, 0, PAGE_SIZE[0], PAGE_SIZE[1], fill=1, stroke=0)
        canvas.setStrokeColor(ACCENT)
        canvas.setLineWidth(2)
        canvas.rect(1.1 * cm, 1.1 * cm, PAGE_SIZE[0] - 2.2 * cm, PAGE_SIZE[1] - 2.2 * cm, fill=0, stroke=1)
        canvas.restoreState()
    else:
        _header_footer(canvas, doc)


def generate_pdf_report() -> bytes:
    """
    Builds the full VerifAI 360 compliance report and returns it as raw PDF
    bytes, ready to hand straight to st.download_button(..., mime="application/pdf").
    """
    summary = ce.compute_compliance_summary()
    risks = db.get_all_risks()
    exposure = re_.risk_exposure_summary(risks)
    n_evidence = len(db.get_all_evidence())
    n_compliant = sum(
        1 for r in summary["requirements"] for s in r["sub_requirements"] if s["status"] == "Compliant"
    )
    n_total = sum(len(r["sub_requirements"]) for r in summary["requirements"])
    n_keys = ai.get_key_count()

    styles = _styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=PAGE_SIZE,
        leftMargin=MARGIN, rightMargin=MARGIN, topMargin=1.6 * cm, bottomMargin=2 * cm,
        title="VerifAI 360 - PCI DSS Compliance Report",
        author="VerifAI 360",
    )

    story = []
    _cover_page(story, styles, summary, exposure, n_evidence)
    _executive_summary(story, styles, summary, exposure, n_evidence, n_compliant, n_total, n_keys)
    _saq_scope_summary(story, styles, summary)
    _compliance_by_requirement(story, styles, summary)
    _cde_scope_section(story, styles)
    _compensating_controls_section(story, styles)
    _testing_tracker_section(story, styles)
    _vendor_register_section(story, styles)
    _gap_report(story, styles)
    _identified_risks(story, styles)
    _evidence_log(story, styles)

    doc.build(story, onFirstPage=_cover_page_background, onLaterPages=_cover_page_background)
    return buffer.getvalue()


# ----------------------------------------------------------------------------
# Attestation of Compliance (AOC) — standalone signature-ready document
# ----------------------------------------------------------------------------

def generate_aoc_pdf(aoc_info: dict) -> bytes:
    """
    Builds a standalone Attestation of Compliance (AOC) summary document —
    the document an executive/QSA signs at the end of an assessment.

    aoc_info keys (all optional, pass what's known):
      organization_name, dba_name, assessor_company, assessor_name,
      executive_name, executive_title, contact_email, assessment_date,
      part2g_statement (any extra attestation statement text)

    NOTE: this is a *summary* AOC generated from this tool's own scored
    self-assessment, not the official PCI SSC AOC template for the selected
    SAQ type. For an actual submission to an acquirer/card brand, use the
    official AOC template that accompanies your SAQ type, available at
    pcisecuritystandards.org — this document is a convenient internal
    starting point, not a replacement for it.
    """
    summary = ce.compute_compliance_summary()
    saq_def = sd.get_saq_definition(summary["saq_type"])
    n_total_in_scope = sum(
        len(r["sub_requirements"]) for r in summary["requirements"] if r["in_scope"]
    )
    n_compliant_in_scope = sum(
        1 for r in summary["requirements"] if r["in_scope"]
        for s in r["sub_requirements"] if s["status"] == "Compliant"
    )
    generated = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    styles = _styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=PAGE_SIZE,
        leftMargin=MARGIN, rightMargin=MARGIN, topMargin=1.8 * cm, bottomMargin=2 * cm,
        title="VerifAI 360 - Attestation of Compliance (Summary)",
        author="VerifAI 360",
    )
    story = []
    story.append(Paragraph("Attestation of Compliance", styles["VFH1"]))
    story.append(Paragraph(f"Summary document generated {generated}", styles["VFCaption"]))
    story.append(Spacer(1, 10))
    story.append(_disclaimer_banner(styles))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This is a self-assessment summary AOC produced by VerifAI 360, <b>not</b> the official "
        "PCI SSC AOC template. For any real submission to an acquirer or card brand, use the "
        "official AOC template that accompanies your SAQ type (pcisecuritystandards.org) and have "
        "it reviewed/completed with a Qualified Security Assessor as applicable.",
        ParagraphStyle("VFAOCNote", fontName="Helvetica-Oblique", fontSize=8.3, leading=11.5,
                        textColor=colors.HexColor("#5a3d00")),
    ))
    story.append(Spacer(1, 14))

    rows = [
        ["Organization (merchant/service provider) name", aoc_info.get("organization_name") or "—"],
        ["DBA (doing business as) name", aoc_info.get("dba_name") or "—"],
        ["SAQ type", saq_def["label"]],
        ["Assessment date", aoc_info.get("assessment_date") or "—"],
        ["Assessor company (if QSA-assisted)", aoc_info.get("assessor_company") or "—"],
        ["Assessor name (if QSA-assisted)", aoc_info.get("assessor_name") or "—"],
        ["Executive signer name", aoc_info.get("executive_name") or "—"],
        ["Executive signer title", aoc_info.get("executive_title") or "—"],
        ["Contact email", aoc_info.get("contact_email") or "—"],
        ["Sub-requirements compliant (in SAQ scope)", f"{n_compliant_in_scope} / {n_total_in_scope}"],
        ["Overall compliance % (in SAQ scope)", f"{summary['overall_pct']}%"],
    ]
    t = Table([["Field", "Value"]] + rows, colWidths=[8 * cm, 8 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d5dee0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    statement = aoc_info.get("part2g_statement") or (
        "The signatory below attests that, to the best of their knowledge, the information in this "
        "self-assessment is accurate and that all applicable PCI DSS requirements referenced above "
        "have been assessed using the evidence on file in VerifAI 360 as of the generation date."
    )
    story.append(Paragraph("Attestation statement", styles["VFH2"]))
    story.append(Paragraph(statement, styles["VFBody"]))
    story.append(Spacer(1, 40))

    sig_rows = [
        ["Executive signature: _______________________________", "Date: ______________"],
        ["", ""],
        ["QSA signature (if applicable): _____________________", "Date: ______________"],
    ]
    sig_t = Table(sig_rows, colWidths=[11 * cm, 5 * cm])
    sig_t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(sig_t)

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buffer.getvalue()
