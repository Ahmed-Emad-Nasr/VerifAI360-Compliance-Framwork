# VerifAI 360 — AI-Driven PCI DSS Self-Assessment Platform

Team members: Amr Mohamed El Sayed, Nazly Mohamed Samir, Youssef Ahmed Mohamed,
Asmaa Ibrahim, Ahmed Emad El Din, Mohamed Hussein El Naggar, Mostafa Ahmed Mostafa.
Mentor: Mostafa ElKady.

## What this project does

You upload evidence (a policy document, a configuration screenshot, a
vulnerability scan report, etc.). The platform:

1. **Extracts** the text/content from the file (PDF, DOCX, image via OCR, or plain text).
2. **Sends it to Gemini** (Google AI Studio's **free** API tier — no credit
   card, no cost) with a condensed PCI DSS v4.0-style requirement catalog
   and asks the model to:
   - Score how **sufficient** the evidence is against each sub-requirement it's
     relevant to (0–100), and label a maturity level.
   - Identify **cross-requirement spanning** — the same evidence can satisfy
     more than one sub-requirement at once.
   - List **gaps** and **actionable recommendations**.
3. **Persists** every assessment in a local SQLite database, so scores
   accumulate across multiple uploads (continuous maturity scoring).
4. **Aggregates** everything into an overall compliance %, per-requirement %,
   a gap report, and a maturity trend chart — all in a Streamlit dashboard.
5. **Scores risk**: every open gap can be synced into **Identified Risks**,
   scored on a standard 5×5 Likelihood × Impact matrix (1–25, bucketed into
   Low/Medium/High/Critical), with an owner, status, and mitigation plan you
   can track over time. See "Risk scoring & Identified Risks" below.

## Risk scoring & Identified Risks

`src/risk_engine.py` adds a lightweight GRC layer on top of the compliance
engine:

- **Likelihood (1–5)** is derived from a sub-requirement's current AI
  sufficiency score — less/weaker evidence ⇒ higher likelihood the control
  fails when it matters.
- **Impact (1–5)** is a fixed weight per top-level PCI DSS requirement
  (e.g. Req 3 "Protect stored account data" and Req 4 "Encrypt transmission"
  are weighted highest, since they most directly endanger cardholder data).
  These weights are a documented default for this project, **not** an
  official PCI SSC scoring scheme — edit `REQUIREMENT_IMPACT_WEIGHTS` in
  `risk_engine.py` to tune them.
- **Risk score = Likelihood × Impact** (1–25): 1–4 Low, 5–9 Medium,
  10–14 High, 15–25 Critical.
- On the **Identified Risks** page, click "Sync risks from gap report" to
  auto-create/refresh one risk per open gap. You can also add fully manual
  risks (vendor risk, project risk, etc.) unrelated to any gap. Risks you've
  moved to Mitigating/Accepted/Closed are left alone by future syncs.
- The **Compliance Dashboard** shows total open risk exposure and a
  Likelihood×Impact heatmap of currently open/mitigating risks.
- Export the full list to CSV from the Identified Risks page.

## ⚠️ Pages marked "(demo)"

Three sidebar pages — **Automated Connectors**, **Alerts & Drift**, and
**QSA Audit View** — are UI mockups of planned features, clearly labeled as
such in-app. Nothing on those pages reads real data: the "Connected"
connector statuses, drift alerts, and the old "SHA-256 hash signature"
column (which previously showed the *same* hash — the SHA-256 of an empty
string — next to every file, which would have been actively misleading in
an audit context) are all illustrative sample data. Treat them as a
roadmap sketch, not working functionality, until they're actually wired up
to real integrations, real diffing logic, and real per-file hashing.

## ⚠️ Important accuracy disclaimer (please read)

- `data/pci_dss_data.json` is an **original, condensed paraphrase** written for
  this student project. It is **not** a reproduction of the official PCI DSS
  standard and does **not** cover every testing procedure. For any real
  assessment, use the actual PCI DSS v4.0.1 document from the PCI Security
  Standards Council: https://www.pcisecuritystandards.org
- The AI's scoring is an automated, preliminary opinion to speed up
  self-assessment work. It is **not** a Qualified Security Assessor (QSA)
  opinion and does not constitute formal PCI DSS validation.
- Model output can be wrong. Treat every score/recommendation as a
  starting point to verify, not a final answer.

## Project structure

```
VerifAI360/
├── app.py                     # Streamlit UI (5 pages)
├── data/
│   └── pci_dss_data.json      # condensed requirement catalog (see disclaimer)
├── src/
│   ├── database.py            # SQLite persistence (evidence, assessments, identified risks)
│   ├── evidence_processor.py  # text/PDF/DOCX/OCR extraction
│   ├── ai_analyzer.py         # Gemini API call + JSON schema validation
│   ├── compliance_engine.py   # scoring aggregation + gap report
│   └── risk_engine.py         # risk scoring (Likelihood x Impact) + identified risks
├── evidence_store/            # uploaded files get copied here
├── requirements.txt
└── .env.example
```

## Design system

The app uses a custom dark theme (`.streamlit/config.toml` for the native
Streamlit theme + injected CSS in `app.py` for cards, badges, and the
page-header component) rather than default Streamlit styling. Key pieces
if you're extending a page:
- `page_header(icon, title, subtitle)` — use this instead of `st.title()`
  at the top of every page, for a consistent icon + title + subtitle look.
- `risk_badge(level)` / `risk_badge_emoji(level)` — consistent
  Low/Medium/High/Critical styling wherever a risk level is shown.
- `demo_banner(text)` — the amber "🧪 Simulated data" banner used on the
  three roadmap/demo pages.
- The sidebar is intentionally split into two `st.radio` groups
  ("Workspace" vs "Roadmap · Demo") with `on_change` callbacks writing to
  `st.session_state["_active_page"]`, so the page in the second group
  doesn't get silently deselected by an unrelated rerun (e.g. clicking a
  button elsewhere on that same demo page).

## Setup

```bash
# 1. Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install the Tesseract OCR engine (needed for image/screenshot evidence)
#    Ubuntu/Debian: sudo apt install tesseract-ocr
#    Fedora:        sudo dnf install tesseract
#    Arch:          sudo pacman -S tesseract
#    macOS:         brew install tesseract
#    Windows:       https://github.com/UB-Mannheim/tesseract/wiki
#
#    The app auto-detects Tesseract on all three OSes (PATH first, then
#    common install locations like C:\Program Files\Tesseract-OCR on
#    Windows or /opt/homebrew/bin on Apple Silicon Macs) — no manual PATH
#    editing needed. If you installed it somewhere non-standard, set
#    TESSERACT_CMD in your .env file to the full path of the binary.

# 4. Get a FREE Gemini API key (no credit card required)
#    -> go to https://aistudio.google.com/apikey, sign in with a Google
#       account, click "Create API key", copy it.
cp .env.example .env
# then edit .env and paste your key next to GOOGLE_API_KEY=
# (optional) set TESSERACT_CMD in .env only if Tesseract isn't auto-detected

# 5. Run the app
streamlit run app.py
```

The app opens at `http://localhost:8501`.

### Why Gemini instead of a paid API

Google AI Studio's Gemini API has a genuinely free tier: no credit card,
no expiration, and (as of this writing) roughly 1,500 requests/day on
`gemini-flash-latest` (the free-tier-eligible Flash model), which is far
more than a student project needs. The code uses the `-latest` alias
rather than pinning a dated model name, since Google periodically retires
older dated models (e.g. `gemini-2.5-flash` stopped accepting new users
in mid-2026) — the alias automatically points at whichever Flash model is
current.
trade-off is that Google may use free-tier prompts/responses to improve
their models (this does not apply to paid tiers), so avoid uploading real
sensitive company data as "evidence" while testing — use sanitized or
sample documents. Free-tier limits can change; if you start getting
quota errors, check the current numbers at
https://ai.google.dev/gemini-api/docs/pricing.

## How the "core objectives" map to code

| Objective | Where it happens |
|---|---|
| Automated sufficiency validation + compliance % | `ai_analyzer.analyze_evidence()` scores each sub-requirement; `compliance_engine.compute_compliance_summary()` aggregates it |
| Multi-requirement cross-mapping | The AI prompt explicitly asks for *every* relevant sub-requirement, not just the targeted one; `compliance_engine.process_uploaded_evidence()` persists one row per mapped sub-requirement (`sub_req_assessment` table) |
| Gap identification | `compliance_engine.build_gap_report()` |
| Continuous maturity scoring | `score_history` table + the trend chart on the Dashboard page; each new upload for a sub-requirement adds a new history point, and `_build_prior_context()` feeds prior evidence back into the next AI call so scoring is cumulative, not isolated |
| Risk scoring + identified risks | `risk_engine.py` (Likelihood × Impact scoring) + `risk_register` table; Identified Risks page for sync-from-gaps, manual risks, ownership/status tracking, and CSV export |

## AI Security & API Security posture

**Implemented:**
- API key loaded from environment only, never hardcoded (`ai_analyzer._get_client()`).
- `.gitignore` prevents committing a real `.env`, the local SQLite DB, or the evidence store.
- Evidence file uploads: filenames are sanitized (`os.path.basename` + charset allowlist) before
  being used to build a filesystem path, with a second `os.path.commonpath` check as defense in
  depth — a malicious filename like `../../etc/passwd` cannot escape `evidence_store/`
  (`compliance_engine._safe_stored_filename`).
- Upload size is capped both at the Streamlit server layer (`.streamlit/config.toml`,
  `maxUploadSize`) and in application code (`compliance_engine.MAX_EVIDENCE_FILE_BYTES`, 25 MB),
  to reduce resource-exhaustion risk from oversized files hitting OCR/PDF parsing.
- **Prompt injection hardening (OWASP LLM01):** evidence text is untrusted, user-supplied content.
  It's wrapped in explicit `<<<EVIDENCE_START>>>` / `<<<EVIDENCE_END>>>` delimiters, any occurrence
  of those literal tokens *inside* the evidence itself is neutralized first (so an attacker can't
  forge a fake "end of evidence" marker to smuggle in new instructions), and the system prompt has
  an explicit, highest-priority rule telling the model to treat everything between the delimiters
  as data to assess, never as instructions to follow — including text that impersonates system/admin
  instructions or tries to dictate a specific score.
- AI output is schema-validated before use (`_parse_json_response`): required fields are checked,
  scores are clamped to 0–100, missing fields get safe defaults.
- Transient-only retry policy: only retryable HTTP statuses (429/500/503/504) trigger backoff;
  everything else (e.g. a malformed request) fails fast instead of retry-looping.

**Known gaps / recommended next steps (roughly by priority):**
1. **No authentication on the app itself.** This is the highest-priority gap if the app is ever
   deployed anywhere other than localhost — it currently stores real security/config evidence with
   no access control. Add an auth layer (Streamlit supports OIDC/SSO via `st.login`, or front it
   with a reverse proxy that enforces auth) before any shared/hosted deployment.
2. **Sensitive data sent to a free-tier third-party API.** Gemini's free tier may use
   prompts/responses to improve their models. For real (non-sanitized) evidence, either use a paid
   tier with a no-training data-use agreement, or add a redaction/anonymization pass before
   evidence text is sent.
3. **No encryption at rest** for `verifai360.db` or `evidence_store/` — both hold potentially
   sensitive security configuration details in plaintext on disk.
4. **No audit log of AI calls** (what evidence, when, which model, what came back) — valuable both
   for QSA-style accountability and for spotting attempted score manipulation over time.
5. **File-type validation is extension-based only**, not content/magic-byte based — a renamed file
   could bypass the allowlist.
6. **Dependencies are unpinned** (`requirements.txt` uses `>=` everywhere) — pin exact versions for
   a production-facing deployment to avoid an unreviewed transitive update introducing a
   vulnerability.

## Extending this for a real capstone submission

Ideas to go further, if the team wants to extend scope:
- Swap the condensed JSON catalog for a licensed, complete copy of the
  official PCI DSS v4.0.1 requirement/testing-procedure text.
- Add authentication + multi-tenant support (one dataset per client/QSA).
- Add a vector index (e.g. embeddings) over the requirement catalog instead
  of stuffing the whole catalog into the prompt, so it scales to a larger
  standard.
- Add a re-scoring job that periodically re-checks evidence "freshness"
  (e.g. a scan report older than 90 days should decay in score).
- Export a full PDF/Word compliance report (there's already a `pdf`/`docx`
  authoring skill pattern to follow for that).
