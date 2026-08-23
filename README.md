<div align="center">

```
██╗   ██╗███████╗██████╗ ██╗███████╗ █████╗ ██╗    ██████╗  ██████╗  ██████╗
██║   ██║██╔════╝██╔══██╗██║██╔════╝██╔══██╗██║    ╚════██╗██╔════╝ ██╔═████╗
██║   ██║█████╗  ██████╔╝██║█████╗  ███████║██║     █████╔╝███████╗ ██║██╔██║
╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██╔══╝  ██╔══██║██║     ╚═══██╗██╔═══██╗████╔╝██║
 ╚████╔╝ ███████╗██║  ██║██║██║     ██║  ██║██║    ██████╔╝╚██████╔╝╚██████╔╝
  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝  ╚═╝╚═╝    ╚═════╝  ╚═════╝  ╚═════╝
```

### 🛡️ AI-Driven PCI DSS Self-Assessment Platform

**Evidence in → scored assessment out.**

```
╔══════════════════════════════════════════════════════════════════════╗
║  ● ENGINES: 2 (CLOUD AI + OFFLINE)     🔐 EVIDENCE: ENCRYPTED AT REST ║
║  ⚑ REQUIREMENTS: 12 / SUB-REQS: 63     ☣  INTEGRITY: SHA-256 HASHED  ║
║  ⚡ INFRA COST: $0                      🧪 TESTS: 62 PASSING          ║
╚══════════════════════════════════════════════════════════════════════╝
```

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Gemini](https://img.shields.io/badge/Google%20Gemini-8E75B2?style=for-the-badge&logo=googlegemini&logoColor=white)

![PCI DSS](https://img.shields.io/badge/PCI%20DSS-v4.0.1%20style-004880?style=for-the-badge&logoColor=white)
![Risk](https://img.shields.io/badge/Risk-5x5%20Matrix-FF6F00?style=for-the-badge&logoColor=white)
![Offline Mode](https://img.shields.io/badge/Offline%20Engine-Zero%20Network-00FF41?style=for-the-badge&logoColor=black)
![Encryption](https://img.shields.io/badge/Fernet-AES--128--CBC%20%2B%20HMAC-CC0000?style=for-the-badge&logoColor=white)

</div>

---

## 👥 `> cat /project/team.txt`

```yaml
Team    : Amr Mohamed El Sayed  ·  Nazly Mohamed Samir  ·  Youssef Ahmed Mohamed
          Asmaa Ibrahim         ·  Ahmed Emad El Din    ·  Mohamed Hussein El Naggar
          Mostafa Ahmed Mostafa
Mentor  : Mostafa ElKady
Type    : Capstone project — Information Security & Digital Forensics
Status  : 🟢 Core functionality production-ready · 3 pages explicitly labeled roadmap
```

---

## 🎯 `> whatis verifai360`

PCI DSS is the security standard any company handling credit-card data must follow. Proving you follow it usually means reading a long checklist by hand and deciding, for every single item: *"do we have proof of this, and is that proof good enough?"*

**VerifAI 360 automates that judgment call.**

You upload a piece of evidence — a policy document, a firewall screenshot, a vulnerability scan report — and an engine reads it, decides which requirement(s) it actually proves, scores how convincing it is, and tells you what's missing. The app turns all of those individual scores into one overall compliance percentage, a gap list, a risk register, and a downloadable PDF report.

> ⚠️ **This accelerates a self-assessment. It does not replace a qualified QSA assessment.** See the [accuracy disclaimer](#️--cat-warningdisclaimer) — it is not a footnote, please read it.

---

## 🗺️ `> cat /ops/architecture_map.ascii`

```
                            ┌──────────────────────┐
                            │   👤 USER (BROWSER)   │
                            │   localhost:8501     │
                            └───────────┬──────────┘
                                        │
                            ┌───────────▼──────────┐
                            │  🖥️  app.py           │
                            │  Streamlit UI        │
                            │  DISPLAY ONLY —      │
                            │  zero business logic │
                            └───────────┬──────────┘
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        │                               │                               │
┌───────▼─────────┐          ┌──────────▼─────────┐         ┌──────────▼────────┐
│ ⚙️  CORE MODULES │          │  🔧 SUPPORT MODULES │         │  🎨 theme.py       │
├─────────────────┤          ├────────────────────┤         ├───────────────────┤
│ compliance_     │          │ evidence_processor │         │ Design tokens +   │
│   engine        │◄────────►│ ai_analyzer        │         │ full stylesheet.  │
│ risk_engine     │          │ local_analyzer     │         │ Charts read their │
│ report_generator│          │ security           │         │ colours from here │
│ scoping_data    │          │ data_portability   │         └───────────────────┘
└───────┬─────────┘          └──────────┬─────────┘
        │                               │
        │              ┌────────────────┴────────────┐
        │              │                             │
        │     ┌────────▼─────────┐        ┌──────────▼──────────┐
        └────►│ 🗄️  database.py   │        │  ☁️  GOOGLE GEMINI   │
              │ THE ONLY FILE    │        │  (free tier)        │
              │ THAT TOUCHES SQL │        │  ⚠️ only outbound    │
              └────────┬─────────┘        │     network call    │
                       │                  └─────────────────────┘
        ┌──────────────┼──────────────┐
        │              │              │
┌───────▼──────┐ ┌─────▼────────┐ ┌───▼──────────────┐
│ verifai360.db│ │evidence_store│ │pci_dss_data.json │
│ 10 tables    │ │🔐 encrypted   │ │12 reqs / 63 subs │
└──────────────┘ └──────────────┘ └──────────────────┘
```

**The one rule that holds the whole design together:** `app.py` renders and nothing else, and `database.py` is the *only* file permitted to touch the database directly. Every number on every screen is traceable to exactly one module that computed it.

---

## 🔄 `> trace --follow upload`

```
  👤 User picks a file on "Upload & Analyze"
        │
        ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  compliance_engine.process_uploaded_evidence()                  │
  └─────────────────────────────────────────────────────────────────┘
        │
        ├─🔍 [1] validate_file_signature()  magic bytes vs extension
        │       └─ a .exe renamed to .pdf is rejected here
        │
        ├─🔑 [2] _sha256_of_file()          integrity fingerprint
        │       └─ duplicate check: already analyzed? stop and ask
        │
        ├─📄 [3] extract_text()             PDF · DOCX · TXT · CSV · OCR
        │
        ├─🧠 [4] ANALYSIS — pick ONE engine per file:
        │       │
        │       ├─ ☁️  ai_analyzer.analyze_evidence()
        │       │     └─► Google Gemini ──► JSON score per sub-requirement
        │       │
        │       └─ 🔒 local_analyzer.analyze_evidence()
        │             └─► fully offline · deterministic · zero network
        │
        ├─🔐 [5] security.encrypt_bytes()   file + extracted text
        │
        └─💾 [6] database.insert_evidence() + insert_assessment()
                └─ one row per mapped sub-requirement, not just the target
        │
        ▼
  📊 Dashboard · Gap Report · Risk Register · PDF
     all re-read the database on view — nothing is manually recalculated
```

---

## ⚡ `> ls /features/`

<div align="center">

```
┌────────────────────────────┬────────────────────────────┬────────────────────────────┐
│   🧠 DUAL ANALYSIS ENGINE   │   📊 LIVE COMPLIANCE STATE  │   🔐 SECURITY BY DEFAULT    │
├────────────────────────────┼────────────────────────────┼────────────────────────────┤
│ Cloud AI (Gemini) for      │ One compliance % rolled up  │ Passcode gate before ANY   │
│ nuance and paraphrasing    │ from every scored sub-req   │ page renders               │
│                            │                            │                            │
│ Offline engine for         │ Per-requirement breakdown   │ Fernet encryption at rest  │
│ sensitive documents        │ scoped to your SAQ type     │ on files AND extracted text│
│                            │                            │                            │
│ ✔ Same file, both engines  │ ✔ Maturity trend over time  │ ✔ SHA-256 per file          │
│ ✔ Deterministic offline    │ ✔ 5x5 risk heatmap          │ ✔ Prompt-injection hardened │
│ ✔ Negation-aware matching  │ ✔ Gap report, worst-first   │ ✔ Full analysis audit log   │
└────────────────────────────┴────────────────────────────┴────────────────────────────┘
```

</div>

### 🧠 Why two engines?

| | ☁️ **AI Engine (Gemini)** | 🔒 **Local Engine (Offline)** |
|---|---|---|
| **Reads like** | A knowledgeable reviewer — context, paraphrasing, nuance | Curated keyword + vocabulary matching |
| **Network** | ⚠️ Evidence text is transmitted via API | ✅ Zero network calls, ever |
| **Determinism** | Varies slightly run to run | ✅ Same file → same score, every time |
| **Negation-aware** | Yes, semantically | ✅ Yes — *"we have **no** firewall policy"* scores as absence |
| **Cost** | $0 (free tier) | $0 |
| **Best for** | Depth on non-sensitive evidence | Anything you can't send off the machine |

The engine is chosen **per file, at upload time**. Privacy is opt-in without giving up capability — a deliberate architectural trade-off, not a limitation.

> 🧪 **Compare mode** runs both engines side by side on the same file. It is read-only by design: nothing is saved, because a comparison shouldn't commit a score you haven't chosen yet.

---

## 📂 `> tree /project`

```
VerifAI360/
├── 🖥️  app.py                     # Streamlit UI — 12 workspace pages + 3 roadmap pages
├── 📋 CHANGES.md                  # what changed in the last review pass, and why
├── 📖 README.md                   # you are here
├── 🔒 SECURITY.md                 # security policy
│
├── ⚙️  .streamlit/
│   └── config.toml                # ⚠️ MUST live here — Streamlit ignores a root config.toml
│
├── 📚 data/
│   └── pci_dss_data.json          # condensed requirement catalog — 12 reqs, 63 sub-reqs
│
├── 🎨 docs/
│   └── architecture.png           # architecture diagram
│
├── 🧩 src/
│   ├── database.py                # 🗄️  SQLite persistence — the ONLY file touching SQL
│   ├── evidence_processor.py      # 📄 PDF/DOCX/OCR extraction + magic-byte validation
│   ├── ai_analyzer.py             # ☁️  Gemini call, schema validation, key + model failover
│   ├── local_analyzer.py          # 🔒 offline deterministic scoring engine
│   ├── security.py                # 🔐 passcode gate + Fernet encryption at rest
│   ├── data_portability.py        # 💾 full-state JSON export / import
│   ├── compliance_engine.py       # ⚙️  the orchestrator: pipeline + scoring + gap report
│   ├── risk_engine.py             # ⚠️  Likelihood × Impact risk scoring
│   ├── report_generator.py        # 📑 PDF compliance report (reportlab)
│   ├── scoping_data.py            # 🎯 static SAQ-type → applicable-requirements table
│   └── theme.py                   # 🎨 design tokens + full stylesheet
│
├── 🧪 tests/                       # 62 passing tests across 7 modules
├── 📦 evidence_store/              # uploaded files, encrypted at rest
├── 🗃️  verifai360.db               # created automatically on first run
├── requirements.txt
└── .env.example
```

### 📑 File-by-file, in one sentence each

| File | What it's for |
|---|---|
| 🖥️ `app.py` | The entire user interface — every screen is drawn here. Contains almost no logic of its own. |
| 🗄️ `src/database.py` | The only file that reads/writes SQLite. Simple `insert_x()` / `update_x()` / `delete_x()` / `get_all_x()` per table, plus the analysis audit trail and `data_fingerprint()` for report caching. |
| 📄 `src/evidence_processor.py` | Turns an uploaded file into plain text — reads PDFs/Word directly, OCRs screenshots via Tesseract, and validates each file's actual byte signature against its claimed extension first. |
| ☁️ `src/ai_analyzer.py` | Talks to Gemini. Builds the prompt, sends the evidence, validates the JSON that comes back, and fails over across multiple API keys and fallback models. |
| 🔒 `src/local_analyzer.py` | A fully offline, deterministic alternative — scores via curated-keyword matching with typo-tolerant fuzzy matching and negation-awareness. No network call, no data leaves the machine. |
| 🔐 `src/security.py` | The app-level passcode gate, brute-force lockout, and Fernet encryption-at-rest for evidence files and extracted text. |
| 💾 `src/data_portability.py` | Full-state JSON export/import of every table, for backup or moving an assessment to another machine. |
| ⚙️ `src/compliance_engine.py` | The orchestrator: runs an evidence upload end-to-end and turns raw scores into the compliance percentage and gap report. |
| ⚠️ `src/risk_engine.py` | Turns a compliance gap into a Likelihood × Impact risk score and manages the register. |
| 📑 `src/report_generator.py` | Builds the downloadable PDF with `reportlab` — no browser or external renderer needed. |
| 🎯 `src/scoping_data.py` | Static lookup: for each SAQ type (A, B, C, D…), which of the 12 top-level requirements actually apply. |
| 🎨 `src/theme.py` | Design tokens + the full stylesheet. Colours are defined once here and reused by the Plotly charts, so nothing is hardcoded twice. |
| ⚙️ `.streamlit/config.toml` | Native Streamlit theme + the server-side upload cap. **Must** live in `.streamlit/` — Streamlit does not read a `config.toml` in the project root. |
| 📚 `data/pci_dss_data.json` | The condensed requirement catalog the whole app is built around (see the disclaimer). |

> 💡 Every file under `src/` opens with a docstring explaining its purpose in depth, and `app.py` has a plain-English comment above each page section naming the module that computes its numbers. **Start there to trace any feature back to its code.**

---

## 📊 `> cat /output/what_every_analysis_returns`

```
┌──────────────────────┬────────────────────────────────────────────────────────┐
│ 🎯 Sufficiency score  │ 0–100 — how well this evidence proves the control      │
│ 📈 Maturity label     │ Initial → Developing → Defined → Managed → Optimized   │
│ 💬 Reasoning          │ A plain-language statement of why it scored that way   │
│ 🕳️  Gaps               │ What is missing or weak                                │
│ 🔧 Recommendations    │ What to add to strengthen it                           │
└──────────────────────┴────────────────────────────────────────────────────────┘
```

🔁 **Cross-mapping:** one document is checked against *every* sub-requirement it could plausibly satisfy — one row per mapped sub-requirement, not just the one you targeted. No need to upload the same file several times.

📉 **Continuous scoring:** every analysis appends to `score_history`, which is what powers the maturity trend chart. Prior evidence is also fed back into the next AI call, so scoring is cumulative rather than isolated.

---

## ⚠️ `> cat /grc/risk_scoring.md`

`src/risk_engine.py` adds a lightweight GRC layer on top of the compliance engine.

```
                          LIKELIHOOD  ──────────────►
                     ┌─────┬─────┬─────┬─────┬─────┐
                  5  │  5  │ 10  │ 15  │ 20  │ 25  │
     ▲               ├─────┼─────┼─────┼─────┼─────┤
     │            4  │  4  │  8  │ 12  │ 16  │ 20  │
   I │               ├─────┼─────┼─────┼─────┼─────┤
   M │            3  │  3  │  6  │  9  │ 12  │ 15  │
   P │               ├─────┼─────┼─────┼─────┼─────┤
   A │            2  │  2  │  4  │  6  │  8  │ 10  │
   C │               ├─────┼─────┼─────┼─────┼─────┤
   T │            1  │  1  │  2  │  3  │  4  │  5  │
                     └─────┴─────┴─────┴─────┴─────┘
                        1     2     3     4     5

   🟢 1–4  LOW      🟡 5–9  MEDIUM      🟠 10–14  HIGH      🔴 15–25  CRITICAL
```

- 🎲 **Likelihood (1–5)** is derived from a sub-requirement's current sufficiency score — weaker evidence ⇒ higher likelihood the control fails when it matters.
- 💥 **Impact (1–5)** is a fixed weight per top-level requirement (Req 3 *"Protect stored account data"* and Req 4 *"Encrypt transmission"* weigh highest). These are a **documented default for this project, not an official PCI SSC scheme** — tune `REQUIREMENT_IMPACT_WEIGHTS` in `risk_engine.py`.
- 🔗 **Sync from gaps:** one click creates/refreshes a risk per open gap. Manual risks (vendor, project) are supported alongside. Risks you've moved to Mitigating/Accepted/Closed are left alone by future syncs.
- 📤 Export the full register to CSV from the Identified Risks page.

---

## 🖥️ `> ls /app/pages/`

### 🟦 Workspace — everyday use

| Page | What it does |
|---|---|
| 🎯 **SAQ Scoping** | Pick your SAQ type; every downstream percentage is scoped to the requirements that actually apply to you |
| 📤 **Upload & Analyze** | The core loop — pick file(s), pick an engine, get scored |
| 📊 **Compliance Dashboard** | Overall %, per-requirement breakdown, maturity trend, risk heatmap, PDF export |
| 🌐 **CDE Scope** | Inventory of the cardholder data environment |
| 🔀 **Compensating Controls** | *"We do it differently, and here's why that's still acceptable"* — a real, expected audit artifact |
| 🧪 **Testing Tracker (Req 11)** | Quarterly scans and annual pen tests, with on-track / due-soon / **overdue** calculated automatically. A live overdue count sits in the sidebar |
| 🏢 **Vendor / TPSP Register** | Third-party providers, how they connect, and whether their AOC is still current |
| ⚠️ **Identified Risks** | The 5×5 register — sync from gaps or add manually, with owner, status and mitigation plan |
| 🕳️ **Gap Report** | Every sub-requirement below threshold, worst first, with the specific gaps behind each |
| 📚 **Requirement Explorer** | Browsable reference library: all 12 requirements, all 63 sub-requirements, current score beside each |
| 🧾 **Evidence Log** | Every file ever submitted, its SHA-256, the engine that scored it — plus the analysis call audit trail |
| ⚙️ **Settings & Security** | Local engine tuning, security status, backup & restore |

### 🟨 Roadmap · Demo — explicitly labeled

> These pages sit in their own sidebar section and each carries a visible **hazard-striped banner** saying it is sample data. Everything outside this section is fully working functionality.

| Page | Status |
|---|---|
| 🔌 **Automated Connectors** | 🚧 UI mockup — sample data only |
| 🚨 **Alerts & Drift** | 🚧 UI mockup — sample data only |
| 🔍 **QSA Audit View** | ⚡ **Partially real** — the compliance %, SHA-256 hashes and audit PDF are live. The external-auditor login and formal sign-off are not |

> 👁️ **Reviewer mode** — a single sidebar toggle disables every button that adds, edits, deletes or analyzes anything. Built for handing the app to a stakeholder with zero risk of changing real data.

---

## 🚀 `> ./setup.sh`

### 1️⃣ Virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

### 2️⃣ Python dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ 👁️ Tesseract OCR (for image/screenshot evidence)

```bash
# Ubuntu/Debian
sudo apt install tesseract-ocr
# Fedora
sudo dnf install tesseract
# Arch
sudo pacman -S tesseract
# macOS
brew install tesseract
# Windows
# https://github.com/UB-Mannheim/tesseract/wiki
```

> 🔍 The app **auto-detects** Tesseract on all three OSes — PATH first, then common install locations like `C:\Program Files\Tesseract-OCR` on Windows or `/opt/homebrew/bin` on Apple Silicon. No manual PATH editing needed. Installed somewhere unusual? Set `TESSERACT_CMD` in `.env` to the full binary path.

### 4️⃣ 🔑 Free Gemini API key — no credit card

```bash
cp .env.example .env
# then edit .env and paste your key next to GOOGLE_API_KEY=
```

Get one at 👉 **https://aistudio.google.com/apikey** — sign in, click *Create API key*, copy.

> 💡 You can skip this entirely and use the **offline engine** for everything. The AI engine is optional.

### 5️⃣ ▶️ Run

```bash
streamlit run app.py
```

Opens at 🌐 **http://localhost:8501**

> 🔐 On first run the app generates an `APP_PASSCODE` and an `ENCRYPTION_KEY` into `.env` if they're missing. Check the file for your passcode.

---

## 💰 `> why gemini?`

Google AI Studio's Gemini API has a genuinely free tier: **no credit card, no expiration**, and roughly **1,500 requests/day** on `gemini-flash-latest` — far more than this project needs.

The code uses the `-latest` alias rather than pinning a dated model name, because Google periodically retires older dated models (e.g. `gemini-2.5-flash` stopped accepting new users in mid-2026). The alias always points at the current Flash model.

> ⚠️ **The trade-off, stated plainly:** Google may use free-tier prompts and responses to improve their models — this does **not** apply to paid tiers. So don't upload real sensitive company data as "evidence" while testing; use sanitized or sample documents, **or use the offline engine**, which is exactly why it exists.
>
> Free-tier limits change — check current numbers at https://ai.google.dev/gemini-api/docs/pricing

---

## 🔐 `> cat /security/posture.log`

### ✅ Implemented

```
[🔑] API KEY HANDLING
     Environment only, never hardcoded. Automatic failover across multiple
     keys (GOOGLE_API_KEY, GOOGLE_API_KEY_2, ... or GOOGLE_API_KEYS="k1,k2")
     when one account's free-tier quota runs out.

[🚪] PATH TRAVERSAL DEFENSE
     Filenames sanitized (basename + charset allowlist) before building any
     filesystem path, with a second os.path.commonpath check as defense in
     depth. A filename like ../../etc/passwd cannot escape evidence_store/.

[🔍] CONTENT-BASED FILE VALIDATION
     validate_file_signature() checks actual magic bytes (PDF, DOCX/ZIP, PNG,
     JPEG, BMP, TIFF, WEBP) against the claimed extension. A renamed file is
     rejected before it reaches pdfplumber/python-docx/pytesseract.
     Honest note: plain-text formats have no fixed signature by design and
     are still trusted as-is — no equivalent check is possible.

[#️⃣] SHA-256 INTEGRITY HASHING
     Computed from the stored file's actual bytes at upload, shown in the
     Evidence Log, QSA Audit View and the PDF — so a hash verifies a file
     on disk hasn't been altered since submission.

[🔐] ENCRYPTION AT REST (Fernet · AES-128-CBC + HMAC)
     Each evidence file and its extracted text excerpt, keyed by
     ENCRYPTION_KEY in .env (auto-generated on first run).
     Honest scope note: this encrypts the sensitive CONTENT, not the whole
     SQLite file. Filenames, scores, dates and sub-requirement IDs stay in
     plain columns because the app must query and aggregate on them.
     Full-database encryption would need SQLCipher — not pip-installable.

[🛡️] PROMPT INJECTION HARDENING (OWASP LLM01)
     Evidence text is untrusted user content. It's wrapped in explicit
     <<<EVIDENCE_START>>> / <<<EVIDENCE_END>>> delimiters, any occurrence of
     those literal tokens INSIDE the evidence is neutralized first (so an
     attacker can't forge a fake end marker), and the system prompt carries a
     highest-priority rule to treat everything between them as data to
     assess — never as instructions, including text impersonating an admin
     or dictating a score.

[✔️] AI OUTPUT VALIDATION
     Schema-validated before use: required fields checked, scores coerced and
     clamped to 0–100, invalid maturity labels defaulted, and any
     sub-requirement ID not in the catalog is DROPPED and reported — a
     hallucinated ID can never silently enter the database.

[⏱️] BRUTE-FORCE THROTTLING
     After MAX_FAILED_ATTEMPTS wrong passcodes from the same caller, an
     increasing lockout kicks in (doubling up to MAX_LOCKOUT_SECONDS).
     Honest scope note: in-process memory keyed by IP — right for the
     localhost/small-team deployment this targets, NOT a substitute for a
     real auth service or WAF behind a multi-instance deployment.

[🔁] TRANSIENT-ONLY RETRY
     Only retryable statuses (429/500/503/504) trigger backoff. A 503 tries
     the next model on the SAME key; a 429 (quota exhausted) skips straight
     to the next KEY, since sibling models share that quota.

[📋] ANALYSIS AUDIT TRAIL
     Every call to either engine, success or failure, recorded with filename,
     engine, model, target sub-requirement, error message and score count.
     Self-prunes to CALL_LOG_MAX_ROWS (5000) so it can't grow unbounded.

[📦] SUPPLY CHAIN
     Every dependency pinned to an exact version (==, not >=).
     .gitignore blocks committing a real .env, the DB, or the evidence store.

[📏] RESOURCE EXHAUSTION
     Upload size capped at BOTH the Streamlit server layer and in application
     code (MAX_EVIDENCE_FILE_BYTES = 25 MB).
```

### 🚧 Known gaps — stated honestly

| # | Gap | Status |
|---|---|---|
| 1 | Single shared passcode, not multi-user/role auth | ⚠️ **Accepted scope limit.** Full RBAC is a separate project if this is ever deployed for a real team |
| 2 | Evidence text reaches a third-party API in AI mode | 🟡 **Mitigated, not eliminated.** The offline engine avoids it entirely. For AI on real sensitive data you'd want a paid tier with a no-training agreement, or a redaction pass — neither is built |
| 3 | Database metadata is not encrypted | 🟡 **By design** — see the encryption note above |
| 4 | Plain-text uploads can't be signature-validated | ⚠️ **Not solvable** — text formats have no magic bytes |

---

## 🧪 `> pytest -q`

```
┌────────────────────────────┬──────────────────────────────────────────────┐
│ 🗄️  test_database           │ persistence layer, every table               │
│ 🔐 test_security           │ passcode gate, lockout, Fernet round-trip    │
│ ☁️  test_ai_analyzer        │ prompt build, JSON validation, failover      │
│ 🔒 test_local_analyzer     │ scoring, fuzzy matching, negation-awareness  │
│ 📄 test_evidence_processor │ extraction + magic-byte validation           │
│ ⚙️  test_compliance_engine  │ full pipeline, scoring, gap report           │
│ 💾 test_data_portability   │ export/import round trip                     │
└────────────────────────────┴──────────────────────────────────────────────┘
```

```bash
pip install -r requirements-dev.txt
pytest -q
```

**62 tests passing.** Input coverage is end-to-end across text, structured CSV and OCR image inputs, with both engines exercised on the same fixtures and the duplicate-detection path covered.

> 🎯 The local engine is **deterministic** — the same file returns the same score every run. That's what makes regression testing meaningful in the first place.

---

## 🎨 `> cat /design/system.md`

The app ships a custom dark theme rather than default Streamlit styling. If you're extending a page, reuse these instead of rolling your own:

| Helper | Use it for |
|---|---|
| `page_header(icon, title, subtitle)` | Every page top — consistent icon + title + subtitle. Use instead of `st.title()` |
| `risk_badge(level)` / `risk_badge_emoji(level)` | Any Low/Medium/High/Critical display |
| `demo_banner(text)` | The hazard-striped "simulated data" banner on roadmap pages |
| `theme.TOKENS` | Colours — never hardcode a hex value |
| `theme.plotly_layout(**overrides)` | Every chart, so they all match the app |

🎨 **Palette:** cyan `#22e4d4` as the app's voice, magenta `#ff2e88` for the HUD frame, and deliberately plain red/amber/green for status — a compliance number on a projector has to stay readable.

🔤 **Type:** Chakra Petch (display) · Inter (body) · JetBrains Mono (all data). Every font has a full local fallback stack, so an offline machine degrades to system faces rather than a serif default.

> 🧭 The sidebar is intentionally split into two `st.radio` groups with `on_change` callbacks writing to `st.session_state["_active_page"]`, so a page in the second group isn't silently deselected by an unrelated rerun.

---

## ⚠️ `> cat /WARNING/disclaimer`

```
╔═══════════════════════════════════════════════════════════════════════════╗
║  🚨  READ THIS BEFORE SHOWING ANY OUTPUT TO ANYONE                        ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                           ║
║  📚  data/pci_dss_data.json is an ORIGINAL, CONDENSED PARAPHRASE written  ║
║      for this student project. It is NOT a reproduction of the official   ║
║      PCI DSS standard and does NOT cover every testing procedure.         ║
║      For any real assessment use the actual PCI DSS v4.0.1 document:      ║
║      https://www.pcisecuritystandards.org                                 ║
║                                                                           ║
║  🎯  The SAQ mapping is a SIMPLIFIED APPROXIMATION of the official        ║
║      PCI SSC mapping.                                                     ║
║                                                                           ║
║  🤖  Scoring is an automated PRELIMINARY OPINION to speed up              ║
║      self-assessment work. It is NOT a Qualified Security Assessor        ║
║      opinion and does not constitute formal PCI DSS validation.           ║
║                                                                           ║
║  ⚠️   Model output can be wrong. Treat every score and recommendation as   ║
║      a starting point to VERIFY — never as a final answer.                ║
║                                                                           ║
║  ✅  This is stated up front here, printed on every page of the generated ║
║      PDF, and repeated in the app itself — so no stakeholder can mistake  ║
║      the output for a certified assessment.                               ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

## 🗺️ `> cat /roadmap/next.md`

```
[ ] 📜  Swap the condensed catalog for a licensed, complete copy of the
        official PCI DSS v4.0.1 requirement and testing-procedure text
[ ] 👥  Multi-user authentication + multi-tenancy (one dataset per client/QSA)
[ ] 🧭  Vector index over the catalog instead of stuffing it into the prompt,
        so it scales past 63 sub-requirements
[ ] ⏳  Evidence freshness decay — a scan report older than 90 days should
        lose score automatically
[ ] 🔌  Wire the Automated Connectors page to real integrations
[ ] 🚨  Wire Compliance Drift Alerts to real diffing logic
[ ] ✍️   Full QSA workflow: reviewer sign-off, sampling notes, interview logs,
        locked-down read-only auditor login
[ ] 🗄️  SQLCipher for full-database encryption (needs a compiled SQLite build)
```

---

<div align="center">

```
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   "A reviewer should start from a filled-in draft,             ║
║    not a blank page."                                          ║
║                                                                ║
║                                    — VerifAI 360               ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
```

**🛡️ Built as a capstone project · Information Security & Digital Forensics**

*Intelligent compliance, automated — evidence in, scored assessment out.*

</div>
