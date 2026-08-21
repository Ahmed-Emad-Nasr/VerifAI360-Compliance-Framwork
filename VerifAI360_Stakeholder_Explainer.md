# VerifAI 360 — What It Is and How It Works
### A plain-language explainer for presenting to stakeholders (no code, just concepts)

---

## 1. The problem this tool solves

PCI DSS (Payment Card Industry Data Security Standard) is the security standard every business that touches credit card data has to follow. Proving compliance means going through **12 top-level requirements**, broken down into **63 detailed sub-requirements**, and for each one, collecting real evidence (policies, configs, scan reports, screenshots) that proves the control is actually in place.

Doing this by hand is slow and error-prone:
- Someone has to manually read every document and decide which of the 63 sub-requirements it actually proves.
- One document often proves *several* sub-requirements at once, and that's easy to miss.
- Scoring "is this evidence good enough?" is subjective — different reviewers give different answers.
- Tracking what's missing, what's weak, and what needs re-testing on a schedule turns into a spreadsheet nightmare.

**VerifAI 360 automates the first pass of this work.** You upload evidence, it tells you which sub-requirements it satisfies and how well, flags what's missing, and rolls everything up into one live compliance percentage — so a human reviewer starts from a filled-in draft instead of a blank page.

---

## 2. Who uses it, and for what

- **A security/compliance person** (like a SOC analyst preparing a self-assessment) uses it as their day-to-day workspace: upload evidence, track gaps, manage vendors, log recurring tests.
- **A manager** gets a one-page executive summary PDF instead of the full audit trail.
- **An auditor / QSA (Qualified Security Assessor)** would eventually get a dedicated read-only view (currently a mockup — more on that in the Roadmap section).
- **Anyone being walked through the tool** (an interviewer, a client, a teammate) can open any page and read a plain-language "what this page does and why" box built into the page itself.

---

## 3. The big picture: what happens when you upload one piece of evidence

This is the core workflow everything else is built around. Five stages happen automatically, in order, every time:

**Stage 1 — Upload.** You pick a file (a policy document, a firewall config screenshot, a scan report, anything) and optionally tell the app which sub-requirement it's meant to prove. You can upload several files at once.

**Stage 2 — Security checks.** Before anything else happens:
- The file's exact bytes are fingerprinted (a SHA-256 hash) — a unique digital fingerprint that changes if even one byte of the file changes later. This is the same integrity-verification concept used in digital forensics chain-of-custody.
- That fingerprint is checked against every file already in the system. If you've uploaded this exact file before, the app stops and asks "you already submitted this — analyze it again anyway?" instead of silently doing duplicate work (and silently spending a second AI API call, if you're using the AI engine).
- The file is then encrypted before it's saved to disk. More on this in the Security section.

**Stage 3 — Analysis.** The text is pulled out of the file (including text buried in screenshots, using OCR) and handed to whichever analysis engine you chose — the AI engine or the Local engine (explained in detail in Section 5). The engine reads the content and, for every sub-requirement it looks genuinely relevant to, produces:
- A **sufficiency score** from 0–100 (how well this evidence proves the control)
- A **maturity label** (Initial → Developing → Defined → Managed → Optimized)
- A plain-language **reasoning statement** for why it scored that way
- A list of **gaps** — specific things that are missing or weak
- **Recommendations** — what to add to strengthen it

One file is very often relevant to more than one sub-requirement (e.g. a network diagram might satisfy parts of three different requirements) — the app catches all of them in one pass instead of making you upload the same file multiple times.

**Stage 4 — Saving.** Everything from Stage 3 gets written to the database: the score, the reasoning, the gaps, the recommendations, and which engine produced them. This is also where a running score history gets built — every time a sub-requirement gets a new score, that data point is saved, which is what powers the trend chart on the Dashboard.

**Stage 5 — It's now live everywhere.** The moment that data is saved, it instantly affects: the overall compliance percentage on the Dashboard, that sub-requirement's status in the Requirement Explorer, whether it still appears in the Gap Report, and (if you choose to sync it) a tracked item in the Risk register. Nothing needs to be manually recalculated — the whole app reads from the same live numbers.

---

## 4. Every page in the app, and what it's actually for

The app is organized as a sidebar with pages grouped into three sections: the everyday **Workspace**, **Settings**, and a **Roadmap/Demo** section for features that aren't real yet (clearly labeled — see Section 8).

### SAQ Scoping — "which rules even apply to us?"
The very first thing a new user should do. PCI DSS has different "SAQ types" (Self-Assessment Questionnaire types) depending on how a business handles card data — a company that only redirects customers to a hosted payment page has a much smaller compliance burden than one that stores card numbers directly. This page is where you pick your business's SAQ type, and that single choice determines which of the 12 top-level requirements are actually "in scope" for every other page in the app. It's the setting that makes the compliance percentage mean something specific to your business, instead of measuring against the entire standard regardless of relevance.

### Upload & Analyze — the front door
Described in full in Section 3. This is where evidence goes in. Two extra things worth knowing:
- You can run **both analysis engines side-by-side** on the same file to compare their results directly.
- You can upload **multiple files in one batch** instead of one at a time.

### Compliance Dashboard — the big picture
The single screen that answers "where do we stand right now?" It shows: an overall compliance percentage (scoped to your chosen SAQ type), a percentage broken down per top-level requirement, a trend line of how scores have changed over time, and a risk heatmap. Nothing is calculated on this page — it's purely a live display of numbers computed elsewhere. This page also has a one-click download for a **one-page executive summary PDF** — a short, manager-friendly version with just the headline numbers, separate from the full audit report.

### CDE Scope — drawing the boundary
CDE stands for Cardholder Data Environment — the part of your network that actually touches card data. This page is a simple record-keeping form: what systems are inside that boundary, what's outside it, and what's merely *connected to* it (which still matters for security). No scoring happens here — it's documentation that any real PCI DSS assessment requires, proving you know exactly where your sensitive perimeter is.

### Compensating Controls — "we do it differently, and here's why that's still okay"
Sometimes a business genuinely can't implement a control exactly as PCI DSS describes it, and does something equivalent instead. This page is a structured form for writing that justification down: what the standard control is, why it doesn't fit, what alternative was used instead, and who approved it. This is a real, expected artifact in any formal audit.

### Recurring Testing Tracker — the stuff you have to keep re-doing
Certain PCI DSS requirements (Requirement 11, specifically) aren't "prove it once and forget it" — they require *recurring* testing: quarterly vulnerability scans, annual penetration tests, and so on. This page logs each test and its result, and automatically calculates whether the next one is on track, due soon, or overdue — a countdown clock for a part of compliance that's very easy to quietly let lapse. The sidebar shows a live overdue count next to this page's name so it's impossible to miss.

### Vendor / TPSP Register — tracking your third parties
TPSP means Third-Party Service Provider — any outside company that touches your cardholder data environment (payment processors, cloud hosts, security vendors). PCI DSS specifically requires you to track and manage *their* compliance, not just your own. This page is a structured register for each vendor: what they do, how they connect to you, and whether their own compliance paperwork is still current.

### Identified Risks — turning findings into action items
A lightweight risk register scored on a standard 5×5 Likelihood × Impact matrix (a scoring model used broadly across security risk management, producing a score from 1–25). Risks can be added manually, or generated automatically by pulling in every unresolved item from the Gap Report with one click. This is the bridge between "the analysis engine found a weak spot" and "someone owns fixing it by when."

### Gap Report & Remediation Plan — the action list
Shows every sub-requirement currently below the "compliant" score threshold, worst first, along with the specific gaps and recommendations attached to it. Where the Dashboard shows you percentages, this page shows you the actual to-do list behind those percentages.

### PCI DSS Requirement Explorer — the reference library
A browsable version of the entire PCI DSS catalog (all 12 requirements, all 63 sub-requirements), with your current score sitting next to each one. Useful for understanding *what a requirement actually asks for*, independent of any score — context, not just numbers.

### Evidence Log — the paper trail
A chronological table of every file ever submitted, including its integrity fingerprint (the SHA-256 hash mentioned earlier) and which analysis engine scored it. This is the audit trail — proof of what was submitted, when, and how it was evaluated.

---

## 5. The two analysis engines, explained without code

This is one of the most important design decisions in the tool, so it's worth explaining properly.

### The AI engine
Sends the extracted text of your evidence to Google's Gemini AI model, which reads it the way a knowledgeable human reviewer would — understanding context, paraphrasing, and nuance. It's the more accurate option, but it needs an internet connection, an API key, and it means the evidence content leaves your machine (even though Google's free tier costs nothing).

### The Local engine
Runs entirely on your own computer, with no internet connection and no data ever leaving the machine. Instead of "understanding" the text the way an AI does, it scores evidence using four transparent, rule-based signals, each one checked and explainable:

1. **Curated keywords** — a hand-picked list of terms expected in real evidence for each sub-requirement (the primary, highest-trust signal). It also tolerates small typos — "firewal policy" still gets recognized as "firewall policy," just with slightly less credit than an exact match.
2. **Title & summary vocabulary** — broader terminology pulled from the sub-requirement's own description, catching evidence that uses the right domain language without hitting an exact curated keyword.
3. **Example-evidence vocabulary** — terminology drawn from the catalog's own examples of "what good evidence looks like" for that control.
4. **Filename cross-check** — a small bonus when the uploaded file's *name* also supports what was already found in its *content* (a misleading filename with no matching content earns nothing — the bonus only fires when the name and the actual content agree).

Every one of those four numbers is visible in the score's reasoning text — nothing is a black box. All four are also individually adjustable on the Settings page, so the scoring behavior can be tuned without touching any code.

### Why have both
The Local engine is faster, free, fully private, and gives identical results every time you run it on the same file (the AI's answers can vary slightly run to run, the way any conversation with an AI model can). The AI engine understands nuance and paraphrasing that a keyword system never will. Rather than forcing a choice, the app lets either one be picked per file — or both at once, side by side, for direct comparison.

---

## 6. Security, explained without code

Two independent protections were added, both designed so they're never silently switched off:

### A passcode gate
Before this feature, anyone who could reach the app on the network could see and edit everything with zero login. Now, a shared passcode is required once per browser session before any page renders. If no passcode was ever configured, the app generates one automatically the first time it runs — security is never accidentally left disabled just because nobody set a password.

### Encryption at rest
The most sensitive thing this app stores is the *content* of the evidence itself. Two things are now encrypted before they ever touch the disk:
- The evidence **file itself**, as stored on disk.
- The **extracted text** saved in the database.

**Honest scope note, stated plainly:** this protects the evidence *content*, not literally every byte in the database. Things like filenames, dates, and scores stay as plain, searchable data, because the app constantly needs to sort and filter on them — encrypting those too would require a much heavier, specialized database setup. If someone got a copy of the raw database file, they'd see *metadata* (what was uploaded, when, scored how) but not the actual evidence content or its extracted text without also having the separate encryption key.

### A read-only "Reviewer mode"
A single toggle in the sidebar that disables every button in the app that adds, edits, deletes, or analyzes anything. Meant for handing the app to someone you're demoing it to (an interviewer, a stakeholder) without any risk of them accidentally changing real data.

---

## 7. Administration: the Settings page

A dedicated page (separate from day-to-day compliance work) covering three things:

- **Local engine tuning** — sliders to adjust how much weight each of the four scoring signals (described in Section 5) gets, plus how strict the typo-tolerance is. Changes apply to every future Local-engine analysis immediately.
- **Security status** — confirms the passcode gate and encryption are active, without ever displaying the actual secrets on screen.
- **Backup & restore** — a one-click export of the entire assessment (every score, risk, vendor record, and setting) as a single file, and a matching restore function. Restoring is a full replacement of current data, not a merge, and the app requires an explicit confirmation before doing it.

---

## 8. What's real vs. what's a roadmap sketch

Three pages are intentionally kept separate under a "Roadmap · Demo" section, and each one carries a visible banner saying so, because it matters that stakeholders never mistake a mockup for a working feature:

- **Automated Evidence Ingestion** — a mockup of what it would look like to auto-pull evidence from tools like a vulnerability scanner instead of manually uploading files. Uses sample data only.
- **Compliance Drift Alerts** — a mockup of what an alert would look like if the app could detect that a previously-compliant control had since changed (a firewall rule got edited, a cloud storage bucket became public). Sample data only.
- **QSA Audit View** — partially real: the compliance percentage and integrity hashes shown are live data. What's still a sketch is the rest of a full external-auditor workflow (a separate read-only login for the auditor, formal sign-off).

Everything outside this section is fully working, real functionality — not a demo.

---

## 9. The one-sentence summary for stakeholders

**VerifAI 360 turns the slowest part of a PCI DSS self-assessment — manually reading evidence and deciding what it proves — into an automated first pass, using either a cloud AI model or a fully offline, transparent scoring engine, while keeping the evidence itself protected behind a login and encryption, and giving anyone reviewing it a live, always-current picture of where compliance actually stands.**
