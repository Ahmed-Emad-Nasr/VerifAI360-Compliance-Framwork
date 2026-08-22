# Review pass — theme rework + bug fixes

Everything below is a change to this repo made in one review pass. Nothing
here changes what the app is for; it changes how it looks, how fast the
offline engine is, and a set of defects that would have shown up in front of
an audience.

**Before you run this:** your own `verifai360.db` was not recoverable from
the archive that was reviewed (its git blob was missing), so this repo ships
without one. Keep your existing database file — the app recreates an empty
one via `db.init_db()` if none is present.

---

## 1. The visual rework

### `src/theme.py` — new file

The stylesheet used to be a ~300-line string literal sitting in the middle of
`app.py`, between the imports and the first page. It is now its own module,
and `app.py` calls `theme.inject()`. That removed 13,793 characters from the
middle of `app.py`.

The module also exports the design tokens, so **the Plotly charts read their
colours from the same place the CSS does**. Previously chart colours were
hardcoded hex values in `app.py` that had already drifted from the palette.

### What changed visually

**Palette — cyan *and* magenta, not cyan alone.** The old theme had a single
teal accent, which reads as a generic dark dashboard. Magenta is not
decoration here: it is the other pole of the RGB split that the glitch
effect on the brand mark actually simulates, and it draws the second half of
the HUD frame. Semantic colours (red / amber / green) were deliberately left
plain and high-contrast — a compliance number on a projector has to be
readable, so nothing glows body text.

**Type — three roles.** Display face is now **Chakra Petch**, a squared
instrument-panel face, replacing Space Grotesk. Inter stays for body copy
(compliance text is dense and needs a neutral face) and JetBrains Mono is
used for everything that is *data*: scores, IDs, hashes, timestamps. All
three have full local fallback stacks, so a machine with no internet degrades
to system faces instead of dropping to a serif default.

### Rendering bugs fixed in the CSS

| Problem | Fix |
|---|---|
| The HUD corner brackets **never rendered on expanders** — `overflow: hidden` clipped elements positioned at `-1px` | Removed the clip, inset the brackets |
| Full-screen scanline overlay used `mix-blend-mode: overlay`, which desaturated every chart and status colour beneath it | Blend mode removed, opacity reduced |
| Same overlay sat at `z-index: 9999`, high enough to cover dropdowns and dialogs | Lowered to `3` |
| Top accent bar hung off `div:first-child`, which breaks whenever Streamlit reorders its internal wrappers | Re-anchored to `[data-testid="stAppViewContainer"]` |
| No reduced-motion support, no visible keyboard focus | Both added |

Roadmap/mockup pages now carry **hazard stripes** rather than a plain tinted
box, so "this is not live data" is unmistakable to anyone looking at the
screen rather than reading the caption.

### `config.toml` was in the wrong place — it was never being read

Streamlit reads `.streamlit/config.toml`, never a `config.toml` in the
project root. The file therefore had no effect: the **25 MB server-side
upload cap was not applied** (Streamlit's 200 MB default was in force) and
neither were the native theme colours. The live copy now sits at
`.streamlit/config.toml`; the root file is kept as a pointer, and the README
references were corrected.

---

## 2. Local engine performance — the most important fix

`local_analyzer._keyword_hits` compared every curated keyword against every
sliding window position in the document using `difflib`'s full `ratio()`.
Cost grew with (document length × keyword count), and a real PCI policy
document is easily 10,000–30,000 words against ~200 keywords.

Measured on documents with genuinely diverse vocabulary:

| Document | Before | After | Speedup |
|---|---|---|---|
| 2,000 words | 6.86 s | 0.34 s | 20× |
| 10,000 words | 35.46 s | 1.67 s | 21× |
| 30,000 words | **105.85 s** | **5.10 s** | 21× |

Three changes, none of which alter the result:

1. **Length band.** `ratio` is `2M/T`, and `M` cannot exceed the shorter
   string's length, so a window outside a computable length range provably
   cannot reach the threshold. Rejected with arithmetic, no comparison.
2. **`quick_ratio` pre-filter.** difflib's own documented upper bound on
   `ratio()`, so anything it rejects could not have qualified.
3. **Window deduplication.** The same phrase recurs constantly in one
   document; comparing it forty times cannot give forty answers. First
   occurrence is kept, which preserves the original earliest-window
   tie-break exactly.

**Verified identical, not assumed.** The optimized function was compared
against the original implementation pulled straight from git across 60
threshold × document-shape combinations (including negation-heavy text,
typo-laden text, no-match text and randomized vocabulary) and 36 full
`analyze_evidence()` runs. Every result matched.

Two real defects surfaced during that verification and are fixed:

- **`difflib.ratio()` is not symmetric.** A first attempt swapped which
  sequence was `a` and which was `b` to make the optimization cheaper, and
  that silently changed borderline results. The original argument order is
  preserved.
- **A floating-point boundary error** made the length bound compute as
  `2.0000000000000004` instead of `2.0`, dropping genuine matches that landed
  exactly on the boundary. Corrected with an epsilon.

---

## 3. Logic and correctness fixes

**Switching language could leave a blank page.** `_active_page` persists
across reruns and held the label from the *previous* language, but the
lookup table was built only from the currently-displayed labels. Nothing
matched, every `elif` fell through, and the user got an empty screen. The map
is now built from both languages, and the toggle carries the open page across
so the nav highlight stays in sync too.

**The read/write status LED was inverted.** With reviewer mode *off* (normal
read/write) the dot rendered dim and dead; with it *on* (read-only) it pulsed
green. Backwards.

**Compare mode wrote the same file into the record twice.** It ran the AI
engine (which saved an evidence row) and then the local engine with
`allow_duplicate=True` (which saved a second row for identical bytes), so one
comparison double-counted the file on the dashboard and left two scores in
the register. Compare mode is now genuinely read-only: both engines run with
`persist=False`, nothing is committed, and the UI says so. Pick an engine and
run it normally to record a result.

**Failed analyses left orphaned encrypted files.** By the time analysis runs,
the file has been copied into `evidence_store/` and encrypted. If the engine
then threw, no evidence row was ever written, so the blob stayed on disk
forever with nothing referencing it. Now cleaned up.

**`reset_all()` only cleared the database.** The encrypted files stayed
behind, so `evidence_store/` grew with every reset and never shrank. It now
purges them and reports how many were removed. The button also clears the
report cache.

**Changing the passcode did nothing until restart.** Settings wrote the new
value to `.env` via `set_key`, but `os.environ` kept the old one — and
`_ensure_env_value` reads `os.environ` first and loads dotenv with
`override=False`, so it could never see the new value. `check_passcode`
validated against the *old* passcode for the rest of the process's life while
the UI claimed the change had taken effect. New `sec.set_passcode()` writes
both, clears any lockout, and validates length; the success message is now
accurate about which sessions are affected.

**Hallucinated sub-requirement IDs were stored and then vanished.** The model
occasionally returns a plausible-looking id that isn't in the catalog. Those
rows were written to the database and then disappeared from every screen,
because the dashboard looks scores up *by catalog id* — so evidence appeared
analyzed with its score nowhere and no error. They are now dropped at the
boundary and reported in the UI.

**Empty model responses crashed with `AttributeError`.** `response.text` is
`None` when a candidate is safety-blocked or hits the token cap before
emitting content, and `.strip()` on that produced a meaningless error.
Now raises a real message naming the finish reason.

**Score parsing was fragile.** `int(a.get("sufficiency_score", 0))` raised a
bare `ValueError`/`TypeError` — not an `AIAnalyzerError` — on `None`,
`"N/A"`, `"72/100"` or `71.5`, so the UI showed a stack-trace-flavoured
message instead of a handled failure. Parsing is now tolerant, and
`gaps`/`recommendations` arriving as a bare string are coerced to lists.

**Reports were rebuilt on every single rerun.** `st.download_button` needs its
bytes up front, so `rg.generate_pdf_report()` ran on every interaction with
the Dashboard and the QSA page — every filter change, every expander click.
They are now behind `@st.cache_data` keyed on a new cheap
`db.data_fingerprint()`, so a report is built once and reused until the data
actually moves.

**Import could splice uploaded text into SQL.** Column names from the
uploaded export JSON went straight into the `INSERT` identifier list, where
they cannot be parameterized. They are now validated against the table's real
schema first — which also turns a stale backup into a readable error instead
of a raw sqlite3 syntax failure.

**Two crashes from restored/hand-edited data.**
`STATUS_OPTIONS.index(r["status"])` raised `ValueError` on an unrecognized
status, and `date.fromisoformat(it["next_due_date"])` raised on a null or
malformed date. One bad row took the whole page down; both now degrade.

**SQLite had no busy timeout.** Two browser tabs writing at once raised
"database is locked" immediately. Added a 15 s timeout, WAL mode so reads
don't block on writes, and an explicit rollback so a failed multi-statement
write can't leave things half-applied.

**Reset-to-defaults didn't redraw.** The weight sliders kept showing the old
values and the caption asked the user to reload manually. Now reruns.

**A comment contradicted the code.** It claimed "Identified Risks" had no
`elif` branch of its own. It does.

---

## Verification

- Full test suite: **62 passed, 3 failed — identical before and after.**
  The 3 failures are artifacts of the review sandbox (no network, so
  `google-genai` had to be stubbed and a real `.env` was present); they fail
  the same way on unmodified code, so they are not regressions. Run real
  `pytest` on your machine to confirm.
- Local analyzer equivalence: 60 threshold × document combinations and 36
  full-pipeline runs, all identical to the original.
- AI response hardening: 28 unit assertions.
- End-to-end pipeline (upload → extract → encrypt → analyze → persist →
  report → export/import): 31 assertions, all passing.
- Every file compiles under `py_compile`.

## Not done

The app itself was never launched — Streamlit and `google-genai` could not be
installed in the review environment (no network), so **every visual change is
unverified in a browser**. Load it locally before the presentation and check
the sidebar, one metric card, one expander, and one chart.

The AI engine path was exercised only through stubs; no real Gemini call was
made.
