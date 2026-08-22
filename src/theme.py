"""
theme.py
---------
All of VerifAI 360's visual identity in one place.

Why this file exists: the stylesheet used to live as a ~300-line string
literal in the middle of app.py, between the imports and the first page.
Anyone opening app.py to change a page had to scroll past it, and anyone
wanting to change a colour had to hunt through page logic to find it.
Pulling it out means app.py is now just "wire up the pages", and the look
of the app is one import away.

DESIGN DIRECTION — "SOC console at 2am"
----------------------------------------
The subject is a security-operations tool, so the visual language is
borrowed from the instruments a security analyst actually looks at:
terminal readouts, HUD targeting frames, telemetry rails, and status
LEDs. Two deliberate choices carry it:

  1. CYAN + MAGENTA, not cyan alone. The previous theme was a single
     teal accent, which reads "generic dark dashboard". Cyan and magenta
     are the two poles of real chromatic aberration — which is exactly
     what the glitch effect on the brand mark is simulating — so the
     second colour is earning its place rather than decorating. Cyan is
     the app's own voice (headings, focus, primary actions); magenta is
     reserved for the HUD frame and the glitch, so it never competes
     with the semantic status colours.

  2. SEMANTIC COLOURS STAY BORING. Red/amber/green mean "critical /
     attention / clear" and nothing else. A compliance number shown to a
     stakeholder has to be readable at a glance on a projector, so
     nothing here glows body text or drops contrast to look moody.

Type is a three-role system: Chakra Petch (squared, instrument-panel
face) for display, Inter for body copy — compliance text is dense and
needs a neutral face — and JetBrains Mono for anything that is data:
scores, IDs, hashes, labels, timestamps.

Every font has a full local fallback stack, and the @import is wrapped so
that a machine with no internet (a locked-down demo laptop, an air-gapped
review room) degrades to system faces instead of falling back to Times.
Motion is gated behind prefers-reduced-motion.
"""

from string import Template

import streamlit as st

# ---------------------------------------------------------------------------
# Design tokens. Change a colour here and it changes everywhere, including
# the Plotly charts (see plotly_layout() at the bottom of this file).
# ---------------------------------------------------------------------------
TOKENS = {
    # surfaces — near-black with a blue cast, never pure #000
    "bg": "#05070d",
    "bg_alt": "#080c15",
    "panel": "#0b1220",
    "panel_raised": "#111a2c",
    "border": "#1d2a42",
    "border_soft": "#162034",
    # brand
    "cyan": "#22e4d4",
    "cyan_bright": "#7ef9ff",
    "cyan_dim": "#178a80",
    "magenta": "#ff2e88",
    "violet": "#7b5cff",
    # text
    "text": "#e9eef7",
    "muted": "#8496b8",
    # semantic status — kept deliberately plain and high-contrast
    "red": "#ff3b5c",
    "amber": "#ffb347",
    "green": "#2fe08a",
}

# Chart colour ramp, exported so the dashboard doesn't hardcode hex values
# that drift out of sync with the stylesheet.
CHART_SCALE = [TOKENS["red"], TOKENS["amber"], TOKENS["green"]]
CHART_LINE = TOKENS["cyan"]
HEATMAP_SCALE = [[0, TOKENS["panel_raised"]], [0.5, TOKENS["amber"]], [1, TOKENS["red"]]]


def plotly_layout(**overrides) -> dict:
    """Shared Plotly layout so every chart matches the app instead of each
    page re-declaring transparent backgrounds and font colours by hand."""
    layout = {
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "font_color": TOKENS["text"],
        "font_family": "JetBrains Mono, Consolas, monospace",
    }
    layout.update(overrides)
    return layout


_CSS_TEMPLATE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

:root {
    --vf-bg: ${bg};
    --vf-bg-alt: ${bg_alt};
    --vf-panel: ${panel};
    --vf-panel-raised: ${panel_raised};
    --vf-border: ${border};
    --vf-border-soft: ${border_soft};

    --vf-accent: ${cyan};
    --vf-accent-2: ${cyan_bright};
    --vf-accent-dim: ${cyan_dim};
    --vf-magenta: ${magenta};
    --vf-violet: ${violet};

    --vf-text: ${text};
    --vf-muted: ${muted};
    --vf-red: ${red};
    --vf-amber: ${amber};
    --vf-green: ${green};

    /* Full fallback stacks: an offline machine gets a sane system face,
       never a serif default. */
    --vf-display: 'Chakra Petch', 'Bahnschrift', 'DIN Alternate', 'Segoe UI', system-ui, sans-serif;
    --vf-body: 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
    --vf-mono: 'JetBrains Mono', 'Cascadia Mono', 'Consolas', 'SF Mono', ui-monospace, monospace;

    --vf-radius: 10px;
    --vf-radius-sm: 6px;
}

/* =========================================================================
   1. CANVAS
   A faint engineering grid, a cyan wash from the top, and a magenta
   counter-wash from the bottom-right so the background has a direction to
   it rather than being a flat dark rectangle.
   ========================================================================= */
html, body, .stApp {
    background-color: var(--vf-bg);
    background-image:
        linear-gradient(rgba(34,228,212,0.035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(34,228,212,0.035) 1px, transparent 1px),
        radial-gradient(ellipse 70% 50% at 50% -8%, rgba(34,228,212,0.10), transparent 62%),
        radial-gradient(ellipse 60% 50% at 100% 108%, rgba(255,46,136,0.07), transparent 60%);
    background-size: 44px 44px, 44px 44px, 100% 100%, 100% 100%;
    background-attachment: fixed;
    color: var(--vf-text);
    font-family: var(--vf-body);
}

/* Scanlines. Deliberately weaker than before and WITHOUT mix-blend-mode:
   the old overlay blended over the whole app and desaturated every chart
   and status colour underneath it. z-index sits below Streamlit's own
   dialogs/menus (which use far higher stacking) so it can never cover a
   modal or a dropdown. */
.stApp::before {
    content: "";
    position: fixed; inset: 0; pointer-events: none; z-index: 3;
    background: repeating-linear-gradient(
        to bottom,
        rgba(255,255,255,0.014) 0px, rgba(255,255,255,0.014) 1px,
        transparent 1px, transparent 3px
    );
}

/* =========================================================================
   2. TYPE
   ========================================================================= */
h1, h2, h3, h4, h5 {
    font-family: var(--vf-display);
    letter-spacing: 0.3px;
    font-weight: 600;
}
h2, h3 { color: var(--vf-text); }
p, li, label, .stMarkdown { font-family: var(--vf-body); }

/* Anything that is DATA gets the mono face: scores, IDs, hashes, code. */
code, kbd, samp, pre,
[data-testid="stMetricValue"],
[data-testid="stMetricLabel"],
.vf-mono {
    font-family: var(--vf-mono) !important;
}
code { color: var(--vf-accent-2); background: rgba(34,228,212,0.08); border-radius: 3px; padding: 1px 5px; }

.block-container { padding-top: 1.4rem; padding-bottom: 4rem; max-width: 1220px; }

/* =========================================================================
   3. TOP TELEMETRY RAIL
   A 2px sweep pinned to the top of the viewport. Attached to the app
   container by data-testid rather than ":first-child", which broke
   whenever Streamlit changed its internal wrapper order.
   ========================================================================= */
[data-testid="stAppViewContainer"]::before {
    content: "";
    position: fixed; top: 0; left: 0; right: 0; height: 2px; z-index: 4;
    pointer-events: none;
    background: linear-gradient(90deg,
        transparent 0%, var(--vf-violet) 15%, var(--vf-accent) 35%,
        var(--vf-accent-2) 50%, var(--vf-accent) 65%, var(--vf-magenta) 85%, transparent 100%);
    background-size: 200% 100%;
    animation: vf-sweep 6s linear infinite;
    opacity: 0.7;
}
@keyframes vf-sweep {
    0%   { background-position: 200% 0; }
    100% { background-position: -200% 0; }
}

/* =========================================================================
   4. SIDEBAR — the console plate
   ========================================================================= */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, var(--vf-panel) 0%, var(--vf-bg-alt) 100%);
    border-right: 1px solid var(--vf-border);
    box-shadow: 4px 0 28px rgba(0,0,0,0.45);
}
section[data-testid="stSidebar"] .block-container { padding-top: 1.1rem; }

.vf-brand {
    display: flex; align-items: center; gap: 10px;
    padding: 10px 12px; margin-bottom: 8px;
    border: 1px solid var(--vf-border);
    border-left: 2px solid var(--vf-accent);
    border-radius: var(--vf-radius-sm);
    background:
        linear-gradient(135deg, rgba(34,228,212,0.07), transparent 55%),
        linear-gradient(315deg, rgba(255,46,136,0.05), transparent 55%),
        var(--vf-panel-raised);
    position: relative; overflow: hidden;
}
/* Slow laser sweep across the brand plate — the one ambient animation. */
.vf-brand::after {
    content: ""; position: absolute; inset: 0;
    background: linear-gradient(105deg, transparent 40%, rgba(126,249,255,0.14) 50%, transparent 60%);
    background-size: 250% 100%;
    animation: vf-sweep 7s linear infinite;
    pointer-events: none;
}
.vf-brand-title {
    font-family: var(--vf-display);
    font-weight: 700; font-size: 1.22rem; color: var(--vf-text);
    letter-spacing: 0.4px;
    animation: vf-glitch 9s infinite;
}
.vf-brand-cursor {
    display: inline-block; width: 8px; height: 1.05em;
    background: var(--vf-accent); margin-left: 3px; vertical-align: text-bottom;
    box-shadow: 0 0 7px var(--vf-accent);
    animation: vf-blink 1.15s steps(1) infinite;
}
/* Real RGB split — this is why the palette has a magenta pole at all. */
@keyframes vf-glitch {
    0%, 93%, 100% { text-shadow: 0 0 16px rgba(34,228,212,0.22); transform: translate(0,0); }
    94% { text-shadow: -2px 0 var(--vf-magenta), 2px 0 var(--vf-accent-2); transform: translate(-1px,0); }
    95% { text-shadow:  2px 0 var(--vf-magenta), -2px 0 var(--vf-accent-2); transform: translate(1px,0); }
    96% { text-shadow: 0 0 16px rgba(34,228,212,0.22); transform: translate(0,0); }
}
@keyframes vf-blink { 50% { opacity: 0; } }

.vf-nav-caption {
    color: var(--vf-muted); font-size: 0.68rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 1.3px;
    margin: 16px 0 4px 4px; font-family: var(--vf-mono);
    display: flex; align-items: center; gap: 8px;
}
/* Hairline that runs from the caption to the edge — a divider that also
   labels, instead of a bare <hr>. */
.vf-nav-caption::after {
    content: ""; flex: 1; height: 1px;
    background: linear-gradient(90deg, var(--vf-border), transparent);
}

/* Sidebar nav reads as a menu, not a form control. */
section[data-testid="stSidebar"] div[role="radiogroup"] label {
    padding: 5px 9px; border-radius: var(--vf-radius-sm); font-size: 0.9rem;
    border-left: 2px solid transparent;
    transition: background 0.14s ease, border-color 0.14s ease;
}
section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {
    background: rgba(34,228,212,0.07);
    border-left-color: var(--vf-accent-dim);
}

/* Status LEDs at the bottom of the sidebar. */
.vf-status-ticker {
    display: flex; align-items: center; gap: 7px; font-family: var(--vf-mono);
    font-size: 0.7rem; color: var(--vf-muted); padding: 7px 3px 2px 3px;
    letter-spacing: 0.4px;
}
.vf-status-dot {
    width: 7px; height: 7px; border-radius: 50%; flex: 0 0 auto;
    background: var(--vf-green); box-shadow: 0 0 7px var(--vf-green);
    animation: vf-pulse 2.2s ease-in-out infinite;
}
.vf-status-dot.vf-status-amber { background: var(--vf-amber); box-shadow: 0 0 7px var(--vf-amber); }
.vf-status-dot.vf-status-dim {
    background: var(--vf-muted); box-shadow: none; animation: none; opacity: 0.55;
}
@keyframes vf-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

/* =========================================================================
   5. PAGE HEADER — reads as a terminal prompt
   ========================================================================= */
.vf-page-header {
    display: flex; align-items: center; gap: 15px;
    padding-bottom: 12px; margin-bottom: 6px;
    border-bottom: 1px solid var(--vf-border-soft);
    position: relative;
}
.vf-page-header::after {
    content: ""; position: absolute; left: 0; bottom: -1px; height: 1px; width: 140px;
    background: linear-gradient(90deg, var(--vf-accent), var(--vf-magenta) 70%, transparent);
    box-shadow: 0 0 9px 1px rgba(34,228,212,0.55);
}
.vf-page-header .vf-icon {
    font-size: 1.65rem; width: 48px; height: 48px; min-width: 48px;
    display: flex; align-items: center; justify-content: center;
    background: rgba(34,228,212,0.10);
    border: 1px solid rgba(34,228,212,0.32);
    border-radius: var(--vf-radius);
    box-shadow: 0 0 18px -3px rgba(34,228,212,0.45), inset 0 0 14px rgba(34,228,212,0.07);
}
.vf-page-header h1 {
    font-size: 1.62rem; margin: 0; line-height: 1.18; font-weight: 700;
    font-family: var(--vf-display); letter-spacing: 0.2px;
}
.vf-page-header .vf-subtitle {
    color: var(--vf-muted); font-size: 0.87rem; margin-top: 4px;
    font-family: var(--vf-mono); line-height: 1.45;
}
/* The prompt caret. Structural, not decorative: it marks where the
   machine's own readout starts. */
.vf-page-header .vf-subtitle::before {
    content: "> "; color: var(--vf-accent); font-weight: 700;
}

/* =========================================================================
   6. HUD CARDS — metrics and expanders
   The corner brackets are the signature element. They were in the old
   theme too but never rendered on expanders, because the expander had
   overflow:hidden and the brackets sit at -1px. Padding on the card and
   inset brackets fixes that without clipping.
   ========================================================================= */
[data-testid="stMetric"] {
    background: linear-gradient(158deg, var(--vf-panel) 0%, var(--vf-panel-raised) 130%);
    border: 1px solid var(--vf-border);
    border-left: 2px solid var(--vf-accent-dim);
    border-radius: var(--vf-radius);
    padding: 17px 19px 13px 19px;
    position: relative;
    transition: border-color 0.16s ease, box-shadow 0.16s ease, transform 0.16s ease;
}
[data-testid="stMetric"]:hover {
    border-color: var(--vf-accent-dim);
    border-left-color: var(--vf-accent);
    box-shadow: 0 0 24px -8px rgba(34,228,212,0.5);
    transform: translateY(-1px);
}
[data-testid="stMetricLabel"] {
    color: var(--vf-muted) !important;
    font-size: 0.72rem !important;
    text-transform: uppercase; letter-spacing: 0.9px;
}
[data-testid="stMetricValue"] {
    font-weight: 700;
    text-shadow: 0 0 14px rgba(34,228,212,0.18);
}

div[data-testid="stExpander"] {
    background: var(--vf-panel);
    border: 1px solid var(--vf-border);
    border-radius: var(--vf-radius);
    margin-bottom: 11px;
    position: relative;
    /* NOT overflow:hidden — that clipped the corner brackets. */
    transition: border-color 0.16s ease;
}
div[data-testid="stExpander"]:hover { border-color: var(--vf-accent-dim); }
div[data-testid="stExpander"] summary { padding: 6px 4px; font-weight: 500; }
div[data-testid="stExpander"] summary:hover { color: var(--vf-accent-2); }

/* Targeting-reticle corners. Cyan top-left, magenta bottom-right — the
   asymmetry is what makes it read as an instrument frame rather than a
   decorative border. */
[data-testid="stMetric"]::before, [data-testid="stMetric"]::after,
div[data-testid="stExpander"]::before, div[data-testid="stExpander"]::after,
.vf-hud-card::before, .vf-hud-card::after {
    content: ""; position: absolute; width: 11px; height: 11px;
    pointer-events: none; opacity: 0.7;
    transition: opacity 0.16s ease;
}
[data-testid="stMetric"]::before,
div[data-testid="stExpander"]::before,
.vf-hud-card::before {
    top: 2px; left: 2px;
    border-top: 2px solid var(--vf-accent); border-left: 2px solid var(--vf-accent);
    border-top-left-radius: 3px;
}
[data-testid="stMetric"]::after,
div[data-testid="stExpander"]::after,
.vf-hud-card::after {
    bottom: 2px; right: 2px;
    border-bottom: 2px solid var(--vf-magenta); border-right: 2px solid var(--vf-magenta);
    border-bottom-right-radius: 3px;
}
[data-testid="stMetric"]:hover::before, [data-testid="stMetric"]:hover::after,
div[data-testid="stExpander"]:hover::before, div[data-testid="stExpander"]:hover::after {
    opacity: 1;
}

/* =========================================================================
   7. CONTROLS
   ========================================================================= */
.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {
    border-radius: var(--vf-radius-sm) !important;
    font-weight: 600 !important;
    font-family: var(--vf-mono) !important;
    font-size: 0.86rem !important;
    letter-spacing: 0.3px;
    border: 1px solid var(--vf-border) !important;
    background: var(--vf-panel-raised) !important;
    color: var(--vf-text) !important;
    transition: border-color 0.15s ease, box-shadow 0.15s ease, color 0.15s ease !important;
}
.stButton > button:hover, .stDownloadButton > button:hover, .stFormSubmitButton > button:hover {
    border-color: var(--vf-accent-dim) !important;
    color: var(--vf-accent-2) !important;
    box-shadow: 0 0 16px -5px rgba(34,228,212,0.55);
}
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"],
.stDownloadButton > button[kind="primary"] {
    background: linear-gradient(120deg, var(--vf-accent), #19c6b8) !important;
    color: #04100f !important;
    border: none !important;
    box-shadow: 0 0 20px -5px rgba(34,228,212,0.75);
}
.stButton > button[kind="primary"]:hover, .stFormSubmitButton > button[kind="primary"]:hover,
.stDownloadButton > button[kind="primary"]:hover {
    color: #04100f !important;
    box-shadow: 0 0 30px -3px rgba(34,228,212,0.95);
}
.stButton > button:disabled, .stFormSubmitButton > button:disabled {
    opacity: 0.45 !important; box-shadow: none !important;
}

.stTextInput input, .stTextArea textarea, .stNumberInput input, .stDateInput input,
div[data-baseweb="select"] > div, div[data-baseweb="input"] {
    background-color: var(--vf-panel-raised) !important;
    border-color: var(--vf-border) !important;
    color: var(--vf-text) !important;
    border-radius: var(--vf-radius-sm) !important;
}
.stTextInput input:focus, .stTextArea textarea:focus, .stNumberInput input:focus {
    border-color: var(--vf-accent) !important;
    box-shadow: 0 0 0 1px var(--vf-accent), 0 0 14px -4px rgba(34,228,212,0.6) !important;
}
/* Keyboard focus must stay visible for anyone tabbing through a demo. */
:focus-visible { outline: 2px solid var(--vf-accent-2) !important; outline-offset: 2px; }

button[data-baseweb="tab"] {
    font-family: var(--vf-mono) !important;
    font-size: 0.84rem !important;
    letter-spacing: 0.3px;
}
button[data-baseweb="tab"][aria-selected="true"] { color: var(--vf-accent) !important; }
div[data-baseweb="tab-highlight"] {
    background-color: var(--vf-accent) !important;
    box-shadow: 0 0 9px rgba(34,228,212,0.7);
}
div[data-baseweb="tab-border"] { background-color: var(--vf-border) !important; }

[data-testid="stFileUploaderDropzone"] {
    background: rgba(34,228,212,0.03) !important;
    border: 1px dashed rgba(34,228,212,0.3) !important;
    border-radius: var(--vf-radius) !important;
}
[data-testid="stFileUploaderDropzone"]:hover { border-color: var(--vf-accent) !important; }

div[data-testid="stProgress"] > div > div > div {
    background: linear-gradient(90deg, var(--vf-accent-dim), var(--vf-accent), var(--vf-accent-2)) !important;
}

/* =========================================================================
   8. STATUS LANGUAGE — badges, banners, alerts
   ========================================================================= */
.vf-badge {
    display: inline-block; padding: 3px 11px; border-radius: 4px;
    font-size: 0.7rem; font-weight: 700; letter-spacing: 0.7px;
    text-transform: uppercase; font-family: var(--vf-mono);
}
.vf-badge-critical {
    background: rgba(255,59,92,0.16); color: #ff8fa1;
    border: 1px solid rgba(255,59,92,0.5);
    animation: vf-critical 2s ease-in-out infinite;
}
.vf-badge-high   { background: rgba(255,179,71,0.15); color: #ffcb83; border: 1px solid rgba(255,179,71,0.45); }
.vf-badge-medium { background: rgba(255,179,71,0.09); color: #ded0a6; border: 1px solid rgba(255,179,71,0.26); }
.vf-badge-low    { background: rgba(47,224,138,0.15); color: #7ceab2; border: 1px solid rgba(47,224,138,0.45); }
@keyframes vf-critical {
    0%, 100% { box-shadow: 0 0 11px -3px rgba(255,59,92,0.65); }
    50%      { box-shadow: 0 0 18px 0px rgba(255,59,92,0.95); }
}

.vf-secure-badge {
    display: inline-flex; align-items: center; gap: 5px;
    font-family: var(--vf-mono); font-size: 0.7rem; font-weight: 700;
    color: #7ceab2; background: rgba(47,224,138,0.1);
    border: 1px solid rgba(47,224,138,0.38);
    border-radius: 4px; padding: 3px 9px; letter-spacing: 0.5px;
}

/* Roadmap/mockup pages get hazard stripes — unmistakably "not live data",
   which matters when a stakeholder is looking at the screen. */
.vf-demo-banner {
    border: 1px solid rgba(255,179,71,0.34);
    border-left: 3px solid var(--vf-amber);
    border-radius: var(--vf-radius-sm);
    padding: 13px 17px; margin-bottom: 17px;
    color: #ffcb83; font-size: 0.86rem; font-family: var(--vf-mono);
    line-height: 1.5;
    background:
        repeating-linear-gradient(45deg,
            rgba(255,179,71,0.055) 0px, rgba(255,179,71,0.055) 9px,
            transparent 9px, transparent 18px);
}

.vf-readonly-banner {
    background: rgba(255,179,71,0.08); border: 1px solid rgba(255,179,71,0.36);
    border-radius: var(--vf-radius-sm); padding: 9px 13px; margin: 6px 0 12px 0;
    font-family: var(--vf-mono); font-size: 0.76rem; color: #ffcb83;
    display: flex; align-items: center; gap: 7px; line-height: 1.4;
}

.vf-about-toggle summary { color: var(--vf-accent) !important; font-family: var(--vf-mono); font-size: 0.8rem; }
.vf-about-toggle { border: 1px dashed rgba(34,228,212,0.34) !important; background: rgba(34,228,212,0.03) !important; }

div[data-testid="stAlert"] { border-radius: var(--vf-radius); border-left-width: 3px; }

/* =========================================================================
   9. DATA SURFACES
   ========================================================================= */
div[data-testid="stDataFrame"] {
    border: 1px solid var(--vf-border);
    border-radius: var(--vf-radius);
    overflow: hidden;
}
hr { border-color: var(--vf-border-soft) !important; }

::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: var(--vf-bg-alt); }
::-webkit-scrollbar-thumb { background: var(--vf-border); border-radius: 6px; }
::-webkit-scrollbar-thumb:hover { background: var(--vf-accent-dim); }

/* =========================================================================
   10. LOGIN
   ========================================================================= */
.vf-login-wrap { max-width: 430px; margin: 7vh auto 0 auto; text-align: center; }
.vf-login-wrap .vf-icon-big {
    font-size: 3.1rem; margin-bottom: 8px;
    filter: drop-shadow(0 0 20px rgba(34,228,212,0.55));
}
.vf-login-wrap h1 {
    font-family: var(--vf-display); font-weight: 700;
    margin-bottom: 2px; letter-spacing: 0.5px;
}
.vf-login-tag {
    color: var(--vf-muted); font-family: var(--vf-mono);
    font-size: 0.79rem; letter-spacing: 1.1px;
}

/* =========================================================================
   11. RESPONSIVE + REDUCED MOTION
   ========================================================================= */
@media (max-width: 640px) {
    .vf-page-header { gap: 11px; }
    .vf-page-header h1 { font-size: 1.28rem; }
    .vf-page-header .vf-icon { width: 40px; height: 40px; min-width: 40px; font-size: 1.35rem; }
    .block-container { padding-top: 1rem; }
}

@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        animation: none !important;
        transition: none !important;
    }
    [data-testid="stMetric"]:hover { transform: none; }
}
</style>
"""

_CSS = Template(_CSS_TEMPLATE).substitute(TOKENS)


def inject():
    """Render the stylesheet. Call once, immediately after set_page_config()."""
    st.markdown(_CSS, unsafe_allow_html=True)
