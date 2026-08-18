"""
database.py
------------
Lightweight SQLite persistence layer for VerifAI 360.

In plain English: this is the ONLY file that talks directly to the
database. Every other file (app.py, compliance_engine.py, risk_engine.py,
report_generator.py) reads/writes data by calling functions in this file —
they never write raw SQL themselves. This keeps all the table/column
knowledge in one place.

The database itself is a single file, `verifai360.db`, in the project's
root folder — SQLite needs no separate server, it's just a file that
Python's built-in `sqlite3` module reads and writes directly.

Tables
------
evidence              : one row per uploaded evidence file
sub_req_assessment    : one row per (evidence, sub-requirement) AI assessment
                         -> this is what enables "cross-requirement spanning":
                            a single evidence file can create MANY rows here.
score_history          : one row per sub-requirement every time its score is
                         recomputed -> enables the "continuous maturity
                         scoring" trend line in the dashboard.
risk_register          : one row per risk (auto-generated from a gap, or
                         entered manually) — powers the Identified Risks page.
app_settings            : simple key/value store (e.g. which SAQ type is
                         currently selected) — not a "real" settings system,
                         just a two-column table (key, value).
cde_scope               : one row per system the user has documented as
                         inside/connected to the Cardholder Data Environment.
compensating_controls  : one row per compensating-control justification.
testing_tracker         : one row per recurring test (scan, pen test, ...).
vendor_register         : one row per third-party vendor/service provider.

REPEATING PATTERN — READ THIS ONCE, THEN SKIM THE REST
--------------------------------------------------------
Most of the tables above (risk_register, cde_scope, compensating_controls,
testing_tracker, vendor_register) follow the exact same four-function
pattern: `insert_x(...)`, `update_x(item_id, **fields)`, `delete_x(item_id)`,
`get_all_x()`. Once you understand one group (e.g. "CDE scope" below),
you already understand the others — they just point at a different table.
`update_x(item_id, **fields)` is intentionally generic: pass only the
columns you want to change as keyword arguments (e.g.
`update_risk(5, status="Closed")`) and it builds the `UPDATE ... SET`
statement for you, so each table doesn't need one hand-written "update"
function per column.
"""

import sqlite3
import json
import os
import hashlib
import datetime
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "verifai360.db")


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                evidence_type TEXT,
                uploaded_at TEXT NOT NULL,
                target_sub_requirement TEXT,
                raw_text_excerpt TEXT,
                sha256 TEXT
            );

            CREATE TABLE IF NOT EXISTS sub_req_assessment (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER NOT NULL,
                sub_requirement_id TEXT NOT NULL,
                is_primary_target INTEGER NOT NULL DEFAULT 0,
                sufficiency_score INTEGER NOT NULL,      -- 0-100
                maturity_level TEXT,                     -- Initial/Developing/Defined/Managed/Optimized
                rationale TEXT,
                gaps TEXT,                                -- JSON list of strings
                recommendations TEXT,                     -- JSON list of strings
                created_at TEXT NOT NULL,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS score_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sub_requirement_id TEXT NOT NULL,
                score INTEGER NOT NULL,
                recorded_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS risk_register (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requirement_id TEXT,
                sub_requirement_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                likelihood INTEGER NOT NULL,     -- 1-5
                impact INTEGER NOT NULL,         -- 1-5
                risk_score INTEGER NOT NULL,     -- likelihood * impact (1-25)
                risk_level TEXT NOT NULL,        -- Low / Medium / High / Critical
                owner TEXT,
                status TEXT NOT NULL DEFAULT 'Open',   -- Open / Mitigating / Accepted / Closed
                mitigation_plan TEXT,
                due_date TEXT,
                source TEXT NOT NULL DEFAULT 'manual', -- 'manual' or 'auto-gap'
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS cde_scope (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                system_name TEXT NOT NULL,
                component_type TEXT,             -- Server / Application / Network device / Endpoint / Storage / Other
                description TEXT,
                in_scope INTEGER NOT NULL DEFAULT 1,   -- 1 = in CDE scope, 0 = documented as out of scope
                connected_to_cde INTEGER NOT NULL DEFAULT 0,  -- "connected-to/security-impacting" per PCI DSS 4.0 scoping
                data_flow_notes TEXT,             -- how cardholder data enters/exits/moves through this system
                owner TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS compensating_controls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sub_requirement_id TEXT NOT NULL,
                original_requirement_text TEXT,
                constraint_reason TEXT,           -- why the standard control can't be implemented as-is
                objective_met TEXT,                -- the control objective this control is meeting instead
                compensating_control_description TEXT NOT NULL,
                additional_risk TEXT,
                validation_evidence TEXT,
                reviewed_by TEXT,
                review_date TEXT,
                next_review_date TEXT,
                status TEXT NOT NULL DEFAULT 'Draft',  -- Draft / Approved / Expired / Retired
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS testing_tracker (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_type TEXT NOT NULL,          -- ASV External Scan / Internal Vuln Scan / Penetration Test / Segmentation Test / Other
                related_requirement TEXT,          -- e.g. '11.3', '11.4', '11.4.5'
                scope_description TEXT,
                frequency TEXT NOT NULL,           -- Quarterly / Semi-Annual / Annual / After significant change
                last_performed_date TEXT,
                next_due_date TEXT NOT NULL,
                result_summary TEXT,
                result_status TEXT,                -- Pass / Fail / Pass with exceptions / Not yet run
                evidence_id INTEGER,               -- optional FK to evidence.id
                owner TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS vendor_register (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor_name TEXT NOT NULL,
                service_provided TEXT,
                pci_dss_responsibility TEXT,       -- Vendor-managed / Shared / Merchant-managed
                cde_connection TEXT,               -- How the vendor connects to / affects the CDE
                compliance_status TEXT NOT NULL DEFAULT 'Unknown',  -- Compliant / Non-Compliant / Unknown / Expired
                attestation_type TEXT,             -- AOC on file / SAQ on file / ROC on file / None
                attestation_expiry TEXT,
                last_reviewed_date TEXT,
                next_review_due TEXT,
                contract_reference TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        _migrate_add_missing_columns(conn)


def _migrate_add_missing_columns(conn):
    """
    Lightweight forward migration for DBs created before a column existed
    (SQLite has no 'ADD COLUMN IF NOT EXISTS', so we check PRAGMA table_info
    first). Keeps existing verifai360.db files working without a manual
    reset when the schema grows.
    """
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(evidence)").fetchall()}
    if "sha256" not in cols:
        conn.execute("ALTER TABLE evidence ADD COLUMN sha256 TEXT")
        _backfill_sha256(conn)


def _backfill_sha256(conn):
    """One-time backfill: compute real SHA-256 hashes for evidence rows uploaded before this
    column existed, so old records don't just show blank/'None' in the Evidence Log and PDF
    report. Silently skips rows whose stored file is no longer on disk."""
    rows = conn.execute("SELECT id, stored_path FROM evidence WHERE sha256 IS NULL").fetchall()
    for r in rows:
        path = r["stored_path"]
        if not path or not os.path.isfile(path):
            continue
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        conn.execute("UPDATE evidence SET sha256 = ? WHERE id = ?", (h.hexdigest(), r["id"]))


def insert_evidence(filename, stored_path, evidence_type, target_sub_requirement, raw_text_excerpt,
                     sha256=None):
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO evidence
               (filename, stored_path, evidence_type, uploaded_at, target_sub_requirement,
                raw_text_excerpt, sha256)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (filename, stored_path, evidence_type, datetime.datetime.utcnow().isoformat(),
             target_sub_requirement, raw_text_excerpt[:2000] if raw_text_excerpt else "", sha256),
        )
        return cur.lastrowid


def insert_assessment(evidence_id, sub_requirement_id, is_primary_target, sufficiency_score,
                       maturity_level, rationale, gaps, recommendations):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO sub_req_assessment
               (evidence_id, sub_requirement_id, is_primary_target, sufficiency_score,
                maturity_level, rationale, gaps, recommendations, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (evidence_id, sub_requirement_id, int(is_primary_target), sufficiency_score,
             maturity_level, rationale, json.dumps(gaps or []), json.dumps(recommendations or []),
             datetime.datetime.utcnow().isoformat()),
        )
        conn.execute(
            """INSERT INTO score_history (sub_requirement_id, score, recorded_at)
               VALUES (?, ?, ?)""",
            (sub_requirement_id, sufficiency_score, datetime.datetime.utcnow().isoformat()),
        )


def get_best_score_per_subreq():
    """
    Compliance score per sub-requirement = MAX sufficiency score across all
    evidence ever submitted for it (a sub-requirement doesn't get worse just
    because someone re-uploads a weaker piece of evidence for something else
    that happens to also map to it; it reflects the best evidence on file).
    """
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT sub_requirement_id, MAX(sufficiency_score) AS best_score
               FROM sub_req_assessment GROUP BY sub_requirement_id"""
        ).fetchall()
        return {r["sub_requirement_id"]: r["best_score"] for r in rows}


def get_assessments_for_subreq(sub_requirement_id):
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT sra.*, e.filename FROM sub_req_assessment sra
               JOIN evidence e ON e.id = sra.evidence_id
               WHERE sra.sub_requirement_id = ?
               ORDER BY sra.created_at DESC""",
            (sub_requirement_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_evidence():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM evidence ORDER BY uploaded_at DESC").fetchall()
        return [dict(r) for r in rows]


def get_score_history(sub_requirement_id=None):
    with get_conn() as conn:
        if sub_requirement_id:
            rows = conn.execute(
                "SELECT * FROM score_history WHERE sub_requirement_id = ? ORDER BY recorded_at",
                (sub_requirement_id,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM score_history ORDER BY recorded_at").fetchall()
        return [dict(r) for r in rows]


def get_latest_assessment_per_subreq():
    """Latest assessment row (any evidence) for every sub-requirement that has one."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT sra.* FROM sub_req_assessment sra
            INNER JOIN (
                SELECT sub_requirement_id, MAX(created_at) AS latest
                FROM sub_req_assessment GROUP BY sub_requirement_id
            ) t ON t.sub_requirement_id = sra.sub_requirement_id AND t.latest = sra.created_at
            """
        ).fetchall()
        return {r["sub_requirement_id"]: dict(r) for r in rows}


# ---------------------------------------------------------------------------
# Risk register
# (insert / update / delete / get_all — see the "REPEATING PATTERN" note
#  in the module docstring above if this is the first CRUD group you're
#  reading)
# ---------------------------------------------------------------------------

def insert_risk(requirement_id, sub_requirement_id, title, description, likelihood, impact,
                 risk_score, risk_level, owner, status, mitigation_plan, due_date, source):
    now = datetime.datetime.utcnow().isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO risk_register
               (requirement_id, sub_requirement_id, title, description, likelihood, impact,
                risk_score, risk_level, owner, status, mitigation_plan, due_date, source,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (requirement_id, sub_requirement_id, title, description, likelihood, impact,
             risk_score, risk_level, owner, status, mitigation_plan, due_date, source, now, now),
        )
        return cur.lastrowid


def update_risk(risk_id, **fields):
    if not fields:
        return
    fields["updated_at"] = datetime.datetime.utcnow().isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    with get_conn() as conn:
        conn.execute(
            f"UPDATE risk_register SET {set_clause} WHERE id = ?",
            (*fields.values(), risk_id),
        )


def delete_risk(risk_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM risk_register WHERE id = ?", (risk_id,))


def get_all_risks():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM risk_register ORDER BY risk_score DESC, created_at DESC").fetchall()
        return [dict(r) for r in rows]


def get_auto_risk_for_subreq(sub_requirement_id):
    """Existing auto-generated (source='auto-gap') risk for a sub-requirement, if any."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM risk_register WHERE sub_requirement_id = ? AND source = 'auto-gap' LIMIT 1",
            (sub_requirement_id,),
        ).fetchone()
        return dict(row) if row else None


def reset_all():
    with get_conn() as conn:
        conn.executescript(
            "DELETE FROM sub_req_assessment; DELETE FROM evidence; "
            "DELETE FROM score_history; DELETE FROM risk_register; "
            "DELETE FROM cde_scope; DELETE FROM compensating_controls; "
            "DELETE FROM testing_tracker; DELETE FROM vendor_register;"
        )


# ---------------------------------------------------------------------------
# App settings (key/value) — used for SAQ type selection, AOC signer info, etc.
# ---------------------------------------------------------------------------

def get_setting(key, default=None):
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key, value):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def get_settings_json(key, default=None):
    raw = get_setting(key)
    if raw is None:
        return default
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return default


def set_settings_json(key, value):
    set_setting(key, json.dumps(value))


# ---------------------------------------------------------------------------
# CDE scope (one row per system inside/connected to the Cardholder Data
# Environment — pure record-keeping, same insert/update/delete/get_all
# CRUD pattern as "Risk register" above)
# ---------------------------------------------------------------------------

def insert_cde_system(system_name, component_type, description, in_scope, connected_to_cde,
                       data_flow_notes, owner):
    now = datetime.datetime.utcnow().isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO cde_scope
               (system_name, component_type, description, in_scope, connected_to_cde,
                data_flow_notes, owner, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (system_name, component_type, description, int(in_scope), int(connected_to_cde),
             data_flow_notes, owner, now, now),
        )
        return cur.lastrowid


def update_cde_system(item_id, **fields):
    if not fields:
        return
    fields["updated_at"] = datetime.datetime.utcnow().isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    with get_conn() as conn:
        conn.execute(f"UPDATE cde_scope SET {set_clause} WHERE id = ?", (*fields.values(), item_id))


def delete_cde_system(item_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM cde_scope WHERE id = ?", (item_id,))


def get_all_cde_systems():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM cde_scope ORDER BY in_scope DESC, system_name").fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Compensating controls (same CRUD pattern as above, different table)
# ---------------------------------------------------------------------------

def insert_compensating_control(sub_requirement_id, original_requirement_text, constraint_reason,
                                 objective_met, compensating_control_description, additional_risk,
                                 validation_evidence, reviewed_by, review_date, next_review_date,
                                 status):
    now = datetime.datetime.utcnow().isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO compensating_controls
               (sub_requirement_id, original_requirement_text, constraint_reason, objective_met,
                compensating_control_description, additional_risk, validation_evidence,
                reviewed_by, review_date, next_review_date, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (sub_requirement_id, original_requirement_text, constraint_reason, objective_met,
             compensating_control_description, additional_risk, validation_evidence, reviewed_by,
             review_date, next_review_date, status, now, now),
        )
        return cur.lastrowid


def update_compensating_control(item_id, **fields):
    if not fields:
        return
    fields["updated_at"] = datetime.datetime.utcnow().isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    with get_conn() as conn:
        conn.execute(f"UPDATE compensating_controls SET {set_clause} WHERE id = ?",
                     (*fields.values(), item_id))


def delete_compensating_control(item_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM compensating_controls WHERE id = ?", (item_id,))


def get_all_compensating_controls():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM compensating_controls ORDER BY sub_requirement_id"
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Recurring testing tracker (Requirement 11: ASV scans, pen tests, segmentation
# tests, ...) — same CRUD pattern as above, different table
# ---------------------------------------------------------------------------

def insert_test_item(test_type, related_requirement, scope_description, frequency,
                      last_performed_date, next_due_date, result_summary, result_status,
                      evidence_id, owner):
    now = datetime.datetime.utcnow().isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO testing_tracker
               (test_type, related_requirement, scope_description, frequency, last_performed_date,
                next_due_date, result_summary, result_status, evidence_id, owner, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (test_type, related_requirement, scope_description, frequency, last_performed_date,
             next_due_date, result_summary, result_status, evidence_id, owner, now, now),
        )
        return cur.lastrowid


def update_test_item(item_id, **fields):
    if not fields:
        return
    fields["updated_at"] = datetime.datetime.utcnow().isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    with get_conn() as conn:
        conn.execute(f"UPDATE testing_tracker SET {set_clause} WHERE id = ?",
                     (*fields.values(), item_id))


def delete_test_item(item_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM testing_tracker WHERE id = ?", (item_id,))


def get_all_test_items():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM testing_tracker ORDER BY next_due_date").fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Vendor / TPSP (third-party service provider) register — same CRUD pattern
# as above, different table
# ---------------------------------------------------------------------------

def insert_vendor(vendor_name, service_provided, pci_dss_responsibility, cde_connection,
                   compliance_status, attestation_type, attestation_expiry, last_reviewed_date,
                   next_review_due, contract_reference, notes):
    now = datetime.datetime.utcnow().isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO vendor_register
               (vendor_name, service_provided, pci_dss_responsibility, cde_connection,
                compliance_status, attestation_type, attestation_expiry, last_reviewed_date,
                next_review_due, contract_reference, notes, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (vendor_name, service_provided, pci_dss_responsibility, cde_connection,
             compliance_status, attestation_type, attestation_expiry, last_reviewed_date,
             next_review_due, contract_reference, notes, now, now),
        )
        return cur.lastrowid


def update_vendor(item_id, **fields):
    if not fields:
        return
    fields["updated_at"] = datetime.datetime.utcnow().isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    with get_conn() as conn:
        conn.execute(f"UPDATE vendor_register SET {set_clause} WHERE id = ?",
                     (*fields.values(), item_id))


def delete_vendor(item_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM vendor_register WHERE id = ?", (item_id,))


def get_all_vendors():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM vendor_register ORDER BY vendor_name").fetchall()
        return [dict(r) for r in rows]
