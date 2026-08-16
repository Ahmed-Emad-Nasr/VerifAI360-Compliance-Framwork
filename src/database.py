"""
database.py
------------
Lightweight SQLite persistence layer for VerifAI 360.

Tables
------
evidence            : one row per uploaded evidence file
sub_req_assessment  : one row per (evidence, sub-requirement) AI assessment
                       -> this is what enables "cross-requirement spanning":
                          a single evidence file can create MANY rows here.
score_history        : one row per sub-requirement every time its score is
                       recomputed -> enables the "continuous maturity
                       scoring" trend line in the dashboard.
"""

import sqlite3
import json
import os
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
                raw_text_excerpt TEXT
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
            """
        )


def insert_evidence(filename, stored_path, evidence_type, target_sub_requirement, raw_text_excerpt):
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO evidence
               (filename, stored_path, evidence_type, uploaded_at, target_sub_requirement, raw_text_excerpt)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (filename, stored_path, evidence_type, datetime.datetime.utcnow().isoformat(),
             target_sub_requirement, raw_text_excerpt[:2000] if raw_text_excerpt else ""),
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
            "DELETE FROM score_history; DELETE FROM risk_register;"
        )
