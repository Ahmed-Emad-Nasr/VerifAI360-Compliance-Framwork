"""
data_portability.py
---------------------
Full-state export/import as a single JSON file — for backing up an
assessment, or moving it to another machine.

WHAT'S INCLUDED: every row from every database table (evidence metadata,
assessments, score history, risks, CDE scope, compensating controls,
testing tracker, vendor register, app settings).

WHAT'S DELIBERATELY NOT INCLUDED: the actual evidence FILES in
evidence_store/ (screenshots, PDFs, etc.) — those can be large binary
files, and mixing binary blobs into a JSON backup makes it unwieldy. The
JSON keeps each evidence row's `stored_path`, `sha256`, and (if
encryption is on) its encrypted text excerpt — enough to prove what was
submitted and re-attach the real files by copying evidence_store/
alongside this JSON if you need a complete backup.

WHAT AN IMPORT DOES: replaces (does not merge) everything currently in
the database with what's in the file — this is a restore, not a merge.
Encrypted text fields are copied through as-is (still encrypted); they'll
only decrypt correctly on a machine that has the SAME ENCRYPTION_KEY in
its .env that produced them. That's intentional — it's the same
trade-off as restoring any encrypted backup.
"""

import json
import datetime

from . import database as db

EXPORT_FORMAT_VERSION = 1

_TABLES = [
    "evidence", "sub_req_assessment", "score_history", "risk_register",
    "app_settings", "cde_scope", "compensating_controls", "testing_tracker",
    "vendor_register",
]


def export_all_data() -> dict:
    with db.get_conn() as conn:
        payload = {
            "format_version": EXPORT_FORMAT_VERSION,
            "exported_at": datetime.datetime.utcnow().isoformat(),
            "tables": {},
        }
        for table in _TABLES:
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()
            payload["tables"][table] = [dict(r) for r in rows]
        return payload


def export_all_data_json(indent=2) -> str:
    return json.dumps(export_all_data(), indent=indent, ensure_ascii=False)


class ImportError_(Exception):
    pass


def import_all_data(payload: dict) -> dict:
    """Wipes current data and restores every table from `payload` (as produced
    by export_all_data()). Returns a summary dict of how many rows were
    restored per table. Raises ImportError_ on a malformed/unrecognized file
    rather than partially importing garbage."""
    if not isinstance(payload, dict) or "tables" not in payload:
        raise ImportError_("This doesn't look like a VerifAI 360 export file (missing 'tables' key).")

    if payload.get("format_version") != EXPORT_FORMAT_VERSION:
        raise ImportError_(
            f"Unsupported export format version {payload.get('format_version')!r} "
            f"(this app writes/reads version {EXPORT_FORMAT_VERSION})."
        )

    tables = payload["tables"]
    unknown = set(tables) - set(_TABLES)
    if unknown:
        raise ImportError_(f"Export file references unknown table(s): {sorted(unknown)}")

    summary = {}
    with db.get_conn() as conn:
        conn.execute("PRAGMA foreign_keys = OFF")  # allow deleting/reinserting out of FK order
        # Delete in FK-safe order (children before parents), then reinsert
        # in the reverse (parents before children).
        delete_order = [
            "sub_req_assessment", "score_history", "testing_tracker", "evidence",
            "risk_register", "cde_scope", "compensating_controls", "vendor_register",
            "app_settings",
        ]
        for table in delete_order:
            conn.execute(f"DELETE FROM {table}")

        insert_order = [
            "evidence", "sub_req_assessment", "score_history", "risk_register",
            "cde_scope", "compensating_controls", "testing_tracker", "vendor_register",
            "app_settings",
        ]
        for table in insert_order:
            rows = tables.get(table, [])
            summary[table] = len(rows)
            for row in rows:
                if not row:
                    continue
                cols = list(row.keys())
                placeholders = ", ".join("?" for _ in cols)
                col_list = ", ".join(cols)
                conn.execute(
                    f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})",
                    [row[c] for c in cols],
                )
        conn.execute("PRAGMA foreign_keys = ON")

    return summary
