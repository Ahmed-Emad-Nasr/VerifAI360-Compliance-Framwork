"""Tests for src/database.py — schema, encryption-at-rest, and settings helpers."""


def test_init_db_creates_tables(isolated_env):
    from src import database as db
    with db.get_conn() as conn:
        tables = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    expected = {"evidence", "sub_req_assessment", "score_history", "risk_register",
                "app_settings", "cde_scope", "compensating_controls", "testing_tracker",
                "vendor_register"}
    assert expected.issubset(tables)


def test_insert_evidence_encrypts_text_by_default(isolated_env):
    from src import database as db
    eid = db.insert_evidence("policy.txt", "/tmp/fake", "text/log/config", "1.1",
                              "sensitive evidence text", sha256="abc123")
    with db.get_conn() as conn:
        row = conn.execute("SELECT raw_text_excerpt, text_encrypted FROM evidence WHERE id=?",
                            (eid,)).fetchone()
    assert row["text_encrypted"] == 1
    assert "sensitive evidence text" not in row["raw_text_excerpt"]  # ciphertext, not plaintext
    assert db.get_evidence_text(eid) == "sensitive evidence text"  # decrypts correctly


def test_insert_evidence_can_skip_encryption(isolated_env):
    from src import database as db
    eid = db.insert_evidence("policy.txt", "/tmp/fake", "text/log/config", "1.1",
                              "plain text", sha256="def456", encrypt=False)
    assert db.get_evidence_text(eid) == "plain text"


def test_find_evidence_by_hash(isolated_env):
    from src import database as db
    eid = db.insert_evidence("a.txt", "/tmp/a", "text/log/config", None, "x", sha256="hash1")
    found = db.find_evidence_by_hash("hash1")
    assert found is not None
    assert found["id"] == eid
    assert db.find_evidence_by_hash("nonexistent") is None


def test_insert_assessment_tracks_analysis_source(isolated_env):
    from src import database as db
    eid = db.insert_evidence("a.txt", "/tmp/a", "text/log/config", None, "x", sha256="h2")
    db.insert_assessment(eid, "1.1", True, 80, "Managed", "reason", ["gap"], ["rec"],
                          analysis_source="local")
    rows = db.get_assessments_for_subreq("1.1")
    assert any(r["analysis_source"] == "local" for r in rows)


def test_settings_json_roundtrip(isolated_env):
    from src import database as db
    db.set_settings_json("local_engine_weights", {"keyword": 0.9})
    assert db.get_settings_json("local_engine_weights") == {"keyword": 0.9}
    assert db.get_settings_json("nonexistent_key", default={"x": 1}) == {"x": 1}


def test_migration_backfills_analysis_source_and_text_encrypted(isolated_env, tmp_path):
    """Simulates an old-schema DB (predating both columns) and confirms
    init_db() adds them without destroying existing rows."""
    import sqlite3
    from src import database as db

    old_db_path = str(tmp_path / "old.db")
    conn = sqlite3.connect(old_db_path)
    conn.execute("""
        CREATE TABLE evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, stored_path TEXT,
            evidence_type TEXT, uploaded_at TEXT, target_sub_requirement TEXT,
            raw_text_excerpt TEXT, sha256 TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE sub_req_assessment (
            id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id INTEGER, sub_requirement_id TEXT,
            is_primary_target INTEGER, sufficiency_score INTEGER, maturity_level TEXT,
            rationale TEXT, gaps TEXT, recommendations TEXT, created_at TEXT
        )
    """)
    conn.execute("INSERT INTO evidence (filename, stored_path, uploaded_at) VALUES (?, ?, ?)",
                 ("old.txt", "/tmp/old", "2025-01-01"))
    conn.commit()
    conn.close()

    db.DB_PATH = old_db_path
    db.init_db()

    with db.get_conn() as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(evidence)").fetchall()}
        assess_cols = {r["name"] for r in conn.execute("PRAGMA table_info(sub_req_assessment)").fetchall()}
        row = conn.execute("SELECT * FROM evidence WHERE filename='old.txt'").fetchone()

    assert "text_encrypted" in cols
    assert "analysis_source" in assess_cols
    assert row is not None  # old row survived the migration
    assert row["text_encrypted"] == 0  # correctly flagged as pre-encryption, plain data
