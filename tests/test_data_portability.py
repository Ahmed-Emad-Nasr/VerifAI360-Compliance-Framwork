"""Tests for src/data_portability.py — full-state export/import."""

import pytest


def test_export_includes_all_tables(isolated_env):
    from src import data_portability as dp
    payload = dp.export_all_data()
    expected = {"evidence", "sub_req_assessment", "score_history", "risk_register",
                "app_settings", "cde_scope", "compensating_controls", "testing_tracker",
                "vendor_register"}
    assert set(payload["tables"].keys()) == expected


def test_export_import_roundtrip_preserves_data(isolated_env):
    from src import database as db
    from src import data_portability as dp

    eid = db.insert_evidence("policy.txt", "/tmp/x", "text/log/config", "1.1",
                              "sensitive text", sha256="hash1")
    db.insert_assessment(eid, "1.1", True, 85, "Managed", "reason", ["gap1"], ["rec1"],
                          analysis_source="local")

    payload = dp.export_all_data()
    summary = dp.import_all_data(payload)

    assert summary["evidence"] == 1
    assert summary["sub_req_assessment"] == 1
    # decrypted text still round-trips correctly after export -> wipe -> import
    assert db.get_evidence_text(eid) == "sensitive text"


def test_import_rejects_malformed_payload(isolated_env):
    from src import data_portability as dp
    with pytest.raises(dp.ImportError_):
        dp.import_all_data({"not_tables": []})


def test_import_rejects_wrong_format_version(isolated_env):
    from src import data_portability as dp
    with pytest.raises(dp.ImportError_):
        dp.import_all_data({"format_version": 999, "tables": {}})


def test_import_rejects_unknown_table(isolated_env):
    from src import data_portability as dp
    with pytest.raises(dp.ImportError_):
        dp.import_all_data({
            "format_version": dp.EXPORT_FORMAT_VERSION,
            "tables": {"not_a_real_table": []},
        })


def test_import_is_a_full_replace_not_a_merge(isolated_env):
    from src import database as db
    from src import data_portability as dp

    db.insert_evidence("old.txt", "/tmp/old", "text/log/config", None, "old text", sha256="old_hash")
    payload_before = dp.export_all_data()

    # Wipe and restore an export that has nothing in it — evidence should disappear.
    empty_payload = {"format_version": dp.EXPORT_FORMAT_VERSION, "tables": {t: [] for t in payload_before["tables"]}}
    dp.import_all_data(empty_payload)
    assert db.get_all_evidence() == []
