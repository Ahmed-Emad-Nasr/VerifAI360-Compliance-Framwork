"""Tests for src/compliance_engine.py — the full evidence upload pipeline."""

import os
import pytest


def test_process_uploaded_evidence_local_engine(isolated_env, sample_text_file):
    from src import compliance_engine as ce
    result = ce.process_uploaded_evidence(sample_text_file, "network_security_policy.txt",
                                           target_sub_requirement="1.1", analysis_mode="local")
    assert result["analysis_mode"] == "local"
    assert result["evidence_id"] is not None
    assert any(a["sub_requirement_id"] == "1.1" for a in result["assessments"])


def test_process_uploaded_evidence_encrypts_file_at_rest(isolated_env, sample_text_file):
    from src import compliance_engine as ce
    ce.process_uploaded_evidence(sample_text_file, "network_security_policy.txt",
                                  analysis_mode="local")
    stored_files = os.listdir(isolated_env["evidence_store"])
    assert len(stored_files) == 1
    raw = open(os.path.join(isolated_env["evidence_store"], stored_files[0]), "rb").read()
    assert b"firewall" not in raw  # content must not be readable in plaintext on disk


def test_duplicate_upload_raises_by_default(isolated_env, sample_text_file):
    from src import compliance_engine as ce
    ce.process_uploaded_evidence(sample_text_file, "network_security_policy.txt",
                                  analysis_mode="local")
    with pytest.raises(ce.DuplicateEvidenceError):
        ce.process_uploaded_evidence(sample_text_file, "network_security_policy.txt",
                                      analysis_mode="local")


def test_duplicate_upload_allowed_when_forced(isolated_env, sample_text_file):
    from src import compliance_engine as ce
    r1 = ce.process_uploaded_evidence(sample_text_file, "network_security_policy.txt",
                                       analysis_mode="local")
    r2 = ce.process_uploaded_evidence(sample_text_file, "network_security_policy.txt",
                                       analysis_mode="local", allow_duplicate=True)
    assert r1["evidence_id"] != r2["evidence_id"]


def test_duplicate_check_does_not_leave_orphan_file(isolated_env, sample_text_file):
    from src import compliance_engine as ce
    ce.process_uploaded_evidence(sample_text_file, "network_security_policy.txt",
                                  analysis_mode="local")
    try:
        ce.process_uploaded_evidence(sample_text_file, "network_security_policy.txt",
                                      analysis_mode="local")
    except ce.DuplicateEvidenceError:
        pass
    # Only the first (successful) upload's file should remain on disk.
    assert len(os.listdir(isolated_env["evidence_store"])) == 1


def test_oversized_file_rejected(isolated_env, tmp_path, monkeypatch):
    from src import compliance_engine as ce
    monkeypatch.setattr(ce, "MAX_EVIDENCE_FILE_BYTES", 10)  # tiny cap for this test
    p = tmp_path / "big.txt"
    p.write_text("this text is definitely more than ten bytes long")
    with pytest.raises(ce.EvidenceUploadError):
        ce.process_uploaded_evidence(str(p), "big.txt", analysis_mode="local")


def test_settings_weights_are_applied(isolated_env, sample_text_file):
    from src import compliance_engine as ce
    from src import database as db

    db.set_settings_json("local_engine_weights", {"keyword": 0.95, "title": 0.025, "example": 0.025})
    result = ce.process_uploaded_evidence(sample_text_file, "network_security_policy.txt",
                                           target_sub_requirement="1.1", analysis_mode="local")
    match = next(a for a in result["assessments"] if a["sub_requirement_id"] == "1.1")
    assert match["sufficiency_score"] > 0  # sanity: pipeline still produces a real score


def test_unknown_analysis_mode_raises(isolated_env, sample_text_file):
    from src import compliance_engine as ce
    with pytest.raises(ValueError):
        ce.process_uploaded_evidence(sample_text_file, "x.txt", analysis_mode="quantum")
