"""
conftest.py
------------
Shared pytest fixtures. The most important one is `isolated_env`, used by
(almost) every test in this suite: it points database.DB_PATH and
compliance_engine.EVIDENCE_STORE at a fresh temp directory for the
duration of one test, so tests never read or write the real
verifai360.db / evidence_store/ that a person might actually be using.
"""

import pytest


@pytest.fixture
def isolated_env(monkeypatch, tmp_path):
    """Redirects the database and evidence store to a throwaway temp
    directory, and gives the local security module a fresh, temp .env so
    encryption/passcode tests don't touch a real .env file either."""
    from src import database as db
    from src import compliance_engine as ce
    from src import security as sec

    db_path = str(tmp_path / "test.db")
    evidence_store = str(tmp_path / "evidence_store")
    env_path = str(tmp_path / ".env")

    monkeypatch.setattr(db, "DB_PATH", db_path)
    monkeypatch.setattr(ce, "EVIDENCE_STORE", evidence_store)
    monkeypatch.setattr(sec, "_ENV_PATH", env_path)
    sec._fernet_instance = None  # force re-derivation from the new temp key

    db.init_db()
    yield {"db_path": db_path, "evidence_store": evidence_store, "env_path": env_path}

    sec._fernet_instance = None  # don't leak this test's key into the next test


@pytest.fixture
def sample_text_file(tmp_path):
    """A small plaintext evidence file with content that should genuinely
    match PCI DSS sub-requirement 1.1 (network security policy)."""
    p = tmp_path / "network_security_policy.txt"
    p.write_text(
        "Network Security Policy: this document defines our firewall policy and roles and "
        "responsibilities for network security. Policy review date: quarterly. Includes a "
        "current network diagram and data flow diagram for the CDE."
    )
    return str(p)
