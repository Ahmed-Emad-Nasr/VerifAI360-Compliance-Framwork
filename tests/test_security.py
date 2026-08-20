"""Tests for src/security.py — passcode gate and Fernet encryption at rest."""


def test_passcode_auto_generated_and_persisted(isolated_env):
    from src import security as sec
    pc = sec.get_or_create_passcode()
    assert len(pc) > 8
    with open(isolated_env["env_path"]) as f:
        content = f.read()
    assert "APP_PASSCODE" in content


def test_check_passcode_correct_and_incorrect(isolated_env):
    from src import security as sec
    pc = sec.get_or_create_passcode()
    assert sec.check_passcode(pc) is True
    assert sec.check_passcode("definitely-wrong") is False


def test_encryption_key_auto_generated(isolated_env):
    from src import security as sec
    key = sec.get_or_create_encryption_key()
    assert len(key) > 20


def test_text_encrypt_decrypt_roundtrip(isolated_env):
    from src import security as sec
    original = "sensitive PCI DSS evidence content"
    token = sec.encrypt_text(original)
    assert original not in token  # ciphertext doesn't leak plaintext
    assert sec.decrypt_text(token) == original


def test_empty_text_roundtrip(isolated_env):
    from src import security as sec
    assert sec.encrypt_text("") == ""
    assert sec.decrypt_text("") == ""


def test_file_encrypt_decrypt_roundtrip(isolated_env, tmp_path):
    from src import security as sec
    p = tmp_path / "evidence.txt"
    p.write_text("firewall policy roles and responsibilities")
    sec.encrypt_file_in_place(str(p))
    encrypted_bytes = p.read_bytes()
    assert b"firewall" not in encrypted_bytes

    dest = tmp_path / "decrypted.txt"
    sec.decrypt_file_to(str(p), str(dest))
    assert dest.read_text() == "firewall policy roles and responsibilities"


def test_decrypt_with_wrong_key_fails_cleanly(isolated_env, tmp_path):
    from src import security as sec
    from cryptography.fernet import Fernet

    p = tmp_path / "evidence.txt"
    p.write_text("secret content")
    sec.encrypt_file_in_place(str(p))

    # Swap in a different key, simulating a mismatched/rotated ENCRYPTION_KEY
    sec._fernet_instance = Fernet(Fernet.generate_key())
    dest = tmp_path / "out.txt"
    try:
        sec.decrypt_file_to(str(p), str(dest))
        assert False, "should have raised DecryptionError"
    except sec.DecryptionError:
        pass
