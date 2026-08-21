"""
security.py
------------
Two independent, previously-missing security controls for VerifAI 360:

1. APP-LEVEL PASSCODE GATE
   Before this module, anyone who could reach the Streamlit port saw every
   page with no login at all. This adds a single shared passcode (not a
   full multi-user/role system — that's a bigger project) that must be
   entered once per browser session before any page renders.

   The passcode is read from APP_PASSCODE in .env. If it's not set, one is
   auto-generated on first run and written to .env for you, and printed to
   the terminal log so you can find it. Nothing is silently insecure by
   default — if you never configured a passcode, one still exists and is
   required.

2. ENCRYPTION AT REST FOR EVIDENCE
   Evidence content is the most sensitive thing this app stores. Two
   things are now encrypted with Fernet (AES-128-CBC + HMAC, from the
   `cryptography` library) using a key in .env (ENCRYPTION_KEY, also
   auto-generated on first run if missing):
     - the evidence FILE itself, as stored in evidence_store/ (encrypted
       in place right after upload; decrypted to a throwaway temp file
       only for the few seconds text-extraction needs, then that temp
       file is deleted)
     - the extracted TEXT EXCERPT stored in the database
     (rationale/gaps/recommendations are assessment *output*, not the
     underlying evidence, and are left as plain text so the app's own
     pages can query/filter/sort them cheaply)

   HONEST SCOPE NOTE: this encrypts the sensitive *content* at rest, not
   the whole SQLite file byte-for-byte — filenames, scores, dates, and
   sub-requirement IDs remain in plain SQLite columns because the app
   needs to query/sort/aggregate on them constantly, and full-database
   encryption would require SQLCipher (a separate compiled SQLite build,
   not installable via plain pip here). If someone gets a copy of
   verifai360.db, they see *metadata* (what was uploaded, when, scored
   how) but not the evidence content itself or its extracted text without
   also having ENCRYPTION_KEY from .env.

   KEEP .env OUT OF VERSION CONTROL AND BACKUPS SEPARATE FROM THE DB —
   losing ENCRYPTION_KEY means the encrypted evidence is unrecoverable by
   design (that's what encryption means); losing APP_PASSCODE just means
   generating a new one.
"""

import os
import secrets
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from dotenv import set_key, load_dotenv

_ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")

_fernet_instance = None


class DecryptionError(Exception):
    pass


def _ensure_env_value(key: str, generator) -> str:
    """Return os.environ[key], auto-generating + persisting to .env if missing."""
    load_dotenv(_ENV_PATH, override=False)
    value = os.environ.get(key)
    if value:
        return value
    value = generator()
    os.environ[key] = value
    try:
        if not os.path.exists(_ENV_PATH):
            open(_ENV_PATH, "a").close()
        set_key(_ENV_PATH, key, value)
    except OSError:
        # Best effort — if .env can't be written (read-only mount, etc.) the
        # value still works for this process, it just won't survive restart.
        pass
    return value


def get_or_create_passcode() -> str:
    return _ensure_env_value("APP_PASSCODE", lambda: secrets.token_urlsafe(9))


def get_or_create_encryption_key() -> str:
    return _ensure_env_value("ENCRYPTION_KEY", lambda: Fernet.generate_key().decode())


# ---------------------------------------------------------------------------
# Passcode brute-force throttling
#
# Without this, someone who can reach the app's HTTP endpoint (not just the
# Streamlit UI — a script hitting the same requests) could try passcodes as
# fast as the network allows. This adds a simple in-memory failed-attempt
# counter per (rough) client identity with an increasing lockout, so a script
# gets slowed to a crawl instead of being able to brute-force a ~12-character
# token_urlsafe passcode at network speed.
#
# HONEST SCOPE NOTE: this is in-process memory, not persisted or shared
# across multiple server workers/replicas — good enough for the single-
# process localhost/small-deployment use case this app targets, not a
# substitute for a real auth service behind a proper reverse proxy /
# WAF-level rate limiter in a larger multi-instance deployment.
# ---------------------------------------------------------------------------
_failed_attempts = {}  # client_key -> (count, locked_until_timestamp)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 30  # doubles per additional failure past the threshold, capped below
MAX_LOCKOUT_SECONDS = 300


def check_lockout(client_key: str):
    """Returns (locked: bool, seconds_remaining: float) for this client_key."""
    import time as _time
    count, locked_until = _failed_attempts.get(client_key, (0, 0))
    remaining = locked_until - _time.time()
    if remaining > 0:
        return True, remaining
    return False, 0.0


def record_failed_attempt(client_key: str):
    import time as _time
    count, _ = _failed_attempts.get(client_key, (0, 0))
    count += 1
    if count >= MAX_FAILED_ATTEMPTS:
        lockout = min(LOCKOUT_SECONDS * (2 ** (count - MAX_FAILED_ATTEMPTS)), MAX_LOCKOUT_SECONDS)
        _failed_attempts[client_key] = (count, _time.time() + lockout)
    else:
        _failed_attempts[client_key] = (count, 0)


def record_successful_attempt(client_key: str):
    _failed_attempts.pop(client_key, None)


def _fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is None:
        key = get_or_create_encryption_key()
        _fernet_instance = Fernet(key.encode())
    return _fernet_instance


def check_passcode(entered: str) -> bool:
    expected = get_or_create_passcode()
    # Constant-time comparison to avoid trivial timing side-channels.
    return secrets.compare_digest(
        hashlib.sha256(entered.encode()).digest(),
        hashlib.sha256(expected.encode()).digest(),
    )


def encrypt_bytes(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt_bytes(token: bytes) -> bytes:
    try:
        return _fernet().decrypt(token)
    except InvalidToken as e:
        raise DecryptionError(
            "Could not decrypt this evidence — ENCRYPTION_KEY in .env doesn't match the key "
            "this file was encrypted with (wrong/rotated key, or corrupted data)."
        ) from e


def encrypt_text(text: str) -> str:
    if not text:
        return ""
    return encrypt_bytes(text.encode("utf-8")).decode("ascii")


def decrypt_text(token: str) -> str:
    if not token:
        return ""
    return decrypt_bytes(token.encode("ascii")).decode("utf-8")


def encrypt_file_in_place(filepath: str) -> None:
    with open(filepath, "rb") as f:
        plaintext = f.read()
    with open(filepath, "wb") as f:
        f.write(encrypt_bytes(plaintext))


def decrypt_file_to(src_encrypted_path: str, dest_plain_path: str) -> None:
    with open(src_encrypted_path, "rb") as f:
        ciphertext = f.read()
    plaintext = decrypt_bytes(ciphertext)
    with open(dest_plain_path, "wb") as f:
        f.write(plaintext)
