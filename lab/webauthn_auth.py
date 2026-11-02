"""
WebAuthn ("passkey") login on top of the existing password login in
gateway.py. Uses discoverable credentials (resident keys), which is what
makes the browser offer a full passwordless picker on login — including
"use a different device", which shows a QR code you scan with your phone
to sign in via Bluetooth proximity (the standard WebAuthn hybrid
transport). None of that QR/cross-device behavior is custom code here —
it's built into the browser once registration asks for a resident key.

Design:
  - Credentials are stored per-account and per-profile (this module is imported
    separately by each gateway process, baseline and hardened), in the
    same /data volume already used by access_log.py, so a registered
    passkey survives container restarts.
  - The in-progress challenge is referenced by the signed Flask session
    and recorded server-side with its purpose, owner and two-minute expiry.
    Verification consumes the server record once, preventing cookie replay
    from reusing a completed ceremony.
  - sign_count is updated on every successful login and checked against
    the authenticator's reported count — the standard WebAuthn
    clone-detection mechanism: a cloned authenticator's counter will
    eventually fall out of sync with the real one's.
"""
import os
import sqlite3
import time

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

DB_PATH = os.environ.get("WEBAUTHN_DB_PATH", "/data/webauthn.db")
RP_ID = os.environ.get("WEBAUTHN_RP_ID", "localhost")
RP_NAME = "MQTT Security Lab"
ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "https://localhost:8443")


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('BEGIN IMMEDIATE')
    conn.execute(
        "CREATE TABLE IF NOT EXISTS credentials ("
        "  credential_id TEXT PRIMARY KEY,"
        "  public_key TEXT NOT NULL,"
        "  sign_count INTEGER NOT NULL"
        ")"
    )
    columns = {r[1] for r in conn.execute('PRAGMA table_info(credentials)')}
    if 'username' not in columns:
        # Before multi-account support every passkey belonged to the sole admin.
        conn.execute("ALTER TABLE credentials ADD COLUMN username TEXT NOT NULL DEFAULT 'admin'")
    if 'user_handle' not in columns:
        conn.execute('ALTER TABLE credentials ADD COLUMN user_handle TEXT')
    conn.execute('CREATE TABLE IF NOT EXISTS challenges (challenge TEXT PRIMARY KEY, purpose TEXT NOT NULL, username TEXT, expires REAL NOT NULL)')
    conn.commit()
    return conn

def save_challenge(challenge, purpose, username=None):
    conn = _connect()
    try:
        conn.execute('DELETE FROM challenges WHERE expires < ?', (time.time(),))
        conn.execute('INSERT INTO challenges VALUES (?, ?, ?, ?)', (challenge, purpose, username, time.time()+120))
        conn.execute('DELETE FROM challenges WHERE challenge NOT IN (SELECT challenge FROM challenges ORDER BY expires DESC LIMIT 500)')
        conn.commit()
    finally:
        conn.close()

def consume_challenge(challenge, purpose, username=None):
    conn = _connect()
    try:
        result = conn.execute('DELETE FROM challenges WHERE challenge=? AND purpose=? AND username IS ? AND expires>=?',
                              (challenge, purpose, username, time.time()))
        conn.commit()
        return result.rowcount == 1
    finally:
        conn.close()


def has_credential() -> bool:
    conn = _connect()
    try:
        return conn.execute("SELECT 1 FROM credentials LIMIT 1").fetchone() is not None
    finally:
        conn.close()


def _all_credentials():
    conn = _connect()
    try:
        return conn.execute("SELECT credential_id, public_key, sign_count FROM credentials").fetchall()
    finally:
        conn.close()


def build_registration_options(username: str):
    existing = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred_id))
        for cred_id, _, _ in _all_credentials()
    ]
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_name=username,
        user_id=username.encode(),
        user_display_name=username,
        exclude_credentials=existing,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    return options, bytes_to_base64url(options.challenge)


def verify_registration(credential_json: dict, expected_challenge_b64: str, username: str) -> None:
    verification = verify_registration_response(
        credential=credential_json,
        expected_challenge=base64url_to_bytes(expected_challenge_b64),
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        require_user_verification=True,
    )
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO credentials (credential_id, public_key, sign_count, username, user_handle) VALUES (?, ?, ?, ?, ?)",
            (
                bytes_to_base64url(verification.credential_id),
                bytes_to_base64url(verification.credential_public_key),
                verification.sign_count,
                username,
                bytes_to_base64url(username.encode()),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def build_authentication_options():
    # No allow_credentials passed: this is what lets the browser show a
    # passwordless "choose your passkey" picker instead of requiring a
    # username be typed first.
    options = generate_authentication_options(
        rp_id=RP_ID,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options, bytes_to_base64url(options.challenge)


def verify_authentication(credential_json: dict, expected_challenge_b64: str):
    cred_id_b64 = credential_json.get("id")
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT credential_id, public_key, sign_count, username, user_handle FROM credentials WHERE credential_id = ?",
            (cred_id_b64,),
        ).fetchone()
        if row is None:
            return False
        _, public_key_b64, sign_count, username, user_handle = row
        if user_handle and credential_json.get('response', {}).get('userHandle') != user_handle:
            return None
        try:
            verification = verify_authentication_response(
                credential=credential_json,
                expected_challenge=base64url_to_bytes(expected_challenge_b64),
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
                credential_public_key=base64url_to_bytes(public_key_b64),
                credential_current_sign_count=sign_count,
                require_user_verification=True,
            )
        except Exception:
            return False
        updated = conn.execute(
            "UPDATE credentials SET sign_count = ? WHERE credential_id = ? AND sign_count = ?",
            (verification.new_sign_count, cred_id_b64, sign_count),
        )
        if updated.rowcount != 1:
            conn.rollback()
            return None
        conn.commit()
        return username
    finally:
        conn.close()
