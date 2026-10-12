"""
secure_common.py - shared application-layer security for the HARDENED devices.

Phase-2 controls implemented here (above what the broker enforces):

  Control 3  Integrity    - every payload is a JSON envelope carrying an
                            HMAC-SHA256 signature over its canonical form, plus
                            JSON-schema validation of the `data` field.
  Control 4  Freshness    - monotonic sequence number + timestamp window +
                            nonce cache reject replayed / stale messages, even
                            when the replay is otherwise perfectly valid and
                            authenticated (the gap TLS + auth leave open).
  Control 5  Accountability - receivers write an append-only JSON-lines audit
                            log recording who sent what, and whether the
                            signature / freshness / schema checks passed.

Transport security (Control 2, TLS) and identity (Control 1, username+ACL) are
configured here too when building the MQTT client, but enforced by the broker.

Stdlib only except `jsonschema`. Compatible with paho-mqtt 1.6.x.
"""
import hashlib
import hmac
import json
import os
import secrets
import time

import paho.mqtt.client as mqtt
from jsonschema import Draft7Validator, ValidationError

# --- Tunables ---------------------------------------------------------------
MAX_CLOCK_SKEW_S = 30.0   # messages older/newer than this are treated as stale
NONCE_CACHE_SIZE = 4096   # remembered nonces per sender (replay window)


# ---------------------------------------------------------------------------
#  Configuration from the environment (injected via docker-compose)
# ---------------------------------------------------------------------------
def env(name, default=None, required=False):
    val = os.environ.get(name, default)
    if required and (val is None or val == ""):
        raise RuntimeError(f"required env var {name} is not set")
    return val


def load_hmac_key():
    """Read the per-device HMAC key, mounted read-only from ./secrets."""
    key_file = env("HMAC_KEY_FILE", required=True)
    with open(key_file, "r", encoding="utf-8") as fh:
        key = fh.read().strip()
    if not key:
        raise RuntimeError(f"HMAC key file {key_file} is empty")
    return key.encode("utf-8")


# ---------------------------------------------------------------------------
#  Signing / envelope
# ---------------------------------------------------------------------------
def canonical_msg(device, seq, ts, nonce, data):
    """
    Deterministic JSON string for the signed body. This exact string is what
    gets transmitted (as envelope["msg"]) AND what both sides HMAC over, so
    there is no cross-language re-serialization hazard (e.g. Python "25.0" vs
    JavaScript "25" for a whole-number float): the verifier hashes the bytes it
    received, never a re-encoding of the parsed object.
    """
    body = {"device": device, "seq": seq, "ts": ts, "nonce": nonce, "data": data}
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _sign_msg(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()


class Signer:
    """Produces signed, sequence-numbered envelopes for one publishing device."""

    def __init__(self, device_id, key):
        self.device_id = device_id
        self.key = key
        self._seq = 0

    def envelope(self, data):
        self._seq += 1
        msg = canonical_msg(self.device_id, self._seq, time.time(),
                            secrets.token_hex(16), data)
        return json.dumps({"msg": msg, "sig": _sign_msg(self.key, msg)})


# ---------------------------------------------------------------------------
#  Verification (integrity + freshness)
# ---------------------------------------------------------------------------
class VerifyResult:
    def __init__(self, ok, reason, device=None, seq=None, data=None):
        self.ok = ok
        self.reason = reason        # "ok" or why it was rejected
        self.device = device
        self.seq = seq
        self.data = data

    def __bool__(self):
        return self.ok


class Verifier:
    """
    Verifies envelopes from one or more senders.

    `keys` maps device-id -> shared HMAC key (bytes). `schema` (optional) is a
    JSON schema the `data` field must satisfy. Keeps per-sender replay state.
    """

    def __init__(self, keys, schema=None):
        self.keys = keys
        self.validator = Draft7Validator(schema) if schema else None
        self._last_seq = {}        # device -> highest seq accepted
        self._nonces = {}          # device -> list of recent nonces (FIFO)

    def verify(self, payload):
        try:
            outer = json.loads(payload)
            msg = outer["msg"]
            sig = outer["sig"]
            env_ = json.loads(msg)
        except (ValueError, TypeError, KeyError):
            return VerifyResult(False, "malformed-json")

        required = ("device", "seq", "ts", "nonce", "data")
        if not all(k in env_ for k in required):
            return VerifyResult(False, "missing-fields")

        device = env_["device"]
        key = self.keys.get(device)
        if key is None:
            return VerifyResult(False, "unknown-device", device=device)

        # --- Integrity: constant-time HMAC over the exact transmitted msg bytes ---
        if not hmac.compare_digest(_sign_msg(key, msg), str(sig)):
            return VerifyResult(False, "bad-signature", device=device, seq=env_.get("seq"))

        # --- Freshness: timestamp window ---
        skew = time.time() - float(env_["ts"])
        if abs(skew) > MAX_CLOCK_SKEW_S:
            return VerifyResult(False, "stale-timestamp", device=device, seq=env_["seq"])

        # --- Freshness: monotonic sequence (rejects straight replay) ---
        seq = int(env_["seq"])
        if seq <= self._last_seq.get(device, 0):
            return VerifyResult(False, "replayed-seq", device=device, seq=seq)

        # --- Freshness: nonce not seen before ---
        seen = self._nonces.setdefault(device, [])
        if env_["nonce"] in seen:
            return VerifyResult(False, "replayed-nonce", device=device, seq=seq)

        # --- Integrity: schema of the business payload ---
        if self.validator is not None:
            try:
                self.validator.validate(env_["data"])
            except ValidationError as exc:
                return VerifyResult(False, f"schema:{exc.message}", device=device, seq=seq)

        # Accept: commit replay state.
        self._last_seq[device] = seq
        seen.append(env_["nonce"])
        if len(seen) > NONCE_CACHE_SIZE:
            del seen[: len(seen) - NONCE_CACHE_SIZE]

        return VerifyResult(True, "ok", device=device, seq=seq, data=env_["data"])


# ---------------------------------------------------------------------------
#  Accountability: append-only audit log (JSON lines)
# ---------------------------------------------------------------------------
class AuditLog:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def record(self, **fields):
        entry = {"audit_ts": time.time(), **fields}
        line = json.dumps(entry, sort_keys=True)
        # Open per-write in append mode: never truncates existing history.
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry


# ---------------------------------------------------------------------------
#  MQTT client wired for the hardened broker (TLS + auth)
# ---------------------------------------------------------------------------
def make_client(client_id):
    """Return a paho client configured for TLS + username/password auth."""
    client = mqtt.Client(client_id=client_id)
    client.username_pw_set(env("MQTT_USERNAME", required=True),
                           env("MQTT_PASSWORD", required=True))
    client.tls_set(ca_certs=env("CA_CERT", "/mosquitto/certs/ca.crt"))
    # Hostname is verified against the cert SANs (broker/localhost/127.0.0.1).
    return client


def broker_endpoint():
    return env("MQTT_HOST", "broker"), int(env("MQTT_PORT", "8883"))
