"""Application controls shared by the simulator, gateway and regression tests."""
import base64
import hashlib
import json
import math
import sqlite3
import time
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

CMD = "home/frontdoor/lock/cmd"
STATE = "home/frontdoor/lock/state"
EVENT = "home/frontdoor/lock/events"
TOPICS = {"sensor": "home/livingroom/temperature", "camera": "home/frontdoor/camera/status", "lock": STATE}
MAX_BYTES = 4096
WINDOW = 30


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sign(private_path, sender_id, mqtt_topic, business_data, **overrides):
    body = {"v": 1, "sender": sender_id, "topic": mqtt_topic, "id": uuid.uuid4().hex,
            "ts": time.time(), "data": business_data, **overrides}
    msg = compact(body)
    key = serialization.load_pem_private_key(Path(private_path).read_bytes(), password=None)
    return compact({"msg": msg, "sig": base64.b64encode(key.sign(msg.encode())).decode()})


def decode(payload):
    if len(payload) > MAX_BYTES:
        raise ValueError("payload-too-large")
    try:
        outer = json.loads(payload)
        if not isinstance(outer, dict) or not isinstance(outer.get("msg"), str):
            raise ValueError()
        body = json.loads(outer["msg"])
        if not isinstance(body, dict):
            raise ValueError()
        return outer, body
    except (ValueError, TypeError, UnicodeError):
        raise ValueError("malformed-envelope") from None


def authenticate(payload, topic, sender, public_path, now=None):
    outer, body = decode(payload)
    if set(body) != {"v", "sender", "topic", "id", "ts", "data"}:
        raise ValueError("envelope-schema")
    if type(body["v"]) is not int or body["v"] != 1 or body["sender"] != sender or body["topic"] != topic:
        raise ValueError("identity-or-topic")
    if not isinstance(body["id"], str) or len(body["id"]) != 32 or any(c not in "0123456789abcdef" for c in body["id"]):
        raise ValueError("invalid-id")
    ts = body["ts"]
    if type(ts) not in (int, float) or not math.isfinite(ts):
        raise ValueError("invalid-timestamp")
    try:
        key = serialization.load_pem_public_key(Path(public_path).read_bytes())
        key.verify(base64.b64decode(outer.get("sig", ""), validate=True), outer["msg"].encode())
    except (InvalidSignature, ValueError, TypeError):
        raise ValueError("bad-signature") from None
    if abs((time.time() if now is None else now) - ts) > WINDOW:
        raise ValueError("stale-timestamp")
    return body


def command_schema(data):
    return isinstance(data, dict) and set(data) == {"cmd"} and data["cmd"] in ("LOCK", "UNLOCK")


class LockPolicy:
    """Persist replay IDs, actuator state and hash-linked decisions in one transaction.

    At most one action per command ID in the freshness window, including restart.
    Logs are tamper-evident only against an independently saved chain head.
    """
    def __init__(self, path, hardened, public_path):
        self.path, self.hardened, self.public_path = str(path), hardened, public_path
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS seen(id TEXT PRIMARY KEY, expires REAL);
                CREATE TABLE IF NOT EXISTS actuator(id INTEGER PRIMARY KEY, state TEXT, actions INTEGER);
                INSERT OR IGNORE INTO actuator VALUES(1, 'LOCKED', 0);
                CREATE TABLE IF NOT EXISTS decisions(n INTEGER PRIMARY KEY, ts REAL, body TEXT, hash TEXT);
            """)

    def connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def state(self):
        with self.connect() as db:
            state, actions = db.execute("SELECT state, actions FROM actuator WHERE id=1").fetchone()
        return {"state": state, "actions": actions}

    def process(self, payload, retained=False, now=None):
        now = time.time() if now is None else now
        body, reason = {}, "accepted"
        try:
            if self.hardened and retained:
                raise ValueError("retained-command")
            body = (authenticate(payload, CMD, "operator", self.public_path, now)
                    if self.hardened else decode(payload)[1])
            if not command_schema(body.get("data")):
                raise ValueError("command-schema")
        except ValueError as exc:
            reason = str(exc)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if self.hardened and reason == "accepted":
                db.execute("DELETE FROM seen WHERE expires < ?", (now,))
                if db.execute("SELECT 1 FROM seen WHERE id=?", (body["id"],)).fetchone():
                    reason = "replay"
                # Persisted limit: at most five accepted commands in two seconds.
                elif db.execute("SELECT count(*) FROM decisions WHERE ts>? AND json_extract(body,'$.accepted')=1", (now - 2,)).fetchone()[0] >= 5:
                    reason = "command-rate"
                else:
                    db.execute("INSERT INTO seen VALUES(?,?)", (body["id"], body["ts"] + WINDOW))
            if reason == "accepted":
                value = "LOCKED" if body["data"]["cmd"] == "LOCK" else "UNLOCKED"
                db.execute("UPDATE actuator SET state=?, actions=actions+1 WHERE id=1", (value,))
            state, actions = db.execute("SELECT state,actions FROM actuator WHERE id=1").fetchone()
            last = db.execute("SELECT n,hash FROM decisions ORDER BY n DESC LIMIT 1").fetchone()
            event = {"n": last[0]+1 if last else 1, "ts": now, "accepted": reason == "accepted",
                     "reason": reason, "command_id": body.get("id") if isinstance(body.get("id"), str) else None,
                     "payload_sha256": hashlib.sha256(payload.encode() if isinstance(payload, str) else payload).hexdigest(),
                     "state": state, "actions": actions, "previous": last[1] if last else "0" * 64}
            encoded = compact(event)
            digest = hashlib.sha256(encoded.encode()).hexdigest()
            db.execute("INSERT INTO decisions VALUES(?,?,?,?)", (event["n"], now, encoded, digest))
        return {**event, "hash": digest}

