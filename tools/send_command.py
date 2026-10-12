"""
send_command.py - operator tool for the HARDENED lock (runs on the host).

Signs a LOCK / UNLOCK command as the authenticated `dashboard` operator and
sends it to the hardened broker over TLS. This is how the signed-command path
is exercised, and the basis for the Phase-2 replay re-run.

Usage (from the repo root, with the hardened stack up):
    python tools/send_command.py LOCK
    python tools/send_command.py UNLOCK
    python tools/send_command.py UNLOCK --replay   # send the SAME envelope twice

Expected result against the hardened lock:
    first send      -> ACCEPTED  (seq advances)
    --replay copy   -> REJECTED: replayed-seq / replayed-nonce  (Freshness)

Self-contained: needs only `paho-mqtt` (the attacks/venv already has it).
Connects to localhost:8883 and trusts broker/certs/ca.crt.
"""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import time

import paho.mqtt.client as mqtt

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CA_CERT = os.path.join(REPO, "broker", "certs", "ca.crt")
OPERATOR_KEY_FILE = os.path.join(REPO, "secrets", "dashboard.hmac.key")
CMD_TOPIC = "home/frontdoor/lock/cmd"
OPERATOR_ID = "dashboard"

USERNAME = os.environ.get("MQTT_USERNAME", "dashboard")
PASSWORD = os.environ.get("MQTT_PASSWORD", "dashboard-pass-2026")
HOST = os.environ.get("MQTT_HOST", "localhost")
PORT = int(os.environ.get("MQTT_PORT", "8883"))

_seq = int(time.time())   # start high so fresh runs always out-rank old state


def canonical_msg(device, seq, ts, nonce, data):
    body = {"device": device, "seq": seq, "ts": ts, "nonce": nonce, "data": data}
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def build_envelope(key, cmd):
    global _seq
    _seq += 1
    msg = canonical_msg(OPERATOR_ID, _seq, time.time(), secrets.token_hex(16), {"cmd": cmd})
    sig = hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()
    return json.dumps({"msg": msg, "sig": sig})


def main():
    ap = argparse.ArgumentParser(description="Send a signed lock command.")
    ap.add_argument("cmd", choices=["LOCK", "UNLOCK"])
    ap.add_argument("--replay", action="store_true",
                    help="send the identical signed envelope twice (replay test)")
    args = ap.parse_args()

    with open(OPERATOR_KEY_FILE, encoding="utf-8") as fh:
        key = fh.read().strip().encode("utf-8")

    envelope = build_envelope(key, args.cmd)

    client = mqtt.Client(client_id="operator-cli")
    client.username_pw_set(USERNAME, PASSWORD)
    client.tls_set(ca_certs=CA_CERT)
    client.connect(HOST, PORT, 60)
    client.loop_start()

    client.publish(CMD_TOPIC, envelope, qos=1).wait_for_publish()
    print(f"[operator] sent {args.cmd}")
    if args.replay:
        time.sleep(0.5)
        client.publish(CMD_TOPIC, envelope, qos=1).wait_for_publish()
        print(f"[operator] re-sent identical {args.cmd} envelope (replay)")

    time.sleep(0.5)
    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as exc:
        sys.exit(f"missing file: {exc}  (did you generate certs/keys?)")
