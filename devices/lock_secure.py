"""
Hardened smart door-lock (Phase 2) - the accountability centerpiece.

Unlike the undefended lock.py, which obeys any plaintext LOCK/UNLOCK string from
anyone, this lock:

  * accepts commands only over TLS from an authenticated client (broker: auth +
    ACL - only `dashboard` may publish to the cmd topic);
  * verifies the command's HMAC signature against the operator key (Integrity);
  * rejects replayed or stale commands via seq + timestamp + nonce (Freshness) -
    this is what stops the Phase-1 replay attack, which auth + TLS alone pass;
  * writes every decision to an append-only audit log (Accountability);
  * publishes its own state as a signed envelope (so subscribers can trust it).
"""
import secure_common as sc

DEVICE_ID = "lock-frontdoor"
STATE_TOPIC = "home/frontdoor/lock/state"
CMD_TOPIC = "home/frontdoor/lock/cmd"
OPERATOR_ID = "dashboard"   # identity authorised to send lock commands

CMD_SCHEMA = {
    "type": "object",
    "properties": {"cmd": {"enum": ["LOCK", "UNLOCK"]}},
    "required": ["cmd"],
    "additionalProperties": False,
}


def main():
    signer = sc.Signer(DEVICE_ID, sc.load_hmac_key())

    # The lock trusts commands signed with the operator's key.
    with open(sc.env("OPERATOR_KEY_FILE", required=True), encoding="utf-8") as fh:
        operator_key = fh.read().strip().encode("utf-8")
    verifier = sc.Verifier({OPERATOR_ID: operator_key}, schema=CMD_SCHEMA)
    audit = sc.AuditLog(sc.env("AUDIT_LOG", "/audit/lock-frontdoor.log"))

    state = {"value": "LOCKED"}

    def on_connect(client, userdata, flags, rc):
        print(f"[lock-secure] connected rc={rc}; subscribing to {CMD_TOPIC}")
        client.subscribe(CMD_TOPIC)
        client.publish(STATE_TOPIC, signer.envelope({"state": "LOCKED"}), retain=True)

    def on_message(client, userdata, msg):
        res = verifier.verify(msg.payload)
        if not res.ok:
            audit.record(event="command_rejected", claimed_device=res.device,
                         seq=res.seq, reason=res.reason, action="none")
            print(f"[lock-secure] REJECTED command: {res.reason} "
                  f"(device={res.device}, seq={res.seq})")
            return

        cmd = res.data["cmd"]
        new_state = "LOCKED" if cmd == "LOCK" else "UNLOCKED"
        state["value"] = new_state
        client.publish(STATE_TOPIC, signer.envelope({"state": new_state}), retain=True)
        audit.record(event="command_accepted", claimed_device=res.device,
                     seq=res.seq, reason="ok", cmd=cmd, action=new_state)
        print(f"[lock-secure] ACCEPTED {cmd} from {res.device} (seq={res.seq}) "
              f"-> state={new_state}")

    client = sc.make_client(DEVICE_ID)
    client.on_connect = on_connect
    client.on_message = on_message
    host, port = sc.broker_endpoint()
    client.connect(host, port, 60)
    client.loop_forever()


if __name__ == "__main__":
    main()
