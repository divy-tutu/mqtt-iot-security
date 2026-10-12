"""
Hardened camera (Phase 2).

Publishes a signed status envelope over TLS with authenticated identity, instead
of the plaintext "ONLINE" string the undefended camera.py sends.
"""
import time

import secure_common as sc

DEVICE_ID = "camera-frontdoor"
TOPIC = "home/frontdoor/camera/status"

DATA_SCHEMA = {
    "type": "object",
    "properties": {"status": {"enum": ["ONLINE", "OFFLINE"]}},
    "required": ["status"],
    "additionalProperties": False,
}


def main():
    signer = sc.Signer(DEVICE_ID, sc.load_hmac_key())
    client = sc.make_client(DEVICE_ID)
    host, port = sc.broker_endpoint()
    client.connect(host, port, 60)
    client.loop_start()

    print(f"[camera-secure] publishing signed status to {TOPIC} (TLS, auth)")
    while True:
        client.publish(TOPIC, signer.envelope({"status": "ONLINE"}))
        print(f"[camera-secure] -> ONLINE  (seq={signer._seq})")
        time.sleep(10)


if __name__ == "__main__":
    main()
