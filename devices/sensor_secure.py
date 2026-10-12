"""
Hardened temperature sensor (Phase 2).

Same behaviour as the undefended sensor.py, but every reading is published as a
signed, sequence-numbered JSON envelope over TLS with authenticated identity.
"""
import time
import random

import secure_common as sc

DEVICE_ID = "sensor-livingroom"
TOPIC = "home/livingroom/temperature"

# Schema the `data` field must satisfy (advertised so subscribers can validate).
DATA_SCHEMA = {
    "type": "object",
    "properties": {
        "temperature": {"type": "number", "minimum": -40, "maximum": 85},
        "unit": {"const": "C"},
    },
    "required": ["temperature", "unit"],
    "additionalProperties": False,
}


def main():
    signer = sc.Signer(DEVICE_ID, sc.load_hmac_key())
    client = sc.make_client(DEVICE_ID)
    host, port = sc.broker_endpoint()
    client.connect(host, port, 60)
    client.loop_start()

    print(f"[sensor-secure] publishing signed temperature to {TOPIC} (TLS, auth)")
    while True:
        temp = round(random.uniform(20.0, 26.0), 1)
        client.publish(TOPIC, signer.envelope({"temperature": temp, "unit": "C"}))
        print(f"[sensor-secure] -> {temp}C  (seq={signer._seq})")
        time.sleep(5)


if __name__ == "__main__":
    main()
