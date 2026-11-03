"""The same workload and actuator model run in both profiles."""
import os
import random
import threading
import time
import urllib.request
from pathlib import Path
import paho.mqtt.client as mqtt
import camera_source
from security import CMD, EVENT, TOPICS, LockPolicy, sign
from transport import client, start, publish
from privacy import pad_envelope, camera_interval

# A JPEG whose byte size changes by more than this fraction between two
# consecutive phone snapshots is treated as motion. This is a deliberately
# cheap, decode-free heuristic for the lab, not real computer-vision detection.
MOTION_DELTA = 0.08


def fetch_phone_frame():
    """Return the latest phone JPEG bytes, or None if no phone camera is set.

    Raises OSError/ValueError (caught by the caller) if a configured phone is
    unreachable or its address fails the SSRF guard in camera_source.
    """
    url = camera_source.resolve_endpoint("snapshot")
    if not url:
        return None
    request = urllib.request.Request(url, headers={"User-Agent": "mqtt-lab-camera"})
    with urllib.request.urlopen(request, timeout=camera_source.FETCH_TIMEOUT) as response:
        return response.read(2_000_000)  # cap a single frame at ~2 MB


def camera_reading(prev_len):
    """Derive camera telemetry from the real phone feed, or simulate it.

    Returns (data, new_prev_len). The envelope schema is unchanged from the
    original simulation; only the values now reflect the real feed when set.
    """
    try:
        frame = fetch_phone_frame()
    except (OSError, ValueError):
        frame = None
    if frame is None:
        if camera_source.get_source() is None:
            # No phone configured: keep the original simulated camera behaviour.
            return {"status": "ONLINE", "motion": int(time.time() // 8) % 2 == 1,
                    "source": "simulated"}, None
        # A phone is configured but momentarily unreachable.
        return {"status": "OFFLINE", "motion": False, "source": "phone"}, None
    motion = prev_len is not None and abs(len(frame) - prev_len) / max(prev_len, 1) > MOTION_DELTA
    return {"status": "ONLINE", "motion": bool(motion), "source": "phone"}, len(frame)

def main():
    who = os.environ["DEVICE"]
    profile = os.environ["PROFILE"]
    Path("/data").mkdir(exist_ok=True)
    policy = LockPolicy("/data/lock.sqlite", profile=="hardened" and os.environ.get("COMMAND_POLICY","full")=="full", "/public/operator.pem") if who=="lock" else None
    c = client(who)
    send_lock = threading.Event()
    def connect(c, userdata, flags, reason, properties):
        if not reason.is_failure and who=="lock":
            # Preserve RETAIN on live messages too, so retained commands cannot execute.
            c.subscribe(CMD, options=mqtt.SubscribeOptions(qos=1, retainAsPublished=True))
            send_lock.set()
    def message(c, userdata, msg):
        decision = policy.process(msg.payload, retained=msg.retain)
        c.publish(EVENT, sign("/identity/signing.pem",who,EVENT,decision), qos=1)
        send_lock.set()
        print(decision, flush=True)
    c.on_connect, c.on_message = connect, message
    start(c)
    rng = random.Random(3141)
    temperature = 23.0
    tick = 0
    prev_frame_len = None
    while True:
        if who=="lock":
            data = policy.state()
            interval = 2
        elif who=="sensor":
            temperature = max(19,min(28,temperature+rng.uniform(-0.15,0.15)))
            data = {"temperature":round(temperature,2),"unit":"C"}
            interval = 2
        else:
            data, prev_frame_len = camera_reading(prev_frame_len)
            interval = camera_interval(data['motion'], profile == 'hardened')
        payload = sign("/identity/signing.pem",who,TOPICS[who],data)
        if who == 'camera' and profile == 'hardened':
            payload = pad_envelope(payload)
        publish(c, TOPICS[who], payload, retain=True)
        tick += 1
        send_lock.wait(interval)
        send_lock.clear()

if __name__=="__main__":
    main()


