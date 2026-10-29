import json
import os
import ssl
import threading
import uuid
from pathlib import Path
import paho.mqtt.client as mqtt

def client(identity=None, profile=None, host=None, port=None, root="/identity", public="/public", anonymous=False, bad_password=False):
    profile = profile or os.environ.get("PROFILE","baseline")
    config = {} if anonymous else json.loads(Path(root,"mqtt.json").read_text())
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"{identity or 'lab'}-{uuid.uuid4().hex[:12]}", protocol=mqtt.MQTTv5)
    if not anonymous:
        c.username_pw_set(config["username"], "deliberately-wrong" if bad_password else config["password"])
    if profile == "hardened":
        context = ssl.create_default_context(cafile=str(Path(public,"ca.crt")))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        c.tls_set_context(context)
    c.endpoint = (host or os.environ.get("MQTT_HOST",f"{profile}-broker"), port or (8883 if profile=="hardened" else 1883))
    return c

def start(c, timeout=8):
    ready = threading.Event()
    result = []
    original = c.on_connect
    def connected(client, userdata, flags, reason, properties):
        result.append(reason)
        if original:
            original(client, userdata, flags, reason, properties)
        ready.set()
    c.on_connect = connected
    c.connect(*c.endpoint, keepalive=30)
    c.loop_start()
    if not ready.wait(timeout):
        c.disconnect()
        c.loop_stop()
        raise TimeoutError("MQTT CONNACK timeout")
    if result[0].is_failure:
        c.disconnect()
        c.loop_stop()
        raise PermissionError(str(result[0]))
    return c

def publish(c, topic, payload, retain=False):
    info = c.publish(topic, payload, qos=1, retain=retain)
    info.wait_for_publish(timeout=5)
    if not info.is_published():
        raise TimeoutError("PUBACK timeout")
    return info.mid

