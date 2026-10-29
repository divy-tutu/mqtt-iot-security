"""The same workload and actuator model run in both profiles."""
import os
import random
import threading
import time
from pathlib import Path
import paho.mqtt.client as mqtt
from security import CMD, EVENT, TOPICS, LockPolicy, sign
from transport import client, start, publish

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
    while True:
        if who=="lock":
            data = policy.state()
            interval = 2
        elif who=="sensor":
            temperature = max(19,min(28,temperature+rng.uniform(-0.15,0.15)))
            data = {"temperature":round(temperature,2),"unit":"C"}
            interval = 2
        else:
            data = {"status":"ONLINE","motion":tick % 15 in (5,6)}
            interval = 2
        publish(c, TOPICS[who], sign("/identity/signing.pem",who,TOPICS[who],data), retain=True)
        tick += 1
        send_lock.wait(interval)
        send_lock.clear()

if __name__=="__main__":
    main()


