import paho.mqtt.client as mqtt

STATE_TOPIC = "home/frontdoor/lock/state"
CMD_TOPIC   = "home/frontdoor/lock/cmd"

def on_connect(client, userdata, flags, rc):
    print(f"[lock] connected rc={rc}, subscribing to {CMD_TOPIC}")
    client.subscribe(CMD_TOPIC)
    client.publish(STATE_TOPIC, "LOCKED", retain=True)

def on_message(client, userdata, msg):
    cmd = msg.payload.decode()
    print(f"[lock] received cmd: {cmd}")
    if cmd in ("LOCK", "UNLOCK"):
        new_state = "LOCKED" if cmd == "LOCK" else "UNLOCKED"
        client.publish(STATE_TOPIC, new_state, retain=True)
        print(f"[lock] state -> {new_state}")

client = mqtt.Client(client_id="lock-frontdoor")
client.on_connect = on_connect
client.on_message = on_message
client.connect("broker", 1883, 60)
client.loop_forever()
