import time, random, paho.mqtt.client as mqtt

client = mqtt.Client(client_id="sensor-livingroom")
client.connect("broker", 1883, 60)
client.loop_start()

print("[sensor] publishing temperature to home/livingroom/temperature")
while True:
    temp = round(random.uniform(20.0, 26.0), 1)
    client.publish("home/livingroom/temperature", str(temp))
    print(f"[sensor] -> {temp}")
    time.sleep(5)
