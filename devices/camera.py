import time, paho.mqtt.client as mqtt

client = mqtt.Client(client_id="camera-frontdoor")
client.connect("broker", 1883, 60)
client.loop_start()

print("[camera] publishing status to home/frontdoor/camera/status")
while True:
    client.publish("home/frontdoor/camera/status", "ONLINE")
    print("[camera] -> ONLINE")
    time.sleep(10)
