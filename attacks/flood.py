import threading, time, paho.mqtt.client as mqtt

N = 200          # number of flood connections
count = {"ok": 0, "fail": 0}
lock = threading.Lock()

def hammer(i):
    try:
        c = mqtt.Client(client_id=f"flood-{i}")
        c.connect("localhost", 1883, 60)
        c.loop_start()
        with lock: count["ok"] += 1
    except Exception:
        with lock: count["fail"] += 1

print(f"[flood] launching {N} rapid connections...")
start = time.time()
threads = [threading.Thread(target=hammer, args=(i,)) for i in range(N)]
for t in threads: t.start()
for t in threads: t.join()
elapsed = time.time() - start
print(f"[flood] done in {elapsed:.2f}s  |  connected={count['ok']}  failed={count['fail']}")
