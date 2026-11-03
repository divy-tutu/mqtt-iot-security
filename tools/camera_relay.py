"""Host-side relay from the dashboard gateway to a phone IP-webcam.

Why this exists: Docker Desktop's Linux VM cannot reach a device on the same
subnet as the Windows host's Wi-Fi when that subnet is an iPhone Personal
Hotspot (e.g. 172.20.10.0/28). The Windows host CAN reach the phone, so this
tiny proxy runs on the host and the gateway container reaches it through
host.docker.internal. On an ordinary shared Wi-Fi router this relay is not
needed: point the dashboard's "Phone camera" field straight at the phone.

It binds 127.0.0.1, so no Windows Firewall rule is required: on Docker Desktop
host.docker.internal already reaches the host's loopback.

Usage (run on the host, keep it running during the demo):

    python tools/camera_relay.py http://<phone-ip>:8080 [listen_port]

Then set the dashboard's phone-camera URL (admin) to:

    http://host.docker.internal:<listen_port>

Example:

    python tools/camera_relay.py http://172.20.10.3:8080 9099
    # dashboard phone-camera URL -> http://host.docker.internal:9099

Stop it with Ctrl+C (or by ending the python process). Restart it if the PC
reboots/sleeps or the phone's IP changes.
"""
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PHONE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else ""
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9099


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = PHONE + self.path
        try:
            upstream = urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": "camera-relay"}),
                timeout=10,
            )
        except Exception:
            self.send_error(502, "phone not reachable")
            return
        self.send_response(upstream.status)
        self.send_header("Content-Type", upstream.headers.get("Content-Type", "application/octet-stream"))
        self.end_headers()
        try:
            while True:
                chunk = upstream.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except Exception:
            pass
        finally:
            upstream.close()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    if not PHONE.startswith("http"):
        sys.exit("Usage: python tools/camera_relay.py http://<phone-ip>:8080 [listen_port]")
    print(f"Relaying http://127.0.0.1:{PORT}  ->  {PHONE}", flush=True)
    print("Set the dashboard phone-camera URL to "
          f"http://host.docker.internal:{PORT}", flush=True)
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", flush=True)
