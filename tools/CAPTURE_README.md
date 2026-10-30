# Wireshark / PyShark traffic analysis

This shows *why* TLS matters with actual captured packets, not just an
assertion — the same workflow used for earlier Phase 1 traffic analysis
(capture with Wireshark's GUI, save a `.pcap`, then read it back). The only
new part here is `capture_compare.py`, which reads the saved files and
prints a clear plaintext-vs-encrypted comparison for your report.

It does **not** do a live capture itself — no Npcap loopback-adapter /
`tshark -D` interface juggling required. You capture with Wireshark
directly (which you already have installed and know how to use), and the
script only analyzes the file afterward.

## 1. Capture the baseline broker's traffic (plaintext, port 1883)

1. Make sure the lab stack is running: `bash setup-hardened.sh` (or, if
   it's already up, `docker compose up -d --wait`) — this brings up both
   the baseline and hardened brokers together.
2. Open **Wireshark** → capture on **"Adapter for Loopback Traffic
   Capture"** (the interface that sees `localhost` traffic, including
   ports Docker Desktop forwards from its containers).
3. Set the capture filter to `tcp port 1883`, click Start.
4. Let it run for ~15-20 seconds while you generate some traffic — sign in
   on the **baseline** dashboard profile and lock/unlock the door a couple
   of times, or run the existing eavesdrop demo in another terminal:
   ```bash
   python attacks/eavesdrop.py
   ```
5. Stop the capture, save as **`tools/baseline_capture.pcapng`**.

## 2. Capture the hardened broker's traffic (TLS, port 8883)

1. Same Wireshark setup, but capture filter `tcp port 8883` this time.
2. Let it run the same ~15-20 seconds while you sign in on the
   **hardened** dashboard profile and lock/unlock the door a couple of
   times.
3. Stop, save as **`tools/hardened_capture.pcapng`**.

## 3. Run the comparison script

```bash
pip install pyshark
python tools/capture_compare.py
```

This opens both captures and prints, for each:
- How many packets were captured
- For the **baseline** one: the actual MQTT topic names, payload text, and
  (if present) login credentials pulled straight out of the packets —
  proving an eavesdropper reads sensor data, lock state, and the operator
  password in plain text
- For the **hardened** one: confirmation that no MQTT content is visible
  at all — just a TLS handshake followed by opaque encrypted
  application-data records, with the encrypted byte count shown instead of
  readable text

Paste that printed output (or a screenshot of it) straight into your
report's traffic-analysis section — a direct, concrete demonstration of
the confidentiality fix, not just a claim.

## If `pyshark` can't find `tshark`

`pyshark` needs the `tshark.exe` that ships with Wireshark. If you get an
error about tshark not being found, pass its path explicitly:
```bash
python tools/capture_compare.py --tshark-path "C:\Program Files\Wireshark\tshark.exe"
```

## If you don't have Wireshark installed yet

Download it from [wireshark.org](https://www.wireshark.org/download.html).
During setup, keep **Npcap** selected (it's bundled in) — that's what
provides the loopback-capture interface. After installing, close and
reopen Git Bash so it can pick up the updated PATH, then confirm with:
```bash
tshark --version
```
