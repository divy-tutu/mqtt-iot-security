# Wireshark / PyShark traffic analysis

## Automated guided demo (recommended)

From the project root, with Docker Desktop running:

```powershell
.\run-guided-demo.ps1
```

The first run builds a dedicated capture/analysis image with tcpdump, TShark
(Wireshark's command-line engine), and PyShark 0.6. No host Python, Npcap, or
manual interface selection is needed. Internet access is needed for the first build.
The Wireshark desktop app is optional for inspecting the resulting files.

The script captures each broker's own network namespace, not Windows loopback.
It runs baseline, full hardening (including replay after restart), and an
intermediate TLS + ACL comparison. Intermediate mode temporarily disables the
application checks; the `finally` block restores and checks full policy on both
the lock and gateway. Do not issue manual commands during measurement.

Each run saves under `results/captures/<run-id>/`:

- `baseline.pcap`, `hardened.pcap`, `intermediate.pcap`: real network captures.
- Matching `.log` / `.json` files: capture exit status and packet-drop evidence.
- `report.json`: archived device outcomes, packet counts, capture hashes, and correlations.
- `lock-public.pem`: public key for independent historical receipt verification.

The expanded suite records 50 checks across three levels, including modification,
audit-proof tampering, bounded command/connection pressure and recovery, and an
eight-window synthetic traffic-analysis probe. Privacy inference is measured
offline from TCP payload volume, not guessed from encrypted payload contents.
See `docs/SYNOPSIS_ALIGNMENT_AND_DEMO.md` for the eight-attack/six-defense mapping.

The current report also lives at `results/guided-demo.json`, and appears on the
authenticated `/lab` page. The browser only reads evidence; it has no Docker control.
Open any PCAP in Wireshark. Use display filter `mqtt` for baseline and `tls` for
the other levels. Expand a baseline PUBLISH and compare its frame number with
the report's matching frames. Payload matches use SHA-256 plus the scenario's
time window. TLS rows have **time-window correlation only**: they cannot identify
an encrypted command, or prove rejection without the signed device evidence.
Duplicate TCP delivery can produce multiple matching frames; this is not an action count.

Capture is limited to the broker port, 180 seconds and 100,000 packets per phase.
Capture uses a larger kernel buffer and a two-second drain period before shutdown.
PCAPs are written to a temporary Docker volume, then copied to Windows after
capture stops, avoiding per-packet Windows mount latency. Zero kernel drops alone
does not establish complete evidence; scenario windows are checked too.
The task-owned capture volume is removed only after its file has been copied out.
Only the short-lived capture container receives `NET_RAW` plus `SETUID`/`SETGID`
for tcpdump's identity initialization; application containers
keep their existing restrictions. Analysis runs offline with no network or added
capabilities. No TLS session secrets are exported. The report counts exposed
credentials without printing them. **Baseline PCAPs contain lab passwords**, so
keep them local; generated captures/results are ignored by Git.

An empty capture, missing scenario traffic, dropped packets, capture timeout,
analysis error, or unexpected device outcome prevents overall verification.
If Docker or the host is forcibly terminated during the intermediate phase, run
`docker compose up -d --wait hardened-lock hardened-gateway` to restore full policy
before using the lab. Normal script failures attempt this automatically.

The earlier manual workflow and teammate's `capture_compare.py` remain available below.

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
