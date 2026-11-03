# MQTT security laboratory

A reproducible comparison of a plausible password-protected legacy MQTT deployment and a hardened deployment. The same sensor, camera, lock state machine, message format, timing, and container resource budgets run in both profiles. The lock is simulated; MQTT authentication, ACL decisions, TLS, signatures, sessions, replay checks, and SQLite persistence are real.

**Start here:** [project redesign and revised synopsis text](docs/PROJECT_REDESIGN.md) explains the security argument, innovation, limitations, and viva preparation.

## Run on Windows

Install/start Docker Desktop with Linux containers, then run from this directory:

~~~powershell
./setup-lab.ps1
~~~

Open [HomePulse](https://localhost:8443/) for the landing page, [My Home](https://localhost:8443/dashboard) for live devices and door controls, or [Security Lab](https://localhost:8443/lab) for signed device decisions and measured comparisons. Plain HTTP on port 8080 redirects to HTTPS. On first setup, choose the initial admin password when prompted; passwords are not written to `runtime/login.txt`. Sign in separately to Baseline and Hardened; navigation between My Home and Security Lab shares the selected profile and its server session.

### Multiple accounts and password storage

Administrators can open [People and access](https://localhost:8443/users) from
the dashboard to list accounts, inspect their stored hashes, and create operators
or additional administrators. Accounts persist in each gateway's Docker data
volume. Creating an account in one profile does not create it in the other.
Only administrators can access the user-management API and full access log;
ordinary operators cannot retrieve password hashes or grant themselves admin access.

Hardened browser passwords use scrypt (`N=32768, r=8, p=3`) with a fresh random
16-character salt. Baseline uses salted PBKDF2-HMAC-SHA256 (600,000 iterations)
and deliberately stores a two-character password suffix as a weak legacy support
hint. Its eight-character mask is fixed, not derived from password length.
The hardened database has no hint or password-length field. The random salt makes
identical passwords produce different hashes; varying hash length is not a security
feature. Neither profile stores full browser passwords or reversible ciphertext.
Admin hash display is an educational feature; a production admin page should not
expose password verifiers unnecessarily. Hashing does not make weak passwords
immune to guessing if a verifier is stolen.

Existing single-admin accounts and passkeys migrate in place. New passkeys belong
to the registering account and sign in as that user, not as a universal admin.
Challenges are stored server-side, expire after two minutes, and are consumed once.
Face/fingerprint recognition remains within Windows Hello/the authenticator;
the app stores credential public keys, not biometric data.

For API checks, supply `LAB_TEST_USERNAME` and `LAB_TEST_PASSWORD` to the test
process or use its interactive password prompt. Credentials should not be committed.
Machine MQTT client credentials remain necessary in their restricted identity
mounts; this hash-only browser-account change does not remove client secrets or
plaintext credentials from intentionally captured baseline MQTT traffic.

The HTTPS certificate is issued by the lab CA at `runtime/public/ca.crt` and is valid for `localhost` and `127.0.0.1`. Trust that CA in the current user's browser/OS certificate store to remove the local-CA warning. Do this only on the lab machine; the CA exists solely for this project.

~~~powershell
./install-local-ca.ps1
# Later, remove the exact lab CA again with:
./remove-local-ca.ps1
~~~

The setup is idempotent: it keeps identities and passwords. On Linux/Git Bash use `bash setup-hardened.sh`. Internet access is required for the first image build. After provisioning, `docker compose up -d --wait` starts the paired experiment. `docker-compose.hardened.yml` is a compatibility entrypoint for the same paired stack.

### Live phone camera (optional)

The security-camera card can show a real feed from your Android or iPhone instead
of the still image or the local webcam. Install any IP-webcam app on the phone
(for example "IP Webcam" on Android, or "DroidCam"/"iVCam" on iOS) and start it so
it serves video on your Wi-Fi at an address like `http://192.168.1.42:8080`. The
default endpoints are `/video` (MJPEG) and `/shot.jpg` (snapshot); apps that match
those work with no further configuration.

Sign in as an administrator, open the camera card on the dashboard, expand **Phone
camera** and enter the phone's base URL. The phone and the PC must be on the same
Wi-Fi. Because the dashboard is HTTPS and the phone serves plain HTTP, the gateway
proxies the stream (`/camera/stream`) so the browser never loads mixed content; the
feed is visible only to a signed-in operator. The camera device also pulls snapshots
to set its signed `status` (ONLINE/OFFLINE) and a decode-free `motion` estimate, so
the real feed and the MQTT telemetry stay connected. With no phone configured, the
camera falls back to the original simulation and nothing else changes.

The phone URL is operator-supplied, so the gateway only accepts private LAN
addresses: loopback, link-local (including the `169.254.169.254` metadata address)
and public addresses are rejected, and the address is re-checked before every fetch.
This is an SSRF guard for a local lab, not a hardened reverse proxy.

On an ordinary shared Wi-Fi router the gateway container reaches the phone
directly. On an iPhone Personal Hotspot (a `172.20.10.0/28` subnet), Docker
Desktop's Linux VM cannot route to that subnet even though the Windows host can.
For that case, run the bundled host relay and point the phone-camera URL at it:

~~~powershell
python tools/camera_relay.py http://<phone-ip>:8080 9099
# then set the dashboard phone-camera URL to http://host.docker.internal:9099
~~~

Keep the relay running during use; restart it if the PC sleeps or the phone's IP
changes. The relay binds `127.0.0.1`, so no firewall rule is needed.

~~~powershell
# Bounded, local experiment: 3 repetitions, alternating profile order
docker compose --profile test run --rm experiment

# Security unit tests; HTTP-session and TLS checks
docker run --rm mqtt-security-lab:local python -m unittest -v test_security
docker compose --profile test run --rm experiment python api_checks.py

# Interactive command with a signed device receipt
docker compose --profile test run --rm experiment python send_command.py UNLOCK --profile hardened

# Inspect broker enforcement and hash-linked lock decisions
docker compose logs --tail 80 hardened-broker hardened-lock
docker compose exec hardened-lock python audit.py

# Stop services without deleting persistent replay state or evidence
docker compose down
~~~

Results are written to `results/latest.json` and `results/latest.md`; the dashboard reads the JSON. This is measured evidence, not a prefilled success matrix. A timeout or missing signed device decision is **inconclusive**. The experiment returns a nonzero exit code on unexpected results. Do not send manual commands during a measured run: they can affect the shared command-rate limit.

## Security comparison

| Layer | Baseline | Hardened |
|---|---|---|
| Broker identity | Random per-device passwords; anonymous denied | Same identity scheme; anonymous denied |
| Authorization | Every enrolled identity can read/write home/# | Exact per-device topics and directions; default deny |
| Transport | Plaintext MQTT inside the lab network | Server-authenticated TLS, hostname and CA validation |
| Operator access | Server session, password hash, JSON API | Same controls; no client-only login |
| Command validation | LOCK/UNLOCK schema | Same schema plus signature, sender and topic binding |
| Freshness | No application replay or age check | 30-second window plus persisted unique command IDs |
| Retained commands | Accepted, representing a common design error | Rejected for both live and subscription delivery |
| Command abuse | No actuator rate cap | At most 5 accepted commands per 2 seconds |
| Evidence | Signed observer receipts for a fair comparison | Same receipts plus enforced command authentication |
| Runtime | Non-root, resource budgets, no host networking | Same isolation budget to avoid confounding results |

The baseline is a **deliberately selected legacy configuration**, not a claim about every real product or modern Mosquitto defaults. Both profiles sign their outgoing telemetry and experiment receipts to keep workload and measurement comparable; only the hardened application requires signature verification on commands. Baseline signing is instrumentation, not an asserted baseline defence.

## Architecture and key boundaries

~~~mermaid
flowchart LR
  UI[Browser operator] -->|local HTTP and session cookie| G[Gateway]
  G -->|signed command and MQTT credentials| B[Profile broker]
  S[Sensor identity] --> B
  C[Camera identity] --> B
  B --> L[Lock policy and durable state]
  L -->|signed decision and state| B
  B -->|telemetry and receipts| G
  E[Local experiment runner] --> B
  E --> R[JSON evidence]
  R --> G
~~~

There are separate baseline and hardened Docker networks. Gateways also join a web network for the dashboard. The broker and each client receive only their own credential/private-key directory; all clients can receive public verification keys and the public CA. The CA private key is not mounted in runtime services. The experiment container intentionally has fixture access to all test identities; it is a lab controller, not an unprivileged attacker. No Docker socket is mounted.

The server keeps the operator private signing key. Compromising only camera credentials does not grant the hardened command topic. Compromising only operator MQTT credentials does not grant the signing key. Compromising the gateway/host or stealing both operator secrets defeats that boundary and is outside the tested protection.

The web interface is **loopback HTTPS for a local lab**. Port 8080 redirects to HTTPS on port 8443. Session cookies are HttpOnly, SameSite=Strict and rewritten as Secure at the TLS proxy. For deployment beyond localhost, use a publicly or organizationally trusted certificate, implement session revocation and per-user roles, and separate the control plane. This repository does not claim production readiness.

## Replay across an actual lock restart

Run the following sequence promptly (within the 30-second freshness window):

~~~powershell
docker compose --profile test run --rm experiment python send_command.py UNLOCK --save
docker compose restart hardened-lock
docker compose --profile test run --rm experiment python send_command.py UNLOCK --replay
~~~

The first decision must be accepted; after restart the identical command must be rejected as `replay`, with the action counter unchanged. After 30 seconds it will instead be rejected as `stale-timestamp`; that is safe but does not specifically demonstrate persistence. Never delete the lock volume between these steps.

## Control ablation

This optional teaching experiment changes just the lock's application policy while retaining TLS and ACLs:

~~~powershell
docker compose -f docker-compose.yml -f docker-compose.ablation.yml up -d hardened-lock hardened-gateway
docker compose --profile test run --rm experiment python send_command.py UNLOCK --save
docker compose --profile test run --rm experiment python send_command.py UNLOCK --replay
# Expected: receipt says accepted; the replay tool exits 1 because protection is absent.
# Restore the full policy immediately after the comparison:
docker compose up -d hardened-lock hardened-gateway
~~~

The dashboard displays an ablation warning while the override is active. The override is explicitly a testing configuration. Run the ordinary full experiment only after restoring the full policy.

## Measurement and evidence

The suite includes anonymous/wrong-password rejection, a legitimate command, camera-to-lock lateral movement, state forgery, wildcard data disclosure, original and repeated commands, changed payloads, expired commands, malformed payloads, invalid command schemas, retained commands, a 12-command burst, and post-burst recovery.

MQTT v5 PUBACK reason codes distinguish authorization denial from client-side send completion. A successful PUBACK alone never proves device execution. Accepted/rejected device receipts include command ID, payload hash, action counter, state, reason, and a hash-chain link. The runner verifies lock signatures and measures publish-to-receipt latency using a monotonic clock.

Reported latency is host-specific end-to-end observation latency, not isolated cryptographic overhead. The small default sample size is for a lab demo, not a statistically strong benchmark. Archive JSON and logs per run; do not treat the last dashboard table as immutable evidence. Broker denies cannot be inferred from subscriber payloads alone.

## Repository layout

- `lab/`: active simulator, security policy, gateway, experiment runner, and tests.
- `broker/config/`: current baseline and hardened broker policies.
- `frontend/`: live dashboard and container web proxy.
- `runtime/`: ignored generated credentials and trust material; do not submit it.
- `results/`: ignored measured outputs; inspect and export selected evidence.
- `devices/`, `attacks/`, and the original `tools/send_command.py`: **legacy v1 code**, retained for comparison. They are not started by the current Compose stack and are not the current demo commands.

The old direct-browser MQTT hooks and browser-embedded keys were removed. Never reuse an old `frontend/.env.local` containing signing keys; the current frontend does not read it and its Docker build excludes environment files.

## Bounds

This is not a universal security wrapper. It does not provide firmware security, secure boot, certificate rotation/revocation, a full IDS, traffic-analysis protection, proven non-repudiation, log immutability, or volumetric DDoS resistance. A signed receipt identifies the holder of a key, not a human. A hash chain needs an independently stored head to detect a full rewrite or tail truncation. Full disk, malicious time changes, broker compromise and host compromise need separate treatment. Limits on broker queues are backlog limits, not a publisher rate limiter.

The baseline and hardened network stacks are real, but the actuator is a software state machine. Correctly report “simulated lock state changed,” not “physical door unlocked.”



On Windows, ./test-ablation.ps1 runs the ablation and restores full controls in a finally block. The dashboard displays an ablation warning while the override is active.

## Automated guided attack and packet-evidence demo

Read [synopsis alignment and the eight-minute demo](docs/SYNOPSIS_ALIGNMENT_AND_DEMO.md)
for the eight-attack/six-defense mapping, corrected claims, threat assumptions,
and what the experiment still does not demonstrate.

Run `.\run-guided-demo.ps1` from PowerShell with Docker Desktop running. It captures
the actual Docker broker traffic, runs the three-level comparison, restores full
hardening, and analyses the PCAPs with PyShark/TShark. View outcomes and packet
evidence at `https://localhost:8443/lab`; open saved PCAPs in Wireshark.
See [capture instructions](tools/CAPTURE_README.md) for evidence interpretation,
artifact locations, and recovery after a forcibly interrupted run.

