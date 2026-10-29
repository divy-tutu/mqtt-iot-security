# MQTT security laboratory

A reproducible comparison of a plausible password-protected legacy MQTT deployment and a hardened deployment. The same sensor, camera, lock state machine, message format, timing, and container resource budgets run in both profiles. The lock is simulated; MQTT authentication, ACL decisions, TLS, signatures, sessions, replay checks, and SQLite persistence are real.

**Start here:** [project redesign and revised synopsis text](docs/PROJECT_REDESIGN.md) explains the security argument, innovation, limitations, and viva preparation.

## Run on Windows

Install/start Docker Desktop with Linux containers, then run from this directory:

~~~powershell
./setup-lab.ps1
~~~

Open [HomePulse](https://localhost:8443/) for the landing page, [My Home](https://localhost:8443/dashboard) for live devices and door controls, or [Security Lab](https://localhost:8443/lab) for signed device decisions and measured comparisons. Plain HTTP on port 8080 redirects to HTTPS. Read `runtime/login.txt` for the generated admin credentials. Sign in separately to Baseline and Hardened; navigation between My Home and Security Lab shares the selected profile and its server session.

The HTTPS certificate is issued by the lab CA at `runtime/public/ca.crt` and is valid for `localhost` and `127.0.0.1`. Trust that CA in the current user's browser/OS certificate store to remove the local-CA warning. Do this only on the lab machine; the CA exists solely for this project.

~~~powershell
./install-local-ca.ps1
# Later, remove the exact lab CA again with:
./remove-local-ca.ps1
~~~

The setup is idempotent: it keeps identities and passwords. On Linux/Git Bash use `bash setup-hardened.sh`. Internet access is required for the first image build. After provisioning, `docker compose up -d --wait` starts the paired experiment. `docker-compose.hardened.yml` is a compatibility entrypoint for the same paired stack.

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

