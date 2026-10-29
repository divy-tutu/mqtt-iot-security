# Project redesign and lab defence

## The claim to defend

**Suggested title:** Reproducible MQTT Security Evaluation with Compromised Device Containment and Durable Command Verification

**Research question:** How much protection is provided by broker authentication and TLS, and which additional failures are prevented by topic authorization, command verification, and durable replay state?

**Contribution:** A containerized security policy and evidence harness for MQTT command systems. It compares realistic misconfiguration with layered controls using the same application workload, records broker and device decisions separately, and tests that freshness enforcement survives a receiver restart. Its novelty is the integration, experiment design, and reproducible evidence, not a new cryptographic algorithm.

Do not claim “all security measures,” “unhackable Docker,” or that nobody has previously built MQTT monitoring. Docker packages the controls; it does not itself enforce application authorization or make an unsafe protocol configuration safe.

## Why the original comparison was unconvincing

The original baseline enabled anonymous access, accepted commands from anyone, and used a browser-only login flag. An open broker is a possible misconfiguration, but using only that case makes every result look predetermined. A better baseline already rejects outsiders and malformed commands. Its defect is trusting every enrolled device with the whole topic tree.

The revised attacker is first given a camera's credentials through a stated compromise assumption. This is a realistic *threat model*, not evidence that a particular real camera product is vulnerable. The camera can publish its own telemetry in both profiles. Only the baseline lets it publish lock commands or observe unrelated telemetry.

The original secure frontend checked a hardcoded password digest in JavaScript and held device HMAC secrets. That does not create a trustworthy server boundary: downloading the bundle can reveal secrets, and changing browser state can bypass the page gate. Both profiles now use a gateway with server-side password checking and authenticated API requests.

## Proposed synopsis replacement

### Background and problem

MQTT brokers distribute telemetry and commands among heterogeneous devices. A deployment can authenticate every client while still granting excessive topic permissions, trusting old commands, or exposing credentials over plaintext transport. Transport security and broker authorization address important threats but do not define whether an application command is fresh, well formed, or safe to execute.

This project studies a simulated smart home containing a temperature sensor, camera, and door lock. Its baseline represents an authenticated legacy LAN deployment with overly broad topic permissions and no application replay protection. Its hardened profile adds TLS, least-privilege authorization, signed commands, durable freshness checks, retained-command rejection, and bounded command processing.

### Objectives

1. Implement the same application workload in two isolated MQTT profiles with explicit, comparable resource budgets.
2. Show which attacks are rejected even by the baseline, including anonymous access and invalid command syntax.
3. Demonstrate lateral movement from a compromised camera identity and test containment through topic permissions.
4. Distinguish broker authorization, message authenticity, freshness, and actuator execution using separate evidence.
5. Validate replay rejection across receiver restart and report bounded abuse and recovery behavior.
6. Export measured outcomes and latency observations to a live dashboard and JSON report.
7. Use an optional control ablation to show the additional value of application verification after TLS and ACLs are already enabled.

### Threat model

The attacker can access only the local experimental broker networks. Test cases vary their stated capability: no credentials, camera credentials, operator MQTT credentials without its signing key, or access to a captured signed application command. A stronger fixture uses the operator signing key to test schema and rate policies independently of signature enforcement. These privileges must not be conflated.

The test controller can manufacture valid samples using test keys. This is measurement infrastructure; it does not mean every attacker has those keys. The host, provisioning material, CA private key, and honest device private signing keys are trusted except where an experiment explicitly models compromise. Physical compromise, firmware attacks, host escape, and Internet-scale attack traffic are outside scope.

### System design

The browser communicates with an authenticated gateway. The gateway holds operator credentials and an Ed25519 private key, publishes commands through the selected broker, and verifies signed device telemetry and receipts. The lock validates commands and stores accepted command IDs, simulated state transitions, and hash-linked decisions transactionally in SQLite. Device containers run without root privileges, with read-only root filesystems and resource limits.

The broker applies per-identity topic permissions. The hardened listener validates connections using password authentication over server-authenticated TLS. This is not mutual TLS: devices do not present client certificates. Public verification keys are distributable; private signing keys stay with their assigned service.

### Evaluation

Run at least three matched repetitions for demonstration, alternate profile order, and preserve complete evidence. Use positive and negative controls before drawing conclusions. Report accepted commands over attempted commands, unauthorized operations that reached the device, specific rejection reasons, bounded-burst acceptance and rejection counts, and successful legitimate operation after the burst.

Measure publish-to-signed-receipt latency with a monotonic clock. Treat median and nearest-rank p95 as descriptive observations at the available sample count. For a stronger performance claim, collect at least 100 legitimate commands per profile in separate idle runs, then repeat under a fixed bounded workload with the same hardware and resource caps. Record image digests, host CPU/memory, Docker version, and competing workloads. Do not compare mixed attack receipts as if they were a clean TLS overhead benchmark.

A missing response is inconclusive. Connection establishment at the TCP layer is not MQTT authentication success. A PUBACK is not proof of actuator execution. A subscription acknowledgement alone is not proof that the client can read forbidden topics; measure actual delivery while a legitimate publisher is active.

### Expected outcomes and limitations

The hypothesis is that authenticated baseline clients can exploit broad permissions and replay old application commands, while the hardened stack rejects those operations without breaking legitimate commands. Evidence must come from actual runs, not expected labels. The local simulation supports claims about broker and application behavior, not hardware safety or production-wide resilience.

Signatures provide integrity and attribution to keys under the key-custody assumptions. Neither signatures alone nor a local database provide legal or operational non-repudiation. Hash-linked logs detect internal modification when an external trusted anchor is available; they do not prevent a privileged host from rewriting history.

## Attack and control matrix

| Scenario | Attacker capability | Why it matters | Evidence and control |
|---|---|---|---|
| Anonymous connection | Network access only | Authentication | CONNACK denial in both profiles |
| Camera-to-lock command | Camera credentials only | Lateral movement and authorization | Baseline actuator receipt; hardened PUBACK denial |
| Forged lock state | Camera credentials and its own signing key | Telemetry integrity | Delivery in baseline; denied cross-topic write in hardened |
| Wildcard subscription | Camera credentials | Least privilege and confidentiality | Actual disclosed topics during live telemetry |
| Replayed command | Captured application envelope plus command publish permission | Freshness distinct from TLS | Duplicate ID rejected; no additional action |
| Modified command | Command publish permission, no operator signing key | Application authenticity | Bad signature; no action |
| Stale command | Controlled signed fixture, timestamp older than 30 seconds | Delayed valid messages | Stale timestamp decision |
| Retained command | Command publish permission | Unwanted execution on live delivery or reconnect | Retained flag preserved and rejected |
| Invalid schema | Signed fixture with invalid command data | Input validation after authentication | Both profiles reject |
| Bounded valid burst | Signing-capable abusive operator fixture | Application abuse and recovery | 12 attempts at 50 ms requested intervals; limit 5 per 2 seconds |
| Restart replay | Previously accepted envelope and command publish permission | Persistence failure | Same action counter after rejection on restart |

“Masquerade,” “spoofing,” and “injection” overlap here; do not count renamed versions of one test as independent discoveries. Repudiation is an evidence property to discuss, not a packet attack implemented by “denying you sent it.” A changed JSON message is payload tampering; it is not automatically a man-in-the-middle experiment.

## A clear lab demonstration

1. Explain the threat model and show that anonymous access is rejected in **both** profiles.
2. Send a legitimate LOCK and UNLOCK. Point to the signed receipt and action counter.
3. Give the experiment the camera account. Show the baseline's cross-device permissions and the hardened broker's explicit denial.
4. Send a valid operator command and replay the identical application envelope. Explain why TLS does not decide business-command freshness.
5. Restart the hardened lock and repeat promptly. Show that the durable command ID survives restart.
6. Run malformed and bounded-burst cases. Explain why validation remains necessary after authentication and signatures.
7. Show recovery and the measured matrix. Identify one known limitation rather than claiming universal protection.
8. If time permits, disable only the application policy with the ablation override, demonstrate replay acceptance under TLS and ACLs, then restore the full policy.

A good one-sentence answer to “what is your innovation?” is: **“We evaluate compromised-device containment and restart-safe command verification with a reproducible evidence pipeline that separates broker denial from actuator execution.”**

## Important corrections to the supplied synopsis

- Modern Mosquitto 2 requires explicit authentication configuration; do not claim its normal remote-listener default is an open anonymous broker.
- Replace “HMAC enables non-repudiation.” All HMAC secret holders can generate the same authenticator.
- Replace “TLS passes replay” with “an authorized publisher can resend a previously valid application command; the application must enforce freshness.” TLS record replay and application replay are different.
- Remove “Supabase authentication and RLS” unless you actually deploy and test that architecture. This revision uses a local gateway.
- Remove implemented claims for PyShark IDS, occupancy inference, cover traffic, connection-flood resistance, or per-device client certificates. They are not part of the validated implementation.
- A live non-retained MQTT state update can be legitimate. The RETAIN flag does not identify an attacker.
- “Append-only because code opens a file in append mode” is not log immutability.
- Identical code and workload support a matched comparison; changing several security layers simultaneously does not isolate the effect of each individual layer. Use the ablation for a narrower causal claim.
- Check bibliographic metadata and read cited papers before submitting; titles and publication years in an earlier draft are not evidence of support.

## Further improvements in priority order

1. **Certificate and credential lifecycle:** add rotation/revocation tests, expiry alarms, and a compromised-device quarantine workflow. Measure revocation latency and recovery; avoid “automatically secure” claims.
2. **Availability evaluation:** collect broker CPU/memory, legitimate delivery ratios, and recovery time during fixed rate/connection budgets. A packet-size or queue cap is not a volumetric DoS defence.
3. **Independent audit anchoring:** export chain heads to a separately administered append-only store. Show that editing a middle record and truncating the tail are both detected against an anchor.
4. **Traffic analysis as a separate experiment:** implement a labelled occupancy schedule, infer occupancy from encrypted packet metadata, and report accuracy and false-positive rate. Then measure fixed-rate padding's privacy gain and bandwidth cost. Do not claim TLS hides timing.
5. **Usable policy packaging:** supply a device enrollment manifest, generate ACLs from it, and validate that requested topic privileges are minimal. Demonstrate one-command enrollment and controlled revocation.

Prefer completing and measuring one extension over adding several untested features. A defendable scope scores better than eight promised attack names with no evidence.

## Primary references

- [Mosquitto authentication methods](https://mosquitto.org/documentation/authentication-methods/) describes explicit authentication choices in Mosquitto 2 and topic access controls.
- [Mosquitto configuration reference](https://mosquitto.org/man/mosquitto-conf-5.html) defines password files, ACLs, TLS settings, packet and queue limits. These limits need to be interpreted individually.
- [OASIS MQTT 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html) defines protocol acknowledgements, QoS behavior, retained messages, and subscription options.
- [NISTIR 8259A](https://csrc.nist.gov/pubs/ir/8259/a/final) provides a baseline vocabulary for device identification, configuration, data protection, interface access, updates, and security-state awareness. This project addresses a subset; it does not establish NIST compliance.

