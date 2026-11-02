# Synopsis alignment and lab demonstration

This review covers `synopsis_final_rised (1).docx` and the current repository.
The strongest defensible contribution is a reproducible, instrumented comparison
of realistic MQTT misconfiguration, conventional broker controls, and application
defenses. Docker makes that comparison repeatable and isolated. It is not a new
cryptographic defense or proof of superiority over production IoT platforms.

## What needs correcting in the synopsis

1. Replace “undefended broker / client-side login” with “password-protected legacy
   baseline with over-broad topic permissions and missing application checks.”
   Anonymous access and malformed commands must fail in both systems. Do not
   weaken the baseline to force all eight examples to succeed.
2. Replace HMAC and non-repudiation claims with Ed25519 signatures and key-based
   accountability. Shared-key MACs cannot distinguish which key holder authored
   a message. Even asymmetric signatures do not prove a particular human acted
   when keys are shared or compromised. The gateway signs operator commands;
   individual browser users do not have independent command-signing identities.
3. Replace Supabase, row-level security, MQTT.js and browser MQTT WebSockets with
   the actual architecture: Flask server sessions, optional WebAuthn passkeys,
   HTTPS reverse proxy, and server-held MQTT credentials/signing keys. Preserve
   the existing passkey/face-unlock demonstration, but distinguish it from MQTT
   device authentication. The baseline also has a real authenticated website.
4. TLS currently authenticates the broker to clients. Per-device mutual TLS is
   not implemented. Device MQTT passwords and topic ACLs are implemented.
5. PyShark analyses PCAPs offline. Live signed device decisions appear in the
   dashboard, but a passive TLS observer cannot inspect replay IDs or signature
   failures inside ciphertext. There is no general live PyShark behavioral IDS.
6. Traffic-analysis mitigation is restricted to the camera channel: fixed-rate
   publishing and fixed-size padded envelopes. The experiment measures a small
   synthetic activity classifier. It does not prove occupancy privacy for a real
   home, all flows, reconnects, door commands, or arbitrary adversaries.
7. “Modification” is application-envelope alteration by an enrolled publisher.
   It is not an executed man-in-the-middle attack against TLS. Replay means
   resubmission of an application envelope through a valid connection, not replay
   of TLS ciphertext. These distinctions belong in the threat model.
8. Both brokers have connection caps. Full mode additionally limits accepted
   lock commands to five per two seconds. There is no per-IP broker rate limiter
   or volumetric DDoS defense. Queue limits are not publish-rate limits.
9. The audit database is hash-linked, not immutable/WORM. Exported receipt
   segments are signed and can be checked against a separately retained anchor.
   Someone able to replace both the proof and its trusted anchor/key remains
   outside this evidence model. Baseline has signed observer instrumentation too.
10. Replace claims that conventional products “fail silently” or have no audit
    support with the narrower comparison actually tested: this project's chosen
    TLS/password/ACL-only configuration versus additional application controls.

## Eight attacks mapped to six defense groups

| Attack class | Realistic attacker assumption | Baseline demonstration | Full defense and evidence |
|---|---|---|---|
| 1 Unauthorized access | Outsider without a valid password | Rejected: a positive control proving the baseline has basic security | Access control; authentication rejection and capture connection evidence |
| 2 Traffic analysis | Observer can see packet timing and size, without TLS keys | Activity-dependent camera traffic permits a simple classifier | Confidentiality plus fixed cadence/padding; held-out synthetic inference accuracy and TCP payload bytes, with residual metadata risk |
| 3 Masquerade | Attacker has operator MQTT password but no signing key | Broker accepts credentials and unsigned schema-valid commands can execute | Access control plus integrity; signed command requirement gives bad-signature receipt and zero action delta |
| 4 Spoofing/injection | Compromised enrolled camera with its own credentials/key | Camera controls lock or publishes false lock state due to over-broad ACLs | Access control and integrity; PUBACK 135, no forged subscriber payload, no lock action |
| 5 Modification | Enrolled publisher edits a captured command, retaining its signature | Schema-valid altered command executes | Integrity; Ed25519 verification rejects changed content |
| 6 Replay | Captured valid application envelope plus publish access | Identical command executes twice | Freshness; persisted ID cache and 30-second timestamp window reject duplication, including after lock restart |
| 7 Repudiation/evidence tampering | Actor disputes action or edits exported evidence; trusted key/anchor retained separately | Instrumentation records device action but baseline does not verify command authorship | Accountability; signed receipt, payload hash, chain links, modification/truncation checks. No claim of legal non-repudiation |
| 8 Availability pressure | Enrolled client sends bounded command bursts or opens many sessions | Twelve commands execute; connection admission is still capped | Availability; limited action count, bounded connections, subsequent legitimate command succeeds. No guarantee of fair new-client access under saturation |

The six groups are **access control, confidentiality, integrity, freshness,
accountability, and availability**. The architecture's broker/device/adversary/
analysis/accountability/web components are components, not six sequential security
barriers. One attack can involve several defense groups, and one group can address
several attacks.

## What the intermediate comparison proves

For the faculty's “baseline is too weak” objection, use the TLS + ACL column as
the main conventional-security comparator. It already has passwords, encryption,
topic permissions, schema checks and connection caps. Its application-level
failures make the strongest case for the additional controls. Keep the legacy
plaintext baseline to illustrate exposure and over-broad permissions.

The intermediate lock accepts authenticated broker traffic without application
signature/replay/rate checks, while broker TLS and topic ACLs remain enabled.
Camera-to-lock attacks should fail there, but stolen-operator-password, modified
payloads, repeated commands, and accepted-action bursts can still succeed.
Full mode adds those application checks. The privacy probe also compares an
unshaped synthetic client with full shaping. The regular hardened camera remains
shaped during this comparison; the isolated probe flow is identified by its source
port, and the privacy result does not measure all broker traffic.

## One command and an eight-minute presentation

Start Docker Desktop, then run from the repository root:

```powershell
.\run-guided-demo.ps1
```

Allow the run to finish before presenting. Do not click manual lock/unlock controls
during measurement: extra legitimate actions invalidate counter comparisons.
The script saves a uniquely named run directory, captures actual broker-network
traffic, runs the three levels, restores full application controls, and analyses
the PCAPs. A failed check remains visible rather than becoming a green result.

1. **Minute 1: establish a credible baseline.** Sign in at
   `https://localhost:8443/lab`. Show that anonymous access and invalid commands
   are rejected in both modes. Explain the compromised-camera/password assumptions.
2. **Minutes 2–3: demonstrate crossed trust boundaries.** Expand camera-to-lock,
   state forgery, and stolen-operator-password evidence. Compare broker PUBACK
   with actual signed lock decisions and before/after action counts. Explain why
   TLS plus ACLs stop one attack but not the stolen operator password case.
3. **Minute 4: demonstrate application checks.** Compare modified-payload and
   replay outcomes across all three levels. Show replay after receiver restart.
4. **Minute 5: show packet evidence.** Open `baseline.pcap` in Wireshark, filter
   `mqtt`, select a matching frame from the report, and inspect topic/payload.
   Open `hardened.pcap`, filter `tls`, and show encrypted data. Do not claim an
   encrypted packet itself proves rejection; use the corresponding signed receipt.
5. **Minute 6: show traffic-analysis limits and mitigation.** Expand the
   traffic-analysis rows. Compare bytes per labeled window and held-out inference
   accuracy. State “four training and four test windows, synthetic workload.”
   Explain that padding/cover traffic costs bandwidth and cannot conceal all flows.
6. **Minute 7: show accountability and availability.** Expand audit-proof,
   bounded-command-burst, connection-pressure, and recovery rows. Explain that
   deliberate tampering uses copies, not the running database. Connection caps
   help both modes; accepted-command limiting adds a distinct full-mode defense.
7. **Minute 8: close with measured claims.** Show all expected outcomes,
   packet-analysis status, and restoration status. Identify residual limitations
   instead of claiming “unhackable” or “better than all existing systems.”

The `results/captures/<run-id>/` directory contains PCAPs, capture/drop logs,
an archived report and the lock public key. Keep baseline captures private because
they contain lab MQTT passwords. These files are ignored by Git. The report
contains packet SHA-256 values and matching frame numbers; TLS correlation is
time-window-only. Source ports identify the synthetic privacy probe, not a human.

To independently check archived signed receipt segments (Python with cryptography):

```powershell
python lab/audit_proof.py results/captures/<run-id>/report.json results/captures/<run-id>/lock-public.pem
```

Retain the anchor/public-key fingerprint separately before demonstrating evidence
tampering. Verifying an anchor supplied by an untrusted attacker proves nothing
about completeness. Historical signature verification does not reapply the
present-time command freshness window.

## Remaining work before claiming complete synopsis compliance

- A passive PyShark live metadata detector with calibrated thresholds and false
  positive/false negative measurements is still absent. Signed live device
  rejection events are not the same thing.
- Per-IP fairness, reconnect admission protection, mTLS identity lifecycle and
  credential revocation are future extensions, not current demonstrated controls.
- General authorized-but-malicious behavioral detection is not implemented;
  deterministic command limits catch only the specifically tested behavior.
- The camera privacy experiment needs repeated runs and larger independent
  traces before claiming general inference resistance. Report bandwidth cost too.
- Strong external audit anchoring and individual user command-signing keys would
  improve attribution. A filesystem report is not an external trusted timestamp.

## Primary references for corrected claims

- [Mosquitto authentication methods](https://mosquitto.org/documentation/authentication-methods/): current listener authentication is explicitly configured; anonymous network access is not a universal modern default.
- [Mosquitto configuration reference](https://mosquitto.org/man/mosquitto-conf-5.html): connection, packet and queue limits have distinct meanings.
- [TLS 1.3 RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html): traffic-analysis resistance needs additional measures and has performance costs.
- [W3C cryptography guidance](https://www.w3.org/TR/security-guidelines-cryptography/): MACs and asymmetric signatures have different attribution properties.
- [NIST digital signature terminology](https://csrc.nist.gov/glossary/term/digital_signature): signature guarantees depend on the trusted key and identity model.
