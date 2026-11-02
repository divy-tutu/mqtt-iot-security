# Validation record

## Expanded synopsis-aligned demonstration validated 2 November 2026

Final run: `results/captures/20261102T134009Z-6a81f260/report.json`.
All 50 expected outcomes matched; packet analysis completed; the runner verified
full policy restoration on lock and gateway. Independently checking all three
archived signed receipt segments with `lab/audit_proof.py` succeeded. This is a
single-host synthetic workload, not a production certification.

| Measurement | Legacy baseline | TLS and ACL only | Full hardening |
|---|---:|---:|---:|
| Commands accepted from the 12-command burst | 12 | 12 | 5 |
| Commands rejected by action-rate policy | 0 | 0 | 7 |
| New sessions admitted from 52 bounded attempts | 43 | 43 | 43 |
| Synthetic activity inference accuracy, four held-out windows | 100% | 100% | 50% |
| Privacy probe TCP payload bytes, eight windows | 6,714 | 7,158 | 34,624 |
| Captured packets | 2,315 | 2,628 | 2,999 |
| Packets with readable MQTT layers | 1,222 | 0 | 0 |
| Packets with TLS application data | 0 | 1,537 | 1,741 |
| Reported kernel packet drops | 0 | 0 | 0 |

The full camera-shaping probe used approximately 4.8 times the TCP payload bytes
of TLS-only. The classifier is a simple byte-volume threshold trained on four
other windows; these results do not establish general occupancy privacy.
Both profiles already cap connections; seven existing clients account for the
43 additional admissions. Legitimate post-pressure commands succeeded.

Additional checks: 15 security unit tests passed on Windows and in the Linux lab
image; five evidence-analysis unit tests passed; TypeScript and the production
frontend build passed. The HTTPS guided-report endpoint returned 401 without a
session, using the trusted local certificate store (local-CA revocation lookup
was best-effort). The authenticated browser displayed the new comparison matrix.

Development validation caught and corrected an audit-export list-aliasing bug
and capture-tail loss. Captures now use a larger kernel buffer, Docker-local
storage, and a two-second drain period before copying the PCAP out. Earlier
development runs that failed evidence checks are not final proof. The first
expanded run has an `INVALIDATED.txt` note because its exported audit segment
failed independent verification. Preserve that history rather than re-labelling
failed evidence as successful.

See [synopsis alignment and demo guide](SYNOPSIS_ALIGNMENT_AND_DEMO.md) for the
eight classes, six defense groups, assumptions, and remaining synopsis gaps.

## Earlier validation

Validated locally on 28 October 2026 (Asia/Kolkata). This is a single-host software-device experiment, not a production security certification.

## Executed checks

| Check | Result |
|---|---|
| Security policy unit tests | 13 passed |
| HTTP session and TLS identity checks | 20 passed |
| Matched live MQTT experiment | 3 repetitions per profile; all 96 report rows matched expectations |
| Legitimate command and post-burst recovery | Accepted in every repetition, both profiles |
| Camera-to-lock lateral movement | Accepted in baseline; broker denied in hardened |
| Camera forging lock state | Delivered in baseline; broker denied in hardened |
| Replayed application command | Accepted again in baseline; rejected in hardened |
| Bounded 12-command burst | Baseline 12 accepted; hardened 5 accepted and 7 rate-rejected in every repetition |
| Receiver restart | Replayed command rejected after restart; action counter remained 25 |
| TLS and ACL only ablation | Replay accepted with application checks disabled; full controls restored |
| Decision-chain validation | Passed for the exported head |
| Frontend | Production build and TypeScript check passed; HTTPS redirect, TLS identity, Secure session cookie, landing, My Home, and Security Lab inspected; both profile logins, profile switching, sign-out, live telemetry, measured comparison, and signed lock confirmation verified |

The 96 report rows consist of 90 behavior observations and six latency summaries. This is not 96 independent attack classes. The report records expected baseline weaknesses as successful *experiment expectations*, not as secure outcomes.

## Evidence

- [Live experiment](evidence/experiment.json) contains outcomes, observed PUBACK codes, device decisions, counters, payload hashes, and latency observations.
- [API and TLS checks](evidence/api-tls.json) records the individual checks.
- [Restart decisions](evidence/restart-decisions.json) contains the original accepted decision and subsequent replay rejection from the persistent device journal.
- [Ablation decision](evidence/ablation-decision.json) records replay acceptance while the application policy was disabled.
- [Audit head](evidence/audit-head.json) is a saved local anchor. Keep a copy outside the lab host for stronger audit assurance.
- [Image identifiers](evidence/images.txt) and [Python environment](evidence/python-environment.txt) record the tested runtime.

Device receipts were signature-verified by the runner while being received. The exported decisions are decoded records, not an offline signature-verifiable receipt archive. Broker-denial evidence is the recorded MQTT v5 acknowledgement plus available broker logs; no packet captures were collected in this validation.

Latency samples are small and include host scheduling, connection effects, broker delivery, and storage. One hardened repetition had a substantial high-latency observation. Do not hide it or describe the p95 as typical cryptographic overhead. Use a dedicated larger latency study before making performance claims.

## Residual scope

The system runs browser HTTPS on localhost using the private lab CA. Remote production deployment needs a publicly or organizationally trusted certificate. The rate test concerns actuator command processing, not broker-wide or network-wide DoS resistance. Full disk, key rotation, revocation, host compromise, firmware security, traffic analysis, and independent immutable audit storage remain outside the demonstrated implementation.

The original v1 simulator and attack scripts are retained as historical sources but are not launched by the active Docker configuration. Use the commands in the root README.
