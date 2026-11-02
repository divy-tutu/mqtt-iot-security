import { useEffect, useState } from "react";

type Row = {
  level: string; scenario: string; attacker: string; expected: string; outcome: string;
  expectation_met: boolean; puback?: number; action_delta?: number;
  before?: { state: string; actions: number }; after?: { state: string; actions: number };
  payload_sha256?: string; decision?: { command_id?: string; reason?: string };
  packet_evidence?: { file: string; correlation: string; matching_payload_frames: number[]; window_packets: number };
  privacy_measurement?: { tcp_payload_bytes: number[]; test_accuracy: number; threshold_bytes: number; interpretation: string };
  admitted?: number; attempted?: number; accepted?: number; rate_rejected?: number;
  modification_detected?: boolean; truncation_detected?: boolean; observation?: string;
};
type Demo = {
  run_id: string; created_utc: string; status: string; controls_restored: boolean;
  all_expectations_met?: boolean; error?: string; rows: Row[];
  packet_analysis?: { status: string; error?: string; captures?: {
    file: string; packets: number; mqtt_packets: number; tls_data_packets: number;
    credential_packets: number; expectation_met: boolean;
  }[] };
};
const label = (s: string) => s.replace(/-/g, " ");
const attacks = [
  { name: "1 · Unauthorized access", controls: "Access control", scenarios: ["anonymous", "wrong-password"], context: "An outsider tries to join without valid credentials. Both profiles should reject this basic attack." },
  { name: "2 · Traffic analysis", controls: "Confidentiality and camera shaping", scenarios: ["traffic-analysis"], context: "A passive observer infers synthetic camera activity from traffic volume. Full mode adds fixed cadence and padding; other network metadata remains visible." },
  { name: "3 · Masquerade", controls: "Access control and integrity", scenarios: ["stolen-operator-password"], context: "A stolen MQTT password passes broker login. The attacker still lacks the operator signing key." },
  { name: "4 · State / command injection", controls: "Access control and integrity", scenarios: ["camera-to-lock", "camera-state-forgery"], context: "An enrolled camera attempts to control the door or publish false lock state." },
  { name: "5 · Modification", controls: "Integrity", scenarios: ["modified-payload"], context: "An authorized publisher edits a captured command but keeps its old signature. This demonstrates application tampering, not a TLS man-in-the-middle." },
  { name: "6 · Replay", controls: "Freshness", scenarios: ["replay-copy", "restart-replay"], context: "A captured application envelope is submitted again through a valid connection. TLS ciphertext replay is not being claimed." },
  { name: "7 · Repudiation / evidence tampering", controls: "Accountability", scenarios: ["audit-proof"], context: "Verify signed device receipts; detect edited or truncated copies using a saved anchor. Baseline also has observer instrumentation. Signatures attribute keys, not humans." },
  { name: "8 · Availability pressure", controls: "Availability", scenarios: ["bounded-command-burst", "connection-pressure", "post-connection-recovery"], context: "Apply bounded command and connection pressure. Both profiles cap connections; full mode additionally limits accepted actions. This is not Internet-scale DoS protection." },
];

export function GuidedDemo({ profile }: { profile: string }) {
  const [report, setReport] = useState<Demo | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    setReport(null);
    const poll = async () => {
      try {
        const response = await fetch(`/api/${profile}/guided-demo`, { signal: controller.signal, cache: "no-store" });
        if (response.status === 404) { setReport(null); setError(""); }
        else if (!response.ok) throw new Error("Cannot load guided evidence. Check your connection and sign-in.");
        else { setReport(await response.json()); setError(""); }
      } catch (e) {
        if (!controller.signal.aborted) { setReport(null); setError(e instanceof Error ? e.message : "Evidence unavailable"); }
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(poll, 3000);
      }
    };
    void poll();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [profile]);
  return <section className="lab-panel guided-demo">
    <div className="panel-heading"><div><p className="eyebrow">Guided experiment · Packet evidence</p><h2>Follow an attack through the layers.</h2></div></div>
    <p className="panel-description">Run <code>.\run-guided-demo.ps1</code> in the project terminal. Capture, attack checks, and PyShark analysis run automatically. Avoid manual commands during measurement.</p>
    <p className="panel-description">Six defense groups: access control · confidentiality · integrity · freshness · accountability · availability. Docker isolates and reproduces the experiment; the controls provide security.</p>
    {error && <p role="alert">{error}</p>}
    {!report && !error && <p className="empty-message">No guided run saved yet.</p>}
    {report && <>
      <p role="status">Saved run: {new Date(report.created_utc).toLocaleString()} · {label(report.status)} · {report.rows.filter(r => r.expectation_met).length}/{report.rows.length} expected outcomes</p>
      <p>Full controls: {report.controls_restored ? "restoration verified" : "restoration pending"}. Packet analysis: {report.packet_analysis?.status ?? "pending"}. Overall: {report.all_expectations_met ? "verified" : "not yet verified"}.</p>
      {(report.error || report.packet_analysis?.error) && <p role="alert">{report.error || report.packet_analysis?.error}</p>}
      <h3>Eight attack classes, with observed evidence</h3>
      <div className="lab-table-wrap"><table className="lab-table"><thead><tr><th>Attack and assumption</th><th>Defense groups</th><th>Baseline</th><th>TLS + ACL only</th><th>Full hardening</th></tr></thead><tbody>
        {attacks.map(attack => <tr key={attack.name}><td><strong>{attack.name}</strong><details><summary>Attacker model</summary><p>{attack.context}</p></details></td><td>{attack.controls}</td>{["baseline", "intermediate", "hardened"].map(level => {
          const rows = report.rows.filter(r => r.level === level && attack.scenarios.includes(r.scenario));
          return <td key={level}>{rows.length ? rows.map(r => <p key={r.scenario}><span className={`result-label ${r.expectation_met ? "neutral" : "needs-attention"}`}>{label(r.outcome)}</span>{r.privacy_measurement && <> · {Math.round(r.privacy_measurement.test_accuracy * 100)}% inference accuracy (4 test windows)</>}</p>) : "Not measured yet"}</td>;
        })}</tr>)}
      </tbody></table></div>
      <div className="lab-table-wrap"><table className="lab-table"><thead><tr><th>Capture</th><th>Packets</th><th>Readable MQTT packets</th><th>TLS data packets</th><th>Check</th></tr></thead>
        <tbody>{report.packet_analysis?.captures?.map(c => <tr key={c.file}><td>{c.file.split("/").pop()}</td><td>{c.packets}</td><td>{c.mqtt_packets}</td><td>{c.tls_data_packets}</td><td>{c.expectation_met ? "Verified" : "Inconclusive"}</td></tr>)}</tbody>
      </table></div>
      <p className="panel-description">PCAPs and the archived report: <code>results/captures/{report.run_id}/</code>. Open PCAPs in Wireshark. TLS visibility shows encryption; signed receipts and action counters establish whether commands executed.</p>
      <div className="lab-table-wrap"><table className="lab-table"><thead><tr><th>Level / scenario</th><th>Expected</th><th>Observed</th><th>Evidence</th></tr></thead>
        <tbody>{report.rows.map((r, i) => <tr key={i}><td>{label(r.level)}<br />{label(r.scenario)}</td><td>{label(r.expected)}</td><td><span className={`result-label ${r.expectation_met ? "neutral" : "needs-attention"}`}>{label(r.outcome)}</span></td><td><details><summary>Inspect evidence</summary>
          <p>{r.attacker}</p><p>PUBACK: {r.puback ?? "not applicable"}; action change: {r.action_delta ?? "not applicable"}</p>
          {r.before && r.after && <p>{r.before.state} ({r.before.actions}) → {r.after.state} ({r.after.actions})</p>}
          {r.decision && <p>Verified receipt: {r.decision.reason}; command: {r.decision.command_id}</p>}
          {r.payload_sha256 && <p style={{ overflowWrap: "anywhere" }}>Payload SHA-256: {r.payload_sha256}</p>}
          {r.privacy_measurement && <p>TCP payload bytes per window: {r.privacy_measurement.tcp_payload_bytes.join(", ")}. Held-out accuracy: {Math.round(r.privacy_measurement.test_accuracy * 100)}%. {r.privacy_measurement.interpretation}</p>}
          {r.attempted !== undefined && <p>Connections admitted: {r.admitted}/{r.attempted}.</p>}
          {r.accepted !== undefined && <p>Commands accepted: {r.accepted}; rate rejected: {r.rate_rejected}.</p>}
          {r.modification_detected !== undefined && <p>Receipt modification detected: {String(r.modification_detected)}; truncation detected: {String(r.truncation_detected)}.</p>}
          {r.observation && <p>{r.observation}</p>}
          {r.packet_evidence && <p>{r.packet_evidence.correlation}. Window: {r.packet_evidence.window_packets} packets. Matching frames: {r.packet_evidence.matching_payload_frames.join(", ") || "none / encrypted"}.</p>}
        </details></td></tr>)}</tbody>
      </table></div>
    </>}
  </section>;
}
