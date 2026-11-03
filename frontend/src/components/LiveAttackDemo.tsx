import { useEffect, useState } from "react";
import { Activity, Lock, ShieldCheck, ShieldAlert } from "lucide-react";

type Result = {
  profile: "baseline" | "hardened"; outcome: string; attacker: string;
  parameters: Record<string, string | number | boolean>; puback?: number; pubacks?: number[];
  before?: { state: string; actions: number }; after?: { state: string; actions: number };
  action_delta?: number; accepted?: number; rate_rejected?: number;
  first_outcome?: string; second_outcome?: string; inference_accuracy?: number;
  sent_per_window?: number[]; attempts?: { attempt: string; outcome: string }[];
  modification_detected?: boolean; truncation_detected?: boolean;
};
type Report = { scenario: string; title: string; created_utc: string; status: string; results: Result[]; error?: string };

const scripts: Record<string, string> = {
  "unauthorized-access":"01-unauthorized-access.ps1", "traffic-analysis":"02-traffic-analysis.ps1",
  "stolen-credential":"03-stolen-credential.ps1", "camera-injection":"04-camera-injection.ps1",
  modification:"05-modification.ps1", replay:"06-replay.ps1",
  "evidence-tampering":"07-evidence-tampering.ps1", "availability-pressure":"08-availability-pressure.ps1",
};
const words = (value?: string) => value ? value.replace(/[-_]/g, " ") : "waiting";
const protectedOutcome = (outcome: string) => ["authentication-rejected", "broker-rejected", "bad-signature", "replay", "tampering-detected", "rate-limited", "inference-reduced"].includes(outcome);

export function LiveAttackDemo({ profile }: { profile: string }) {
  const [report, setReport] = useState<Report | null>(null);
  useEffect(() => {
    const controller = new AbortController(); let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const response = await fetch(`/api/${profile}/local-attack`, { signal: controller.signal, cache:"no-store" });
        if (response.ok) setReport(await response.json());
      } finally { if (!controller.signal.aborted) timer = setTimeout(poll, 1000); }
    }
    void poll(); return () => { controller.abort(); clearTimeout(timer); };
  }, [profile]);

  return <section className="lab-panel live-attack-demo">
    <div className="panel-heading"><div><p className="eyebrow">Local attack runner</p><h2>Run locally. Observe here.</h2></div><Activity size={22} /></div>
    {!report ? <><p className="panel-description">Run one file from <code>attacks\demo</code>. This page contains no attack controls.</p><p className="empty-message">No local attack result yet.</p></> : <>
      <p className="panel-description">Latest: <strong>{report.title}</strong> · {new Date(report.created_utc).toLocaleString()} · {words(report.status)}</p>
      <code>.\attacks\demo\{scripts[report.scenario]}</code>
      {report.error && <p role="alert" className="notice notice-error">{report.error}</p>}
      <div className="live-attack-grid">
        {(["baseline","hardened"] as const).map(name => {
          const result = report.results.find(item => item.profile === name);
          const protectedResult = Boolean(result && protectedOutcome(result.outcome));
          return <article className={`attack-result-card ${result ? protectedResult ? "blocked" : "compromised" : ""}`} key={name}>
            <p className="eyebrow">{name}</p><div className="attack-door-state">{protectedResult ? <ShieldCheck size={28} /> : <ShieldAlert size={28} />}</div>
            <h3>{result ? words(result.outcome) : report.status === "running" ? "Running…" : "No result"}</h3>
            {result && <>
              <p><strong>Attacker:</strong> {result.attacker}</p>
              {result.puback !== undefined && <p><strong>PUBACK:</strong> {result.puback}</p>}
              {result.before && result.after && <p><strong>Door:</strong> {result.before.state} ({result.before.actions}) → {result.after.state} ({result.after.actions}); delta {result.action_delta}</p>}
              {result.first_outcome && <p><strong>Attempts:</strong> {words(result.first_outcome)} → {words(result.second_outcome)}</p>}
              {result.accepted !== undefined && <p><strong>Burst:</strong> {result.accepted} accepted; {result.rate_rejected} rate-rejected</p>}
              {result.inference_accuracy !== undefined && <p><strong>Inference accuracy:</strong> {Math.round(result.inference_accuracy*100)}%; sent/window {result.sent_per_window?.join(", ")}</p>}
              {result.attempts && <p><strong>Attempts:</strong> {result.attempts.map(item => `${words(item.attempt)}: ${words(item.outcome)}`).join(" · ")}</p>}
              {result.modification_detected !== undefined && <p><strong>Evidence:</strong> modification detected {String(result.modification_detected)}; truncation detected {String(result.truncation_detected)}</p>}
              <div className="attack-parameters">{Object.entries(result.parameters).map(([key,value]) => <span key={key}>{words(key)}: {String(value)}</span>)}</div>
            </>}
          </article>;
        })}
      </div>
    </>}
    <p className="table-note"><Lock size={12} /> The website only reads the saved result. Docker and attack execution remain on the host.</p>
  </section>;
}
