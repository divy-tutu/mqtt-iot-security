import { useState } from "react";
import { Link } from "react-router-dom";
import { Activity, ArrowRight, ArrowUpRight, Check, Download, KeyRound, Lock, ShieldAlert, ShieldCheck, Thermometer, Camera, Unlock } from "lucide-react";
import { Layout } from "@/components/Layout";
import { ModeToggle } from "@/components/ModeToggle";
import { useMode } from "@/lib/mode";
import { useLab, type DeviceRecord, type Report } from "@/hooks/useLab";
import thermostatImage from "@/assets/thermostat.jpg";
import cameraImage from "@/assets/security-camera.jpg";

const devices = [
  { topic: "home/livingroom/temperature", name: "Living room", description: "Smart thermostat", icon: Thermometer, image: thermostatImage },
  { topic: "home/frontdoor/lock/state", name: "Front door", description: "Smart lock", icon: Lock, image: null },
  { topic: "home/frontdoor/camera/status", name: "Entrance", description: "Security camera", icon: Camera, image: cameraImage },
];
const readable = (value?: string) => value ? value.replace(/[-_]/g, " ") : "Awaiting data";

function DeviceCard({ index, item, connected, technical }: { index: number; item?: DeviceRecord; connected: boolean; technical: boolean }) {
  const device = devices[index];
  const Icon = device.icon;
  const age = item ? Math.max(0, Date.now() / 1000 - item.received) : Infinity;
  const live = connected && age <= 6;
  const value = !item ? "—" : index === 0 ? `${item.data.temperature}°` : index === 1 ? item.data.state === "LOCKED" ? "Locked" : item.data.state === "UNLOCKED" ? "Unlocked" : "Unknown" : item.data.status === "ONLINE" ? "Online" : item.data.status;
  return <article className="home-device-card">
    <div className={`device-visual ${device.image ? "" : "lock-visual"}`}>
      {device.image ? <img src={device.image} alt={device.description} /> : <div className="door-illustration" aria-hidden="true"><div className="door-panel"><div className="lock-hardware"><span className="lock-led" /><Lock size={26} strokeWidth={1.2} /><div className="door-handle" /></div></div></div>}
      <span className={`device-status ${live ? "is-live" : ""}`}><span />{live ? "Live" : item ? "Stale" : "Waiting"}</span>
      <span className="device-visual-label"><Icon size={14} />{device.description}</span>
    </div>
    <div className="device-information">
      <div className="flex items-end justify-between gap-3"><div><p className="eyebrow">{device.name}</p><p className="device-value">{value}<span>{item && index === 0 ? "C" : ""}</span></p></div><Icon size={22} strokeWidth={1.3} className="text-muted-foreground mb-3" /></div>
      <div className="device-verification">{item?.verified ? <><ShieldCheck size={14} /> Verified reading</> : <><ShieldAlert size={14} /> {item ? "Unverified reading" : "No reading yet"}</>}
        <span>{Number.isFinite(age) ? `${Math.round(age)}s ago` : ""}</span></div>
      {technical && <div className="device-technical"><code>{device.topic}</code>{index === 1 && <p>Executed actions: {item?.data.actions ?? "—"}</p>}</div>}
    </div>
  </article>;
}

function Evidence({ report }: { report: Report | null }) {
  const lastRepeat = report?.rows.length ? Math.max(...report.rows.map(row => row.repeat)) : 0;
  const rows = report?.rows.filter(row => row.repeat === lastRepeat) ?? [];
  function download() {
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url; link.download = "mqtt-experiment.json"; link.click(); URL.revokeObjectURL(url);
  }
  return <section className="lab-panel" id="comparison">
    <div className="panel-heading"><div><p className="eyebrow">Measured evidence</p><h2>The same test. Two outcomes.</h2></div>
      {report && <button className="quiet-button" onClick={download}><Download size={15} /> Export JSON</button>}</div>
    <p className="panel-description">{report ? `Latest run · ${new Date(report.created_utc).toLocaleString()} · ${report.all_expectations_met ? "All expected behaviours matched." : "Some checks need attention."}` : "No experiment report yet. Run the comparison to see actual outcomes here."}</p>
    {rows.length > 0 ? <div className="lab-table-wrap"><table className="lab-table">
      <thead><tr><th scope="col">Scenario</th><th scope="col">Baseline</th><th scope="col">Hardened</th></tr></thead>
      <tbody>{[...new Set(rows.map(row => row.scenario))].map(name => <tr key={name}><th scope="row">{readable(name)}</th>
        {(["baseline", "hardened"] as const).map(profile => {
          const row = rows.find(row => row.scenario === name && row.profile === profile);
          return <td key={profile}><span className={`result-label ${row?.expectation_met ? profile === "baseline" ? "neutral" : "" : "needs-attention"}`}>{readable(row?.outcome)}</span>
            {row?.median_ms !== undefined && <span className="result-detail">Median {row.median_ms.toFixed(1)} ms · p95 {row.p95_ms?.toFixed(1)} ms</span>}</td>;
        })}</tr>)}</tbody>
    </table></div> : <div className="empty-evidence"><Activity size={26} /><p>Your experiment evidence will appear here.</p><code>docker compose --profile test run --rm experiment</code></div>}
    <p className="table-note">Results show the latest repetition. The JSON includes every repetition. “Expected” includes deliberately demonstrated baseline weaknesses.</p>
  </section>;
}

export default function Dashboard({ view = "home" }: { view?: "home" | "lab" }) {
  const { mode: profile } = useMode();
  const lab = useLab(profile, view === "lab");
  const { snapshot, report, session, error, networkError, busy, pending } = lab;
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const technical = view === "lab";
  const secure = profile === "hardened";
  const decision = snapshot?.events.find(event => event.data.command_id === pending);
  const connected = Boolean(snapshot?.connected);
  const profileTitle = secure ? "Hardened" : "Baseline";
  const signedIn = session === "authenticated";
  const latest = snapshot?.events.slice(0, 3) ?? [];
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (await lab.login(username.trim(), password)) setPassword("");
  }

  return <Layout>
    <section className="workspace container-full">
      <div className="workspace-title">
        <div><p className="eyebrow">{technical ? "Look beneath the surface" : "Your connected space"}</p>
          <h1>{technical ? "Security, in focus." : "Welcome home."}</h1>
          <p className="workspace-subtitle">{technical ? "Follow each command from broker permission to device decision." : "A closer connection to the things that make a home."}</p></div>
        <div className="workspace-profile"><span className="eyebrow">Viewing profile</span><ModeToggle disabled={busy} /></div>
      </div>

      {networkError && <p role="status" className="notice notice-warning">{networkError}</p>}
      {error && <p role="alert" className="notice notice-error">{error}</p>}
      {snapshot?.application_policy === "broker-only" && <p role="alert" className="notice notice-warning">Ablation active: TLS and topic permissions remain enabled, but the lock’s application security checks are disabled.</p>}

      {!signedIn ? <section className="signin-panel">
        <div className="signin-story">
          <div className="signin-story-content"><span className="signin-icon"><KeyRound size={25} strokeWidth={1.3} /></span><p className="eyebrow">A space of your own</p><h2>Come on in.</h2><p>Your home’s live devices and security insights, together in one place.</p>
            <div className="signin-trust"><ShieldCheck size={16} /> Access checked by your home gateway</div></div>
        </div>
        <form onSubmit={submit} className="signin-form">
          <p className="eyebrow">{profileTitle} environment</p><h2>{session === "checking" && !networkError ? "Connecting to your home" : "Operator sign in"}</h2>
          <p className="form-intro">Sign in to view live devices{technical ? " and explore the security evidence" : " and manage your front door"}.</p>
          <label htmlFor="username">Username<input id="username" value={username} onChange={event => setUsername(event.target.value)} autoComplete="username" required /></label>
          <label htmlFor="password">Password<input id="password" type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" required /></label>
          <button className="primary-button w-full" disabled={busy}>{busy ? "Signing in…" : "Enter your home"}<ArrowRight size={17} /></button>
          <details className="credentials-help"><summary>Using the local lab?</summary><p>Your generated operator login is in <code>runtime/login.txt</code>. Each profile has its own authenticated session.</p></details>
        </form>
      </section> : <>
        <div className="connection-bar"><span className={`connection-indicator ${connected ? "connected" : ""}`}><span />{connected ? "Connected to your home" : "Reconnecting to your home"}</span>
          <span className="connection-caption">3 simulated devices · {profileTitle} profile</span><button className="quiet-button" disabled={busy} onClick={() => void lab.logout()}>Sign out <ArrowUpRight size={14} /></button></div>

        {technical && <section className={`policy-banner ${secure ? "protected" : "baseline"}`}>
          {secure ? <ShieldCheck size={24} strokeWidth={1.5} /> : <ShieldAlert size={24} strokeWidth={1.5} />}
          <div><h2>{secure ? "Layered controls enabled" : "Authenticated, with broad permissions"}</h2>
            <p>{secure ? "TLS · exact topic permissions · Ed25519 signatures · durable replay checks · command-rate limits" : "Passwords and command validation are enabled. Broad topic access, plaintext transport, and missing freshness checks expose the trusted-LAN assumption."}</p></div>
        </section>}

        <div className="section-heading"><h2>{technical ? "Live device state" : "Your home, at a glance."}</h2><span className="text-xs text-muted-foreground">Updates every few seconds</span></div>
        <section className="home-device-grid" aria-label="Live devices">{devices.map((device, index) => <DeviceCard key={device.topic} index={index} item={snapshot?.messages[device.topic]} connected={connected} technical={technical} />)}</section>

        <div className="control-grid">
          <section className="door-control">
            <div className="panel-heading"><div><p className="eyebrow">Make yourself at home</p><h2>Your front door.</h2></div><span className="round-icon"><KeyRound size={23} strokeWidth={1.3} /></span></div>
            <p className="panel-description">Lock or unlock the simulated door. A device confirmation lets you know when it’s done.</p>
            <div className="command-buttons">
              <button className="primary-button" disabled={busy || !connected} onClick={() => void lab.command("LOCK")}><Lock size={16} /> Lock door</button>
              <button className="secondary-button" disabled={busy || !connected} onClick={() => void lab.command("UNLOCK")}><Unlock size={16} /> Unlock door</button>
            </div>
            <p role="status" className={`command-feedback ${decision?.data.accepted ? "confirmed" : ""}`}>{pending ? decision ? <><Check size={15} />{decision.data.accepted ? `Confirmed · Door ${decision.data.state?.toLowerCase()}` : `Not executed · ${readable(decision.data.reason)}`}</> : <><Activity size={15} />Waiting for the device to confirm your command.</> : <><ShieldCheck size={15} />{technical ? "Broker acknowledgement and device execution are verified separately." : "Your commands are signed by the home gateway."}</>}</p>
          </section>
          <aside className="security-summary">
            <span className="round-icon">{secure ? <ShieldCheck size={24} strokeWidth={1.3} /> : <ShieldAlert size={24} strokeWidth={1.3} />}</span>
            <p className="eyebrow">A little more peace of mind</p><h2>{secure ? "Protection in layers." : "See the difference."}</h2>
            <p>{secure ? "Your devices have individual permissions. The lock checks each command before acting, including whether it has already been used." : "This profile shows a password-protected home that trusts enrolled devices too broadly. Compare it with the hardened profile to see what changes."}</p>
            <Link className="text-link" to={technical ? "/dashboard" : "/lab"}>{technical ? "Back to your home" : "Explore the security lab"}<ArrowRight size={16} /></Link>
          </aside>
        </div>

        {technical ? <>
          <section className="lab-panel">
            <div className="panel-heading"><div><p className="eyebrow">Live verification</p><h2>Every decision has a story.</h2></div><Activity size={21} strokeWidth={1.4} /></div>
            <p className="panel-description">Signed lock receipts show what happened. Gateway verification failures appear separately.</p>
            <div className="lab-table-wrap event-table-wrap"><table className="lab-table"><thead><tr><th scope="col">Received</th><th scope="col">Decision</th><th scope="col">State</th><th scope="col">Actions</th><th scope="col">Evidence</th></tr></thead>
              <tbody>{snapshot?.events.map((event, index) => <tr key={`${event.received}-${index}`}><td className="tabular-nums">{new Date(event.received * 1000).toLocaleTimeString()}</td>
                <td><span className={`result-label ${event.data.accepted ? "" : "needs-attention"}`}>{readable(event.data.reason)}</span></td><td>{event.data.state ?? "—"}</td><td>{event.data.actions ?? "—"}</td><td className="text-xs">{event.verified ? `Verified lock signature · #${event.data.n}` : "Gateway rejection"}</td></tr>)}</tbody>
            </table>{!snapshot?.events.length && <p className="empty-message">No decisions yet. Send a command or run an experiment.</p>}</div>
          </section>
          <Evidence report={report} />
          <p className="lab-scope">Local simulated devices · Browser access uses loopback HTTP; hardened MQTT uses TLS. Signed receipts identify keys, not people. Traffic analysis, firmware security, and Internet-scale DoS are outside this demo.</p>
        </> : <section className="recent-activity">
          <div className="section-heading"><h2>Around the home.</h2><Link to="/lab" className="text-link">View full activity <ArrowUpRight size={14} /></Link></div>
          {latest.length ? latest.map((event, index) => <div className="activity-row" key={`${event.received}-${index}`}><span className="activity-icon">{event.data.accepted ? <Lock size={16} /> : <ShieldAlert size={16} />}</span><div><p>{event.data.accepted ? `Front door ${event.data.state?.toLowerCase()}` : "A command was not executed"}</p><span>{event.verified ? "Confirmed by the lock" : "Gateway verification"} · {readable(event.data.reason)}</span></div><time>{new Date(event.received * 1000).toLocaleTimeString()}</time></div>) : <p className="empty-message">Your device confirmations will appear here.</p>}
        </section>}
      </>}
    </section>
  </Layout>;
}
