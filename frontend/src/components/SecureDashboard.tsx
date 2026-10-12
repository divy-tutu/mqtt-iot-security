import { useState } from "react";
import {
  Thermometer,
  Lock,
  Camera,
  Unlock,
  ShieldCheck,
  ShieldAlert,
  KeyRound,
  LogOut,
} from "lucide-react";
import { toast } from "sonner";
import { LiveDeviceCard } from "@/components/LiveDeviceCard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useSecureMqtt } from "@/hooks/useSecureMqtt";
import { isSecurelyAuthed, secureLogin, secureLogout } from "@/lib/auth";
import { TOPICS, MQTT_WSS_URL, SECURE_CONFIGURED } from "@/lib/mqtt-config";
import type { ConnStatus } from "@/hooks/useMqtt";
import { cn } from "@/lib/utils";

const statusLabel: Record<ConnStatus, string> = {
  connecting: "Connecting…",
  connected: "Connected (TLS)",
  reconnecting: "Reconnecting…",
  offline: "Offline",
  error: "Connection failed",
};

/* --- A real login gate (contrast with the insecure build's no-op flag) --- */
const SecureLogin = ({ onSuccess }: { onSuccess: () => void }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    const ok = await secureLogin(username.trim(), password);
    setBusy(false);
    if (ok) onSuccess();
    else setErr("Invalid credentials.");
  };

  return (
    <div className="max-w-md mx-auto border border-primary/30 bg-primary/5 p-8 md:p-10">
      <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-primary/10 mb-5">
        <KeyRound className="w-6 h-6 text-primary" />
      </div>
      <h2 className="font-serif text-2xl text-foreground mb-2">Sign in</h2>
      <p className="text-sm text-muted-foreground mb-6">
        The secure build validates credentials and guards the dashboard — the
        device grid and broker connection only load after a successful login.
      </p>
      <form onSubmit={submit} className="space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="su">Username</Label>
          <Input id="su" value={username} onChange={(e) => setUsername(e.target.value)}
                 autoComplete="username" placeholder="admin" />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="sp">Password</Label>
          <Input id="sp" type="password" value={password}
                 onChange={(e) => setPassword(e.target.value)}
                 autoComplete="current-password" placeholder="••••••••" />
        </div>
        {err && <p className="text-sm text-destructive">{err}</p>}
        <Button type="submit" disabled={busy} className="w-full">
          {busy ? "Checking…" : "Sign in"}
        </Button>
      </form>
      <p className="text-xs text-muted-foreground/70 mt-5 font-mono">
        demo: admin / homepulse-secure-2026
      </p>
    </div>
  );
};

const ConnectionPill = ({ status }: { status: ConnStatus }) => {
  const ok = status === "connected";
  return (
    <span className="inline-flex items-center gap-2 text-[11px] tracking-[0.15em] uppercase text-muted-foreground">
      <span className={cn("w-2 h-2 rounded-full",
        ok ? "bg-green-500 animate-pulse" : status === "error" ? "bg-destructive" : "bg-amber-500")} />
      {statusLabel[status]}
      <span className="font-mono text-[10px] normal-case tracking-normal text-muted-foreground/60">
        {MQTT_WSS_URL}
      </span>
    </span>
  );
};

const VerifiedBadge = ({ seq }: { seq?: number }) => (
  <span className="inline-flex items-center gap-1.5 text-[10px] tracking-[0.12em] uppercase text-green-600">
    <ShieldCheck className="w-3.5 h-3.5" />
    Signed &amp; verified{seq !== undefined ? ` · seq ${seq}` : ""}
  </span>
);

/* --- The authenticated, verified device view --- */
const SecureView = ({ onLogout }: { onLogout: () => void }) => {
  const { status, error, messages, events, sendCommand } = useSecureMqtt(true);
  const [sending, setSending] = useState(false);

  const temp = messages[TOPICS.temperature];
  const lock = messages[TOPICS.lockState];
  const cam = messages[TOPICS.cameraStatus];

  const rejected = events.filter((e) => !e.ok);

  const send = async (cmd: "LOCK" | "UNLOCK") => {
    setSending(true);
    try {
      await sendCommand(cmd);
      toast.success(`Signed ${cmd} command sent`, {
        description: "HMAC-signed with the operator key; the lock verifies it before acting.",
      });
    } catch (e) {
      toast.error("Command failed", { description: (e as Error).message });
    } finally {
      setSending(false);
    }
  };

  return (
    <>
      <div className="flex items-center justify-between gap-4 mb-8 flex-wrap">
        <ConnectionPill status={status} />
        <Button variant="ghost" size="sm" onClick={onLogout} className="gap-2">
          <LogOut className="w-4 h-4" /> Sign out
        </Button>
      </div>

      {error && (
        <div className="border border-destructive/40 bg-destructive/5 p-4 mb-6 text-sm">
          <p className="text-destructive font-medium">Secure connection failed: {error}</p>
          <p className="text-foreground/70 mt-1">
            The browser must trust the testbed CA to open <code className="font-mono text-xs">wss://localhost:9002</code>.
            Import <code className="font-mono text-xs">broker/certs/ca.crt</code> into your OS/browser trust store,
            and ensure the hardened stack is up.
          </p>
        </div>
      )}

      {/* Testbed honesty notice */}
      <div className="border border-primary/30 bg-primary/5 p-4 mb-6 flex gap-3">
        <ShieldCheck className="w-5 h-5 text-primary shrink-0 mt-0.5" />
        <div className="text-sm text-foreground/80 leading-relaxed">
          <span className="font-medium text-foreground">Two auth layers, both real here.</span>{" "}
          Human → dashboard (the login above) and machine → broker (TLS + the{" "}
          <code className="font-mono text-xs">dashboard</code> credential + ACLs). Each card below is
          driven only by an envelope whose <span className="text-foreground">HMAC signature and freshness</span>{" "}
          verified in your browser.{" "}
          <span className="text-muted-foreground">
            Testbed simplification: the HMAC keys are shipped to the browser via env — a real
            deployment would keep them server-side.
          </span>
        </div>
      </div>

      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
        <LiveDeviceCard
          name="Living Room Thermostat" room="Living Room" topic={TOPICS.temperature}
          icon={Thermometer} value={temp?.value ?? null} lastTs={temp?.ts ? temp.ts * 1000 : undefined}
          badge={temp ? <VerifiedBadge seq={temp.seq} /> : undefined}
        />
        <LiveDeviceCard
          name="Front Door Lock" room="Front Door" topic={TOPICS.lockState}
          icon={lock?.value === "UNLOCKED" ? Unlock : Lock}
          value={lock?.value ?? null} lastTs={lock?.ts ? lock.ts * 1000 : undefined}
          badge={lock ? <VerifiedBadge seq={lock.seq} /> : undefined}
        />
        <LiveDeviceCard
          name="Front Door Camera" room="Front Door" topic={TOPICS.cameraStatus}
          icon={Camera} value={cam?.value ?? null} lastTs={cam?.ts ? cam.ts * 1000 : undefined}
          badge={cam ? <VerifiedBadge seq={cam.seq} /> : undefined}
        />
      </div>

      {/* Signed lock control */}
      <div className="mt-10 border border-border p-6">
        <h3 className="text-[11px] font-semibold tracking-[0.2em] uppercase text-muted-foreground mb-4">
          Lock control (signed commands)
        </h3>
        <div className="flex items-center gap-3">
          <Button onClick={() => send("LOCK")} disabled={sending || status !== "connected"} className="gap-2">
            <Lock className="w-4 h-4" /> Lock
          </Button>
          <Button onClick={() => send("UNLOCK")} disabled={sending || status !== "connected"}
                  variant="outline" className="gap-2">
            <Unlock className="w-4 h-4" /> Unlock
          </Button>
          <p className="text-xs text-muted-foreground ml-2">
            Signed with the operator key and sent to{" "}
            <code className="font-mono">{TOPICS.lockCmd}</code>; the lock rejects any replay.
          </p>
        </div>
      </div>

      {/* Verification log */}
      {events.length > 0 && (
        <div className="mt-10">
          <h3 className="text-[11px] font-semibold tracking-[0.2em] uppercase text-muted-foreground mb-3">
            Envelope verification log (live)
            {rejected.length > 0 && (
              <span className="ml-2 text-destructive normal-case tracking-normal">
                · {rejected.length} rejected
              </span>
            )}
          </h3>
          <div className="border border-border divide-y divide-border font-mono text-xs">
            {events.map((e, i) => (
              <div key={`${e.ts}-${i}`} className="flex items-center gap-3 px-4 py-2">
                <span className="text-muted-foreground/60 shrink-0">
                  {new Date(e.ts).toLocaleTimeString()}
                </span>
                <span className={cn("shrink-0 inline-flex items-center gap-1 w-28",
                  e.ok ? "text-green-600" : "text-destructive")}>
                  {e.ok ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                  {e.ok ? "verified" : "rejected"}
                </span>
                <span className="text-foreground/70 truncate">{e.topic}</span>
                <span className="ml-auto text-foreground/60">
                  {e.device ?? "?"}{e.seq !== undefined ? ` seq ${e.seq}` : ""} · {e.reason}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
};

export const SecureDashboard = () => {
  const [authed, setAuthed] = useState(isSecurelyAuthed());

  if (!SECURE_CONFIGURED) {
    return (
      <div className="max-w-2xl mx-auto border border-dashed border-amber-500/50 bg-amber-500/5 p-10 text-center">
        <ShieldAlert className="w-10 h-10 text-amber-600 mx-auto mb-4" />
        <h2 className="font-serif text-2xl text-foreground mb-3">Secure build not configured</h2>
        <p className="text-sm text-muted-foreground leading-relaxed">
          The secure dashboard needs <code className="font-mono text-xs">frontend/.env.local</code>{" "}
          (broker credential + HMAC keys). Run{" "}
          <code className="font-mono text-xs">./setup-hardened.sh</code> from the repo root, then restart{" "}
          <code className="font-mono text-xs">vite</code>.
        </p>
      </div>
    );
  }

  if (!authed) return <SecureLogin onSuccess={() => setAuthed(true)} />;

  return <SecureView onLogout={() => { secureLogout(); setAuthed(false); }} />;
};
