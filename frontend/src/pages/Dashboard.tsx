import { Thermometer, Lock, Camera, AlertTriangle, Unlock, ShieldOff } from "lucide-react";
import { Layout } from "@/components/Layout";
import { LiveDeviceCard } from "@/components/LiveDeviceCard";
import { SecureStub } from "@/components/SecureStub";
import { useMode } from "@/lib/mode";
import { useMqtt, type ConnStatus } from "@/hooks/useMqtt";
import { TOPICS, MQTT_WS_URL } from "@/lib/mqtt-config";
import { cn } from "@/lib/utils";

const statusLabel: Record<ConnStatus, string> = {
  connecting: "Connecting…",
  connected: "Connected",
  reconnecting: "Reconnecting…",
  offline: "Offline",
  error: "Connection failed",
};

const ConnectionPill = ({ status }: { status: ConnStatus }) => {
  const ok = status === "connected";
  return (
    <span className="inline-flex items-center gap-2 text-[11px] tracking-[0.15em] uppercase text-muted-foreground">
      <span
        className={cn(
          "w-2 h-2 rounded-full",
          ok ? "bg-green-500 animate-pulse" : status === "error" ? "bg-destructive" : "bg-amber-500"
        )}
      />
      {statusLabel[status]}
      <span className="font-mono text-[10px] normal-case tracking-normal text-muted-foreground/60">
        {MQTT_WS_URL}
      </span>
    </span>
  );
};

const InsecureDashboard = () => {
  const { status, error, messages, lockEvents } = useMqtt(true);

  const temp = messages[TOPICS.temperature];
  const lock = messages[TOPICS.lockState];
  const cam = messages[TOPICS.cameraStatus];

  const intrusions = lockEvents.filter((e) => e.kind !== "baseline");
  const latestIntrusion = intrusions[0];
  const tampered = intrusions.length > 0;

  return (
    <>
      <div className="flex flex-col gap-2 mb-8">
        <ConnectionPill status={status} />
        {error && (
          <p className="text-xs text-destructive font-mono">
            {error} — is the broker up? (<code>docker compose up</code>, WS on 9001)
          </p>
        )}
      </div>

      {/* App-layer vulnerability note */}
      <div className="border border-amber-500/40 bg-amber-500/5 p-4 mb-6 flex gap-3">
        <ShieldOff className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
        <div className="text-sm text-foreground/80 leading-relaxed">
          <span className="font-medium text-foreground">App layer is unprotected.</span>{" "}
          The login never validates credentials (it just sets a{" "}
          <code className="font-mono text-xs">sessionStorage</code> flag in{" "}
          <code className="font-mono text-xs">lib/auth.ts</code>), and{" "}
          <code className="font-mono text-xs">/dashboard</code> has no route guard — anyone can
          open it directly, no login required. But the UI is not the real boundary…
        </div>
      </div>

      {/* Broker-layer attack banner — driven by real retained messages */}
      {tampered && (
        <div className="border border-destructive bg-destructive/10 p-4 mb-6 flex gap-3 animate-in fade-in">
          <AlertTriangle className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
          <div className="text-sm leading-relaxed">
            <p className="font-medium text-destructive">
              Unauthenticated client published to{" "}
              <code className="font-mono text-xs">{latestIntrusion.topic}</code>
            </p>
            <p className="text-foreground/70 mt-1">
              An anonymous MQTT client (no credentials) forged{" "}
              <code className="font-mono text-xs">{latestIntrusion.payload}</code> onto the lock.
              Because this dashboard subscribes to <code className="font-mono text-xs">home/#</code>{" "}
              anonymously, the forged retained message drives the card below — exactly what{" "}
              <code className="font-mono text-xs">attacks/inject.py</code> produces.
            </p>
          </div>
        </div>
      )}

      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
        <LiveDeviceCard
          name="Living Room Thermostat"
          room="Living Room"
          topic={TOPICS.temperature}
          icon={Thermometer}
          value={temp ? `${temp.value}°C` : null}
          lastTs={temp?.ts}
        />
        <LiveDeviceCard
          name="Front Door Lock"
          room="Front Door"
          topic={TOPICS.lockState}
          icon={tampered && lock?.value === "UNLOCKED" ? Unlock : Lock}
          value={lock?.value ?? null}
          lastTs={lock?.ts}
          alarmed={tampered}
        />
        <LiveDeviceCard
          name="Front Door Camera"
          room="Front Door"
          topic={TOPICS.cameraStatus}
          icon={Camera}
          value={cam?.value ?? null}
          lastTs={cam?.ts}
        />
      </div>

      {/* Live event log for the lock — real broker traffic */}
      {lockEvents.length > 0 && (
        <div className="mt-10">
          <h3 className="text-[11px] font-semibold tracking-[0.2em] uppercase text-muted-foreground mb-3">
            Lock topic activity (live from broker)
          </h3>
          <div className="border border-border divide-y divide-border font-mono text-xs">
            {lockEvents.map((e, i) => (
              <div key={`${e.ts}-${i}`} className="flex items-center gap-3 px-4 py-2">
                <span className="text-muted-foreground/60 shrink-0">
                  {new Date(e.ts).toLocaleTimeString()}
                </span>
                <span
                  className={cn(
                    "shrink-0 w-24 uppercase tracking-wider text-[10px]",
                    e.kind === "baseline" ? "text-muted-foreground" : "text-destructive"
                  )}
                >
                  {e.kind === "baseline" ? "device" : "forged"}
                </span>
                <span className="text-foreground/70 truncate">{e.topic}</span>
                <span className="text-foreground ml-auto">{e.payload}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
};

const Dashboard = () => {
  const mode = useMode((s) => s.mode);

  return (
    <Layout>
      <section className="py-16 md:py-24">
        <div className="container-full">
          <div className="flex items-end justify-between mb-10 gap-4">
            <div>
              <p className="text-[11px] font-semibold tracking-[0.3em] uppercase text-primary mb-3">
                My Home
              </p>
              <h1 className="font-serif text-4xl md:text-5xl text-foreground">Your Devices</h1>
            </div>
            <span
              className={cn(
                "text-[11px] font-semibold tracking-[0.2em] uppercase px-3 py-1.5",
                mode === "insecure"
                  ? "bg-destructive/10 text-destructive"
                  : "bg-primary/10 text-primary"
              )}
            >
              {mode} mode
            </span>
          </div>

          {mode === "insecure" ? <InsecureDashboard /> : <SecureStub />}
        </div>
      </section>
    </Layout>
  );
};

export default Dashboard;
