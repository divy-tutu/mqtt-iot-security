import { useEffect, useRef, useState } from "react";
import type { SecurityMode } from "@/lib/mode";

export type Decision = { accepted?: boolean; reason?: string; state?: string; actions?: number; command_id?: string; n?: number };
export type DeviceRecord = { topic: string; data: Decision & { temperature?: number; status?: string; motion?: boolean }; received: number; verified: boolean };
export type Snapshot = { application_policy?: string; connected: boolean; messages: Record<string, DeviceRecord>; events: DeviceRecord[]; server_time: number };
export type ReportRow = { profile: string; scenario: string; repeat: number; expectation_met: boolean; outcome: string; median_ms?: number; p95_ms?: number };
export type Report = { created_utc: string; rows: ReportRow[]; all_expectations_met: boolean; error?: string };

export function useLab(profile: SecurityMode, includeReport: boolean) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [session, setSession] = useState<"checking" | "authenticated" | "signedout">("checking");
  const [error, setError] = useState("");
  const [networkError, setNetworkError] = useState("");
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<string | null>(null);
  const generation = useRef(0);
  const base = `/api/${profile}`;

  useEffect(() => {
    const current = ++generation.current;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    let polls = 0;
    setSession("checking"); setSnapshot(null); setReport(null);
    setPending(null); setError(""); setNetworkError(""); setBusy(false);
    async function poll() {
      try {
        const response = await fetch(`${base}/snapshot`, { signal: controller.signal });
        if (current !== generation.current) return;
        if (response.status === 401) {
          setSession("signedout"); setSnapshot(null); setReport(null); setNetworkError("");
        } else {
          if (!response.ok) throw new Error("Gateway unavailable");
          const data: Snapshot = await response.json();
          if (current !== generation.current) return;
          setSnapshot(data); setSession("authenticated"); setNetworkError("");
          if (includeReport && polls++ % 5 === 0) {
            const result = await fetch(`${base}/report`, { signal: controller.signal });
            if (result.ok) {
              const evidence: Report = await result.json();
              if (current === generation.current) setReport(evidence);
            }
          }
        }
      } catch {
        if (current === generation.current) {
          setNetworkError("Your home is temporarily offline. Reconnecting automatically.");
          setSnapshot(null);
        }
      } finally {
        if (current === generation.current) timer = setTimeout(poll, 1000);
      }
    }
    void poll();
    return () => { generation.current++; controller.abort(); clearTimeout(timer); };
  }, [base, includeReport]);

  async function post(path: string, body: object) {
    const response = await fetch(`${base}/${path}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || "The request could not be completed. Please try again.");
    }
    return response.json();
  }

  async function login(username: string, password: string) {
    const current = generation.current;
    setBusy(true); setError("");
    try {
      await post("login", { username, password });
      // Authentication is confirmed by the following server snapshot.
      return current === generation.current;
    } catch (e) {
      if (current === generation.current) setError((e as Error).message);
      return false;
    } finally { if (current === generation.current) setBusy(false); }
  }

  async function command(cmd: "LOCK" | "UNLOCK") {
    const current = generation.current;
    setBusy(true); setError("");
    try {
      const data = await post("command", { cmd });
      if (current === generation.current) setPending(data.command_id);
    } catch (e) { if (current === generation.current) setError((e as Error).message); }
    finally { if (current === generation.current) setBusy(false); }
  }

  async function logout() {
    const current = generation.current;
    setBusy(true); setError("");
    try {
      await post("logout", {});
      if (current === generation.current) {
        setSession("signedout"); setSnapshot(null); setReport(null); setPending(null);
      }
    } catch (e) { if (current === generation.current) setError((e as Error).message); }
    finally { if (current === generation.current) setBusy(false); }
  }

  return { snapshot, report, session, error, networkError, busy, pending, login, command, logout };
}
