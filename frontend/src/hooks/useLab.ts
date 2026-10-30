import { useEffect, useRef, useState } from "react";
import type { SecurityMode } from "@/lib/mode";
import { base64urlToBuffer, bufferToBase64url } from "@/lib/webauthn";

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

  // --- WebAuthn / passkey ---------------------------------------------
  // Mirrors login()/command() above in structure: same busy/error/
  // generation-guard pattern, just a different ceremony underneath.

  async function webauthnStatus(): Promise<boolean> {
    try {
      const res = await fetch(`${base}/webauthn/status`);
      if (!res.ok) return false;
      const data = await res.json();
      return Boolean(data.registered);
    } catch {
      return false;
    }
  }

  async function registerPasskey() {
    setBusy(true); setError("");
    try {
      // Their gateway rejects any POST without a JSON content-type (part of
      // its same-origin/CSRF check in protect()) — this endpoint takes no
      // body, but still needs the header to pass that check.
      const optionsRes = await fetch(`${base}/webauthn/register/options`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
      });
      if (!optionsRes.ok) throw new Error("Could not start passkey setup.");
      const options = await optionsRes.json();
      const publicKey: PublicKeyCredentialCreationOptions = {
        ...options,
        challenge: base64urlToBuffer(options.challenge),
        user: { ...options.user, id: base64urlToBuffer(options.user.id) },
        excludeCredentials: (options.excludeCredentials ?? []).map(
          (c: { id: string; type: string }) => ({ ...c, id: base64urlToBuffer(c.id) }),
        ),
      };
      const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
      const response = credential.response as AuthenticatorAttestationResponse;
      const payload = {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToBase64url(response.clientDataJSON),
          attestationObject: bufferToBase64url(response.attestationObject),
        },
      };
      const verifyRes = await fetch(`${base}/webauthn/register/verify`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
      });
      if (!verifyRes.ok) throw new Error("Passkey setup failed.");
      return true;
    } catch (e) {
      setError((e as Error).message || "Passkey setup failed. Your device may not support passkeys.");
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function loginWithPasskey() {
    const current = generation.current;
    setBusy(true); setError("");
    try {
      const optionsRes = await fetch(`${base}/webauthn/login/options`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
      });
      if (!optionsRes.ok) throw new Error("Could not start passkey sign-in.");
      const options = await optionsRes.json();
      const publicKey: PublicKeyCredentialRequestOptions = {
        ...options,
        challenge: base64urlToBuffer(options.challenge),
        allowCredentials: (options.allowCredentials ?? []).map(
          (c: { id: string; type: string }) => ({ ...c, id: base64urlToBuffer(c.id) }),
        ),
      };
      const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
      const response = credential.response as AuthenticatorAssertionResponse;
      const payload = {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToBase64url(response.clientDataJSON),
          authenticatorData: bufferToBase64url(response.authenticatorData),
          signature: bufferToBase64url(response.signature),
          userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : undefined,
        },
      };
      const verifyRes = await fetch(`${base}/webauthn/login/verify`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
      });
      if (!verifyRes.ok) {
        const data = await verifyRes.json().catch(() => ({}));
        throw new Error(data.error || "Passkey sign-in failed.");
      }
      return current === generation.current;
    } catch (e) {
      if (current === generation.current) setError((e as Error).message || "Passkey sign-in failed.");
      return false;
    } finally {
      if (current === generation.current) setBusy(false);
    }
  }

  return {
    snapshot, report, session, error, networkError, busy, pending,
    login, command, logout, webauthnStatus, registerPasskey, loginWithPasskey,
  };
}
