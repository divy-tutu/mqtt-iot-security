/**
 * Browser-side crypto for the SECURE build — the mirror image of
 * devices/secure_common.py, using the Web Crypto API (crypto.subtle).
 *
 *  - verifyEnvelope(): checks the HMAC-SHA256 signature over the exact `msg`
 *    string that was transmitted (Integrity), then seq + timestamp + nonce
 *    freshness (replay protection).
 *  - signCommand(): produces a signed {msg,sig} envelope for a lock command,
 *    signed with the operator key — exactly what tools/send_command.py sends.
 *
 * Web Crypto needs a secure context; http://localhost counts as one, so this
 * works under `vite dev` without TLS on the page itself.
 *
 * Testbed caveat: the HMAC keys reach the browser via Vite env vars. A real
 * deployment would never ship device/operator keys to a client — see the
 * on-screen notice in the secure dashboard.
 */

const MAX_CLOCK_SKEW_S = 30;

const enc = new TextEncoder();

async function hmacHex(keyStr: string, msg: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(keyStr),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Deterministic JSON with recursively sorted keys and no whitespace,
 *  matching Python's json.dumps(sort_keys=True, separators=(",",":")). */
export function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJSON).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const parts = Object.keys(obj)
    .sort()
    .map((k) => JSON.stringify(k) + ":" + canonicalJSON(obj[k]));
  return "{" + parts.join(",") + "}";
}

export interface SignedFields {
  device: string;
  seq: number;
  ts: number;
  nonce: string;
  data: Record<string, unknown>;
}

export type VerifyReason =
  | "ok"
  | "malformed-json"
  | "missing-fields"
  | "unknown-device"
  | "bad-signature"
  | "stale-timestamp"
  | "replayed-seq"
  | "replayed-nonce";

export interface VerifyResult {
  ok: boolean;
  reason: VerifyReason;
  device?: string;
  seq?: number;
  ts?: number;
  data?: Record<string, unknown>;
}

/**
 * Stateful verifier: keeps per-device replay state (highest seq + seen nonces),
 * just like the Python Verifier. `keys` maps device-id -> hex HMAC key.
 */
export class EnvelopeVerifier {
  private lastSeq = new Map<string, number>();
  private nonces = new Map<string, Set<string>>();

  constructor(private keys: Record<string, string | undefined>) {}

  async verify(payload: string): Promise<VerifyResult> {
    let msg: string;
    let sig: string;
    let f: SignedFields;
    try {
      const outer = JSON.parse(payload);
      msg = outer.msg;
      sig = outer.sig;
      f = JSON.parse(msg);
    } catch {
      return { ok: false, reason: "malformed-json" };
    }
    if (
      typeof msg !== "string" ||
      typeof sig !== "string" ||
      !f ||
      f.device === undefined ||
      f.seq === undefined ||
      f.ts === undefined ||
      f.nonce === undefined ||
      f.data === undefined
    ) {
      return { ok: false, reason: "missing-fields" };
    }

    const key = this.keys[f.device];
    if (!key) return { ok: false, reason: "unknown-device", device: f.device };

    // Integrity: HMAC over the exact transmitted msg bytes.
    const expected = await hmacHex(key, msg);
    if (expected !== sig) {
      return { ok: false, reason: "bad-signature", device: f.device, seq: f.seq };
    }

    // Freshness: timestamp window.
    if (Math.abs(Date.now() / 1000 - f.ts) > MAX_CLOCK_SKEW_S) {
      return { ok: false, reason: "stale-timestamp", device: f.device, seq: f.seq };
    }
    // Freshness: monotonic sequence.
    if (f.seq <= (this.lastSeq.get(f.device) ?? 0)) {
      return { ok: false, reason: "replayed-seq", device: f.device, seq: f.seq };
    }
    // Freshness: unseen nonce.
    const seen = this.nonces.get(f.device) ?? new Set<string>();
    if (seen.has(f.nonce)) {
      return { ok: false, reason: "replayed-nonce", device: f.device, seq: f.seq };
    }

    this.lastSeq.set(f.device, f.seq);
    seen.add(f.nonce);
    this.nonces.set(f.device, seen);
    return { ok: true, reason: "ok", device: f.device, seq: f.seq, ts: f.ts, data: f.data };
  }
}

// Monotonic seq for operator commands (seconds-based, like send_command.py).
let cmdSeq = Math.floor(Date.now() / 1000);

/** Build a signed {msg,sig} lock command as the `dashboard` operator. */
export async function signCommand(
  operatorKey: string,
  cmd: "LOCK" | "UNLOCK"
): Promise<string> {
  cmdSeq += 1;
  const nonce = crypto
    .getRandomValues(new Uint8Array(16))
    .reduce((s, b) => s + b.toString(16).padStart(2, "0"), "");
  const msg = canonicalJSON({
    device: "dashboard",
    seq: cmdSeq,
    ts: Date.now() / 1000,
    nonce,
    data: { cmd },
  });
  const sig = await hmacHex(operatorKey, msg);
  return JSON.stringify({ msg, sig });
}
