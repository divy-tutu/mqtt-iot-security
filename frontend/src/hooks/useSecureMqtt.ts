import { useCallback, useEffect, useRef, useState } from "react";
import mqtt, { type MqttClient } from "mqtt";
import {
  MQTT_WSS_URL,
  SECURE_BROKER,
  HMAC_KEYS,
  OPERATOR_HMAC_KEY,
  TOPICS,
  WILDCARD,
} from "@/lib/mqtt-config";
import { EnvelopeVerifier, signCommand, type VerifyReason } from "@/lib/secure-crypto";
import type { ConnStatus } from "@/hooks/useMqtt";

export interface VerifiedMessage {
  topic: string;
  device: string;
  seq: number;
  ts: number;
  value: string;
  verified: boolean;
  reason: VerifyReason;
  count: number;
}

export interface VerifyEvent {
  ts: number;
  topic: string;
  device?: string;
  seq?: number;
  ok: boolean;
  reason: VerifyReason;
}

export interface SecureMqttState {
  status: ConnStatus;
  error: string | null;
  messages: Record<string, VerifiedMessage>;
  events: VerifyEvent[];
  /** Sign + publish a lock command; resolves once published (or rejects). */
  sendCommand: (cmd: "LOCK" | "UNLOCK") => Promise<void>;
}

const MAX_EVENTS = 25;

/** Render the business value out of a verified envelope's `data`. */
function formatValue(topic: string, data: Record<string, unknown>): string {
  if (topic === TOPICS.temperature) return `${data.temperature}°${data.unit ?? "C"}`;
  if (topic === TOPICS.lockState) return String(data.state);
  if (topic === TOPICS.cameraStatus) return String(data.status);
  return JSON.stringify(data);
}

/**
 * Secure counterpart to useMqtt: connects to the HARDENED broker over TLS
 * WebSockets with the `dashboard` credential, verifies every signed envelope
 * (HMAC + freshness) before trusting it, and can send signed lock commands.
 *
 * A message that fails verification is logged as rejected and does NOT update
 * the displayed device value — a forged or replayed state cannot drive the UI.
 */
export function useSecureMqtt(enabled: boolean): SecureMqttState {
  const [status, setStatus] = useState<ConnStatus>("connecting");
  const [error, setError] = useState<string | null>(null);
  const [messages, setMessages] = useState<Record<string, VerifiedMessage>>({});
  const [events, setEvents] = useState<VerifyEvent[]>([]);
  const clientRef = useRef<MqttClient | null>(null);
  const verifierRef = useRef<EnvelopeVerifier | null>(null);

  useEffect(() => {
    if (!enabled) return;

    setStatus("connecting");
    setError(null);
    setMessages({});
    setEvents([]);
    verifierRef.current = new EnvelopeVerifier(HMAC_KEYS);

    const client = mqtt.connect(MQTT_WSS_URL, {
      clientId: `homepulse-secure-${Math.random().toString(16).slice(2, 10)}`,
      username: SECURE_BROKER.username,
      password: SECURE_BROKER.password,
      reconnectPeriod: 3000,
      connectTimeout: 8000,
    });
    clientRef.current = client;

    client.on("connect", () => {
      setStatus("connected");
      setError(null);
      client.subscribe(WILDCARD, { qos: 0 });
    });
    client.on("reconnect", () => setStatus("reconnecting"));
    client.on("offline", () => setStatus("offline"));
    client.on("error", (err) => {
      setStatus("error");
      setError(err?.message ?? "connection error");
    });

    client.on("message", async (topic, payloadBuf) => {
      const verifier = verifierRef.current;
      if (!verifier) return;
      const res = await verifier.verify(payloadBuf.toString());
      const ts = Date.now();

      setEvents((prev) =>
        [
          { ts, topic, device: res.device, seq: res.seq, ok: res.ok, reason: res.reason },
          ...prev,
        ].slice(0, MAX_EVENTS)
      );

      // Only a verified envelope updates the displayed device value.
      if (res.ok && res.data) {
        setMessages((prev) => ({
          ...prev,
          [topic]: {
            topic,
            device: res.device!,
            seq: res.seq!,
            ts: res.ts!,
            value: formatValue(topic, res.data!),
            verified: true,
            reason: res.reason,
            count: (prev[topic]?.count ?? 0) + 1,
          },
        }));
      }
    });

    return () => {
      clientRef.current = null;
      client.end(true);
    };
  }, [enabled]);

  const sendCommand = useCallback(async (cmd: "LOCK" | "UNLOCK") => {
    const client = clientRef.current;
    if (!client || !OPERATOR_HMAC_KEY) throw new Error("not connected");
    const envelope = await signCommand(OPERATOR_HMAC_KEY, cmd);
    await new Promise<void>((resolve, reject) =>
      client.publish(TOPICS.lockCmd, envelope, { qos: 1 }, (err) =>
        err ? reject(err) : resolve()
      )
    );
  }, []);

  return { status, error, messages, events, sendCommand };
}
