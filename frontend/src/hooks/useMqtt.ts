import { useEffect, useRef, useState } from "react";
import mqtt, { type MqttClient } from "mqtt";
import { MQTT_WS_URL, TOPICS, WILDCARD } from "@/lib/mqtt-config";

export type ConnStatus = "connecting" | "connected" | "reconnecting" | "offline" | "error";

export interface TopicMessage {
  value: string;
  ts: number;
  count: number;
}

export interface LockEvent {
  ts: number;
  topic: string;
  payload: string;
  /** "baseline" = the device's own retained state on connect; others are post-connect writes. */
  kind: "baseline" | "forged-state" | "injected-cmd";
}

export interface MqttState {
  status: ConnStatus;
  error: string | null;
  /** latest payload per topic, keyed by full topic string */
  messages: Record<string, TopicMessage>;
  /** real lock-write events observed on the wire, newest first (capped) */
  lockEvents: LockEvent[];
}

const MAX_EVENTS = 20;

/**
 * Connects to the undefended broker over WebSockets with NO credentials —
 * exactly what attacks/eavesdrop.py and attacks/enumerate.py do over 1883 —
 * and subscribes to the "home/#" wildcard. Everything rendered from this hook
 * is a real message delivered by the broker; nothing is synthesized in JS.
 */
export function useMqtt(enabled: boolean): MqttState {
  const [status, setStatus] = useState<ConnStatus>("connecting");
  const [error, setError] = useState<string | null>(null);
  const [messages, setMessages] = useState<Record<string, TopicMessage>>({});
  const [lockEvents, setLockEvents] = useState<LockEvent[]>([]);
  const clientRef = useRef<MqttClient | null>(null);
  // whether we've already recorded the retained baseline for lock/state
  const sawLockBaseline = useRef(false);

  useEffect(() => {
    if (!enabled) return;

    setStatus("connecting");
    setError(null);
    sawLockBaseline.current = false;

    const client = mqtt.connect(MQTT_WS_URL, {
      // anonymous: no username / password — the vulnerability on display
      clientId: `homepulse-dashboard-${Math.random().toString(16).slice(2, 10)}`,
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

    client.on("message", (topic, payloadBuf, packet) => {
      const payload = payloadBuf.toString();
      const ts = Date.now();

      setMessages((prev) => ({
        ...prev,
        [topic]: { value: payload, ts, count: (prev[topic]?.count ?? 0) + 1 },
      }));

      // Distinguish the device's own state from a live intrusion using the MQTT
      // RETAIN flag. Per spec the broker sets retain=1 only when replaying the
      // stored message to a NEW subscription (our baseline, and any re-delivery
      // after a reconnect); a live publish forwarded to an already-subscribed
      // client arrives with retain=0. Flagging only retain=0 writes removes the
      // false "forged" alarm on reconnect while still catching real injections.
      const isRetained = packet?.retain === true;

      if (topic === TOPICS.lockState) {
        if (isRetained) {
          // Stored state replayed on (re)subscribe — record the baseline once,
          // ignore later re-deliveries so reconnects don't raise a false alarm.
          if (!sawLockBaseline.current) {
            sawLockBaseline.current = true;
            setLockEvents((prev) =>
              [{ ts, topic, payload, kind: "baseline" as const }, ...prev].slice(0, MAX_EVENTS)
            );
          }
        } else {
          // A live write to lock/state: nothing legitimate republishes it in
          // this testbed, so this is the attacker forging state.
          sawLockBaseline.current = true;
          setLockEvents((prev) =>
            [{ ts, topic, payload, kind: "forged-state" as const }, ...prev].slice(0, MAX_EVENTS)
          );
        }
      } else if (topic === TOPICS.lockCmd) {
        // Nothing in the UI publishes commands; a cmd on the wire is injected.
        setLockEvents((prev) =>
          [{ ts, topic, payload, kind: "injected-cmd" as const }, ...prev].slice(0, MAX_EVENTS)
        );
      }
    });

    return () => {
      clientRef.current = null;
      client.end(true);
    };
  }, [enabled]);

  return { status, error, messages, lockEvents };
}
