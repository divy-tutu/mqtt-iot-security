/**
 * WebSocket endpoint for the (undefended) Mosquitto broker.
 *
 * The browser connects here with MQTT.js. The broker exposes this via:
 *   listener 9001 / protocol websockets   (broker/config/mosquitto.undefended.conf)
 *   ports: "9001:9001"                     (docker-compose.yml)
 *
 * Override at build time with VITE_MQTT_WS_URL. If the frontend is itself run
 * inside the compose network (served from a container that resolves the
 * "broker" service name), set VITE_MQTT_WS_URL=ws://broker:9001. By default we
 * assume the frontend runs on the host (vite dev / preview) and the browser
 * reaches the published port on localhost.
 */
export const MQTT_WS_URL =
  (import.meta.env.VITE_MQTT_WS_URL as string | undefined) ?? "ws://localhost:9001";

/** Real device topics published over the 1883 path by devices/*.py. */
export const TOPICS = {
  temperature: "home/livingroom/temperature",
  lockState: "home/frontdoor/lock/state",
  lockCmd: "home/frontdoor/lock/cmd",
  cameraStatus: "home/frontdoor/camera/status",
} as const;

/** Wildcard the dashboard subscribes to — exactly what an anonymous client can do. */
export const WILDCARD = "home/#";

/* ------------------------------------------------------------------------- *
 *  SECURE build configuration (Phase 2 - hardened broker).
 *
 *  All values come from frontend/.env.local (git-ignored), written by
 *  ../setup-hardened.sh. The browser connects over TLS WebSockets with the
 *  `dashboard` identity and holds the per-device HMAC keys needed to verify
 *  signed envelopes and sign lock commands (a testbed simplification).
 * ------------------------------------------------------------------------- */
const env = import.meta.env;

export const MQTT_WSS_URL =
  (env.VITE_MQTT_WSS_URL as string | undefined) ?? "wss://localhost:9002";

export const SECURE_BROKER = {
  username: (env.VITE_MQTT_USERNAME as string | undefined) ?? "dashboard",
  password: (env.VITE_MQTT_PASSWORD as string | undefined) ?? "",
};

/** Per-device HMAC keys, keyed by the device-id used in the signed envelope. */
export const HMAC_KEYS: Record<string, string | undefined> = {
  "sensor-livingroom": env.VITE_HMAC_SENSOR as string | undefined,
  "lock-frontdoor": env.VITE_HMAC_LOCK as string | undefined,
  "camera-frontdoor": env.VITE_HMAC_CAMERA as string | undefined,
};

/** Operator key the dashboard signs lock commands with. */
export const OPERATOR_HMAC_KEY = env.VITE_HMAC_OPERATOR as string | undefined;

/** True when the secure build has the env it needs to actually run. */
export const SECURE_CONFIGURED = Boolean(
  SECURE_BROKER.password && OPERATOR_HMAC_KEY && HMAC_KEYS["lock-frontdoor"]
);
