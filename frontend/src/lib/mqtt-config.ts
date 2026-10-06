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
