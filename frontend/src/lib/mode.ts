import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";

/**
 * Security posture the user is viewing the testbed in.
 *  - "insecure": the live, unauthenticated path (anonymous MQTT over WebSockets).
 *  - "secure":   a hardened path — not yet implemented (shown as a stub).
 *
 * Persisted to sessionStorage so the choice made on the landing page carries
 * into the dashboard without a server round-trip.
 */
export type SecurityMode = "insecure" | "secure";

interface ModeState {
  mode: SecurityMode;
  setMode: (mode: SecurityMode) => void;
  toggle: () => void;
}

export const useMode = create<ModeState>()(
  persist(
    (set, get) => ({
      mode: "insecure",
      setMode: (mode) => set({ mode }),
      toggle: () => set({ mode: get().mode === "insecure" ? "secure" : "insecure" }),
    }),
    {
      name: "homepulse-security-mode",
      storage: createJSONStorage(() => sessionStorage),
    }
  )
);
