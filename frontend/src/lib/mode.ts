import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

// This stores only the selected view. API authorization is always server-side.
export type SecurityMode = "baseline" | "hardened";
interface ModeState {
  mode: SecurityMode;
  setMode: (mode: SecurityMode) => void;
}
export const useMode = create<ModeState>()(
  persist(
    (set) => ({
      mode: "hardened",
      setMode: (mode) => set({ mode }),
    }),
    {
      name: "homepulse-profile-v2",
      storage: createJSONStorage(() => sessionStorage),
    }
  )
);
