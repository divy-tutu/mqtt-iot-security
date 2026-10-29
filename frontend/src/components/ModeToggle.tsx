import { ShieldCheck, ShieldAlert } from "lucide-react";
import { useMode, type SecurityMode } from "@/lib/mode";

export const ModeToggle = ({ disabled = false }: { disabled?: boolean }) => {
  const { mode, setMode } = useMode();
  return (
    <div className="profile-toggle" role="group" aria-label="Security profile">
      {(["baseline", "hardened"] as SecurityMode[]).map(value => {
        const Icon = value === "hardened" ? ShieldCheck : ShieldAlert;
        return <button key={value} aria-pressed={mode === value} disabled={disabled}
          onClick={() => setMode(value)} className={mode === value ? "is-active" : ""}>
          <Icon size={15} aria-hidden="true" />{value === "hardened" ? "Hardened" : "Baseline"}
        </button>;
      })}
    </div>
  );
};
