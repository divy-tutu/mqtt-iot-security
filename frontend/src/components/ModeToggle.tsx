import { ShieldAlert, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import { useMode, type SecurityMode } from "@/lib/mode";

/**
 * Secure / Insecure segmented toggle. Rendered top-right in the Header so it
 * stays in the same place on the landing page and the dashboard. The choice is
 * persisted (sessionStorage) and read by the dashboard to pick which path to show.
 */
export const ModeToggle = () => {
  const mode = useMode((s) => s.mode);
  const setMode = useMode((s) => s.setMode);

  const options: { value: SecurityMode; label: string; icon: typeof ShieldAlert }[] = [
    { value: "insecure", label: "Insecure", icon: ShieldAlert },
    { value: "secure", label: "Secure", icon: ShieldCheck },
  ];

  return (
    <div
      role="radiogroup"
      aria-label="Security mode"
      className="inline-flex items-center border border-border bg-background/60 backdrop-blur-sm"
    >
      {options.map((opt) => {
        const active = mode === opt.value;
        const Icon = opt.icon;
        return (
          <button
            key={opt.value}
            role="radio"
            aria-checked={active}
            onClick={() => setMode(opt.value)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-medium tracking-[0.15em] uppercase transition-colors",
              active
                ? opt.value === "insecure"
                  ? "bg-destructive text-destructive-foreground"
                  : "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            <Icon className="w-3.5 h-3.5" />
            {opt.label}
          </button>
        );
      })}
    </div>
  );
};
