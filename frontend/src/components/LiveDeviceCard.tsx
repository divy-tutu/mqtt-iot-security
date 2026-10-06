import { type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface LiveDeviceCardProps {
  name: string;
  room: string;
  topic: string;
  icon: LucideIcon;
  /** formatted live value, or null if nothing has arrived yet */
  value: string | null;
  lastTs?: number;
  /** render in an alarmed state (e.g. lock was tampered with) */
  alarmed?: boolean;
}

export const LiveDeviceCard = ({
  name,
  room,
  topic,
  icon: Icon,
  value,
  lastTs,
  alarmed,
}: LiveDeviceCardProps) => {
  const hasData = value !== null;

  return (
    <div
      className={cn(
        "border p-6 flex flex-col gap-4 transition-colors duration-300",
        alarmed ? "border-destructive bg-destructive/5" : "border-border bg-card"
      )}
    >
      <div className="flex items-start justify-between">
        <Icon className={cn("w-6 h-6", alarmed ? "text-destructive" : "text-primary")} />
        <span
          className={cn(
            "inline-flex items-center gap-1.5 text-[10px] tracking-[0.15em] uppercase",
            hasData ? "text-muted-foreground" : "text-muted-foreground/50"
          )}
        >
          <span
            className={cn(
              "w-1.5 h-1.5 rounded-full",
              hasData ? "bg-green-500 animate-pulse" : "bg-muted-foreground/40"
            )}
          />
          {hasData ? "Live" : "Waiting"}
        </span>
      </div>

      <div>
        <h3 className="font-serif text-2xl text-foreground">{name}</h3>
        <p className="text-sm text-muted-foreground">{room}</p>
      </div>

      <div
        className={cn(
          "font-serif text-4xl tabular-nums transition-colors",
          alarmed ? "text-destructive" : hasData ? "text-foreground" : "text-muted-foreground/40"
        )}
      >
        {value ?? "—"}
      </div>

      <div className="mt-auto pt-2 border-t border-border/60 flex items-center justify-between text-[10px] text-muted-foreground font-mono">
        <span className="truncate">{topic}</span>
        {lastTs ? <span>{new Date(lastTs).toLocaleTimeString()}</span> : null}
      </div>
    </div>
  );
};
