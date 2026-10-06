import { ShieldCheck, Construction } from "lucide-react";

/**
 * Placeholder for the hardened path. Deliberately shows NO device data — the
 * secure broker (TLS, authentication, ACLs, no anonymous access) is not yet
 * implemented, and faking "secure" data would defeat the point of the testbed.
 */
export const SecureStub = () => (
  <div className="border border-dashed border-primary/40 bg-primary/5 p-12 md:p-16 text-center max-w-2xl mx-auto">
    <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-primary/10 mb-6">
      <ShieldCheck className="w-7 h-7 text-primary" />
    </div>
    <h2 className="font-serif text-3xl text-foreground mb-4">Secure Mode</h2>
    <p className="inline-flex items-center gap-2 text-[11px] font-semibold tracking-[0.2em] uppercase text-primary mb-6">
      <Construction className="w-4 h-4" />
      Not Yet Implemented
    </p>
    <p className="text-muted-foreground leading-relaxed">
      The hardened path — TLS, per-device authentication, topic ACLs, and no
      anonymous access — has not been built yet. No device data is shown here on
      purpose: there is no trustworthy secure broker to read from, and
      fabricating "secure" readings would misrepresent the system.
    </p>
    <p className="text-sm text-muted-foreground mt-6">
      Switch to <span className="text-destructive font-medium">Insecure</span> (top-right)
      to see the live, unauthenticated path and the attack in action.
    </p>
  </div>
);
