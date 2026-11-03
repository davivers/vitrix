import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { createContext, useContext, useEffect, type ReactNode } from "react";
import { api } from "../api";
import AuthPage from "../pages/Auth";
import type { Me, Role } from "../types";
import { ErrorBox, btnSecondary } from "./ui";

const MeContext = createContext<Me | null>(null);

/** The signed-in person (or the local single-user session when auth is off). Only valid under <AuthGate>. */
export function useMe(): Me {
  const me = useContext(MeContext);
  if (!me) throw new Error("useMe must be used inside <AuthGate>");
  return me;
}

export const can = (me: Me, role: Role) => me.can[role] === true;

/**
 * Shows the sign-in screen when the server requires accounts and there is no valid session.
 * A 401 from any API call (expired or revoked session) sends the person back here.
 */
export function AuthGate({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const me = useQuery({ queryKey: ["me"], queryFn: api.me, staleTime: 60_000, retry: false });

  useEffect(() => {
    const onUnauthorized = () => {
      qc.clear(); // nothing from the previous session may stay in memory
      void qc.invalidateQueries({ queryKey: ["me"] });
    };
    window.addEventListener("vitrix:unauthorized", onUnauthorized);
    return () => window.removeEventListener("vitrix:unauthorized", onUnauthorized);
  }, [qc]);

  if (me.isLoading) {
    return (
      <div className="grid h-full place-items-center text-muted">
        <Loader2 className="animate-spin" size={22} aria-label="Loading" />
      </div>
    );
  }
  if (me.error || !me.data) {
    return (
      <div className="mx-auto mt-24 max-w-md space-y-4 px-4">
        <ErrorBox message={(me.error as Error | null)?.message ?? "Could not load the session."} />
        <button type="button" className={btnSecondary} onClick={() => me.refetch()}>
          Try again
        </button>
      </div>
    );
  }
  if (me.data.enabled && !me.data.authenticated) {
    return <AuthPage onSignedIn={(data) => qc.setQueryData(["me"], data)} />;
  }
  return <MeContext.Provider value={me.data}>{children}</MeContext.Provider>;
}
