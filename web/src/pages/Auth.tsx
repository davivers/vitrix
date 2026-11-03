import { useMutation, useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { GitBranch, Loader2, LogIn, Mail, UserPlus } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { api } from "../api";
import { Logo } from "../components/Logo";
import { ErrorBox, btnPrimary, btnSecondary, inputCls } from "../components/ui";
import type { Me } from "../types";

const params = () => new URLSearchParams(window.location.search);

/** Removes ?invite= and ?auth_error= from the address bar once they have been read. */
function cleanUrl() {
  const url = new URL(window.location.href);
  url.searchParams.delete("invite");
  url.searchParams.delete("auth_error");
  window.history.replaceState({}, "", url.pathname + (url.search || "") + url.hash);
}

/** Sign in / create account, local or with GitHub. Shown in place of the app when auth is enabled. */
export default function AuthPage({ onSignedIn }: { onSignedIn: (me: Me) => void }) {
  const config = useQuery({ queryKey: ["auth-config"], queryFn: api.authConfig });
  const invite = useMemo(() => params().get("invite"), []);
  const oauthError = useMemo(() => params().get("auth_error"), []);
  const cfg = config.data;
  const canRegister = Boolean(cfg?.bootstrap || cfg?.allow_signup || invite);
  const [tab, setTab] = useState<"signin" | "register">(invite || cfg?.bootstrap ? "register" : "signin");
  const mode = cfg?.bootstrap ? "register" : canRegister ? tab : "signin";

  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");

  const submit = useMutation({
    mutationFn: () => (mode === "register" ? api.register({ email, name, password, invite }) : api.login(email, password)),
    onSuccess: (me) => {
      cleanUrl();
      onSignedIn(me);
    },
  });
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!submit.isPending) submit.mutate();
  };

  const githubHref = `/api/auth/github/start${invite ? `?invite=${encodeURIComponent(invite)}` : ""}`;
  const title = cfg?.bootstrap ? "Create the first account" : mode === "register" ? (invite ? "Accept your invitation" : "Create your account") : "Sign in";

  return (
    <div className="grid min-h-full place-items-center px-4 py-10">
      <div className="w-full max-w-[420px] space-y-6">
        <div className="flex justify-center">
          <Logo />
        </div>

        <div className="glass space-y-5 rounded-2xl p-6">
          <div>
            <h1 className="text-xl font-semibold text-strong">{title}</h1>
            <p className="mt-1 text-sm text-muted">
              {cfg?.bootstrap
                ? "No account exists yet. The first account becomes the owner of this workspace."
                : invite
                  ? `You were invited to ${cfg?.workspace ?? "a workspace"}. Use the email address the invite was sent to.`
                  : cfg?.workspace
                    ? `Workspace: ${cfg.workspace}`
                    : "Detection-as-Code for your team."}
            </p>
          </div>

          {oauthError && <ErrorBox message={oauthError} />}

          {canRegister && !cfg?.bootstrap && (
            <div className="grid grid-cols-2 gap-1 rounded-[10px] border border-line bg-surface p-1" role="tablist" aria-label="Account">
              {(
                [
                  ["signin", "Sign in", LogIn],
                  ["register", "Create account", UserPlus],
                ] as const
              ).map(([key, label, Icon]) => (
                <button
                  key={key}
                  type="button"
                  role="tab"
                  aria-selected={mode === key}
                  onClick={() => {
                    setTab(key);
                    submit.reset();
                  }}
                  className={clsx(
                    "inline-flex items-center justify-center gap-1.5 rounded-md py-1.5 text-[13px]",
                    mode === key ? "bg-accent-soft font-semibold text-strong" : "text-muted hover:text-text",
                  )}
                >
                  <Icon size={14} aria-hidden /> {label}
                </button>
              ))}
            </div>
          )}

          {cfg?.github && (
            <>
              <a href={githubHref} className={clsx(btnSecondary, "w-full py-2.5")}>
                <GitBranch size={16} aria-hidden /> Continue with GitHub
              </a>
              <div className="flex items-center gap-3 text-xs text-subtle" aria-hidden>
                <span className="h-px flex-1 bg-line" /> or with email <span className="h-px flex-1 bg-line" />
              </div>
            </>
          )}

          <form onSubmit={onSubmit} className="space-y-3.5">
            {mode === "register" && (
              <label className="block space-y-1.5">
                <span className="text-[13px] font-medium text-strong">Name</span>
                <input value={name} onChange={(e) => setName(e.target.value)} className={inputCls} autoComplete="name" maxLength={100} required />
              </label>
            )}
            <label className="block space-y-1.5">
              <span className="text-[13px] font-medium text-strong">Email</span>
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className={inputCls} autoComplete="email" maxLength={254} required autoFocus />
            </label>
            <label className="block space-y-1.5">
              <span className="text-[13px] font-medium text-strong">Password</span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={inputCls}
                autoComplete={mode === "register" ? "new-password" : "current-password"}
                minLength={mode === "register" ? 10 : undefined}
                maxLength={256}
                required
              />
              {mode === "register" && <span className="block text-xs text-subtle">At least 10 characters.</span>}
            </label>

            {submit.error && <ErrorBox message={(submit.error as Error).message} />}

            <button type="submit" disabled={submit.isPending} className={clsx(btnPrimary, "w-full py-2.5")}>
              {submit.isPending ? <Loader2 size={16} className="animate-spin" aria-hidden /> : <Mail size={16} aria-hidden />}
              {mode === "register" ? (cfg?.bootstrap ? "Create the owner account" : "Create account") : "Sign in"}
            </button>
          </form>

          {!canRegister && cfg && !cfg.bootstrap && <p className="text-center text-xs text-subtle">New here? Registration is by invitation: ask a workspace admin for an invite link.</p>}
        </div>

        <p className="text-center text-xs text-subtle">Sessions use an HttpOnly cookie. Your password is never stored, only a salted hash.</p>
      </div>
    </div>
  );
}
