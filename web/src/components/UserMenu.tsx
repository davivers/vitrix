import { useMutation } from "@tanstack/react-query";
import clsx from "clsx";
import { ChevronsUpDown, KeyRound, Loader2, LogOut, Plug, Settings, ShieldCheck, Users, X, type LucideIcon } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { LanguageControl, ThemeControl } from "./ThemeControl";
import { useMe } from "./auth";
import { ErrorBox, btnPrimary, btnSecondary, inputCls } from "./ui";
import { t } from "../i18n";

// Avatar backgrounds: fixed (theme-independent) with white initials, each >= 4.5:1 against white.
const PALETTE = ["#2563EB", "#C2570C", "#0B7A6B", "#9D2A7E", "#6B5B00"];

function initials(label: string): string {
  const parts = label.replace(/@.*/, "").split(/[\s._-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts.length > 1 ? parts[parts.length - 1][0] : "")).toUpperCase();
}

/** Round avatar: the GitHub picture when there is one, otherwise initials on a colour derived from the email. */
export function Avatar({ name, email, url, size = 32 }: { name: string; email: string; url?: string | null; size?: number }) {
  const [broken, setBroken] = useState(false);
  const seed = [...email].reduce((n, ch) => n + ch.charCodeAt(0), 0);
  if (url && url.startsWith("https://") && !broken) {
    return <img src={url} alt="" width={size} height={size} referrerPolicy="no-referrer" onError={() => setBroken(true)} className="shrink-0 rounded-full bg-surface-2 object-cover" style={{ width: size, height: size }} />;
  }
  return (
    <span
      aria-hidden
      className="grid shrink-0 place-items-center rounded-full font-bold text-on-brand"
      style={{ width: size, height: size, background: PALETTE[seed % PALETTE.length], fontSize: size * 0.38 }}
    >
      {initials(name || email)}
    </span>
  );
}

const ROLE_LABEL = { viewer: t("l_viewer"), editor: t("l_editor"), admin: t("l_admin"), owner: t("l_owner") } as const;

function PasswordDialog({ onClose }: { onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const change = useMutation({ mutationFn: () => api.changePassword(current, next) });
  useEffect(() => {
    const dlg = ref.current;
    if (dlg && !dlg.open) dlg.showModal();
  }, []);
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    change.mutate();
  };
  return (
    <dialog ref={ref} onClose={onClose} aria-labelledby="pw-title" className="glass m-auto w-[min(420px,calc(100vw-32px))] rounded-2xl bg-surface p-0 text-text backdrop:bg-black/50">
      <form onSubmit={onSubmit} className="space-y-4 p-6">
        <div className="flex items-start justify-between gap-4">
          <h2 id="pw-title" className="text-lg font-semibold text-strong">
            {t("change_password")}
          </h2>
          <button type="button" onClick={onClose} aria-label={t("close")} className="rounded-md p-1 text-muted hover:bg-surface-2 hover:text-text">
            <X size={18} aria-hidden />
          </button>
        </div>
        {change.isSuccess ? (
          <p className="text-sm text-good">{t("password_changed_your_other_sessions_w")}</p>
        ) : (
          <>
            <label className="block space-y-1.5">
              <span className="text-sm font-medium text-strong">{t("current_password")}</span>
              <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} className={inputCls} autoComplete="current-password" required />
            </label>
            <label className="block space-y-1.5">
              <span className="text-sm font-medium text-strong">{t("new_password")}</span>
              <input type="password" value={next} onChange={(e) => setNext(e.target.value)} className={inputCls} autoComplete="new-password" minLength={10} required />
              <span className="block text-xs text-subtle">{t("at_least_10_characters")}</span>
            </label>
            {change.error && <ErrorBox message={(change.error as Error).message} />}
          </>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className={btnSecondary}>
            {change.isSuccess ? t("l_done") : t("l_cancel")}
          </button>
          {!change.isSuccess && (
            <button type="submit" disabled={change.isPending} className={btnPrimary}>
              {change.isPending && <Loader2 size={15} className="animate-spin" aria-hidden />} {t("change_password")}
            </button>
          )}
        </div>
      </form>
    </dialog>
  );
}

function Item({ icon: Icon, children, onClick, to, danger }: { icon: LucideIcon; children: ReactNode; onClick?: () => void; to?: string; danger?: boolean }) {
  const cls = clsx("flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-[13.5px] focus-visible:bg-surface-2", danger ? "text-bad hover:bg-bad-soft" : "text-text hover:bg-surface-2");
  const inner = (
    <>
      <Icon size={16} className="shrink-0" aria-hidden /> {children}
    </>
  );
  return to ? (
    <Link to={to} role="menuitem" onClick={onClick} className={cls}>
      {inner}
    </Link>
  ) : (
    <button type="button" role="menuitem" onClick={onClick} className={cls}>
      {inner}
    </button>
  );
}

/**
 * Account menu at the bottom of the sidebar: avatar and name; opens upwards with the person's
 * workspace, role and shortcuts (Team, Settings, Connections, password) and Sign out.
 */
export function UserMenu() {
  const me = useMe();
  const [open, setOpen] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const user = me.user;

  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        const items = [...(box.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? [])];
        const at = items.indexOf(document.activeElement as HTMLElement);
        items[(at + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length]?.focus();
        e.preventDefault();
      }
    };
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey);
    box.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const signOut = useMutation({
    mutationFn: api.logout,
    onSettled: () => window.location.assign("/"), // a full reload drops everything the previous session loaded
  });

  const name = user?.name || user?.email || t("l_local_mode");
  const email = user?.email ?? t("l_no_sign_in_local_single_user_sessi");
  const sub = user ? `${ROLE_LABEL[user.role]}${me.workspace ? ` · ${me.workspace}` : ""}` : t("l_auth_is_off");
  const close = () => setOpen(false);

  return (
    <div ref={box} className="relative mt-3 border-t border-line pt-3">
      {open && (
        <div role="menu" aria-label={t("account")} className="glass absolute bottom-[calc(100%+4px)] left-0 z-50 w-64 rounded-xl bg-surface p-1.5 shadow-pop lg:w-full lg:min-w-[15rem]">
          <div className="px-2.5 pb-2 pt-1.5">
            <p className="truncate text-[13px] font-semibold text-strong">{name}</p>
            <p className="truncate text-xs text-subtle">{email}</p>
            {user && (
              <p className="mt-1.5 flex items-center gap-1.5 text-xs text-muted">
                <ShieldCheck size={13} className="text-accent" aria-hidden /> {t("um_role_of", { role: ROLE_LABEL[user.role], ws: me.workspace ?? "" })}
                {user.github_login && <span className="text-subtle">· @{user.github_login}</span>}
              </p>
            )}
          </div>
          <div className="my-1 h-px bg-line" />
          {user && (
            <Item icon={Users} to="/team" onClick={close}>
              {t("team_and_access")}
            </Item>
          )}
          <div className="my-1 h-px bg-line" />
          <p className="px-2.5 pt-1 text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("appearance")}</p>
          <ThemeControl menu />
          <p className="px-2.5 pt-1 text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("language_label")}</p>
          <LanguageControl menu />
          <div className="my-1 h-px bg-line" />
          <Item icon={Settings} to="/settings" onClick={close}>
            {t("settings")}
          </Item>
          <Item icon={Plug} to="/connections" onClick={close}>
            {t("connections")}
          </Item>
          {user && (
            <Item
              icon={KeyRound}
              onClick={() => {
                close();
                setPasswordOpen(true);
              }}
            >
              Change password
            </Item>
          )}
          {user ? (
            <>
              <div className="my-1 h-px bg-line" />
              <Item icon={LogOut} danger onClick={() => signOut.mutate()}>
                {signOut.isPending ? t("l_signing_out") : t("l_sign_out")}
              </Item>
            </>
          ) : (
            <p className="px-2.5 py-2 text-xs text-subtle">
              {t("turn_on_accounts_with")} <span className="font-mono">auth.enabled</span> {t("in_vitrix_yml")}
            </p>
          )}
        </div>
      )}

      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={t("um_account_menu", { name })}
        className={clsx("flex w-full items-center gap-2.5 rounded-[10px] p-1.5 text-left transition-colors hover:bg-surface", open && "bg-surface")}
      >
        <Avatar name={name} email={user?.email ?? "local"} url={user?.avatar_url} />
        <span className="hidden min-w-0 flex-1 lg:block">
          <span className="block truncate text-[13px] font-semibold text-strong">{name}</span>
          <span className="block truncate text-[11.5px] text-subtle">{sub}</span>
        </span>
        <ChevronsUpDown size={15} className="hidden shrink-0 text-subtle lg:block" aria-hidden />
      </button>
      {passwordOpen && <PasswordDialog onClose={() => setPasswordOpen(false)} />}
    </div>
  );
}
