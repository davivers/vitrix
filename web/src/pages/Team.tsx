import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, GitBranch, Loader2, Mail, Pencil, Trash2, UserPlus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { can, useMe } from "../components/auth";
import { Section, timeAgo } from "../components/dash";
import { Avatar } from "../components/UserMenu";
import { Card, ErrorBox, PageHeader, btnPrimary, btnSecondary, inputCls } from "../components/ui";
import type { CreatedInvite, Member, Role } from "../types";
import { t } from "../i18n";

const ROLES: { id: Role; label: string; can: string }[] = [
  { id: "viewer", label: t("l_viewer"), can: t("tm_can_viewer") },
  { id: "editor", label: t("l_editor"), can: t("tm_can_editor") },
  { id: "admin", label: t("l_admin"), can: t("tm_can_admin") },
  { id: "owner", label: t("l_owner"), can: t("tm_can_owner") },
];

const ACTION: Record<string, string> = {
  login: t("tm_a_login"),
  "login.failed": t("tm_a_login_failed"),
  "account.register": t("tm_a_register"),
  "account.github_linked": t("tm_a_gh"),
  "invite.created": t("tm_a_invited"),
  "invite.revoked": t("tm_a_revoked"),
  "member.role": t("tm_a_role"),
  "member.removed": t("l_removed_a_member"),
  "password.changed": t("tm_a_pw"),
  "workspace.renamed": t("tm_a_rename"),
  "rule.ci_submitted": t("tm_a_rule_ci"),
  "config.ci_submitted": "sent vitrix.yml to CI",
  "pull_request.opened": "opened a pull request",
};

const iso = (epoch: number | null) => (epoch ? new Date(epoch * 1000).toISOString() : null);

function MemberRow({ m, myRole, meId, onChanged }: { m: Member; myRole: Role; meId: number; onChanged: () => void }) {
  const [confirm, setConfirm] = useState(false);
  const setRole = useMutation({ mutationFn: (role: Role) => api.setRole(m.id, role), onSuccess: onChanged });
  const remove = useMutation({ mutationFn: () => api.removeMember(m.id), onSuccess: onChanged });
  const iAmOwner = myRole === "owner";
  const locked = m.role === "owner" && !iAmOwner; // only an owner may touch an owner
  const options = ROLES.filter((r) => r.id !== "owner" || iAmOwner);
  const error = (setRole.error ?? remove.error) as Error | null;
  return (
    <li className="flex flex-wrap items-center gap-3 px-4 py-3">
      <Avatar name={m.name} email={m.email} url={m.avatar_url} size={36} />
      <span className="min-w-[12rem] flex-1">
        <span className="block truncate text-[13.5px] font-semibold text-strong">
          {m.name || m.email} {m.id === meId && <span className="font-normal text-subtle">(you)</span>}
        </span>
        <span className="flex flex-wrap items-center gap-x-2 text-xs text-subtle">
          <span className="truncate">{m.email}</span>
          {m.github_login && (
            <span className="inline-flex items-center gap-1">
              <GitBranch size={11} aria-hidden /> @{m.github_login}
            </span>
          )}
          {!m.has_password && <span>{t("github_only")}</span>}
        </span>
      </span>
      <span className="text-xs text-subtle">{m.last_login ? t("tm_active_ago", { t: timeAgo(iso(m.last_login)) }) : t("tm_never")}</span>
      <label className="sr-only" htmlFor={`role-${m.id}`}>
        {t("role_of")} {m.name || m.email}
      </label>
      <select
        id={`role-${m.id}`}
        value={m.role}
        disabled={locked || setRole.isPending}
        onChange={(e) => setRole.mutate(e.target.value as Role)}
        className="rounded-[10px] border border-line bg-surface px-2.5 py-1.5 text-[13px] text-text disabled:opacity-60"
      >
        {options.map((r) => (
          <option key={r.id} value={r.id} className="bg-surface">
            {r.label}
          </option>
        ))}
        {!options.some((r) => r.id === m.role) && <option value={m.role}>{m.role}</option>}
      </select>
      {confirm ? (
        <span className="flex items-center gap-1.5">
          <button type="button" onClick={() => remove.mutate()} disabled={remove.isPending} className="rounded-md bg-bad-soft px-2.5 py-1.5 text-xs font-semibold text-bad hover:brightness-110">
            {remove.isPending ? t("tm_removing") : t("tm_remove")}
          </button>
          <button type="button" onClick={() => setConfirm(false)} className="rounded-md px-2 py-1.5 text-xs text-muted hover:text-text">
            {t("cancel")}
          </button>
        </span>
      ) : (
        <button type="button" disabled={locked} onClick={() => setConfirm(true)} aria-label={`Remove ${m.name || m.email}`} className="rounded-md p-1.5 text-subtle hover:bg-surface-2 hover:text-bad disabled:opacity-40">
          <Trash2 size={15} aria-hidden />
        </button>
      )}
      {error && (
        <div className="w-full">
          <ErrorBox message={error.message} />
        </div>
      )}
    </li>
  );
}

function InviteForm({ myRole, onCreated }: { myRole: Role; onCreated: () => void }) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("editor");
  const [created, setCreated] = useState<CreatedInvite | null>(null);
  const [copied, setCopied] = useState(false);
  const create = useMutation({
    mutationFn: () => api.invite(email, role),
    onSuccess: (inv) => {
      setCreated(inv);
      setEmail("");
      onCreated();
    },
  });
  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setCreated(null);
    create.mutate();
  };
  const copy = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.link);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* no clipboard permission: the link is selectable below */
    }
  };
  return (
    <div className="space-y-3">
      <form onSubmit={onSubmit} className="flex flex-wrap gap-2">
        <label className="min-w-[14rem] flex-1">
          <span className="sr-only">{t("email_to_invite")}</span>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="colleague@company.com" className={inputCls} required maxLength={254} />
        </label>
        <label>
          <span className="sr-only">{t("role")}</span>
          <select value={role} onChange={(e) => setRole(e.target.value as Role)} className="h-full rounded-[10px] border border-line bg-surface px-2.5 text-[13px] text-text">
            {ROLES.filter((r) => r.id !== "owner" || myRole === "owner").map((r) => (
              <option key={r.id} value={r.id} className="bg-surface">
                {r.label}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" disabled={create.isPending} className={btnPrimary}>
          {create.isPending ? <Loader2 size={15} className="animate-spin" aria-hidden /> : <UserPlus size={15} aria-hidden />} {t("tm_create_invite")}
        </button>
      </form>
      {create.error && <ErrorBox message={(create.error as Error).message} />}
      {created && (
        <div className="space-y-2 rounded-[10px] border border-accent/30 bg-accent-soft p-3">
          <p className="flex items-center gap-1.5 text-[13px] font-medium text-strong">
            <Mail size={14} aria-hidden /> {t("invite_for")} {created.email} as {created.role}: share this link
          </p>
          <div className="flex gap-2">
            <input readOnly value={created.link} onFocus={(e) => e.currentTarget.select()} aria-label={t("invite_link")} className={`${inputCls} font-mono text-xs`} />
            <button type="button" onClick={copy} className={btnSecondary}>
              {copied ? <Check size={14} aria-hidden /> : <Copy size={14} aria-hidden />} {copied ? t("l_copied") : t("l_copy")}
            </button>
          </div>
          <p className="text-xs text-muted">
            {t("shown_only_once_the_server_keeps_just_")} {t("tm_invite_note", { d: created.expires_in_days, email: created.email })}
          </p>
        </div>
      )}
    </div>
  );
}

export default function TeamPage() {
  const me = useMe();
  const qc = useQueryClient();
  const workspace = useQuery({ queryKey: ["workspace"], queryFn: api.workspace });
  const isAdmin = can(me, "admin");
  const audit = useQuery({ queryKey: ["audit"], queryFn: api.audit, enabled: isAdmin });
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["workspace"] });
    void qc.invalidateQueries({ queryKey: ["audit"] });
    void qc.invalidateQueries({ queryKey: ["me"] }); // my own role may have changed: the session stays, the UI adapts
  };
  const [renaming, setRenaming] = useState(false);
  const [name, setName] = useState("");
  const rename = useMutation({
    mutationFn: () => api.renameWorkspace(name),
    onSuccess: () => {
      setRenaming(false);
      refresh();
      void qc.invalidateQueries({ queryKey: ["me"] });
    },
  });
  const revoke = useMutation({ mutationFn: (id: number) => api.revokeInvite(id), onSuccess: refresh });

  const w = workspace.data;
  const myRole = me.user?.role ?? "viewer";

  if (!me.enabled) {
    return (
      <div className="mx-auto max-w-3xl px-4 py-8 sm:px-8">
        <PageHeader title={t("team")} subtitle={t("accounts_are_off_so_vitrix_runs_as_a_s")} />
        <Card className="space-y-3 p-5 text-[13px] text-muted">
          <p>{t("to_let_several_people_work_in_the_same")}</p>
          <pre className="rounded-[10px] border border-line bg-code p-3 font-mono text-xs text-code-text">{`auth:\n  enabled: true\n  # GitHub sign-in: set VITRIX_GITHUB_CLIENT_ID and VITRIX_GITHUB_CLIENT_SECRET`}</pre>
          <p>{t("the_first_account_to_register_becomes_")}</p>
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-8">
      <PageHeader
        title={t("team")}
        subtitle={t("everyone_who_works_in_this_workspace_w")}
        actions={
          isAdmin && !renaming ? (
            <button type="button" className={btnSecondary} onClick={() => { setName(w?.name ?? ""); setRenaming(true); }}>
              <Pencil size={14} aria-hidden /> {t("rename_workspace")}
            </button>
          ) : undefined
        }
      />
      {workspace.error && <ErrorBox message={(workspace.error as Error).message} />}

      <div className="grid gap-5">
        {renaming && (
          <Card className="p-4">
            <form onSubmit={(e) => { e.preventDefault(); rename.mutate(); }} className="flex flex-wrap gap-2">
              <label className="min-w-[14rem] flex-1">
                <span className="sr-only">{t("workspace_name")}</span>
                <input value={name} onChange={(e) => setName(e.target.value)} className={inputCls} maxLength={80} required autoFocus />
              </label>
              <button type="submit" className={btnPrimary} disabled={rename.isPending}>
                {t("save")}
              </button>
              <button type="button" className={btnSecondary} onClick={() => setRenaming(false)}>
                {t("cancel")}
              </button>
            </form>
            {rename.error && <div className="mt-2"><ErrorBox message={(rename.error as Error).message} /></div>}
          </Card>
        )}

        <Section title={w?.name ?? t("l_workspace")} aside={w ? t("tm_members", { n: w.member_count, m: w.member_count === 1 ? t("tm_member") : t("tm_members_w"), role: w.role }) : undefined}>
          {!isAdmin && <p className="text-[13px] text-muted">{t("only_admins_see_the_member_list_invite")}</p>}
          {isAdmin && w?.members && (
            <ul className="-mx-5 divide-y divide-line">
              {w.members.map((m) => (
                <MemberRow key={m.id} m={m} myRole={myRole} meId={me.user?.id ?? 0} onChanged={refresh} />
              ))}
            </ul>
          )}
        </Section>

        {isAdmin && (
          <Section title={t("invite_people")} aside={t("registration_is_by_invitation")}>
            <InviteForm myRole={myRole} onCreated={refresh} />
            {w?.invites && w.invites.length > 0 && (
              <div className="mt-5">
                <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-subtle">{t("pending_invites")}</h3>
                <ul className="divide-y divide-line">
                  {w.invites.map((i) => (
                    <li key={i.id} className="flex items-center gap-3 py-2 text-[13px]">
                      <span className="min-w-0 flex-1 truncate text-text">{i.email}</span>
                      <span className="text-xs text-muted">{i.role}</span>
                      <span className="text-xs text-subtle">{t("expires")} {timeAgo(iso(i.expires_at))}</span>
                      <button type="button" onClick={() => revoke.mutate(i.id)} className="rounded-md px-2 py-1 text-xs text-muted hover:bg-surface-2 hover:text-bad">
                        {t("revoke")}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </Section>
        )}

        <Section title={t("roles")}>
          <dl className="grid gap-x-6 gap-y-2.5 text-[13px] sm:grid-cols-[7rem_1fr]">
            {ROLES.map((r) => (
              <div key={r.id} className="contents">
                <dt className="font-semibold text-strong">{r.label}</dt>
                <dd className="text-muted">{r.can}</dd>
              </div>
            ))}
          </dl>
        </Section>

        {isAdmin && (
          <Section title={t("audit_log")} aside={t("latest_100_events")}>
            {audit.error && <ErrorBox message={(audit.error as Error).message} />}
            <ul className="-mx-5 divide-y divide-line">
              {(audit.data ?? []).map((a, i) => (
                <li key={i} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-5 py-2 text-[13px]">
                  <span className="w-24 shrink-0 text-xs text-subtle">{timeAgo(iso(a.ts))}</span>
                  <span className="font-medium text-strong">{a.actor}</span>
                  <span className="text-muted">{ACTION[a.action] ?? a.action}</span>
                  {a.detail && <span className="min-w-0 truncate font-mono text-xs text-subtle">{a.detail}</span>}
                </li>
              ))}
              {audit.data?.length === 0 && <li className="px-5 py-4 text-sm text-subtle">{t("no_events_yet")}</li>}
            </ul>
          </Section>
        )}
      </div>
    </div>
  );
}
