import { useQuery } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import { AlertTriangle, CheckCircle2, Loader2, RotateCcw, Rocket, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { LanguageControl, ThemeControl } from "../components/ThemeControl";
import { useIsDark } from "../theme";
import { yamlExtensions } from "../components/code";
import { Section } from "../components/dash";
import { PublishDialog } from "../components/PublishDialog";
import { Card, ErrorBox, PageHeader, TargetSwatch, btnPrimary } from "../components/ui";
import type { ConfigCheck, ConfigView } from "../types";
import { t } from "../i18n";

function fmt(v: unknown): string {
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (Array.isArray(v)) return v.length ? v.join(", ") : "—";
  return String(v);
}

function Effective({ cfg }: { cfg: Omit<ConfigView, "path" | "text"> }) {
  const row = "grid grid-cols-[9rem_1fr] gap-3 py-2 text-[13px]";
  return (
    <dl className="divide-y divide-line">
      <div className={row}>
        <dt className="text-subtle">{t("active_siems")}</dt>
        <dd className="flex flex-wrap gap-1.5">
          {cfg.targets.map((t) => (
            <span key={t} className="inline-flex items-center gap-1.5 rounded-md bg-surface-2 px-2 py-0.5 font-mono text-xs text-text">
              <TargetSwatch target={t} /> {t}
            </span>
          ))}
        </dd>
      </div>
      <div className={row}>
        <dt className="text-subtle">{t("default_language")}</dt>
        <dd className="font-mono text-text">{cfg.default_target ?? t("l_every_active_target")}</dd>
      </div>
      <div className={row}>
        <dt className="text-subtle">{t("routes")}</dt>
        <dd className="text-text">
          {cfg.routes.length === 0 ? (
            <span className="text-muted">{t("none")}</span>
          ) : (
            <ul className="space-y-0.5 font-mono text-xs">
              {cfg.routes.map((r) => (
                <li key={r.match}>
                  {r.match} → {r.target.join(", ")}
                </li>
              ))}
            </ul>
          )}
        </dd>
      </div>
      <div className={row}>
        <dt className="text-subtle">{t("folders")}</dt>
        <dd className="font-mono text-xs text-text">
          rules {cfg.rules_dir}/ · cases {cfg.cases_dir}/ · datasets {cfg.datasets_dir ?? "—"}/ · output {cfg.output_dir}/
        </dd>
      </div>
      <div className={row}>
        <dt className="text-subtle">{t("requires_cases")}</dt>
        <dd className="text-text">{cfg.require_cases ? t("st_req_cases") : t("l_no_lower")}</dd>
      </div>
      <div className={row}>
        <dt className="text-subtle">{t("extra_pipelines")}</dt>
        <dd className="font-mono text-xs text-text">{cfg.extra_pipelines.length ? cfg.extra_pipelines.join(", ") : <span className="font-sans text-muted">{t("none")}</span>}</dd>
      </div>
      <div className={row}>
        <dt className="text-subtle">GitHub</dt>
        <dd className="font-mono text-xs text-text">
          {cfg.github ? (
            `${cfg.github.repo} @ ${cfg.github.base}${cfg.github.path ? ` (${cfg.github.path}/)` : ""}${cfg.github.workflow ? ` · CI: ${cfg.github.workflow}` : ""}`
          ) : (
            <span className="font-sans text-muted">{t("not_configured")}</span>
          )}
        </dd>
      </div>
    </dl>
  );
}

function CheckResult({ check, pending, dirty }: { check: ConfigCheck | null; pending: boolean; dirty: boolean }) {
  if (!check) return null;
  return (
    <div className="space-y-2" aria-live="polite">
      <p className="flex items-center gap-2 text-sm font-medium">
        {pending ? (
          <Loader2 size={15} className="animate-spin text-muted" aria-hidden />
        ) : check.ok ? (
          <CheckCircle2 size={15} className="text-good" aria-hidden />
        ) : (
          <XCircle size={15} className="text-bad" aria-hidden />
        )}
        <span className="text-strong">{pending ? t("l_validating") : check.ok ? (dirty ? t("st_valid") : t("st_current_valid")) : t("st_invalid")}</span>
      </p>
      {check.errors.map((e) => (
        <p key={e} className="flex gap-2 text-[13px]">
          <span className="shrink-0 font-medium text-bad">{t("error")}</span>
          <span className="text-text [overflow-wrap:anywhere]">{e}</span>
        </p>
      ))}
      {check.warnings.map((w) => (
        <p key={w} className="flex gap-2 text-[13px]">
          <AlertTriangle size={14} className="mt-0.5 shrink-0 text-warn" aria-hidden />
          <span className="text-text">{w}</span>
        </p>
      ))}
    </div>
  );
}

export default function SettingsPage() {
  const config = useQuery({ queryKey: ["config"], queryFn: api.config });
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const [text, setText] = useState<string | null>(null);
  const [check, setCheck] = useState<ConfigCheck | null>(null);
  const [pending, setPending] = useState(false);
  const [publishOpen, setPublishOpen] = useState(false);
  const dark = useIsDark();
  const extensions = useMemo(() => yamlExtensions(dark), [dark]);

  const original = config.data?.text ?? "";
  const current = text ?? original;
  const dirty = text !== null && text !== original;

  useEffect(() => {
    if (!config.data) return;
    const ctrl = new AbortController();
    setPending(true);
    const timer = setTimeout(() => {
      api
        .validateConfig(current, ctrl.signal)
        .then((c) => {
          setCheck(c);
          setPending(false);
        })
        .catch((e: Error) => {
          if (e.name !== "AbortError") setPending(false);
        });
    }, 400);
    return () => {
      clearTimeout(timer);
      ctrl.abort();
    };
  }, [current, config.data]);

  const localReady: boolean | null = pending || !check ? null : check.ok;

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
      <PageHeader
        title={t("settings")}
        subtitle={t("the_repository_s_vitrix_yml_nothing_is")}
      />
      {config.error && <ErrorBox message={(config.error as Error).message} />}

      {config.data && (
        <div className="grid gap-5 xl:grid-cols-[1fr_1.15fr]">
          <div className="flex flex-col gap-5">
            <Section title={t("effective_configuration")} aside={dirty ? t("st_with_changes") : (config.data.path ?? t("st_defaults"))}>
              <Effective cfg={check?.config ?? config.data} />
            </Section>
            <Section title={t("quality_gate_criteria")} aside="quality_gate">
              <dl className="space-y-1.5 text-[12.5px]">
                {Object.entries((check?.config ?? config.data).quality_gate).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-3">
                    <dt className="font-mono text-muted">{k}</dt>
                    <dd className="text-right font-mono text-text">{fmt(v)}</dd>
                  </div>
                ))}
              </dl>
            </Section>
            <Section title={t("appearance")} aside={t("this_browser_only")}>
              <ThemeControl />
              <p className="mb-2 mt-4 text-[13px] font-medium text-strong">{t("language_label")}</p>
              <LanguageControl />
            </Section>
            <Section title={t("about")}>
              <dl className="grid grid-cols-[9rem_1fr] gap-y-1.5 text-[13px]">
                <dt className="text-subtle">{t("version")}</dt>
                <dd className="font-mono text-text">{health.data?.version ?? "—"}</dd>
                <dt className="text-subtle">{t("server")}</dt>
                <dd className="text-text">{t("local_no_authentication_localhost_only")}</dd>
                <dt className="text-subtle">{t("writes")}</dt>
                <dd className="text-text">{t("only_through_github_ci_validated_branc")}</dd>
              </dl>
            </Section>
          </div>

          <Card className="flex h-[720px] flex-col overflow-hidden">
            <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
              <h2 className="font-mono text-[13px] font-semibold text-strong">{config.data.path ?? "vitrix.yml"}</h2>
              {dirty && (
                <button type="button" onClick={() => setText(null)} className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted hover:bg-surface-2 hover:text-text">
                  <RotateCcw size={13} aria-hidden /> {t("discard_changes")}
                </button>
              )}
            </div>
            <div className="min-h-0 flex-1 overflow-auto">
              <CodeMirror value={current} onChange={setText} extensions={extensions} theme="none" height="100%" basicSetup={{ foldGutter: false }} />
            </div>
            <div className="space-y-3 border-t border-line p-4">
              <CheckResult check={check} pending={pending} dirty={dirty} />
              <button type="button" disabled={!dirty} onClick={() => setPublishOpen(true)} className={btnPrimary}>
                <Rocket size={16} aria-hidden /> {t("publish_change")}
              </button>
              {!dirty && <p className="text-xs text-subtle">{t("edit_the_file_to_publish_a_change")}</p>}
            </div>
          </Card>
        </div>
      )}
      {publishOpen && (
        <PublishDialog
          mode={{ kind: "config", text: current }}
          localReady={localReady}
          localDetail={check && !check.ok ? check.errors.join("; ") : undefined}
          onClose={() => setPublishOpen(false)}
        />
      )}
    </div>
  );
}
