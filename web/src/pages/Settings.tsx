import { useQuery } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import { CheckCircle2, RefreshCw, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useMe } from "../components/auth";
import { LanguageControl, ThemeControl } from "../components/ThemeControl";
import { useIsDark } from "../theme";
import { yamlExtensions } from "../components/code";
import { timeAgo } from "../components/dash";
import { Card, ErrorBox, PageHeader, TargetSwatch } from "../components/ui";
import { GATE_LABELS, fmt } from "../components/flow";
import { EditorState } from "@codemirror/state";
import { EditorView } from "@codemirror/view";
import { t } from "../i18n";

const NAV = ["general", "appearance", "languages", "gate", "folders", "about", "yml"] as const;

/** One label/value row; no card per fact (settings-v2 spec). */
function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid min-h-11 grid-cols-1 gap-x-4 gap-y-0.5 border-b border-line py-2.5 text-[14px] last:border-0 sm:grid-cols-[12rem_1fr]">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 text-text [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

function Block({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-h`} className="scroll-mt-6 border-t border-line pt-6 first:border-0 first:pt-0">
      <h2 id={`${id}-h`} className="mb-2 text-[15px] font-semibold text-strong">
        {title}
      </h2>
      <dl>{children}</dl>
    </section>
  );
}

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="ml-2 rounded px-1.5 py-0.5 text-xs text-muted hover:bg-surface-2 hover:text-text"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* no clipboard permission */
        }
      }}
    >
      {done ? t("l_copied") : t("l_copy")}
    </button>
  );
}

export default function SettingsPage() {
  const me = useMe();
  const config = useQuery({ queryKey: ["config"], queryFn: api.config, refetchOnWindowFocus: "always" }); // vitrix.yml is hot-reloaded: show edits made elsewhere
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const dark = useIsDark();
  const extensions = useMemo(() => [...yamlExtensions(dark), EditorState.readOnly.of(true), EditorView.editable.of(false)], [dark]);
  const current = config.data?.text ?? "";

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-8">
      <PageHeader
        title={t("settings")}
        subtitle={t("the_repository_s_vitrix_yml_nothing_is")}
      />
      {config.error && <ErrorBox message={(config.error as Error).message} />}
      {config.data?.reload_error && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-bad/30 bg-bad-soft p-3 text-sm text-bad" role="alert">
          <XCircle size={16} className="mt-0.5 shrink-0" aria-hidden />
          <div className="min-w-0 [overflow-wrap:anywhere]">
            {t("st_reload_error")} <span className="font-mono">{config.data.reload_error}</span>
          </div>
        </div>
      )}
      {config.data?.restart_required && config.data.restart_required.length > 0 && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-line bg-surface p-3 text-sm text-text" role="status">
          <RefreshCw size={16} className="mt-0.5 shrink-0 text-accent" aria-hidden />
          {t("st_restart", { keys: config.data.restart_required.join(", ") })}
        </div>
      )}

      {config.isLoading && <p className="text-sm text-muted">{t("loading")}</p>}
      {config.data && (() => {
        const cfg = config.data;
        const file = config.data.file || config.data.path;
        return (
          <div className="grid gap-6 lg:grid-cols-[12rem_1fr]">
            <nav aria-label={t("st_sections")} className="no-scrollbar flex gap-1 overflow-x-auto lg:sticky lg:top-6 lg:flex-col lg:self-start lg:overflow-visible">
              {NAV.map((id) => (
                <a key={id} href={`#${id}`} className="whitespace-nowrap rounded-md border-l-2 border-transparent px-3 py-1.5 text-[13.5px] text-muted hover:bg-surface-2 hover:text-text">
                  {t(`st_nav_${id}` as "st_nav_general")}
                </a>
              ))}
            </nav>
            <div className="max-w-[760px] space-y-6">
              <Block id="general" title={t("st_nav_general")}>
                <Row label={t("st_file")}>
                  {file ? (
                    <>
                      <span className="font-mono text-[13px]">{file}</span>
                      <CopyBtn text={file} />
                    </>
                  ) : (
                    <span className="text-muted">{t("st_no_file")}</span>
                  )}
                </Row>
                <Row label={t("state")}>
                  <span className="inline-flex flex-wrap items-center gap-2">
                    <CheckCircle2 size={14} className="text-good" aria-hidden />
                    {config.data.loaded_at != null
                      ? t("st_loaded", { when: timeAgo(typeof config.data.loaded_at === "number" ? new Date(config.data.loaded_at < 1e12 ? config.data.loaded_at * 1000 : config.data.loaded_at).toISOString() : config.data.loaded_at) })
                      : t("st_defaults")}
                    <button type="button" className="inline-flex items-center gap-1 rounded-md border border-line px-2 py-0.5 text-xs hover:bg-surface-2" onClick={() => void config.refetch()}>
                      <RefreshCw size={12} className={config.isFetching ? "animate-spin" : undefined} aria-hidden /> {t("st_reload")}
                    </button>
                  </span>
                  <span className="mt-1 block text-xs text-muted">{t("st_hot")}</span>
                </Row>
                <Row label={t("default_language")}>{cfg.default_target ? <span className="font-mono">{cfg.default_target}</span> : t("l_every_active_target")}</Row>
                <Row label={t("requires_cases")}>{cfg.require_cases ? t("st_req_cases") : t("l_no_lower")}</Row>
              </Block>

              <Block id="appearance" title={t("appearance")}>
                <Row label={t("st_theme")}>
                  <ThemeControl />
                </Row>
                <Row label={t("language_label")}>
                  <LanguageControl />
                  <span className="mt-1 block text-xs text-muted">{t("this_browser_only")}</span>
                </Row>
              </Block>

              <Block id="languages" title={t("cn_languages")}>
                <Row label={t("active_siems")}>
                  <span className="flex flex-wrap gap-1.5">
                    {cfg.targets.map((x) => (
                      <span key={x} className="inline-flex items-center gap-1.5 rounded-md bg-surface-2 px-2 py-0.5 font-mono text-xs">
                        <TargetSwatch target={x} /> {x}
                      </span>
                    ))}
                  </span>
                  <Link to="/connections" className="mt-1 inline-block text-xs font-medium text-accent hover:underline">
                    {t("st_details_conn")}
                  </Link>
                </Row>
                <Row label={t("routes")}>
                  {cfg.routes.length === 0 ? (
                    <span className="text-muted">{t("none")}</span>
                  ) : (
                    <ul className="space-y-0.5 font-mono text-xs">
                      {cfg.routes.map((r) => (
                        <li key={r.match}>
                          {r.match} {"->"} {r.target.join(", ")}
                        </li>
                      ))}
                    </ul>
                  )}
                </Row>
                <Row label={t("extra_pipelines")}>{cfg.extra_pipelines.length ? <span className="font-mono text-xs">{cfg.extra_pipelines.join(", ")}</span> : <span className="text-muted">{t("none")}</span>}</Row>
              </Block>

              <Block id="gate" title={t("quality_gate_criteria")}>
                {Object.entries(cfg.quality_gate).map(([k, v]) => (
                  <Row key={k} label={GATE_LABELS[k] ?? k}>
                    <span className="font-mono text-[13px]">{fmt(v, k)}</span>
                  </Row>
                ))}
              </Block>

              <Block id="folders" title={t("folders")}>
                {(
                  [
                    ["rules", cfg.rules_dir],
                    ["cases", cfg.cases_dir],
                    ["datasets", cfg.datasets_dir],
                    ["output", cfg.output_dir],
                  ] as const
                ).map(([k, v]) => (
                  <Row key={k} label={k}>
                    {v ? (
                      <>
                        <span className="font-mono text-[13px]">{v}/</span>
                        <CopyBtn text={v} />
                      </>
                    ) : (
                      <span className="text-muted">-</span>
                    )}
                  </Row>
                ))}
                <Row label="GitHub">
                  {cfg.github ? <span className="font-mono text-[13px]">{`${cfg.github.repo} @ ${cfg.github.base}${cfg.github.workflow ? ` · CI: ${cfg.github.workflow}` : ""}`}</span> : <span className="text-muted">{t("not_configured")}</span>}
                </Row>
              </Block>

              <Block id="about" title={t("about")}>
                <Row label={t("version")}>
                  <span className="font-mono">{health.data?.version ?? "-"}</span>
                </Row>
                <Row label={t("server")}>{me.enabled ? t("st_mode_accounts") : t("st_mode_open")}</Row>
                <Row label={t("writes")}>{t("st_writes_note")}</Row>
              </Block>

              <section id="yml" aria-labelledby="yml-h" className="scroll-mt-6 border-t border-line pt-6">
                <details>
                  <summary id="yml-h" className="cursor-pointer text-[15px] font-semibold text-strong">
                    {t("st_view_yml")}
                  </summary>
                  <Card className="mt-3 flex h-[480px] flex-col overflow-hidden">
                    <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
                      <h3 className="font-mono text-[13px] font-semibold text-strong">{config.data.path ?? "vitrix.yml"}</h3>
                      <span className="text-xs text-muted">{t("st_readonly_yml")}</span>
                      <CopyBtn text={current} />
                    </div>
                    <div className="min-h-0 flex-1 overflow-auto bg-code">
                      <CodeMirror value={current} extensions={extensions} theme="none" height="100%" readOnly basicSetup={{ foldGutter: false }} />
                    </div>
                  </Card>
                </details>
              </section>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
