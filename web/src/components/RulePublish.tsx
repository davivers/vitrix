import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { PublishDialog } from "./PublishDialog";
import { ErrorBox } from "./ui";

/** Publish dialog for a rule that already exists on disk (used from the Rules tab). */
export function RulePublish({ id, onClose }: { id: string; onClose: () => void }) {
  const rule = useQuery({ queryKey: ["rule", id], queryFn: () => api.rule(id), retry: false });
  const text = rule.data?.text ?? "";
  const cases = rule.data?.tests.cases_text ?? "";
  const check = useQuery({ queryKey: ["publish-check", id, rule.data?.sha], queryFn: () => api.validate(text, cases.trim() ? cases : null, id), enabled: Boolean(rule.data), retry: false });
  if (rule.error) return <div className="fixed inset-x-4 top-4 z-50"><ErrorBox message={(rule.error as Error).message} /></div>;
  if (!rule.data) return null;
  const q = check.data?.quality;
  return (
    <PublishDialog
      mode={{ kind: "rule", ruleId: id, rule: text, cases, file: rule.data.sha ? { sha: rule.data.sha, cases_sha: rule.data.cases_sha ?? null } : undefined }}
      localReady={check.data ? check.data.state !== "fail" && Boolean(q?.ready) : null}
      localDetail={q && !q.ready ? q.blockers.join("; ") : undefined}
      onClose={onClose}
    />
  );
}
