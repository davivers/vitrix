"""The rule lifecycle: Write → Validate → Test → Replay → Analyze → Quality gate → Deploy.

Functions that combine lint, conversion, test cases, replay, Git history and the quality gate
into reports for the API, the CLI (`vitrix gate`, `vitrix replay`, `vitrix report`) and the UI.
"""

from __future__ import annotations

import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import attack, routing
from .backends import available_targets
from .cases import run_rule_cases
from .config import Config
from .evaluator import UnsupportedError, evaluate, exclusion_selections
from .gate import QUESTIONS, STAGE_LABELS, STAGES, evaluate_rule
from .governance import rule_governance
from .history import history
from .lint import Issue, lint_files
from .loader import RuleFile
from .replay import (
    ReplayError,
    check_expectations,
    dataset_files,
    dataset_name,
    load_events,
    load_expectations,
    replay,
    resolve_dataset,
)
from .service import (
    TACTIC_IDS,
    TACTICS,
    _case,
    _extra_pipelines,
    _first_detection,
    _issue,
    _load_all,
    convert_all,
    list_rules,
    repo_stats,
    resolve_rule,
    rule_id,
    summarize,
)

# column order of the Enterprise ATT&CK matrix
ATTACK_ORDER = [
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact",
]
KINDS = ("positive", "negative", "false_positive", "edge")


def _files(cfg: Config) -> tuple[list[RuleFile], dict[str, str]]:
    return _load_all(cfg) if cfg.rules_dir.is_dir() else ([], {})


# --------------------------------------------------------------------------- replay


def list_datasets(cfg: Config) -> list[dict]:
    out = []
    for path in dataset_files(cfg):
        try:
            rules, others = load_expectations(path)
            error = None
        except ReplayError as exc:
            rules, others, error = {}, None, str(exc)
        out.append({"name": dataset_name(cfg, path), "size": path.stat().st_size, "expectations": len(rules),
                    "others": others, "expect_error": error})
    return out


def _with_ids(cfg: Config, files: list[RuleFile]) -> list[tuple[str, RuleFile]]:
    return [(rule_id(cfg, rf.path), rf) for rf in files]


def run_dataset(cfg: Config, name: str, files: list[RuleFile] | None = None) -> dict:
    """Replay one repository dataset and check its expectations (regression). KeyError if missing."""
    path = resolve_dataset(cfg, name)
    if path is None:
        raise KeyError(name)
    if files is None:
        files, _ = _files(cfg)
    result = replay(_with_ids(cfg, files), load_events(path.read_text(encoding="utf-8"), path.name))
    rules, others = load_expectations(path)
    checks = check_expectations(result, rules, others)
    return {"dataset": name, **result, "checks": checks, "passed": all(c["passed"] for c in checks),
            "has_expectations": bool(rules) or others is not None}


def replay_text(cfg: Config, text: str, rule_text: str | None = None) -> dict:
    """Replay pasted events: every repository rule, or only the rule being edited."""
    events = load_events(text, "events")
    if rule_text is not None:
        try:
            docs = [d for d in yaml.safe_load_all(rule_text) if d is not None]
        except yaml.YAMLError as exc:
            raise ReplayError(f"the rule is not valid YAML: {exc}") from exc
        return replay([("<editor>", RuleFile(Path("<editor>"), "<editor>", rule_text, docs))], events)
    files, _ = _files(cfg)
    return replay(_with_ids(cfg, files), events)


def _replay_index(cfg: Config, files: list[RuleFile]) -> tuple[list[dict], dict[str, list[dict]]]:
    """Run every dataset once: (summary per dataset, checks per rule)."""
    datasets: list[dict] = []
    by_rule: dict[str, list[dict]] = {}
    for path in dataset_files(cfg):
        name = dataset_name(cfg, path)
        try:
            res = run_dataset(cfg, name, files)
        except ReplayError as exc:
            datasets.append({"dataset": name, "error": str(exc), "passed": False, "checks": [], "events": 0, "rules_matched": 0})
            continue
        datasets.append({k: v for k, v in res.items() if k != "rules"})
        for c in res["checks"]:
            by_rule.setdefault(c["rule"], []).append({**c, "dataset": name})
    return datasets, by_rule


# --------------------------------------------------------------------------- quality gate


def _rule_quality(cfg: Config, rf: RuleFile, issues: list[Issue], extra: list, replay_checks: list[dict],
                  age_days: float | None = None) -> dict:
    results, problems = run_rule_cases(cfg, rf)
    doc = routing.first_detection(rf.docs)
    chosen = routing.resolve(cfg, rule_id(cfg, rf.path), doc)
    conv = convert_all(rf.text, chosen.targets, extra, cfg.kql)
    detection_docs = [d for d in rf.docs if isinstance(d, dict) and "detection" in d]
    return evaluate_rule(
        cfg.gate, doc if isinstance(doc, dict) else None, None, issues, results, problems,
        {t: c["ok"] for t, c in conv.items()}, any(exclusion_selections(d) for d in detection_docs), replay_checks, age_days,
        rule_governance(doc),
    )


def _ages(cfg: Config) -> dict[str, float]:
    hist = history(cfg)
    return {rid: info["age_days"] for rid, info in hist.get("rules", {}).items()} if hist.get("available") else {}


def quality_report(cfg: Config, only: str | None = None) -> dict:
    """The lifecycle rule by rule. `only` limits it to one rule (id inside rules/)."""
    files, broken = _files(cfg)
    extra = _extra_pipelines(cfg)
    lint_by_rule: dict[str, list[Issue]] = {}
    for issue in lint_files(files, set(available_targets())):
        lint_by_rule.setdefault(issue.rule, []).append(issue)
    datasets, replay_by_rule = _replay_index(cfg, files)
    ages = _ages(cfg)

    rules: list[dict] = []
    for rf in files:
        rid = rule_id(cfg, rf.path)
        if only is not None and rid != only:
            continue
        q = _rule_quality(cfg, rf, lint_by_rule.get(rf.rel, []), extra, replay_by_rule.get(rid, []), ages.get(rid))
        s = summarize(_first_detection(rf.docs))
        rules.append({"id": rid, "file": rf.rel, "title": s["title"], "level": s["level"], "status": s["status"],
                      "age_days": ages.get(rid), **q})
    for rel, message in broken.items():
        if only is not None and rel != only:
            continue
        q = evaluate_rule(cfg.gate, None, message, [], [], [], {}, False, [])
        rules.append({"id": rel, "file": rel, "title": rel, "level": None, "status": None, "age_days": ages.get(rel), **q})
    rules.sort(key=lambda r: (r["ready"], r["score"], r["id"]))
    return {
        "summary": {
            "total": len(rules),
            "ready": sum(r["ready"] for r in rules),
            "blocked": sum(not r["ready"] for r in rules),
            "health": round(sum(r["score"] for r in rules) / len(rules)) if rules else None,
            "stale": sum(1 for r in rules if any(c["id"] == "review" and c["passed"] is False for c in r["checks"])),
        },
        "stages": [{"id": s, "label": STAGE_LABELS[s], "counts": dict(Counter(r["stages"][s] for r in rules))} for s in STAGES],
        "questions": [{"id": q, "text": t, "counts": dict(Counter(r["answers"][q] for r in rules))} for q, t in QUESTIONS.items()],
        "gate": dict(vars(cfg.gate)),
        "datasets": datasets,
        "rules": rules,
    }


def draft_quality(cfg: Config, validation: dict, rule_text: str, cases_given: bool, path: str | None = None) -> dict:
    """Quality gate of a rule being edited (Editor), built from the validate_text result.

    With `path` (an existing rule), replay expectations and Git age for that rule apply too.
    """
    from .cases import CaseResult

    try:
        docs = [d for d in yaml.safe_load_all(rule_text) if d is not None]
        parse_error = None
    except yaml.YAMLError as exc:
        docs, parse_error = [], f"invalid YAML: {exc}"
    doc = routing.first_detection(docs) if docs else None
    issues = [Issue.from_dict(i) for i in validation["lint"]]
    tests = validation.get("tests") or {"results": [], "problems": []}
    results = [CaseResult("<editor>", r["name"], r["expect"], r["got"], r["passed"], r["error"], r["kind"], r["exercises_filter"])
               for r in tests["results"]]
    problems = [Issue.from_dict(p) for p in tests["problems"]]
    if not cases_given and cfg.require_cases:
        problems.append(Issue("error", "<editor>", "no test cases"))
    final = {t: validation["conversions"][t]["ok"] for t in validation.get("targets", []) if t in validation.get("conversions", {})}
    detection_docs = [d for d in docs if isinstance(d, dict) and "detection" in d]

    datasets: list[dict] = []
    replay_checks: list[dict] = []
    if detection_docs:
        draft = RuleFile(Path("<editor>"), path or "<editor>", rule_text, docs)
        for dpath in dataset_files(cfg):
            name = dataset_name(cfg, dpath)
            try:
                res = replay([(path or "<editor>", draft)], load_events(dpath.read_text(encoding="utf-8"), dpath.name))
                expectations, _ = load_expectations(dpath)
            except ReplayError as exc:
                datasets.append({"dataset": name, "error": str(exc)})
                continue
            r = res["rules"][0]
            datasets.append({"dataset": name, "events": res["events"], "matches": r["matches"], "duration_ms": r["duration_ms"], "error": r["error"]})
            if path and path in expectations:
                replay_checks += [{**c, "dataset": name} for c in check_expectations(res, {path: expectations[path]}, None)]
    q = evaluate_rule(cfg.gate, doc if isinstance(doc, dict) else None, parse_error, issues, results, problems,
                      final, any(exclusion_selections(d) for d in detection_docs), replay_checks,
                      _ages(cfg).get(path) if path else None, rule_governance(doc))
    return {**q, "datasets": datasets}


# --------------------------------------------------------------------------- test suites and coverage


def test_suites(cfg: Config) -> dict:
    """Every test case in the repository, with its kind (positive, negative, false positive, edge)."""
    files, broken = _files(cfg)
    started = time.perf_counter()
    rules = []
    for rf in files:
        results, problems = run_rule_cases(cfg, rf)
        s = summarize(_first_detection(rf.docs))
        rules.append({"id": rule_id(cfg, rf.path), "file": rf.rel, "title": s["title"], "level": s["level"],
                      "results": [_case(r) for r in results], "problems": [_issue(p) for p in problems]})
    cases = [c for r in rules for c in r["results"]]
    by_kind = {k: {"total": sum(c["kind"] == k for c in cases), "passed": sum(c["kind"] == k and c["passed"] for c in cases)} for k in KINDS}
    return {
        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        "total": len(cases),
        "passed": sum(c["passed"] for c in cases),
        "by_kind": by_kind,
        "rules": rules,
        "broken": [{"file": f, "error": e} for f, e in broken.items()],
    }


def coverage(cfg: Config) -> dict:
    """ATT&CK matrix: tactics in Enterprise order, techniques cited by the rules and their rules."""
    rules = list_rules(cfg)
    names = dict(TACTICS)
    tactics = []
    for slug in ATTACK_ORDER:
        in_tactic = [r for r in rules if slug in r["tactics"]]
        techniques: dict[str, list[dict]] = {}
        for r in in_tactic:
            for t in r["techniques"] or ["—"]:
                techniques.setdefault(t, []).append({"id": r["id"], "title": r["title"], "state": r["state"], "level": r["level"]})
        tactics.append({"slug": slug, "id": TACTIC_IDS[slug], "name": names[slug], "rules": len(in_tactic),
                        "techniques": [{"id": t, "rules": rs} for t, rs in sorted(techniques.items())]})
    return {
        "tactics": tactics,
        "logsources": logsource_coverage(cfg),
        "unmapped": [{"id": r["id"], "title": r["title"]} for r in rules if not r["techniques"]],
        "techniques": len({t for r in rules for t in r["techniques"]}),
        "covered": sum(t["rules"] > 0 for t in tactics),
        "total": len(tactics),
        "catalog": attack.catalog(),
    }


def logsource_coverage(cfg: Config) -> list[dict]:
    """Rules, tactics and techniques per data source (logsource product / category / service)."""
    files, _ = _files(cfg)
    groups: dict[str, dict] = {}
    for rf in files:
        doc = _first_detection(rf.docs)
        if not isinstance(doc, dict):
            continue
        ls = doc.get("logsource") if isinstance(doc.get("logsource"), dict) else {}
        key = " / ".join(str(ls[k]) for k in ("product", "category", "service") if ls.get(k)) or "(no logsource)"
        s = summarize(doc)
        g = groups.setdefault(key, {"logsource": key, "product": ls.get("product"), "rules": 0, "techniques": set(), "tactics": set()})
        g["rules"] += 1
        g["techniques"] |= set(s["techniques"])
        g["tactics"] |= set(s["tactics"])
    return sorted(({**g, "techniques": sorted(g["techniques"]), "tactics": sorted(g["tactics"])} for g in groups.values()),
                  key=lambda g: (-g["rules"], g["logsource"]))


def navigator_layer(cfg: Config) -> dict:
    """A MITRE ATT&CK Navigator layer (format 4.5): every technique with its rule count and titles.

    Open it at https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer → Upload).
    """
    rules = list_rules(cfg)
    by_tech: dict[str, list[dict]] = {}
    for r in rules:
        for t in r["techniques"]:
            by_tech.setdefault(t, []).append(r)
    top = max((len(v) for v in by_tech.values()), default=1)
    return {
        "name": f"Vitrix · {cfg.github.repo if cfg.github else cfg.root.name}",
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "16"},
        "domain": "enterprise-attack",
        "description": "Coverage of the repository's Sigma rules (generated by Vitrix).",
        "techniques": [
            {
                "techniqueID": t,
                "score": len(rs),
                "comment": "; ".join(r["title"] or r["id"] for r in rs)[:1000],
                "enabled": True,
                "metadata": [{"name": "rule", "value": r["id"]} for r in rs[:20]],
                "showSubtechniques": "." in t,
            }
            for t, rs in sorted(by_tech.items())
        ],
        "gradient": {"colors": ["#d9d4fc", "#6d5bf0"], "minValue": 0, "maxValue": top},
        "legendItems": [],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
    }


def _matching_events(rf: RuleFile | None, events: list[dict]) -> tuple[list[int], str | None]:
    if rf is None:
        return [], None
    docs = [d for d in rf.docs if isinstance(d, dict) and "detection" in d]
    try:
        return [i for i, e in enumerate(events, 1) if any(evaluate(d, e) for d in docs)], None
    except UnsupportedError as exc:
        return [], str(exc)


def impact_analysis(cfg: Config, path: str | None, rule_text: str) -> dict:
    """Rule impact analysis: the saved rule vs. the edited version, on the same datasets.

    Shows, before the pull request, how many events each version matches and which events start
    or stop matching. For a new rule (nothing saved yet) `before` is null.
    """
    try:
        draft_docs = [d for d in yaml.safe_load_all(rule_text) if d is not None]
    except yaml.YAMLError as exc:
        raise ReplayError(f"the edited rule is not valid YAML: {exc}") from exc
    saved_path = resolve_rule(cfg, path) if path else None
    saved = None
    if saved_path is not None:
        text = saved_path.read_text(encoding="utf-8")
        saved = RuleFile(saved_path, path or "", text, [d for d in yaml.safe_load_all(text) if d is not None])
    draft = RuleFile(Path("<editor>"), "<editor>", rule_text, draft_docs)
    out = []
    for dpath in dataset_files(cfg):
        name = dataset_name(cfg, dpath)
        try:
            events = load_events(dpath.read_text(encoding="utf-8"), dpath.name)
            expectations, _ = load_expectations(dpath)
        except ReplayError as exc:
            out.append({"dataset": name, "error": str(exc)})
            continue
        after, err_after = _matching_events(draft, events)
        before, err_before = _matching_events(saved, events)
        expected = expectations.get(path) if path else None
        out.append({
            "dataset": name,
            "events": len(events),
            "before": len(before) if saved else None,
            "after": len(after),
            "added": sorted(set(after) - set(before))[:50],
            "removed": sorted(set(before) - set(after))[:50],
            "error": err_after or err_before,
            "expected": expected,
            "meets_expectation": None if expected is None else (
                len(after) >= expected["min"] and (expected["max"] is None or len(after) <= expected["max"])),
        })
    return {"rule": path, "saved": saved is not None, "datasets": out,
            "changed": any(d.get("added") or d.get("removed") for d in out)}


# --------------------------------------------------------------------------- reports


def report(cfg: Config) -> dict:
    """Consolidated report: quality gate, tests, coverage, replay and history."""
    hist = history(cfg)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repository": cfg.github.repo if cfg.github else cfg.root.name,
        "quality": quality_report(cfg),
        "tests": test_suites(cfg),
        "coverage": coverage(cfg),
        "stats": repo_stats(cfg),
        "history": {k: hist.get(k) for k in ("available", "commits", "head", "authors")} if hist.get("available") else {"available": False},
    }


_MARK = {"ok": "✅", "warn": "⚠️", "fail": "❌", "skip": "—", "pending": "⏳"}
_KIND_LABEL = {"positive": "Positive", "negative": "Negative", "false_positive": "False positive", "edge": "Edge"}


def report_markdown(data: dict) -> str:
    """The report in Markdown (to attach to a PR, wiki or ticket)."""
    q, t, c, s = data["quality"], data["tests"], data["coverage"], data["stats"]
    summary = q["summary"]
    lines = [
        f"# Vitrix report · {data['repository']}",
        "",
        f"Generated at {data['generated_at']}.",
        "",
        "## Quality gate",
        "",
        f"**{summary['ready']} of {summary['total']} rules ready to publish**; {summary['blocked']} blocked."
        + (f" Average health score: **{summary['health']}/100**." if summary.get("health") is not None else ""),
        "",
        "| Question | yes | warning | no |",
        "|---|---|---|---|",
    ]
    lines += [f"| {x['id']}. {x['text']} | {x['counts'].get('ok', 0)} | {x['counts'].get('warn', 0)} | {x['counts'].get('fail', 0)} |" for x in q["questions"]]
    lines += ["", "| Rule | Health | " + " | ".join(STAGE_LABELS[st] for st in STAGES) + " | Blockers |", "|---|---|" + "---|" * (len(STAGES) + 1)]
    lines += [f"| `{r['id']}` | {r['score']} | " + " | ".join(_MARK[r["stages"][st]] for st in STAGES) + f" | {'; '.join(r['blockers']) or '—'} |"
              for r in q["rules"]]
    lines += ["", "## Tests", "", f"{t['passed']} of {t['total']} cases passed.", "", "| Kind | Cases | Passed |", "|---|---|---|"]
    lines += [f"| {_KIND_LABEL[k]} | {v['total']} | {v['passed']} |" for k, v in t["by_kind"].items()]
    lines += ["", "## ATT&CK coverage", "", f"{c['covered']} of {c['total']} tactics, {c['techniques']} techniques.", ""]
    lines += [f"- **{x['id']} {x['name']}**: {x['rules']} rule(s)" + (f" · {', '.join(tt['id'] for tt in x['techniques'])}" if x["techniques"] else "")
              for x in c["tactics"]]
    lines += ["", "### Data sources", ""]
    lines += [f"- `{g['logsource']}`: {g['rules']} rule(s), {len(g['techniques'])} technique(s)" for g in c["logsources"]] or ["No rules."]
    lines += ["", "## Replay", ""]
    if q["datasets"]:
        for d in q["datasets"]:
            state = d.get("error") or ("expectations met" if d["passed"] else "expectations failed")
            lines.append(f"- `{d['dataset']}`: {d.get('events', 0)} events, {d.get('rules_matched', 0)} rules fired · {state}")
    else:
        lines.append("No dataset in datasets/.")
    lines += ["", "## Rule set", "",
              f"{s['rules']['total']} rules; {s['lint']['errors']} lint errors and {s['lint']['warnings']} warnings; "
              f"{s['conversion_failures']} conversion failures.", ""]
    return "\n".join(lines)
