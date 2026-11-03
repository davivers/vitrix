"""O fluxo de uma regra: Escrever → Validar → Testar → Replay → Analisar → Quality gate → Deploy.

Funções que juntam lint, conversão, casos de teste, replay e o quality gate em relatórios
para a API, a CLI (`vitrix gate`, `vitrix replay`, `vitrix report`) e a interface.
"""

from __future__ import annotations

import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import routing
from .backends import available_targets
from .cases import run_rule_cases
from .config import Config
from .evaluator import exclusion_selections
from .gate import QUESTIONS, STAGE_LABELS, STAGES, evaluate_rule
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
    rule_id,
    summarize,
)

# ordem das colunas da matriz Enterprise ATT&CK
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
    """Replay de um dataset do repositório, conferindo as expectativas (regressão). KeyError se não existe."""
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
    """Replay de eventos colados na interface: todas as regras do repositório, ou só a regra em edição."""
    events = load_events(text, "eventos")
    if rule_text is not None:
        try:
            docs = [d for d in yaml.safe_load_all(rule_text) if d is not None]
        except yaml.YAMLError as exc:
            raise ReplayError(f"a regra não é um YAML válido: {exc}") from exc
        return replay([("<editor>", RuleFile(Path("<editor>"), "<editor>", rule_text, docs))], events)
    files, _ = _files(cfg)
    return replay(_with_ids(cfg, files), events)


def _replay_index(cfg: Config, files: list[RuleFile]) -> tuple[list[dict], dict[str, list[dict]]]:
    """Roda todos os datasets uma vez: (resumo por dataset, verificações por regra)."""
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


def _rule_quality(cfg: Config, rf: RuleFile, issues: list[Issue], extra: list, replay_checks: list[dict]) -> dict:
    results, problems = run_rule_cases(cfg, rf)
    doc = routing.first_detection(rf.docs)
    chosen = routing.resolve(cfg, rule_id(cfg, rf.path), doc)
    conv = convert_all(rf.text, chosen.targets, extra)
    detection_docs = [d for d in rf.docs if isinstance(d, dict) and "detection" in d]
    return evaluate_rule(
        cfg.gate, doc if isinstance(doc, dict) else None, None, issues, results, problems,
        {t: c["ok"] for t, c in conv.items()}, any(exclusion_selections(d) for d in detection_docs), replay_checks,
    )


def quality_report(cfg: Config, only: str | None = None) -> dict:
    """O fluxo regra a regra. `only` limita a uma regra (id dentro de rules/)."""
    files, broken = _files(cfg)
    extra = _extra_pipelines(cfg)
    lint_by_rule: dict[str, list[Issue]] = {}
    for issue in lint_files(files, set(available_targets())):
        lint_by_rule.setdefault(issue.rule, []).append(issue)
    datasets, replay_by_rule = _replay_index(cfg, files)

    rules: list[dict] = []
    for rf in files:
        rid = rule_id(cfg, rf.path)
        if only is not None and rid != only:
            continue
        q = _rule_quality(cfg, rf, lint_by_rule.get(rf.rel, []), extra, replay_by_rule.get(rid, []))
        s = summarize(_first_detection(rf.docs))
        rules.append({"id": rid, "file": rf.rel, "title": s["title"], "level": s["level"], "status": s["status"], **q})
    for rel, message in broken.items():
        if only is not None and rel != only:
            continue
        q = evaluate_rule(cfg.gate, None, message, [], [], [], {}, False, [])
        rules.append({"id": rel, "file": rel, "title": rel, "level": None, "status": None, **q})
    rules.sort(key=lambda r: (r["ready"], r["id"]))
    return {
        "summary": {"total": len(rules), "ready": sum(r["ready"] for r in rules), "blocked": sum(not r["ready"] for r in rules)},
        "stages": [{"id": s, "label": STAGE_LABELS[s], "counts": dict(Counter(r["stages"][s] for r in rules))} for s in STAGES],
        "questions": [{"id": q, "text": t, "counts": dict(Counter(r["answers"][q] for r in rules))} for q, t in QUESTIONS.items()],
        "gate": dict(vars(cfg.gate)),
        "datasets": datasets,
        "rules": rules,
    }


def draft_quality(cfg: Config, validation: dict, rule_text: str, cases_given: bool) -> dict:
    """Quality gate de uma regra ainda não salva (Editor), a partir do resultado de validate_text.

    Sem replay de regressão (a regra ainda não tem caminho), mas roda os datasets para mostrar
    quantos eventos de cada um ela pegaria.
    """
    from .cases import CaseResult

    try:
        docs = [d for d in yaml.safe_load_all(rule_text) if d is not None]
        parse_error = None
    except yaml.YAMLError as exc:
        docs, parse_error = [], f"YAML inválido: {exc}"
    doc = routing.first_detection(docs) if docs else None
    issues = [Issue(i["severity"], "<editor>", i["message"]) for i in validation["lint"]]
    tests = validation.get("tests") or {"results": [], "problems": []}
    results = [CaseResult("<editor>", r["name"], r["expect"], r["got"], r["passed"], r["error"], r["kind"], r["exercises_filter"]) for r in tests["results"]]
    problems = [Issue(p["severity"], "<editor>", p["message"]) for p in tests["problems"]]
    if not cases_given and cfg.require_cases:
        problems.append(Issue("error", "<editor>", "sem casos de teste"))
    final = {t: validation["conversions"][t]["ok"] for t in validation.get("targets", []) if t in validation.get("conversions", {})}
    detection_docs = [d for d in docs if isinstance(d, dict) and "detection" in d]
    q = evaluate_rule(cfg.gate, doc if isinstance(doc, dict) else None, parse_error, issues, results, problems,
                      final, any(exclusion_selections(d) for d in detection_docs), [])

    datasets = []
    if detection_docs:
        for path in dataset_files(cfg):
            try:
                res = replay([("<editor>", RuleFile(Path("<editor>"), "<editor>", rule_text, docs))], load_events(path.read_text(encoding="utf-8"), path.name))
            except ReplayError as exc:
                datasets.append({"dataset": dataset_name(cfg, path), "error": str(exc)})
                continue
            r = res["rules"][0]
            datasets.append({"dataset": dataset_name(cfg, path), "events": res["events"], "matches": r["matches"],
                             "duration_ms": r["duration_ms"], "error": r["error"]})
    return {**q, "datasets": datasets}


# --------------------------------------------------------------------------- test suites e cobertura


def test_suites(cfg: Config) -> dict:
    """Todos os casos de teste do repositório, com o tipo (positivo, negativo, falso positivo, borda)."""
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
    """Matriz ATT&CK: táticas na ordem da Enterprise, técnicas citadas e as regras de cada uma."""
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
        "unmapped": [{"id": r["id"], "title": r["title"]} for r in rules if not r["techniques"]],
        "techniques": len({t for r in rules for t in r["techniques"]}),
        "covered": sum(t["rules"] > 0 for t in tactics),
        "total": len(tactics),
    }


# --------------------------------------------------------------------------- relatórios


def report(cfg: Config) -> dict:
    """Relatório consolidado: quality gate, testes, cobertura e replay."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repository": cfg.github.repo if cfg.github else cfg.root.name,
        "quality": quality_report(cfg),
        "tests": test_suites(cfg),
        "coverage": coverage(cfg),
        "stats": repo_stats(cfg),
    }


_MARK = {"ok": "✅", "warn": "⚠️", "fail": "❌", "skip": "—", "pending": "⏳"}
_KIND_LABEL = {"positive": "Positivo", "negative": "Negativo", "false_positive": "Falso positivo", "edge": "Borda"}


def report_markdown(data: dict) -> str:
    """O relatório em Markdown (para anexar a um PR, wiki ou ticket)."""
    q, t, c, s = data["quality"], data["tests"], data["coverage"], data["stats"]
    lines = [
        f"# Relatório Vitrix · {data['repository']}",
        "",
        f"Gerado em {data['generated_at']}.",
        "",
        "## Quality gate",
        "",
        f"**{q['summary']['ready']} de {q['summary']['total']} regras prontas para publicação**; {q['summary']['blocked']} bloqueadas.",
        "",
        "| Pergunta | ok | aviso | falha |",
        "|---|---|---|---|",
    ]
    lines += [f"| {x['id']}. {x['text']} | {x['counts'].get('ok', 0)} | {x['counts'].get('warn', 0)} | {x['counts'].get('fail', 0)} |" for x in q["questions"]]
    lines += ["", "| Regra | " + " | ".join(STAGE_LABELS[st] for st in STAGES) + " | Bloqueios |", "|---|" + "---|" * (len(STAGES) + 1)]
    lines += [f"| `{r['id']}` | " + " | ".join(_MARK[r["stages"][st]] for st in STAGES) + f" | {'; '.join(r['blockers']) or '—'} |" for r in q["rules"]]
    lines += ["", "## Testes", "", f"{t['passed']} de {t['total']} casos passaram.", "", "| Tipo | Casos | Aprovados |", "|---|---|---|"]
    lines += [f"| {_KIND_LABEL[k]} | {v['total']} | {v['passed']} |" for k, v in t["by_kind"].items()]
    lines += ["", "## Cobertura ATT&CK", "", f"{c['covered']} de {c['total']} táticas, {c['techniques']} técnicas.", ""]
    lines += [f"- **{x['id']} {x['name']}**: {x['rules']} regra(s)" + (f" · {', '.join(tt['id'] for tt in x['techniques'])}" if x["techniques"] else "") for x in c["tactics"]]
    lines += ["", "## Replay", ""]
    if q["datasets"]:
        for d in q["datasets"]:
            state = d.get("error") or ("expectativas ok" if d["passed"] else "expectativas reprovadas")
            lines.append(f"- `{d['dataset']}`: {d.get('events', 0)} eventos, {d.get('rules_matched', 0)} regras dispararam · {state}")
    else:
        lines.append("Nenhum dataset em datasets/.")
    lines += ["", "## Acervo", "",
              f"{s['rules']['total']} regras; {s['lint']['errors']} erros e {s['lint']['warnings']} avisos de lint; {s['conversion_failures']} falhas de conversão.", ""]
    return "\n".join(lines)
