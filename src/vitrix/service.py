"""Camada de serviço: o que a API (e qualquer interface) consome.

Tudo aqui devolve dicts simples, prontos para virar JSON. A CLI e a API usam as mesmas
funções do motor por baixo, então os números das telas são os mesmos do `vitrix check`.
"""

from __future__ import annotations

import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import routing
from .backends import available_targets, convert_text, load_extra_pipelines
from .cases import CaseResult, cases_path, parse_cases, run_cases, run_rule_cases
from .config import Config, ConfigError, parse_config_text
from .github import GitHubClient, GitHubError, branch_slug
from .lint import Issue, lint_doc, lint_files
from .loader import RULE_SUFFIXES, RuleFile, RuleLoadError, find_rule_files, load_rule

# Táticas do MITRE ATT&CK com o nome usado nas tags do Sigma (attack.<slug>).
TACTICS = [
    ("initial_access", "Acesso inicial"),
    ("execution", "Execução"),
    ("persistence", "Persistência"),
    ("privilege_escalation", "Escalação de privilégios"),
    ("defense_evasion", "Evasão de defesa"),
    ("credential_access", "Acesso a credenciais"),
    ("discovery", "Descoberta"),
    ("lateral_movement", "Movimentação lateral"),
    ("collection", "Coleta"),
    ("command_and_control", "Comando e controle"),
    ("exfiltration", "Exfiltração"),
    ("impact", "Impacto"),
    ("reconnaissance", "Reconhecimento"),
    ("resource_development", "Desenvolvimento de recursos"),
]
_TACTIC_SLUGS = {slug for slug, _ in TACTICS}
TACTIC_IDS = {
    "reconnaissance": "TA0043", "resource_development": "TA0042", "initial_access": "TA0001", "execution": "TA0002",
    "persistence": "TA0003", "privilege_escalation": "TA0004", "defense_evasion": "TA0005", "credential_access": "TA0006",
    "discovery": "TA0007", "lateral_movement": "TA0008", "collection": "TA0009", "command_and_control": "TA0011",
    "exfiltration": "TA0010", "impact": "TA0040",
}
_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


class ServiceError(Exception):
    """Falha de configuração que a interface deve mostrar (ex.: pipeline extra inválido)."""


# --------------------------------------------------------------------------- helpers


def _issue(i: Issue) -> dict:
    return {"severity": i.severity, "message": i.message}


def _case(r: CaseResult) -> dict:
    return {"name": r.name, "expect": r.expect, "got": r.got, "passed": r.passed, "error": r.error,
            "kind": r.kind, "exercises_filter": r.exercises_filter}


def _state(issues: list[Issue], results: list[CaseResult], conversion_failed: bool = False) -> str:
    if conversion_failed or any(i.severity == "error" for i in issues) or any(not r.passed for r in results):
        return "fail"
    if any(i.severity == "warning" for i in issues):
        return "warn"
    return "ok"


def _extra_pipelines(cfg: Config) -> list:
    try:
        return load_extra_pipelines(cfg.extra_pipelines)
    except Exception as exc:
        raise ServiceError(f"não foi possível carregar extra_pipelines: {exc}") from exc


def summarize(doc: object) -> dict:
    if not isinstance(doc, dict):
        return {"sigma_id": "", "title": "", "status": None, "level": None, "description": "", "tags": [], "tactics": [], "techniques": []}
    tags = [t for t in (doc.get("tags") or []) if isinstance(t, str)]
    tactics = sorted({t[len("attack."):] for t in tags if t.startswith("attack.") and t[len("attack."):] in _TACTIC_SLUGS})
    techniques = sorted({m.group(1).upper() for t in tags if (m := _TECHNIQUE.match(t))})
    return {
        "sigma_id": str(doc.get("id", "")),  # UUID da regra; "id" nas respostas é o caminho usado na URL
        "title": str(doc.get("title", "")),
        "status": doc.get("status"),
        "level": doc.get("level"),
        "description": str(doc.get("description", "")),
        "tags": tags,
        "tactics": tactics,
        "techniques": techniques,
    }


def _first_detection(docs: list) -> object:
    return next((d for d in docs if isinstance(d, dict) and "detection" in d), docs[0] if docs else None)


def rule_id(cfg: Config, path: Path) -> str:
    """Identificador estável usado nas URLs: caminho relativo à pasta de regras."""
    try:
        return path.resolve().relative_to(cfg.rules_dir.resolve()).as_posix()
    except ValueError:
        return path.name


def resolve_rule(cfg: Config, rid: str) -> Path | None:
    """Resolve um id em arquivo. Só aceita arquivos de regra dentro da pasta de regras."""
    base = cfg.rules_dir.resolve()
    candidate = (base / rid).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        return None
    if candidate.suffix not in RULE_SUFFIXES or not candidate.is_file():
        return None
    return candidate


def convert_all(text: str, target_names: list[str], extra: list) -> dict:
    registry = available_targets()
    out: dict[str, dict] = {}
    for name in target_names:
        target = registry.get(name)
        if target is None:
            out[name] = {"ok": False, "label": name, "error": "alvo desconhecido"}
            continue
        try:
            out[name] = {"ok": True, "label": target.label, "extension": target.extension,
                         "query": convert_text(text, target, extra)}
        except Exception as exc:  # erros do pySigma e de plugins de terceiros
            message = " ".join(str(exc).split()) or type(exc).__name__
            out[name] = {"ok": False, "label": target.label, "error": f"{type(exc).__name__}: {message}"}
    return out


def _load_all(cfg: Config) -> tuple[list[RuleFile], dict[str, str]]:
    files: list[RuleFile] = []
    broken: dict[str, str] = {}
    for path in find_rule_files([], cfg):
        try:
            files.append(load_rule(path, cfg))
        except RuleLoadError as exc:
            broken[cfg.rel(path)] = str(exc)
    return files, broken


def _top_issues(issues: list[Issue], problems: list[Issue], results: list[CaseResult], conv: dict, limit: int = 3) -> list[dict]:
    """As pendências que explicam o estado da regra, erros primeiro (para a lista de pendências)."""
    found: list[dict] = []
    for c in conv.values():
        if not c["ok"]:
            found.append({"severity": "error", "message": f"falha de conversão ({c['label']}): {c.get('error', '')}"})
    for r in results:
        if not r.passed:
            detail = r.error or f"esperado {r.expect}, obtido {r.got}"
            found.append({"severity": "error", "message": f"caso “{r.name}”: {detail}"})
    found.extend(_issue(i) for i in [*issues, *problems])
    found.sort(key=lambda i: i["severity"] != "error")
    return found[:limit]


# --------------------------------------------------------------------------- consultas


def list_rules(cfg: Config) -> list[dict]:
    if not cfg.rules_dir.is_dir():
        return []
    files, broken = _load_all(cfg)
    extra = _extra_pipelines(cfg)
    known = set(available_targets())
    issues_by_rule: dict[str, list[Issue]] = {}
    for issue in lint_files(files, known):
        issues_by_rule.setdefault(issue.rule, []).append(issue)

    out: list[dict] = []
    for rf in files:
        issues = issues_by_rule.get(rf.rel, [])
        results, problems = run_rule_cases(cfg, rf)
        chosen = routing.resolve(cfg, rule_id(cfg, rf.path), routing.first_detection(rf.docs))
        conv = convert_all(rf.text, chosen.targets, extra)
        out.append({
            "issues": _top_issues(issues, problems, results, conv),
            "id": rule_id(cfg, rf.path),
            "file": rf.rel,
            **summarize(_first_detection(rf.docs)),
            "targets": chosen.targets,  # linguagem(ns) final(is)
            "target_source": chosen.source,  # rule | route | default | all
            "conversion": {name: c["ok"] for name, c in conv.items()},
            "state": _state([*issues, *problems], results, any(not c["ok"] for c in conv.values())),
            "lint": {
                "errors": sum(i.severity == "error" for i in issues),
                "warnings": sum(i.severity == "warning" for i in issues),
            },
            "tests": {"total": len(results), "passed": sum(r.passed for r in results)},
        })
    for rel, message in broken.items():
        out.append({
            "id": rel, "file": rel, "sigma_id": "", "title": rel, "status": None, "level": None, "description": "",
            "tags": [], "tactics": [], "techniques": [], "targets": [], "target_source": None, "conversion": {},
            "state": "fail", "error": message, "issues": [{"severity": "error", "message": message}],
            "lint": {"errors": 1, "warnings": 0}, "tests": {"total": 0, "passed": 0},
        })
    return sorted(out, key=lambda r: r["id"])


def rule_detail(cfg: Config, rid: str) -> dict:
    """Tudo sobre uma regra. Levanta KeyError se o id não existe."""
    path = resolve_rule(cfg, rid)
    if path is None:
        raise KeyError(rid)
    files, _ = _load_all(cfg)
    rf = next((f for f in files if f.path == path), None)
    if rf is None:
        try:
            rf = load_rule(path, cfg)
        except RuleLoadError as exc:
            return {"id": rid, "file": cfg.rel(path), "text": path.read_text(encoding="utf-8"), "summary": summarize(None),
                    "state": "fail", "lint": [{"severity": "error", "message": str(exc)}], "conversions": {}, "targets": [], "target_source": None,
                    "tests": {"cases_file": None, "cases_text": None, "results": [], "problems": []}}
        files.append(rf)

    issues = [i for i in lint_files(files, set(available_targets())) if i.rule == rf.rel]
    results, problems = run_rule_cases(cfg, rf)
    cpath = cases_path(cfg, rf)
    chosen = routing.resolve(cfg, rid, routing.first_detection(rf.docs))
    # a linguagem final vem primeiro; os demais alvos ativos ficam para pré-visualização
    conversions = convert_all(rf.text, list(dict.fromkeys([*chosen.targets, *cfg.targets])), _extra_pipelines(cfg))
    conv_failed = any(not conversions[t]["ok"] for t in chosen.targets if t in conversions)
    return {
        "id": rid,
        "file": rf.rel,
        "text": rf.text,
        "summary": summarize(_first_detection(rf.docs)),
        "state": _state([*issues, *problems], results, conv_failed),
        "targets": chosen.targets,
        "target_source": chosen.source,
        "lint": [_issue(i) for i in issues],
        "conversions": conversions,
        "tests": {
            "cases_file": cfg.rel(cpath) if cpath.is_file() else None,
            "cases_text": cpath.read_text(encoding="utf-8") if cpath.is_file() else None,
            "results": [_case(r) for r in results],
            "problems": [_issue(p) for p in problems],
        },
    }


def validate_text(cfg: Config, text: str, cases_text: str | None = None, targets: list[str] | None = None) -> dict:
    """Valida uma regra que ainda não foi salva: lint, conversão e (opcional) casos de teste."""
    rel = "<editor>"
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        return {"state": "fail", "lint": [{"severity": "error", "message": f"YAML inválido: {exc}"}],
                "conversions": {}, "tests": None}

    issues: list[Issue] = []
    if not docs:
        issues.append(Issue("error", rel, "documento vazio"))
    for doc in docs:
        issues.extend(lint_doc(doc, rel, set(available_targets())))

    chosen = routing.resolve(cfg, None, routing.first_detection(docs)) if docs else routing.Resolved(list(cfg.targets), "all")
    counted = list(targets) if targets else chosen.targets  # só a linguagem final reprova a regra
    names = list(dict.fromkeys([*counted, *([] if targets else cfg.targets)]))
    conversions = convert_all(text, names, _extra_pipelines(cfg)) if docs else {}

    tests = None
    results: list[CaseResult] = []
    problems: list[Issue] = []
    if cases_text is not None:
        cases, problems = parse_cases(cases_text, "cases", rel)
        results, problems = run_cases(cfg, rel, docs, cases, problems)
        tests = {"results": [_case(r) for r in results], "problems": [_issue(p) for p in problems]}

    failed_conversion = any(not conversions[t]["ok"] for t in counted if t in conversions)
    state = _state([*issues, *problems], results)
    if failed_conversion and state != "fail":
        state = "fail"
    return {"state": state, "targets": chosen.targets, "target_source": chosen.source,
            "lint": [_issue(i) for i in issues], "conversions": conversions, "tests": tests}


def repo_stats(cfg: Config) -> dict:
    """Números para os dashboards, todos derivados do repositório (sem dados de SIEM nem de CI)."""
    rules = list_rules(cfg)
    tactic_counts: Counter[str] = Counter()
    techniques: set[str] = set()
    for r in rules:
        tactic_counts.update(r["tactics"])
        techniques.update(r["techniques"])

    tactics = [{"slug": slug, "id": TACTIC_IDS[slug], "name": name, "count": tactic_counts.get(slug, 0)} for slug, name in TACTICS]
    covered = [t for t in tactics if t["count"] > 0]
    parsed = [r for r in rules if "error" not in r]
    return {
        # etapas do pipeline, na ordem do `vitrix check`
        "pipeline": {
            "parse": {"ok": len(parsed), "failed": len(rules) - len(parsed)},
            "validation": {s: sum(r["state"] == s for r in rules) for s in ("ok", "warn", "fail")},
            "conversion": {"ok": sum(all(r["conversion"].values()) for r in parsed),
                           "failed": sum(not all(r["conversion"].values()) for r in parsed)},
        },
        "rules": {
            "total": len(rules),
            "by_status": dict(Counter(r["status"] or "sem status" for r in rules)),
            "by_level": dict(Counter(r["level"] or "sem level" for r in rules)),
            "by_state": dict(Counter(r["state"] for r in rules)),
        },
        "mitre": {
            "tactics": sorted(tactics, key=lambda t: (-t["count"], t["name"])),
            "covered": len(covered),
            "total": len(TACTICS),
            "coverage_pct": round(100 * len(covered) / len(TACTICS)),
            "techniques": len(techniques),
            "uncovered": [t["name"] for t in tactics if t["count"] == 0],
        },
        "lint": {
            "errors": sum(r["lint"]["errors"] for r in rules),
            "warnings": sum(r["lint"]["warnings"] for r in rules),
        },
        "tests": {
            "total": sum(r["tests"]["total"] for r in rules),
            "passed": sum(r["tests"]["passed"] for r in rules),
            "rules_without_cases": sum(r["tests"]["total"] == 0 for r in rules),
            "rules_all_passing": sum(r["tests"]["total"] > 0 and r["tests"]["passed"] == r["tests"]["total"] for r in rules),
        },
        "targets": cfg.targets,
        "by_target": dict(Counter(t for r in rules for t in r["targets"])),
        "conversion_failures": sum(any(not ok for ok in r["conversion"].values()) for r in rules),
    }


# --------------------------------------------------------------------------- pull requests

_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")


class ChangeError(Exception):
    """Pedido de mudança inválido (caminho ruim, regra reprovada). Vira HTTP 422."""


def normalize_rule_path(path: str) -> str:
    """Valida o caminho da regra dentro de rules/ (ex.: windows/minha_regra.yml)."""
    raw = path.strip().replace("\\", "/")
    parts = [p for p in raw.split("/") if p]
    if not parts or raw.startswith("/") or any(not _SAFE_SEGMENT.match(p) for p in parts):
        raise ChangeError("caminho inválido: use pastas e nomes com letras, números, '.', '_' ou '-' (ex.: windows/minha_regra.yml)")
    if Path(parts[-1]).suffix not in RULE_SUFFIXES:
        raise ChangeError("o arquivo da regra deve terminar em .yml ou .yaml")
    return "/".join(parts)


def _pr_body(summary: dict, validation: dict, rule_repo_path: str, cases_repo_path: str | None, is_new: bool) -> str:
    tests = validation.get("tests") or {"results": []}
    passed = sum(r["passed"] for r in tests["results"])
    warnings = [i["message"] for i in validation["lint"] if i["severity"] == "warning"]
    lines = [
        f"{'Nova regra' if is_new else 'Alteração de regra'} enviada pela interface do Vitrix.",
        "",
        f"- **Regra:** {summary['title'] or '(sem título)'} (`{rule_repo_path}`)",
        f"- **level:** `{summary['level'] or '—'}` · **status:** `{summary['status'] or '—'}`",
        f"- **ATT&CK:** {', '.join(summary['techniques']) or '—'}",
        f"- **Linguagem final:** {', '.join(validation['targets']) or '—'}",
        f"- **Testes locais:** {passed}/{len(tests['results'])}" + (f" (`{cases_repo_path}`)" if cases_repo_path else " (sem casos)"),
    ]
    if warnings:
        lines += ["", "**Avisos do lint:**", *[f"- {w}" for w in warnings]]
    lines += ["", "O CI do repositório roda `vitrix check` neste PR."]
    return "\n".join(lines)


def propose_change(
    cfg: Config,
    path: str,
    rule_text: str,
    cases_text: str | None,
    title: str | None = None,
    client: GitHubClient | None = None,
) -> dict:
    """Abre um PR com a regra (e os casos) editados. Nada é gravado no disco local.

    Regras reprovadas (estado "fail") não viram PR: o CI reprovaria do mesmo jeito.
    """
    if cfg.github is None:
        raise GitHubError("configure a seção 'github' no vitrix.yml (repo e base) para abrir pull requests", status=503)
    rel = normalize_rule_path(path)
    validation = validate_text(cfg, rule_text, cases_text if cases_text and cases_text.strip() else None)
    if validation["state"] == "fail":
        raise ChangeError("a regra está reprovada (erros de lint, conversão ou testes); corrija antes de abrir o pull request")

    docs = [d for d in yaml.safe_load_all(rule_text) if d is not None]
    summary = summarize(_first_detection(docs))
    rule_file = cfg.rules_dir / rel
    is_new = not rule_file.is_file()
    rule_repo_path = cfg.github.repo_path(cfg.rel(rule_file))
    files = {rule_repo_path: rule_text}
    cases_repo_path = None
    if cases_text and cases_text.strip():
        cases_repo_path = cfg.github.repo_path(cfg.rel(cfg.cases_dir / rel))
        files[cases_repo_path] = cases_text

    name = summary["title"] or rel
    pr_title = (title or "").strip() or f"{'feat' if is_new else 'tune'}: {'nova regra' if is_new else 'ajusta'} {name}"
    client = client or GitHubClient(cfg.github)
    pr = client.open_pull_request(files, pr_title[:200], _pr_body(summary, validation, rule_repo_path, cases_repo_path, is_new), branch_slug(rel))
    return {**pr, "title": pr_title[:200], "files": sorted(files), "is_new": is_new, "state": validation["state"]}


def github_status(cfg: Config) -> dict:
    """O que a interface precisa saber para mostrar (ou não) o botão de PR. Nunca expõe o token."""
    from .github import token_from_env

    if cfg.github is None:
        return {"configured": False, "repo": None, "base": None, "token": token_from_env() is not None}
    return {"configured": True, "repo": cfg.github.repo, "base": cfg.github.base, "token": token_from_env() is not None}


# --------------------------------------------------------------------------- conector do GitHub (leitura)

ACTIVITY_TTL = 60.0  # segundos; a API do GitHub limita a 5.000 chamadas/hora por token
_activity_cache: dict[tuple[str, str], tuple[float, dict]] = {}


def github_activity(cfg: Config, client: GitHubClient | None = None, refresh: bool = False) -> dict:
    """PRs abertos, tempo até o merge e execuções de CI, do GitHub. Nunca levanta exceção:
    sem configuração, sem token ou com erro, devolve `available: false` e o motivo."""
    if cfg.github is None:
        return {"available": False, "reason": "not_configured", "message": "configure a seção 'github' no vitrix.yml"}
    key = (cfg.github.repo, cfg.github.base)
    cached = _activity_cache.get(key)
    if cached and not refresh and time.monotonic() - cached[0] < ACTIVITY_TTL:
        return cached[1]
    try:
        client = client or GitHubClient(cfg.github)
        data = {"available": True, **client.activity(), "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    except GitHubError as exc:
        reason = "no_token" if exc.status == 503 else "error"
        return {"available": False, "reason": reason, "message": str(exc)}
    _activity_cache[key] = (time.monotonic(), data)
    return data


# --------------------------------------------------------------------------- vitrix.yml pela interface


def config_view(cfg: Config) -> dict:
    """Configuração efetiva e o texto do vitrix.yml (para a tela de Configurações)."""
    return {
        "path": cfg.rel(cfg.path) if cfg.path else None,
        "text": cfg.path.read_text(encoding="utf-8") if cfg.path else "",
        "targets": cfg.targets,
        "default_target": cfg.default_target,
        "routes": [{"match": m, "target": t} for m, t in cfg.routes],
        "rules_dir": cfg.rel(cfg.rules_dir),
        "cases_dir": cfg.rel(cfg.cases_dir),
        "output_dir": cfg.rel(cfg.output_dir),
        "extra_pipelines": [cfg.rel(p) for p in cfg.extra_pipelines],
        "require_cases": cfg.require_cases,
        "github": {"repo": cfg.github.repo, "base": cfg.github.base, "path": cfg.github.path} if cfg.github else None,
    }


def validate_config_text(cfg: Config, text: str) -> dict:
    """Valida um vitrix.yml editado, como se substituísse o atual. Não grava nada."""
    try:
        new = parse_config_text(text, cfg.root)
    except ConfigError as exc:
        return {"ok": False, "errors": [str(exc)], "warnings": [], "config": None}
    errors: list[str] = []
    warnings: list[str] = []
    known = set(available_targets())
    unknown = sorted(routing.config_target_names(new) - known)
    if unknown:
        errors.append(f"alvo desconhecido: {', '.join(unknown)} (disponíveis: {', '.join(sorted(known))})")
    if new.default_target and new.default_target not in new.targets:
        warnings.append(f"default_target '{new.default_target}' não está em targets: só aparece nas regras sem rota")
    for p in new.extra_pipelines:
        if not p.is_file():
            errors.append(f"extra_pipelines: arquivo não encontrado: {new.rel(p)}")
    if not new.rules_dir.is_dir():
        warnings.append(f"rules_dir '{new.rel(new.rules_dir)}' não existe neste repositório")
    if new.github is None:
        warnings.append("sem a seção 'github': a interface não abre pull requests nem mostra o CI")
    view = config_view(new)
    view.pop("text")
    view.pop("path")
    return {"ok": not errors, "errors": errors, "warnings": warnings, "config": view}


def propose_config_change(cfg: Config, text: str, title: str | None = None, client: GitHubClient | None = None) -> dict:
    """Abre um PR alterando o vitrix.yml. Configuração inválida não vira PR."""
    if cfg.github is None:
        raise GitHubError("configure a seção 'github' no vitrix.yml (repo e base) para abrir pull requests", status=503)
    check = validate_config_text(cfg, text)
    if not check["ok"]:
        raise ChangeError("configuração inválida: " + "; ".join(check["errors"]))
    repo_path = cfg.github.repo_path(cfg.rel(cfg.path) if cfg.path else "vitrix.yml")
    pr_title = ((title or "").strip() or "chore: atualiza vitrix.yml")[:200]
    body = "\n".join([
        "Alteração do `vitrix.yml` enviada pela tela de Configurações do Vitrix.",
        "",
        f"- **targets:** {', '.join(check['config']['targets'])}",
        f"- **default_target:** {check['config']['default_target'] or '—'}",
        f"- **rotas:** {len(check['config']['routes'])}",
        *([""] + ["**Avisos:**"] + [f"- {w}" for w in check["warnings"]] if check["warnings"] else []),
        "",
        "O CI do repositório roda `vitrix check` neste PR.",
    ])
    client = client or GitHubClient(cfg.github)
    pr = client.open_pull_request({repo_path: text}, pr_title, body, "config")
    return {**pr, "title": pr_title, "files": [repo_path], "is_new": False, "state": "ok"}
