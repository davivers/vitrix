"""Casos de teste das regras: eventos de exemplo com o resultado esperado.

Para cada arquivo em rules/ o motor procura o arquivo de mesmo caminho em cases/:

    rules/windows/powershell_encoded.yml  ->  cases/windows/powershell_encoded.yml

Formato:

    cases:
      - name: Positivo · powershell -enc
        expect: match            # ou no_match
        event:
          Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
          CommandLine: 'powershell.exe -enc JABzAA=='

`kind` (opcional) diz o que o caso representa; sem ele, vale `positive` para match e
`negative` para no_match:

    positive         comportamento malicioso que a regra deve pegar (expect: match)
    negative         evento comum que não deve disparar (expect: no_match)
    false_positive   atividade legítima parecida com o ataque: admin, conta de serviço,
                     ferramenta de TI (expect: no_match)
    edge             caso de borda: campo ausente, nulo, maiúsculas, valor no limite

Num caso no_match, o motor também verifica se ele **exercita uma exclusão**: se o evento
dispararia a regra sem as seleções `filter*` (ou negadas na condição), o caso prova que a
exclusão funciona.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import yaml

from .config import Config
from .evaluator import UnsupportedError, evaluate, exclusion_selections
from .lint import Issue, _walk_fields
from .loader import RuleFile

EXPECTATIONS = ("match", "no_match")
KINDS = {"positive": "match", "negative": "no_match", "false_positive": "no_match", "edge": None}


@dataclass
class CaseResult:
    rule: str
    name: str
    expect: str
    got: str  # "match" | "no_match" | "erro"
    passed: bool
    error: str | None = None
    kind: str = "positive"
    exercises_filter: bool = False  # no_match que só não disparou por causa de uma exclusão


def cases_path(cfg: Config, rf: RuleFile) -> Path:
    try:
        rel = rf.path.resolve().relative_to(cfg.rules_dir.resolve())
    except ValueError:
        rel = Path(rf.path.name)
    return cfg.cases_dir / rel


def parse_cases(text: str, name: str, rel: str) -> tuple[list[dict], list[Issue]]:
    """Lê o texto de um arquivo de casos. `name` aparece nas mensagens; `rel` identifica a regra."""
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        return [], [Issue("error", rel, f"arquivo de casos com YAML inválido: {exc}")]
    cases = data.get("cases") if isinstance(data, dict) else None
    if not isinstance(cases, list) or not cases:
        return [], [Issue("error", rel, f"{name}: defina uma lista 'cases' com ao menos um caso")]
    problems: list[Issue] = []
    valid: list[dict] = []
    for i, case in enumerate(cases, start=1):
        label = f"{name}, caso {i}"
        if not isinstance(case, dict) or not isinstance(case.get("event"), dict):
            problems.append(Issue("error", rel, f"{label}: 'event' deve ser um mapa de campos"))
        elif case.get("expect") not in EXPECTATIONS:
            problems.append(Issue("error", rel, f"{label}: 'expect' deve ser match ou no_match"))
        elif "kind" in case and case["kind"] not in KINDS:
            problems.append(Issue("error", rel, f"{label}: 'kind' deve ser {', '.join(KINDS)}"))
        elif KINDS.get(case.get("kind", "")) not in (None, case["expect"]):
            problems.append(Issue("error", rel, f"{label}: kind {case['kind']} exige expect: {KINDS[case['kind']]}"))
        else:
            valid.append(case)

    # qualidade dos dados de teste
    seen: dict[str, int] = {}
    for i, case in enumerate(valid, start=1):
        key = json.dumps(case["event"], sort_keys=True, default=str)
        if key in seen:
            problems.append(Issue("warning", rel, f"{name}, caso {i}: evento idêntico ao do caso {seen[key]}"))
        seen.setdefault(key, i)
    return valid, problems


def case_kind(case: dict) -> str:
    return case.get("kind") or ("positive" if case["expect"] == "match" else "negative")


def _rule_fields(docs: list) -> set[str]:
    fields: set[str] = set()
    for d in docs:
        if isinstance(d, dict) and isinstance(d.get("detection"), dict):
            fields |= {spec.split("|")[0].lower() for spec, _ in _walk_fields(d["detection"])}
    return fields


def run_cases(
    cfg: Config, rel: str, docs: list, cases: list[dict], problems: list[Issue]
) -> tuple[list[CaseResult], list[Issue]]:
    """Executa casos já lidos contra os documentos de uma regra."""
    problems = list(problems)
    if cfg.require_cases and cases:
        kinds = {c["expect"] for c in cases}
        for needed in EXPECTATIONS:
            if needed not in kinds:
                problems.append(Issue("error", rel, f"faltam casos do tipo {needed} (um positivo e um negativo, no mínimo)"))

    detection_docs = [d for d in docs if isinstance(d, dict) and "detection" in d]
    fields = _rule_fields(detection_docs)
    results: list[CaseResult] = []
    for i, case in enumerate(cases, start=1):
        name = str(case.get("name") or f"caso {i}")
        expect = case["expect"]
        kind = case_kind(case)
        try:
            matched = any(evaluate(d, case["event"]) for d in detection_docs)
            exercises = not matched and any(
                exclusion_selections(d) and evaluate(d, case["event"], force_false=exclusion_selections(d))
                for d in detection_docs
            )
        except UnsupportedError as exc:
            results.append(CaseResult(rel, name, expect, "erro", False, str(exc), kind))
            continue
        got = "match" if matched else "no_match"
        results.append(CaseResult(rel, name, expect, got, got == expect, None, kind, exercises))
        if expect == "no_match" and fields and not fields & {str(k).lower() for k in case["event"]}:
            problems.append(Issue("warning", rel, f"caso “{name}”: o evento não tem nenhum campo usado pela regra; não testa nada"))
    return results, problems


def run_rule_cases(cfg: Config, rf: RuleFile) -> tuple[list[CaseResult], list[Issue]]:
    cpath = cases_path(cfg, rf)
    if not cpath.is_file():
        if cfg.require_cases:
            return [], [Issue("error", rf.rel, f"sem casos de teste (esperado em {cfg.rel(cpath)})")]
        return [], []
    cases, problems = parse_cases(cpath.read_text(encoding="utf-8"), cpath.name, rf.rel)
    return run_cases(cfg, rf.rel, rf.docs, cases, problems)
