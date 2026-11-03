"""Quality gate: a regra está pronta para ser publicada?

O fluxo de uma regra no Vitrix:

    Escrever → Validar → Testar → Replay → Analisar → Quality gate → Deploy

Cada verificação pertence a uma etapa e responde a uma das cinco perguntas:

    1. A regra está sintaticamente correta?           (validate)
    2. A lógica de detecção funciona?                 (test)
    3. Existem falsos positivos conhecidos?            (analyze)
    4. A regra detecta os comportamentos esperados?    (test, replay, analyze)
    5. A regra está pronta para ser publicada?         (gate: todas as bloqueantes passam)

Os critérios vêm de `quality_gate` no vitrix.yml (ver config.GateConfig). Uma verificação
`blocking` reprovada barra a publicação; as não bloqueantes só aparecem como recomendação.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .cases import CaseResult
from .config import GateConfig
from .lint import Issue

STAGES = ("write", "validate", "test", "replay", "analyze", "gate", "deploy")
STAGE_LABELS = {
    "write": "Escrever",
    "validate": "Validar",
    "test": "Testar",
    "replay": "Replay",
    "analyze": "Analisar",
    "gate": "Quality gate",
    "deploy": "Deploy",
}
QUESTIONS = {
    1: "A regra está sintaticamente correta?",
    2: "A lógica de detecção funciona?",
    3: "Existem falsos positivos conhecidos?",
    4: "A regra detecta os comportamentos esperados?",
    5: "A regra está pronta para ser publicada?",
}


@dataclass
class Check:
    id: str
    stage: str
    question: int
    label: str
    passed: bool | None  # None = não se aplica
    blocking: bool
    detail: str = ""


def evaluate_rule(
    gate: GateConfig,
    doc: dict | None,
    parse_error: str | None,
    issues: list[Issue],
    results: list[CaseResult],
    problems: list[Issue],
    final_conversion: dict[str, bool],
    has_exclusions: bool,
    replay_checks: list[dict],
) -> dict:
    """Todas as verificações de uma regra, o estado de cada etapa e se ela está pronta."""
    checks: list[Check] = []

    def add(id: str, stage: str, q: int, label: str, passed: bool | None, blocking: bool = True, detail: str = "") -> None:
        checks.append(Check(id, stage, q, label, passed, blocking, detail))

    doc = doc or {}
    errors = [i for i in issues if i.severity == "error"]
    warnings = [i for i in issues if i.severity == "warning"]
    case_errors = [p for p in problems if p.severity == "error"]
    case_warnings = [p for p in problems if p.severity == "warning"]

    # 1 · Validar
    add("parse", "write", 1, "YAML válido", parse_error is None, detail=parse_error or "")
    add("schema", "validate", 1, "Schema e lint sem erros", parse_error is None and not errors,
        detail="; ".join(i.message for i in errors[:3]))
    failed_conv = [t for t, ok in final_conversion.items() if not ok]
    add("conversion", "validate", 1, "Conversão para a linguagem final", bool(final_conversion) and not failed_conv,
        detail=f"falhou: {', '.join(failed_conv)}" if failed_conv else ", ".join(final_conversion))
    add("warnings", "validate", 1, "Sem avisos de lint", not warnings, blocking=not gate.allow_warnings,
        detail="; ".join(i.message for i in warnings[:3]))

    # 2 · Testar
    kinds = [r.kind for r in results]
    positives = sum(r.expect == "match" for r in results)
    negatives = sum(r.expect == "no_match" for r in results)
    failed = [r for r in results if not r.passed]
    add("cases_pass", "test", 2, "Todos os casos passam", bool(results) and not failed and not case_errors,
        detail="; ".join(f"{r.name}: {r.error or f'esperado {r.expect}, obtido {r.got}'}" for r in failed[:3])
        or "; ".join(p.message for p in case_errors[:2]) or (f"{len(results)} casos" if results else "sem casos"))
    add("positive_cases", "test", 4, f"Ao menos {gate.min_positive} caso positivo", positives >= gate.min_positive,
        detail=f"{positives} positivos")
    add("negative_cases", "test", 2, f"Ao menos {gate.min_negative} caso negativo", negatives >= gate.min_negative,
        detail=f"{negatives} negativos")
    add("edge_cases", "test", 2, "Caso de borda (campo ausente, nulo, maiúsculas)", "edge" in kinds, blocking=False,
        detail="adicione um caso com kind: edge" if "edge" not in kinds else f"{kinds.count('edge')} de borda")

    # 4 · Replay
    if replay_checks:
        bad = [c for c in replay_checks if not c["passed"]]
        add("replay", "replay", 4, "Replay bate com as expectativas", not bad,
            detail="; ".join(f"{c['dataset']}: {c['message']}" for c in bad[:3]) or f"{len(replay_checks)} dataset(s)")
    else:
        add("replay", "replay", 4, "Expectativa em algum dataset de replay", None if not gate.require_replay else False,
            blocking=gate.require_replay, detail="nenhum dataset define expectativa para esta regra")

    # 3/4 · Analisar
    level = doc.get("level")
    needs_fp = level in gate.false_positive_levels
    fp = kinds.count("false_positive")
    add("false_positive_cases", "analyze", 3,
        f"Caso de falso positivo (exigido para level {', '.join(gate.false_positive_levels)})" if needs_fp else "Caso de falso positivo",
        fp > 0, blocking=needs_fp, detail=f"{fp} casos false_positive" if fp else "adicione um caso com kind: false_positive")
    add("falsepositives_doc", "analyze", 3, "Falsos positivos documentados (falsepositives)", bool(doc.get("falsepositives")),
        blocking=False)
    if has_exclusions:
        exercised = sum(r.exercises_filter for r in results)
        add("exclusion_tested", "analyze", 3, "Exclusão (filter) testada por um caso", exercised > 0,
            blocking=gate.require_filter_test,
            detail=f"{exercised} caso(s) provam a exclusão" if exercised else "nenhum caso no_match depende do filter")
    tags = [t for t in (doc.get("tags") or []) if isinstance(t, str)] if isinstance(doc.get("tags"), list) else []
    has_technique = any(t.startswith("attack.t") for t in tags)
    add("mitre", "analyze", 4, "Mapeada em técnica ATT&CK", has_technique, blocking=gate.require_mitre,
        detail=", ".join(t[7:].upper() for t in tags if t.startswith("attack.t")) or "sem tag attack.tXXXX")
    add("data_quality", "analyze", 2, "Casos de teste sem problemas de qualidade", not case_warnings, blocking=False,
        detail="; ".join(p.message for p in case_warnings[:2]))

    # 5 · Gate
    status = doc.get("status")
    add("status", "gate", 5, "Status publicável", status not in gate.blocked_status,
        detail=f"status {status}" if status else "sem status")

    blockers = [c for c in checks if c.blocking and c.passed is False]
    ready = not blockers
    return {
        "ready": ready,
        "stages": _stages(checks, ready),
        "checks": [asdict(c) for c in checks],
        "blockers": [c.label for c in blockers],
        "answers": {q: _answer(checks, q, ready) for q in QUESTIONS},
    }


def _stage_state(checks: list[Check]) -> str:
    applicable = [c for c in checks if c.passed is not None]
    if not applicable:
        return "skip"
    if any(c.blocking and not c.passed for c in applicable):
        return "fail"
    if any(not c.passed for c in applicable):
        return "warn"
    return "ok"


def _stages(checks: list[Check], ready: bool) -> dict[str, str]:
    """ok | warn | fail | skip | pending por etapa do fluxo."""
    states = {s: _stage_state([c for c in checks if c.stage == s]) for s in STAGES if s not in ("gate", "deploy")}
    states["gate"] = "ok" if ready else "fail"
    # Deploy: o Vitrix não envia regras ao SIEM; publicar = merge do PR e o dist/ gerado no CI.
    states["deploy"] = "pending" if ready else "skip"
    return states


def _answer(checks: list[Check], q: int, ready: bool) -> str:
    if q == 5:
        return "ok" if ready else "fail"
    return _stage_state([c for c in checks if c.question == q])
