"""Lint de regras Sigma: schema mínimo, consistência da condição e metadados."""

from __future__ import annotations

import difflib
import fnmatch
import hashlib
import json
import re
import uuid
from dataclasses import dataclass

from . import routing
from .evaluator import UnsupportedError, check_supported, condition_refs
from .loader import RuleFile

STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|[gs]\d{4}|[a-z_]+)$")
ATTACK_TACTICS = {
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact",
}
# Campos de topo do Sigma; um campo parecido com um destes provavelmente é erro de digitação.
SIGMA_FIELDS = {
    "title", "id", "related", "name", "taxonomy", "status", "description", "license", "author", "references", "date",
    "modified", "tags", "logsource", "detection", "fields", "falsepositives", "level", "scope", "vitrix",
}
# Modificadores do Sigma (especificação 2.x). Fora desta lista, o pySigma recusa a regra.
SIGMA_MODIFIERS = {
    "contains", "startswith", "endswith", "all", "base64", "base64offset", "wide", "utf16le", "utf16be", "utf16",
    "windash", "re", "i", "m", "s", "cidr", "lt", "lte", "gt", "gte", "expand", "fieldref", "exists", "cased",
    "hour", "minute", "day", "week", "month", "year",
}
DATE = re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}$")
# Quantificador sobre um grupo que já tem quantificador: (a+)+, (\w*)*, (x+){2,} — backtracking catastrófico.
NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")
MAX_COMPARISONS = 50  # acima disso a regra fica cara no SIEM e difícil de revisar


def _walk_fields(detection: dict):
    """(spec do campo, valores) de todas as seleções em mapa (inclusive listas de mapas)."""
    for key, sel in detection.items():
        if key in ("condition", "timeframe"):
            continue
        for item in sel if isinstance(sel, list) else [sel]:
            if isinstance(item, dict):
                for spec, value in item.items():
                    yield str(spec), value if isinstance(value, list) else [value]


def _detection_checks(detection: dict, err, warn) -> None:
    """Modificadores, regex e complexidade de uma detecção."""
    comparisons = 0
    for spec, values in _walk_fields(detection):
        field, *mods = spec.split("|")
        comparisons += max(1, len(values))
        unknown = [m for m in mods if m not in SIGMA_MODIFIERS]
        if unknown:
            hint = difflib.get_close_matches(unknown[0], SIGMA_MODIFIERS, n=1)
            err(f"modificador desconhecido '{unknown[0]}' no campo {field}" + (f" (quis dizer '{hint[0]}'?)" if hint else ""))
        if "re" in mods:
            for value in values:
                try:
                    re.compile(str(value))
                except re.error as exc:
                    err(f"regex inválida no campo {field}: {exc}")
                    continue
                if NESTED_QUANTIFIER.search(str(value)):
                    warn(f"regex com quantificador aninhado no campo {field}: risco de backtracking catastrófico no SIEM")
    if comparisons > MAX_COMPARISONS:
        warn(f"regra complexa: {comparisons} comparações (limite recomendado {MAX_COMPARISONS}); considere dividir")


def detection_fingerprint(doc: dict) -> str | None:
    """Assinatura da lógica (logsource + detection) para achar regras duplicadas."""
    if not isinstance(doc.get("detection"), dict):
        return None
    payload = json.dumps({"logsource": doc.get("logsource"), "detection": doc["detection"]}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class Issue:
    severity: str  # "error" | "warning"
    rule: str  # caminho do arquivo
    message: str

    def __str__(self) -> str:
        label = "erro" if self.severity == "error" else "aviso"
        return f"{label}: {self.message}"


def _is_uuid(value: object) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


def lint_doc(doc: object, rel: str, known_targets: set[str] | None = None) -> list[Issue]:
    issues: list[Issue] = []

    def err(msg: str) -> None:
        issues.append(Issue("error", rel, msg))

    def warn(msg: str) -> None:
        issues.append(Issue("warning", rel, msg))

    if not isinstance(doc, dict):
        err("o documento YAML deve ser um mapa")
        return issues
    if "action" in doc or "correlation" in doc:
        return issues  # documentos globais/correlação não passam pelo lint de detecção

    title = doc.get("title")
    if not isinstance(title, str) or not title.strip():
        err("campo obrigatório ausente: title")

    if "id" not in doc:
        err("campo obrigatório ausente: id")
    elif not _is_uuid(doc["id"]):
        err(f"id não é um UUID válido: {doc['id']!r}")

    if "status" not in doc:
        warn("campo recomendado ausente: status")
    elif doc["status"] not in STATUSES:
        err(f"status inválido: {doc['status']!r} (use {', '.join(sorted(STATUSES))})")

    if "level" not in doc:
        warn("campo recomendado ausente: level")
    elif doc["level"] not in LEVELS:
        err(f"level inválido: {doc['level']!r} (use {', '.join(sorted(LEVELS))})")

    logsource = doc.get("logsource")
    if not isinstance(logsource, dict) or not any(k in logsource for k in ("category", "product", "service")):
        err("logsource deve ter ao menos category, product ou service")

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        err("campo obrigatório ausente: detection")
    elif "condition" not in detection:
        err("detection sem condition")
    else:
        selections = {k for k in detection if k not in ("condition", "timeframe")}
        if not selections:
            err("detection não define nenhuma seleção")
        cond = detection["condition"]
        used_names: set[str] = set()
        used_patterns: set[str] = set()
        for c in cond if isinstance(cond, list) else [cond]:
            names, patterns = condition_refs(str(c))
            used_names |= names
            used_patterns |= patterns
        for name in sorted(used_names - selections):
            err(f"a condição cita '{name}', que não existe em detection")
        for pattern in sorted(used_patterns):
            if pattern.lower() != "them" and not any(fnmatch.fnmatchcase(s, pattern) for s in selections):
                err(f"o padrão '{pattern}' da condição não casa com nenhuma seleção")
        covered = set(used_names)
        for pattern in used_patterns:
            covered |= selections if pattern.lower() == "them" else {s for s in selections if fnmatch.fnmatchcase(s, pattern)}
        for name in sorted(selections - covered):
            warn(f"a seleção '{name}' não é usada na condição")
        _detection_checks(detection, err, warn)

    for key in doc:
        if key not in SIGMA_FIELDS:
            hint = difflib.get_close_matches(str(key), SIGMA_FIELDS, n=1, cutoff=0.8)
            if hint:
                warn(f"campo '{key}' não é do Sigma; quis dizer '{hint[0]}'?")
    for key in ("tags", "falsepositives", "references"):
        if key in doc and not (isinstance(doc[key], list) and all(isinstance(v, str) for v in doc[key])):
            err(f"'{key}' deve ser uma lista de textos")
    for key in ("date", "modified"):
        if key in doc and not DATE.match(str(doc[key])):
            warn(f"'{key}' fora do formato AAAA-MM-DD: {doc[key]!r}")

    for message in routing.problems(doc):
        err(message)
    if known_targets is not None:
        for name in routing.declared(doc) or []:
            if name not in known_targets:
                err(f"vitrix.target: alvo desconhecido '{name}' (disponíveis: {', '.join(sorted(known_targets))})")

    if not doc.get("description"):
        warn("campo recomendado ausente: description")
    if not doc.get("falsepositives"):
        warn("campo recomendado ausente: falsepositives")
    tags = [t for t in (doc.get("tags") or []) if isinstance(t, str)] if isinstance(doc.get("tags"), list) else []
    if not any(t.startswith("attack.t") for t in tags):
        warn("sem tag de técnica MITRE (ex.: attack.t1059.001)")
    else:
        for tag in tags:
            if not tag.startswith("attack."):
                continue
            m = ATTACK_TAG.match(tag)
            if not m:
                warn(f"tag MITRE fora do padrão: {tag}")
            elif re.fullmatch(r"[a-z_]+", m.group(1)) and m.group(1) not in ATTACK_TACTICS:
                hint = difflib.get_close_matches(m.group(1), ATTACK_TACTICS, n=1)
                warn(f"tática ATT&CK desconhecida: {tag}" + (f" (quis dizer attack.{hint[0]}?)" if hint else ""))
        if not any(t[len("attack."):] in ATTACK_TACTICS for t in tags if t.startswith("attack.")):
            warn("técnica MITRE sem a tática correspondente (ex.: attack.execution)")

    try:
        check_supported(doc)
    except UnsupportedError as exc:
        warn(f"o avaliador local não cobre esta regra ({exc}); `vitrix test` não poderá testá-la")

    return issues


def lint_files(files: list[RuleFile], known_targets: set[str] | None = None) -> list[Issue]:
    issues: list[Issue] = []
    seen: dict[str, str] = {}
    logic: dict[str, str] = {}
    for rf in files:
        if not rf.docs:
            issues.append(Issue("error", rf.rel, "arquivo vazio"))
            continue
        for doc in rf.docs:
            issues.extend(lint_doc(doc, rf.rel, known_targets))
            if isinstance(doc, dict) and "id" in doc and _is_uuid(doc["id"]):
                rid = str(doc["id"]).lower()
                if rid in seen and seen[rid] != rf.rel:
                    issues.append(Issue("error", rf.rel, f"id duplicado (já usado em {seen[rid]})"))
                seen.setdefault(rid, rf.rel)
            fp = detection_fingerprint(doc) if isinstance(doc, dict) else None
            if fp:
                if fp in logic and logic[fp] != rf.rel:
                    issues.append(Issue("warning", rf.rel, f"lógica de detecção idêntica a {logic[fp]} (regra redundante)"))
                logic.setdefault(fp, rf.rel)
    return issues
