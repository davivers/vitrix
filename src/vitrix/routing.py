"""Linguagem final de cada regra: para qual(is) alvo(s) ela é convertida.

Ordem de decisão, da mais específica para a mais geral:

1. `vitrix.target` dentro da própria regra (string ou lista);
2. a primeira entrada de `routes` do vitrix.yml cujo `match` casa com o caminho da regra;
3. `default_target` do vitrix.yml;
4. todos os `targets` ativos do vitrix.yml.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from .config import Config
from .loader import RuleFile

KEY = "vitrix"
RULE_KEYS = {"target"}


@dataclass(frozen=True)
class Resolved:
    targets: list[str]
    source: str  # "rule" | "route" | "default" | "all" | "override"


def first_detection(docs: list) -> object:
    return next((d for d in docs if isinstance(d, dict) and "detection" in d), docs[0] if docs else None)


def declared(doc: object) -> list[str] | None:
    """Alvos escolhidos na regra, ou None se ela não escolheu (ou se o campo é inválido)."""
    if not isinstance(doc, dict):
        return None
    block = doc.get(KEY)
    if not isinstance(block, dict):
        return None
    value = block.get("target")
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, list) and value and all(isinstance(v, str) and v.strip() for v in value):
        return [v.strip() for v in value]
    return None


def problems(doc: object) -> list[str]:
    """Mensagens de erro de formato do bloco `vitrix` da regra (usadas pelo lint)."""
    if not isinstance(doc, dict) or KEY not in doc:
        return []
    block = doc[KEY]
    if not isinstance(block, dict):
        return [f"'{KEY}' deve ser um mapa (ex.: {KEY}: {{target: splunk}})"]
    out = [f"chave desconhecida em '{KEY}': {k}" for k in block if k not in RULE_KEYS]
    if "target" in block and declared(doc) is None:
        out.append(f"'{KEY}.target' deve ser um nome de alvo ou uma lista não vazia de nomes")
    return out


def resolve(cfg: Config, rule_rel: str | None, doc: object, override: list[str] | None = None) -> Resolved:
    """Decide os alvos de uma regra. `rule_rel` é o caminho dentro de rules/ (None: regra ainda não salva)."""
    if override:
        return Resolved(list(override), "override")
    chosen = declared(doc)
    if chosen:
        return Resolved(chosen, "rule")
    if rule_rel is not None:
        for pattern, targets in cfg.routes:
            if fnmatchcase(rule_rel, pattern):
                return Resolved(list(targets), "route")
    if cfg.default_target:
        return Resolved([cfg.default_target], "default")
    return Resolved(list(cfg.targets), "all")


def config_target_names(cfg: Config) -> set[str]:
    """Todos os nomes de alvo citados no vitrix.yml (para validar contra os disponíveis)."""
    names = set(cfg.targets)
    if cfg.default_target:
        names.add(cfg.default_target)
    for _, targets in cfg.routes:
        names.update(targets)
    return names


def rules_rel(cfg: Config, path: Path) -> str:
    """Caminho do arquivo dentro de rules/ (usado nas rotas e nas URLs)."""
    try:
        return path.resolve().relative_to(cfg.rules_dir.resolve()).as_posix()
    except ValueError:
        return path.name


def plan(cfg: Config, files: list[RuleFile], override: list[str] | None = None) -> dict[str, Resolved]:
    """Alvos de cada arquivo de regra, indexados por `RuleFile.rel`."""
    return {rf.rel: resolve(cfg, rules_rel(cfg, rf.path), first_detection(rf.docs), override) for rf in files}
