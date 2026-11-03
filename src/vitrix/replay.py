"""Replay de logs: roda todas as regras contra um conjunto de eventos, localmente.

Serve para três coisas:

- **simulação de ameaças**: um dataset com eventos de um ataque (PowerShell codificado,
  dump de credenciais, persistência...) mostra quais regras pegam o quê;
- **falsos positivos**: um dataset de atividade normal do ambiente não deveria disparar nada;
- **regressão**: cada dataset pode ter um arquivo de expectativas com quantos eventos cada
  regra deve pegar. Se uma alteração muda esse número, o replay acusa.

Datasets ficam em `datasets/` (opção `datasets_dir` do vitrix.yml), um por arquivo:
JSON (lista de eventos ou `{"events": [...]}`), JSON Lines (`.jsonl`, um evento por linha)
ou YAML (lista ou `events:`). As expectativas ficam ao lado, em `<nome>.expect.yml`:

    expect:
      windows/powershell_encoded.yml: 2          # exatamente 2 eventos
      windows/schtasks_system.yml: {min: 1}       # ao menos 1
    others: 0                                     # demais regras: 0 (padrão: sem limite)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .config import Config
from .evaluator import UnsupportedError, evaluate
from .loader import RuleFile

DATASET_SUFFIXES = {".json", ".jsonl", ".ndjson", ".yml", ".yaml"}
EXPECT_SUFFIX = ".expect.yml"
MAX_EVENTS = 100_000
MAX_SAMPLE = 20  # índices de eventos que casaram, por regra


class ReplayError(Exception):
    """Dataset ou arquivo de expectativas inválido."""


def load_events(text: str, name: str = "dataset") -> list[dict]:
    """Lê eventos de JSON, JSON Lines ou YAML. Cada evento é um mapa de campos."""
    text = text.strip()
    if not text:
        return []
    data: object
    try:
        data = json.loads(text)
    except ValueError:
        lines = [ln for ln in text.splitlines() if ln.strip()]
        try:
            data = [json.loads(ln) for ln in lines]
        except ValueError:
            try:
                data = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                raise ReplayError(f"{name}: não é JSON, JSON Lines nem YAML válido ({exc})") from exc
    if isinstance(data, dict):
        data = data.get("events", [data])
    if not isinstance(data, list):
        raise ReplayError(f"{name}: esperado uma lista de eventos")
    if len(data) > MAX_EVENTS:
        raise ReplayError(f"{name}: {len(data)} eventos; o limite é {MAX_EVENTS}")
    bad = next((i for i, e in enumerate(data, 1) if not isinstance(e, dict)), None)
    if bad:
        raise ReplayError(f"{name}: o evento {bad} não é um mapa de campos")
    return data  # type: ignore[return-value]


@dataclass
class RuleReplay:
    rule: str  # caminho dentro de rules/
    title: str
    level: str | None
    matches: int = 0
    sample: list[int] = field(default_factory=list)  # índices (base 1) dos eventos que casaram
    duration_ms: float = 0.0
    error: str | None = None  # regra fora do subconjunto do avaliador local

    def as_dict(self) -> dict:
        return {"rule": self.rule, "title": self.title, "level": self.level, "matches": self.matches,
                "sample": self.sample, "duration_ms": round(self.duration_ms, 2), "error": self.error}


def replay(rules: list[tuple[str, RuleFile]], events: list[dict]) -> dict:
    """Roda cada regra (id, arquivo) contra todos os eventos. Mede o tempo de cada uma."""
    out: list[RuleReplay] = []
    started = time.perf_counter()
    for rid, rf in rules:
        docs = [d for d in rf.docs if isinstance(d, dict) and "detection" in d]
        head = docs[0] if docs else {}
        r = RuleReplay(rid, str(head.get("title", rid)), head.get("level"))
        t0 = time.perf_counter()
        try:
            for i, event in enumerate(events, 1):
                if any(evaluate(d, event) for d in docs):
                    r.matches += 1
                    if len(r.sample) < MAX_SAMPLE:
                        r.sample.append(i)
        except UnsupportedError as exc:
            r.error = str(exc)
        r.duration_ms = (time.perf_counter() - t0) * 1000
        out.append(r)
    matched = {i for r in out for i in r.sample}
    return {
        "events": len(events),
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "rules_matched": sum(r.matches > 0 for r in out),
        "events_matched_sample": len(matched),
        "rules": [r.as_dict() for r in sorted(out, key=lambda r: (-r.matches, r.rule))],
    }


# --------------------------------------------------------------------------- datasets e expectativas


def dataset_files(cfg: Config) -> list[Path]:
    root = cfg.datasets_dir
    if root is None or not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in DATASET_SUFFIXES and not p.name.endswith(EXPECT_SUFFIX))


def dataset_name(cfg: Config, path: Path) -> str:
    if cfg.datasets_dir is None:
        raise ReplayError("datasets_dir não configurado")
    return path.resolve().relative_to(cfg.datasets_dir.resolve()).as_posix()


def resolve_dataset(cfg: Config, name: str) -> Path | None:
    """Só aceita arquivos de dataset dentro de datasets_dir."""
    if cfg.datasets_dir is None:
        return None
    base = cfg.datasets_dir.resolve()
    candidate = (base / name).resolve()
    if not candidate.is_relative_to(base) or candidate.suffix not in DATASET_SUFFIXES or not candidate.is_file():
        return None
    return candidate


def expect_path(path: Path) -> Path:
    return path.with_name(path.name.rsplit(".", 1)[0] + EXPECT_SUFFIX)


def load_expectations(path: Path) -> tuple[dict[str, dict], int | None]:
    """(regra -> {min, max}, limite para as demais regras). Sem arquivo: ({}, None)."""
    epath = expect_path(path)
    if not epath.is_file():
        return {}, None
    try:
        data = yaml.safe_load(epath.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ReplayError(f"{epath.name}: YAML inválido ({exc})") from exc
    if not isinstance(data, dict) or not isinstance(data.get("expect", {}), dict):
        raise ReplayError(f"{epath.name}: use 'expect: {{regra: quantidade}}'")
    rules: dict[str, dict] = {}
    for rule, spec in (data.get("expect") or {}).items():
        if isinstance(spec, int) and not isinstance(spec, bool):
            rules[str(rule)] = {"min": spec, "max": spec}
        elif isinstance(spec, dict) and set(spec) <= {"min", "max"} and all(isinstance(v, int) for v in spec.values()):
            rules[str(rule)] = {"min": spec.get("min", 0), "max": spec.get("max")}
        else:
            raise ReplayError(f"{epath.name}: expectativa de {rule} deve ser um número ou {{min, max}}")
    others = data.get("others")
    if others is not None and (not isinstance(others, int) or isinstance(others, bool)):
        raise ReplayError(f"{epath.name}: 'others' deve ser um número")
    return rules, others


def check_expectations(result: dict, rules: dict[str, dict], others: int | None) -> list[dict]:
    """Compara as contagens do replay com as expectativas. Só devolve as regras verificadas."""
    checks: list[dict] = []
    got = {r["rule"]: r["matches"] for r in result["rules"]}
    for rule, spec in sorted(rules.items()):
        n = got.get(rule)
        if n is None:
            checks.append({"rule": rule, "expected": spec, "got": None, "passed": False, "message": "regra não encontrada"})
            continue
        ok = n >= spec["min"] and (spec["max"] is None or n <= spec["max"])
        checks.append({"rule": rule, "expected": spec, "got": n, "passed": ok, "message": None if ok else _describe(spec, n)})
    if others is not None:
        for rule, n in sorted(got.items()):
            if rule not in rules and n > others:
                spec = {"min": 0, "max": others}
                checks.append({"rule": rule, "expected": spec, "got": n, "passed": False, "message": _describe(spec, n)})
    return checks


def _describe(spec: dict, n: int) -> str:
    if spec["max"] is not None and spec["min"] == spec["max"]:
        want = f"exatamente {spec['min']}"
    elif spec["max"] is None:
        want = f"ao menos {spec['min']}"
    else:
        want = f"entre {spec['min']} e {spec['max']}"
    return f"esperado {want} evento(s), obtido {n}"
