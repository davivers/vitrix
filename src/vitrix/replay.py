"""Log replay: run every rule against a set of events, locally.

It serves three purposes:

- **threat simulation**: a dataset with the events of an attack (encoded PowerShell,
  credential dumping, persistence...) shows which rules catch what;
- **false positives**: a dataset of normal activity in the environment should fire nothing;
- **regression**: each dataset may have an expectations file with how many events each rule
  must match. If a change moves that number, replay reports it.

Datasets live in `datasets/` (`datasets_dir` in vitrix.yml), one per file: JSON (a list of
events or `{"events": [...]}`), JSON Lines (`.jsonl`, one event per line) or YAML (a list or
`events:`). Expectations sit next to them, in `<name>.expect.yml`:

    expect:
      windows/powershell_encoded.yml: 2          # exactly 2 events
      windows/schtasks_system.yml: {min: 1}       # at least 1
    others: 0                                     # every other rule: 0 (default: no limit)
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
MAX_SAMPLE = 20  # indexes of matching events, per rule


class ReplayError(Exception):
    """Invalid dataset or expectations file."""


def load_events(text: str, name: str = "dataset") -> list[dict]:
    """Read events from JSON, JSON Lines or YAML. Each event is a mapping of fields."""
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
                raise ReplayError(f"{name}: not valid JSON, JSON Lines or YAML ({exc})") from exc
    if isinstance(data, dict):
        data = data.get("events", [data])
    if not isinstance(data, list):
        raise ReplayError(f"{name}: expected a list of events")
    if len(data) > MAX_EVENTS:
        raise ReplayError(f"{name}: {len(data)} events; the limit is {MAX_EVENTS}")
    bad = next((i for i, e in enumerate(data, 1) if not isinstance(e, dict)), None)
    if bad:
        raise ReplayError(f"{name}: event {bad} is not a mapping of fields")
    return data  # type: ignore[return-value]


@dataclass
class RuleReplay:
    rule: str  # path inside rules/
    title: str
    level: str | None
    matches: int = 0
    sample: list[int] = field(default_factory=list)  # 1-based indexes of the matching events
    duration_ms: float = 0.0
    error: str | None = None  # rule outside the local evaluator's subset

    def as_dict(self) -> dict:
        return {"rule": self.rule, "title": self.title, "level": self.level, "matches": self.matches,
                "sample": self.sample, "duration_ms": round(self.duration_ms, 2), "error": self.error}


def replay(rules: list[tuple[str, RuleFile]], events: list[dict]) -> dict:
    """Run each rule (id, file) against every event, timing each one."""
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


# --------------------------------------------------------------------------- datasets and expectations


def dataset_files(cfg: Config) -> list[Path]:
    root = cfg.datasets_dir
    if root is None or not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in DATASET_SUFFIXES and not p.name.endswith(EXPECT_SUFFIX))


def dataset_name(cfg: Config, path: Path) -> str:
    if cfg.datasets_dir is None:
        raise ReplayError("datasets_dir is not configured")
    return path.resolve().relative_to(cfg.datasets_dir.resolve()).as_posix()


def resolve_dataset(cfg: Config, name: str) -> Path | None:
    """Only dataset files inside datasets_dir are accepted."""
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
    """(rule -> {min, max}, limit for every other rule). No file: ({}, None)."""
    epath = expect_path(path)
    if not epath.is_file():
        return {}, None
    try:
        data = yaml.safe_load(epath.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ReplayError(f"{epath.name}: invalid YAML ({exc})") from exc
    if not isinstance(data, dict) or not isinstance(data.get("expect", {}), dict):
        raise ReplayError(f"{epath.name}: use 'expect: {{rule: count}}'")
    rules: dict[str, dict] = {}
    for rule, spec in (data.get("expect") or {}).items():
        if isinstance(spec, int) and not isinstance(spec, bool):
            rules[str(rule)] = {"min": spec, "max": spec}
        elif isinstance(spec, dict) and set(spec) <= {"min", "max"} and all(isinstance(v, int) for v in spec.values()):
            rules[str(rule)] = {"min": spec.get("min", 0), "max": spec.get("max")}
        else:
            raise ReplayError(f"{epath.name}: the expectation for {rule} must be a number or {{min, max}}")
    others = data.get("others")
    if others is not None and (not isinstance(others, int) or isinstance(others, bool)):
        raise ReplayError(f"{epath.name}: 'others' must be a number")
    return rules, others


def check_expectations(result: dict, rules: dict[str, dict], others: int | None) -> list[dict]:
    """Compare replay counts with the expectations. Returns only the checked rules."""
    checks: list[dict] = []
    got = {r["rule"]: r["matches"] for r in result["rules"]}
    for rule, spec in sorted(rules.items()):
        n = got.get(rule)
        if n is None:
            checks.append({"rule": rule, "expected": spec, "got": None, "passed": False, "message": "rule not found"})
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
        want = f"exactly {spec['min']}"
    elif spec["max"] is None:
        want = f"at least {spec['min']}"
    else:
        want = f"between {spec['min']} and {spec['max']}"
    return f"expected {want} event(s), got {n}"
