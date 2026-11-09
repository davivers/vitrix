"""Log replay: run every rule against a set of events, locally.

It shows which events a rule matches, like a logtest tool: an attack dataset shows which rules
catch what, a dataset of normal activity shows the noise. It is information only and never
blocks a rule, a run or a pull request.

Datasets live in `datasets/` (`datasets_dir` in vitrix.yml), one per file: JSON (a list of
events or `{"events": [...]}`), JSON Lines (`.jsonl`, one event per line) or YAML (a list or
`events:`). Optional notes sit next to them, in `<name>.expect.yml` (shown by `vitrix replay`):

    expect:
      windows/powershell_encoded.yml: 2          # exactly 2 events
      windows/schtasks_system.yml: {min: 1}       # at least 1
    others: 0                                     # every other rule: 0 (default: no limit)

`others` suits a dataset of normal activity. On an attack dataset it would fail every new rule
that correctly detects the attack.
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
    """Invalid dataset, expectations file or draft rule. `code`/`hint` feed the structured API error."""

    def __init__(self, message: str, code: str = "invalid-rule", hint: str | None = None):
        super().__init__(message)
        self.code, self.hint = code, hint

    def payload(self) -> dict:
        return {"code": self.code, "message": str(self), "hint": self.hint}


def error_payload(exc: Exception, **where: object) -> dict:
    """Structured replay error `{code, message, hint, path?, line?, ...}` for a dataset / case / rule.

    Codes: `unsupported` (outside the local evaluator's subset), `regex-timeout`, `bad-dataset`,
    `invalid-rule`, `internal`. Never a raw exception string without a hint."""
    from .evaluator import RegexError  # local: keeps the module header light

    msg = " ".join(str(exc).split())
    if isinstance(exc, ReplayError):
        code, hint = exc.code, exc.hint
    elif ("timed out" in msg or "budget exhausted" in msg) and (isinstance(exc, RegexError) or msg.startswith("regex ")):
        code = "regex-timeout"
        hint = "A |re pattern backtracks too much. Avoid nested quantifiers such as (a+)+ and test it in the Regex Workbench."
    elif isinstance(exc, RegexError):
        code, hint = "invalid-regex", "Fix the |re pattern (see the Regex Workbench for the exact position of the error)."
    elif isinstance(exc, UnsupportedError):
        code = "unsupported"
        hint = "Replay evaluates a subset of Sigma locally. Simplify the unsupported part, or test the converted query in your SIEM."
    else:
        code, hint = "invalid-rule", "The detection section could not be evaluated; check its structure against the Sigma specification."
    return {"code": code, "message": msg, **{k: v for k, v in where.items() if v is not None}, "hint": hint}


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
                raise ReplayError(f"{name}: not valid JSON, JSON Lines or YAML ({exc})", code="bad-dataset", hint="Valid formats: JSON list, JSON Lines (one event per line) or YAML; every event must be a mapping of fields.") from exc
    if isinstance(data, dict):
        data = data.get("events", [data])
    if not isinstance(data, list):
        raise ReplayError(f"{name}: expected a list of events", code="bad-dataset", hint="Valid formats: JSON list, JSON Lines (one event per line) or YAML; every event must be a mapping of fields.")
    if len(data) > MAX_EVENTS:
        raise ReplayError(f"{name}: {len(data)} events; the limit is {MAX_EVENTS}", code="bad-dataset", hint="Valid formats: JSON list, JSON Lines (one event per line) or YAML; every event must be a mapping of fields.")
    bad = next((i for i, e in enumerate(data, 1) if not isinstance(e, dict)), None)
    if bad:
        raise ReplayError(f"{name}: event {bad} is not a mapping of fields", code="bad-dataset", hint="Valid formats: JSON list, JSON Lines (one event per line) or YAML; every event must be a mapping of fields.")
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
        raise ReplayError(f"{epath.name}: invalid YAML ({exc})", code="bad-expectation", hint="Use `expect: {rule: count}` or `{min, max}`, and an integer `others`.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("expect", {}), dict):
        raise ReplayError(f"{epath.name}: use 'expect: {{rule: count}}'", code="bad-expectation", hint="Use `expect: {rule: count}` or `{min, max}`, and an integer `others`.")
    rules: dict[str, dict] = {}
    for rule, spec in (data.get("expect") or {}).items():
        if isinstance(spec, int) and not isinstance(spec, bool):
            rules[str(rule)] = {"min": spec, "max": spec}
        elif isinstance(spec, dict) and set(spec) <= {"min", "max"} and all(isinstance(v, int) for v in spec.values()):
            rules[str(rule)] = {"min": spec.get("min", 0), "max": spec.get("max")}
        else:
            raise ReplayError(f"{epath.name}: the expectation for {rule} must be a number or {{min, max}}", code="bad-expectation", hint="Use `expect: {rule: count}` or `{min, max}`, and an integer `others`.")
    others = data.get("others")
    if others is not None and (not isinstance(others, int) or isinstance(others, bool)):
        raise ReplayError(f"{epath.name}: 'others' must be a number", code="bad-expectation", hint="Use `expect: {rule: count}` or `{min, max}`, and an integer `others`.")
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
                checks.append({"rule": rule, "expected": spec, "got": n, "passed": False, "message": _describe_others(spec, n)})
    return checks


def _describe(spec: dict, n: int) -> str:
    if spec["max"] is not None and spec["min"] == spec["max"]:
        want = f"exactly {spec['min']}"
    elif spec["max"] is None:
        want = f"at least {spec['min']}"
    else:
        want = f"between {spec['min']} and {spec['max']}"
    return f"expected {want} event(s), got {n}"


def _describe_others(spec: dict, n: int) -> str:
    """The same failure when the limit is the dataset's `others`, not an expectation for this rule."""
    return (f"{_describe(spec, n)}: this rule is not listed under `expect:`, so the dataset's `others: {spec['max']}` limit applies. "
            "If these matches are correct, list the rule under `expect:` in the .expect.yml or remove `others`.")


# --------------------------------------------------------------------------- draft replay (Editor)

MAX_DRAFT_YAML = 200_000  # characters of rule YAML accepted from the Editor
MAX_DRAFT_SAMPLE = 50  # matching events returned per dataset
MAX_DRAFT_DATASETS = 50  # datasets per request


def list_dataset_info(cfg: Config) -> list[dict]:
    """Datasets for the picker: name, size, event count (None if unreadable) and error."""
    out = []
    for path in dataset_files(cfg):
        try:
            n, error = len(load_events(path.read_text(encoding="utf-8"), path.name)), None
        except (ReplayError, OSError, UnicodeDecodeError) as exc:
            n, error = None, str(exc)
        try:
            rules, others = load_expectations(path)
            expect_error = None
        except ReplayError as exc:
            rules, others, expect_error = {}, None, str(exc)
        out.append({"name": dataset_name(cfg, path), "events": n, "size": path.stat().st_size, "error": error,
                    "has_expectations": bool(rules) or others is not None, "expect_error": expect_error})
    return out


def case_selections(docs: list, event: dict) -> list[dict]:
    """Per selection of the rule: did it match this event and, per field, what was expected vs. found."""
    from .cases import _field_matches, _lookup  # noqa: PLC0415  (same helpers `explain` uses)
    from .evaluator import _eval_selection, _selections, exclusion_selections

    out: list[dict] = []
    for doc in docs:
        excl = exclusion_selections(doc)
        for sname, sel in _selections(doc).items():
            fields: list[dict] = []
            if isinstance(sel, dict):
                for spec, raw in sel.items():
                    field = str(spec).split("|")[0]
                    found, actual = _lookup(event, field)
                    fields.append({"field": str(spec), "expected": raw, "actual": actual if found else None,
                                   "present": found, "matched": _field_matches(str(spec), raw, event)})
                matched = all(f["matched"] for f in fields) if fields else True
            else:
                try:
                    matched = bool(_eval_selection(sel, event))
                except UnsupportedError:
                    matched = False
            out.append({"name": sname, "exclusion": sname in excl, "matched": matched, "fields": fields})
    return out


def _run_cases(cfg: Config, cases_text: str | None, path: str | None, detection_docs: list) -> tuple[list[dict], list[dict]]:
    """Cases (events with an expectation) of the draft, evaluated against the draft. Returns (cases, problems)."""
    from .cases import case_kind, cases_path, parse_cases, run_cases  # noqa: PLC0415
    from .service import resolve_rule  # noqa: PLC0415

    if cases_text is None and path:
        saved = resolve_rule(cfg, path)
        cpath = cases_path(cfg, RuleFile(saved, path, "", [])) if saved else None
        cases_text = cpath.read_text(encoding="utf-8") if cpath and cpath.is_file() else None
    if not cases_text or not cases_text.strip():
        return [], []
    valid, problems = parse_cases(cases_text, "cases", path or "<editor>")
    results, more = run_cases(cfg, path or "<editor>", detection_docs, valid, problems)
    out = []
    for case, r in zip(valid, results, strict=False):
        error = None
        if r.error:
            error = error_payload(UnsupportedError(r.error))
        out.append({
            "name": r.name, "kind": case_kind(case), "expected": r.expect, "matched": None if r.got == "error" else r.got == "match",
            "passed": r.passed, "hint": r.hint, "error": error, "error_text": r.error, "event": case["event"],
            "selections": case_selections(detection_docs, case["event"]) if r.got != "error" else [],
        })
    return out, [{"severity": i.severity, "code": i.code, "message": i.message, "hint": i.hint, "line": i.line, "column": i.column}
                 for i in more]


def _matching(docs: list, events: list[dict]) -> list[int]:
    return [i for i, e in enumerate(events, 1) if any(evaluate(d, e) for d in docs)]


def replay_draft(cfg: Config, rule_text: str, names: list[str] | None = None, path: str | None = None,
                 cases_text: str | None = None, compare: bool = False) -> dict:
    """Run an unsaved rule (YAML text) against datasets (and its cases). `names` None = all.

    `path` is the rule id used to look the draft up in `<dataset>.expect.yml` (an existing rule
    being edited); without it a dataset's `others` limit, if any, still applies.
    `cases_text` is the cases YAML of the draft (default: the saved cases file of `path`).
    `compare` adds `before` / `added` / `removed` per dataset against the saved version of `path`.
    Raises ReplayError (code `invalid-rule` / `bad-dataset`) for bad input; per-dataset failures
    come back as `error: {code, message, hint}` (old string in `error_text`).
    """
    if len(rule_text) > MAX_DRAFT_YAML:
        raise ReplayError(f"the rule is larger than {MAX_DRAFT_YAML} characters", hint="Split the rule or remove generated content.")
    try:
        docs = [d for d in yaml.safe_load_all(rule_text) if d is not None]
    except yaml.YAMLError as exc:
        raise ReplayError(f"the rule is not valid YAML: {exc}", hint="Fix the YAML syntax (indent with spaces, `:` after keys).") from exc
    if not any(isinstance(d, dict) and "detection" in d for d in docs):
        raise ReplayError("the rule has no 'detection' section", hint="Add `detection:` with at least one selection and a `condition`.")
    if names is None:
        paths = dataset_files(cfg)
    else:
        if len(names) > MAX_DRAFT_DATASETS:
            raise ReplayError(f"at most {MAX_DRAFT_DATASETS} datasets per request", code="bad-dataset")
        paths = []
        for n in dict.fromkeys(names):
            p = resolve_dataset(cfg, n)
            if p is None or p.name.endswith(EXPECT_SUFFIX):
                raise ReplayError(f"unknown dataset: {n!r}", code="bad-dataset", hint="Pick a dataset from GET /api/datasets.")
            paths.append(p)
    rid = path or "<editor>"
    detection_docs = [d for d in docs if isinstance(d, dict) and "detection" in d]
    saved_docs: list | None = None
    if compare and path:
        from .service import resolve_rule  # noqa: PLC0415

        sp = resolve_rule(cfg, path)
        if sp is not None:
            try:
                saved_docs = [d for d in yaml.safe_load_all(sp.read_text(encoding="utf-8")) if isinstance(d, dict) and "detection" in d]
            except (yaml.YAMLError, OSError):
                saved_docs = None
    started = time.perf_counter()
    cases, case_problems = _run_cases(cfg, cases_text, path, detection_docs)
    results: list[dict] = []

    def fail(item: dict, exc: Exception, **where: object) -> None:
        err = error_payload(exc, dataset=item["dataset"], **where)
        item.update(error=err, error_text=str(exc), passed=False, matches=0, sample=[])

    for p in paths:
        name = dataset_name(cfg, p)
        item: dict = {"dataset": name, "events": 0, "matches": 0, "duration_ms": 0.0, "expectation": None,
                      "passed": None, "message": None, "error": None, "error_text": None, "sample": [], "truncated": False}
        if compare:
            item.update(before=None, added=[], removed=[])
        try:
            events = load_events(p.read_text(encoding="utf-8"), p.name)
            expect_rules, others = load_expectations(p)
        except (ReplayError, OSError, UnicodeDecodeError) as exc:
            fail(item, exc if isinstance(exc, ReplayError) else ReplayError(str(exc), code="bad-dataset", hint="Check the file is readable UTF-8."))
            results.append(item)
            continue
        item["events"] = len(events)
        t0 = time.perf_counter()
        after: list[int] = []
        try:
            for i, event in enumerate(events, 1):
                if any(evaluate(d, event) for d in detection_docs):
                    after.append(i)
                    if len(item["sample"]) < MAX_DRAFT_SAMPLE:
                        item["sample"].append({"index": i, "event": event})
            item["matches"] = len(after)
        except UnsupportedError as exc:  # never a silent pass
            fail(item, exc)
            after = []
        except (AttributeError, TypeError, ValueError, KeyError) as exc:  # malformed detection section
            fail(item, ReplayError(f"the detection section could not be evaluated ({type(exc).__name__}: {exc})"))
            after = []
        item["duration_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        item["truncated"] = item["matches"] > len(item["sample"])
        if compare and item["error"] is None:
            before: list[int] = []
            if saved_docs is not None:
                try:
                    before = _matching(saved_docs, events)
                except UnsupportedError:
                    before = []
            item["before"] = len(before) if saved_docs is not None else None
            add, rem = sorted(set(after) - set(before)), sorted(set(before) - set(after))
            item["added"] = [{"index": i, "event": events[i - 1]} for i in add[:MAX_DRAFT_SAMPLE]]
            item["removed"] = [{"index": i, "event": events[i - 1]} for i in rem[:MAX_DRAFT_SAMPLE]]
            item["added_total"], item["removed_total"] = len(add), len(rem)
        if item["error"] is None:
            spec = expect_rules.get(rid) if path else None
            describe = _describe
            if spec is None and others is not None:
                spec, describe = {"min": 0, "max": others}, _describe_others
            if spec is not None:
                ok = item["matches"] >= spec["min"] and (spec["max"] is None or item["matches"] <= spec["max"])
                item.update(expectation=spec, passed=ok, message=None if ok else describe(spec, item["matches"]))
        results.append(item)
    cases_ok = all(c["passed"] for c in cases) if cases else None
    return {"rule": rid, "duration_ms": round((time.perf_counter() - started) * 1000, 2), "datasets": results,
            "saved": (saved_docs is not None) if compare else None,
            "cases": cases, "case_problems": case_problems, "cases_passed": cases_ok,
            "passed": (all(r["passed"] is not False for r in results) if results else None),
            "message": None if results else "no datasets to replay",
            "errors": sum(r["error"] is not None for r in results)}
