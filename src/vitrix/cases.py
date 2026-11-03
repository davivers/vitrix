"""Rule test cases: sample events with the expected result.

For every file in rules/ the engine looks for the file with the same path in cases/:

    rules/windows/powershell_encoded.yml  ->  cases/windows/powershell_encoded.yml

Format:

    cases:
      - name: Positive · powershell -enc
        expect: match            # or no_match
        event:
          Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
          CommandLine: 'powershell.exe -enc JABzAA=='

`kind` (optional) says what the case represents; without it, match means `positive` and
no_match means `negative`:

    positive         malicious behaviour the rule must catch (expect: match)
    negative         ordinary event that must not fire (expect: no_match)
    false_positive   legitimate activity that looks like the attack: admin, service account,
                     IT tool (expect: no_match)
    edge             edge case: missing or null field, casing, boundary value

For a no_match case the engine also checks whether it **exercises an exclusion**: if the event
would fire the rule without its `filter*` selections (or the ones negated in the condition),
the case proves the exclusion works.
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
    got: str  # "match" | "no_match" | "error"
    passed: bool
    error: str | None = None
    kind: str = "positive"
    exercises_filter: bool = False  # no_match that only did not fire because of an exclusion
    event: dict | None = None  # the sample event, so the UI can show what was tested


def cases_path(cfg: Config, rf: RuleFile) -> Path:
    try:
        rel = rf.path.resolve().relative_to(cfg.rules_dir.resolve())
    except ValueError:
        rel = Path(rf.path.name)
    return cfg.cases_dir / rel


def parse_cases(text: str, name: str, rel: str) -> tuple[list[dict], list[Issue]]:
    """Read the text of a cases file. `name` appears in messages; `rel` identifies the rule."""
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        return [], [Issue("error", rel, f"cases file is not valid YAML: {exc}")]
    cases = data.get("cases") if isinstance(data, dict) else None
    if not isinstance(cases, list) or not cases:
        return [], [Issue("error", rel, f"{name}: define a 'cases' list with at least one case")]
    problems: list[Issue] = []
    valid: list[dict] = []
    for i, case in enumerate(cases, start=1):
        label = f"{name}, case {i}"
        if not isinstance(case, dict) or not isinstance(case.get("event"), dict):
            problems.append(Issue("error", rel, f"{label}: 'event' must be a mapping of fields"))
        elif case.get("expect") not in EXPECTATIONS:
            problems.append(Issue("error", rel, f"{label}: 'expect' must be match or no_match"))
        elif "kind" in case and case["kind"] not in KINDS:
            problems.append(Issue("error", rel, f"{label}: 'kind' must be one of {', '.join(KINDS)}"))
        elif KINDS.get(case.get("kind", "")) not in (None, case["expect"]):
            problems.append(Issue("error", rel, f"{label}: kind {case['kind']} requires expect: {KINDS[case['kind']]}"))
        else:
            valid.append(case)

    # test data quality
    seen: dict[str, int] = {}
    for i, case in enumerate(valid, start=1):
        key = json.dumps(case["event"], sort_keys=True, default=str)
        if key in seen:
            problems.append(Issue("warning", rel, f"{name}, case {i}: same event as case {seen[key]}"))
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
    """Run already-parsed cases against the documents of a rule."""
    problems = list(problems)
    if cfg.require_cases and cases:
        kinds = {c["expect"] for c in cases}
        for needed in EXPECTATIONS:
            if needed not in kinds:
                problems.append(Issue("error", rel, f"missing {needed} cases (at least one positive and one negative)"))

    detection_docs = [d for d in docs if isinstance(d, dict) and "detection" in d]
    fields = _rule_fields(detection_docs)
    results: list[CaseResult] = []
    for i, case in enumerate(cases, start=1):
        name = str(case.get("name") or f"case {i}")
        expect = case["expect"]
        kind = case_kind(case)
        try:
            matched = any(evaluate(d, case["event"]) for d in detection_docs)
            exercises = not matched and any(
                exclusion_selections(d) and evaluate(d, case["event"], force_false=exclusion_selections(d))
                for d in detection_docs
            )
        except UnsupportedError as exc:
            results.append(CaseResult(rel, name, expect, "error", False, str(exc), kind, event=case["event"]))
            continue
        got = "match" if matched else "no_match"
        results.append(CaseResult(rel, name, expect, got, got == expect, None, kind, exercises, case["event"]))
        if expect == "no_match" and fields and not fields & {str(k).lower() for k in case["event"]}:
            problems.append(Issue("warning", rel, f"case “{name}”: the event has none of the fields the rule uses; it tests nothing"))
    return results, problems


def run_rule_cases(cfg: Config, rf: RuleFile) -> tuple[list[CaseResult], list[Issue]]:
    cpath = cases_path(cfg, rf)
    if not cpath.is_file():
        if cfg.require_cases:
            return [], [Issue("error", rf.rel, f"no test cases (expected at {cfg.rel(cpath)})")]
        return [], []
    cases, problems = parse_cases(cpath.read_text(encoding="utf-8"), cpath.name, rf.rel)
    return run_cases(cfg, rf.rel, rf.docs, cases, problems)
