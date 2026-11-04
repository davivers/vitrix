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
from .evaluator import UnsupportedError, _selections, evaluate, exclusion_selections
from .lint import Issue, Locator, _walk_fields
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
    hint: str | None = None  # why a failed case failed and what to change


def cases_path(cfg: Config, rf: RuleFile) -> Path:
    try:
        rel = rf.path.resolve().relative_to(cfg.rules_dir.resolve())
    except ValueError:
        rel = Path(rf.path.name)
    return cfg.cases_dir / rel


CASE_EXAMPLE = "cases:\n  - name: Positive - suspicious process\n    expect: match\n    event:\n      Image: 'C:\\Windows\\System32\\cmd.exe'"


def _cissue(severity: str, rel: str, msg: str, code: str, hint: str, loc: Locator | None = None, path: tuple = (), value: bool = False) -> Issue:
    line, col = loc.find(path, value) if loc else (None, None)
    return Issue(severity, rel, msg, code, ".".join(str(p) for p in path) or None, line, col, hint, None, "cases")


def parse_cases(text: str, name: str, rel: str) -> tuple[list[dict], list[Issue]]:
    """Read the text of a cases file. `name` appears in messages; `rel` identifies the rule.
    Issues carry `file: "cases"`: their line/column point into the cases file."""
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        return [], [Issue("error", rel, f"cases file is not valid YAML: {exc}", "cases-invalid-yaml", None,
                          mark.line + 1 if mark else None, mark.column + 1 if mark else None,
                          "Fix the YAML syntax of the cases file (indent with spaces, put `:` after keys, quote values with special characters).",
                          None, "cases")]
    locs = Locator.for_text(text)
    loc = locs[0] if locs else None
    cases = data.get("cases") if isinstance(data, dict) else None
    if not isinstance(cases, list) or not cases:
        return [], [_cissue("error", rel, f"{name}: define a 'cases' list with at least one case", "cases-missing",
                            f"Start the file with a `cases:` list, e.g.\n`{CASE_EXAMPLE}`.", loc)]
    problems: list[Issue] = []
    valid: list[dict] = []
    index: dict[int, int] = {}  # id(case) -> position in the file
    for i, case in enumerate(cases, start=1):
        label = f"{name}, case {i}"
        at = ("cases", i - 1)
        if not isinstance(case, dict) or not isinstance(case.get("event"), dict):
            problems.append(_cissue("error", rel, f"{label}: 'event' must be a mapping of fields", "case-bad-event",
                                    "Give each case an `event:` with field: value pairs, e.g.\n`event:\n  Image: 'C:\\Windows\\System32\\cmd.exe'`.",
                                    loc, (*at, "event") if isinstance(case, dict) and "event" in case else at))
        elif case.get("expect") not in EXPECTATIONS:
            problems.append(_cissue("error", rel, f"{label}: 'expect' must be match or no_match", "case-bad-expect",
                                    "Set `expect: match` if the rule should fire for this event, or `expect: no_match` if it should not.",
                                    loc, (*at, "expect") if "expect" in case else at, True))
        elif "kind" in case and case["kind"] not in KINDS:
            problems.append(_cissue("error", rel, f"{label}: 'kind' must be one of {', '.join(KINDS)}", "case-bad-kind",
                                    f"Use one of: {', '.join(KINDS)} (or remove `kind`).", loc, (*at, "kind"), True))
        elif KINDS.get(case.get("kind", "")) not in (None, case["expect"]):
            problems.append(_cissue("error", rel, f"{label}: kind {case['kind']} requires expect: {KINDS[case['kind']]}", "case-kind-mismatch",
                                    f"A `{case['kind']}` case must have `expect: {KINDS[case['kind']]}`; change `expect` or the `kind`.",
                                    loc, (*at, "expect"), True))
        else:
            valid.append(case)
            index[id(case)] = i - 1

    # test data quality
    seen: dict[str, int] = {}
    for i, case in enumerate(valid, start=1):
        key = json.dumps(case["event"], sort_keys=True, default=str)
        if key in seen:
            problems.append(_cissue("warning", rel, f"{name}, case {i}: same event as case {seen[key]}", "case-duplicate-event",
                                    f"This case repeats case {seen[key]}. Change a value so it tests something new, or delete it.",
                                    loc, ("cases", index[id(case)], "event")))
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


def _lookup(event: dict, field: str) -> tuple[bool, object]:
    for k, v in event.items():
        if str(k).lower() == field.lower():
            return True, v
    return False, None


def _field_matches(spec: str, raw: object, event: dict) -> bool:
    mini = {"detection": {"s": {spec: raw}, "condition": "s"}}
    try:
        return bool(evaluate(mini, event))
    except UnsupportedError:
        return False


def _short(value: object, limit: int = 60) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def explain(docs: list, event: dict, expect: str, name: str = "") -> str:
    """Plain-English reason a case failed: which selection/field of the rule did (not) match the event."""
    for doc in docs:
        sels = _selections(doc)
        excl = exclusion_selections(doc)
        if expect == "match":  # the rule did not fire
            for sname, sel in sels.items():
                if sname in excl or not isinstance(sel, dict):
                    continue
                bad = []
                for spec, raw in sel.items():
                    if _field_matches(str(spec), raw, event):
                        continue
                    field = str(spec).split("|")[0]
                    found, value = _lookup(event, field)
                    want = raw if not isinstance(raw, list) else raw[:3]
                    state = f"is {_short(value)}" if found else "is missing from the event"
                    bad.append(f"`{field}` {state} but the rule needs `{spec}: {_short(want)}`")
                if bad:
                    return (f"Case “{name}” expects a match, but selection `{sname}` did not match: " + "; ".join(bad[:3])
                            + ". Edit the event so those fields satisfy the rule, or change `expect` to no_match if this event should be ignored.")
            hit = [n for n in excl if isinstance(sels.get(n), dict) and all(_field_matches(str(k), v, event) for k, v in sels[n].items())]
            if hit:
                return (f"Case “{name}” expects a match, but the exclusion `{', '.join(hit)}` matched this event, so the rule stays silent. "
                        "Remove the excluded values from the event, or set `expect: no_match` (kind false_positive).")
            return f"Case “{name}” expects a match but the rule's condition is false for this event; compare the event with each selection of the rule."
        fired = [n for n, sel in sels.items() if n not in excl and isinstance(sel, dict)
                 and all(_field_matches(str(k), v, event) for k, v in sel.items())]
        if fired:
            fields = ", ".join(f"`{k}`" for k in list(sels[fired[0]])[:4])
            return (f"Case “{name}” expects no match, but selection `{fired[0]}` matched (fields {fields}). Change at least one of those values "
                    "in the event so it no longer satisfies the rule, or set `expect: match` if the rule should fire.")
    return f"Case “{name}” expects no match but the rule fired; change a field the rule checks in the event."


def run_cases(
    cfg: Config, rel: str, docs: list, cases: list[dict], problems: list[Issue]
) -> tuple[list[CaseResult], list[Issue]]:
    """Run already-parsed cases against the documents of a rule."""
    problems = list(problems)
    if cfg.require_cases and cases:
        kinds = {c["expect"] for c in cases}
        for needed in EXPECTATIONS:
            if needed not in kinds:
                problems.append(Issue("error", rel, f"missing {needed} cases (at least one positive and one negative)", "cases-missing-kind", "cases",
                                      None, None, f"Add a case with `expect: {needed}`: "
                                      + ("an event the rule must catch." if needed == "match" else "a similar but benign event the rule must ignore."),
                                      None, "cases"))

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
            results.append(CaseResult(rel, name, expect, "error", False, str(exc), kind, event=case["event"],
                                      hint="The local evaluator cannot run this rule, so the case cannot be checked here. Simplify the "
                                           "unsupported part or test the converted query in your SIEM."))
            continue
        got = "match" if matched else "no_match"
        hint = None if got == expect else explain(detection_docs, case["event"], expect, name)
        results.append(CaseResult(rel, name, expect, got, got == expect, None, kind, exercises, case["event"], hint))
        if expect == "no_match" and fields and not fields & {str(k).lower() for k in case["event"]}:
            problems.append(Issue("warning", rel, f"case “{name}”: the event has none of the fields the rule uses; it tests nothing",
                                  "case-tests-nothing", f"cases.{i - 1}.event", None, None,
                                  f"Use at least one of the rule's fields in this event: {', '.join(sorted(fields))}. "
                                  "Otherwise a no_match case passes for the wrong reason.", None, "cases"))
    return results, problems


def run_rule_cases(cfg: Config, rf: RuleFile) -> tuple[list[CaseResult], list[Issue]]:
    cpath = cases_path(cfg, rf)
    if not cpath.is_file():
        if cfg.require_cases:
            return [], [Issue("error", rf.rel, f"no test cases (expected at {cfg.rel(cpath)})", "no-cases", None, None, None,
                              f"Create {cfg.rel(cpath)} with a positive and a negative case, e.g.\n`{CASE_EXAMPLE}`.", None, "cases")]
        return [], []
    cases, problems = parse_cases(cpath.read_text(encoding="utf-8"), cpath.name, rf.rel)
    return run_cases(cfg, rf.rel, rf.docs, cases, problems)
