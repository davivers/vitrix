"""Quality gate: is the rule ready to be published?

The lifecycle of a rule in Vitrix:

    Write → Validate → Test → Replay → Analyze → Quality gate → Deploy

Every check belongs to a stage and answers one of five questions:

    1. Is the rule syntactically correct?              (validate)
    2. Does the detection logic work?                  (test)
    3. Are there known false positives?                (analyze)
    4. Does the rule detect the expected behaviour?    (test, analyze)
    5. Is the rule ready to be published?              (gate: every blocking check passes)

Replay is a tool to try a rule on real logs: it has no checks here and never affects approval.

Criteria come from `quality_gate` in vitrix.yml (see config.GateConfig). A failed `blocking`
check stops publication; non-blocking ones show up as recommendations. A rule is **approved**
when no blocking check fails and its health score reaches `min_score`. Deploy means: the
change was validated by the real CI engine and merged; Vitrix does not push to SIEMs yet.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .cases import CaseResult
from .config import GateConfig
from .lint import Issue

STAGES = ("write", "validate", "test", "replay", "analyze", "gate", "deploy")
STAGE_LABELS = {
    "write": "Write",
    "validate": "Validate",
    "test": "Test",
    "replay": "Replay",
    "analyze": "Analyze",
    "gate": "Quality gate",
    "deploy": "Deploy",
}
QUESTIONS = {
    1: "Is the rule syntactically correct?",
    2: "Does the detection logic work?",
    3: "Are there known false positives?",
    4: "Does the rule detect the expected behaviour?",
    5: "Is the rule ready to be published?",
}


@dataclass
class Check:
    id: str
    stage: str
    question: int
    label: str
    passed: bool | None  # None = not applicable
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
    age_days: float | None = None,
    governance: dict | None = None,
) -> dict:
    """Every check for one rule, the state of each stage and whether it is ready.

    `age_days`: days since the last change in Git (None = no history; the periodic review
    check does not apply). `governance`: governance.rule_governance() of the rule (owner,
    review deadline, suppressions).
    """
    gov = governance or {"owner": None, "review_by": None, "review_state": None, "suppressions": []}
    checks: list[Check] = []

    def add(id: str, stage: str, q: int, label: str, passed: bool | None, blocking: bool = True, detail: str = "") -> None:
        checks.append(Check(id, stage, q, label, passed, blocking, detail))

    doc = doc or {}
    errors = [i for i in issues if i.severity == "error"]
    warnings = [i for i in issues if i.severity == "warning"]
    case_errors = [p for p in problems if p.severity == "error"]
    case_warnings = [p for p in problems if p.severity == "warning"]

    # 1 · Validate
    add("parse", "write", 1, "Valid YAML", parse_error is None, detail=parse_error or "")
    add("schema", "validate", 1, "Schema and lint without errors", parse_error is None and not errors,
        detail="; ".join(i.message for i in errors[:3]))
    failed_conv = [t for t, ok in final_conversion.items() if not ok]
    if final_conversion and set(final_conversion) == {"sigma"}:  # kept as Sigma: nothing to convert
        add("conversion", "validate", 1, "Converts to the final query language", None, detail="not applicable: kept as Sigma (no conversion)")
    else:
        add("conversion", "validate", 1, "Converts to the final query language", bool(final_conversion) and not failed_conv,
            detail=f"failed: {', '.join(failed_conv)}" if failed_conv else ", ".join(final_conversion))
    add("warnings", "validate", 1, "No lint warnings", not warnings, blocking=not gate.allow_warnings,
        detail="; ".join(i.message for i in warnings[:3]))

    # 2 · Test
    kinds = [r.kind for r in results]
    positives = sum(r.expect == "match" for r in results)
    negatives = sum(r.expect == "no_match" for r in results)
    failed = [r for r in results if not r.passed]
    add("cases_pass", "test", 2, "All test cases pass", bool(results) and not failed and not case_errors,
        detail="; ".join(f"{r.name}: {r.error or f'expected {r.expect}, got {r.got}'}" for r in failed[:3])
        or "; ".join(p.message for p in case_errors[:2]) or (f"{len(results)} cases" if results else "no test cases"))
    add("positive_cases", "test", 4, f"At least {gate.min_positive} positive case(s)", positives >= gate.min_positive,
        detail=f"{positives} positive")
    add("negative_cases", "test", 2, f"At least {gate.min_negative} negative case(s)", negatives >= gate.min_negative,
        detail=f"{negatives} negative")
    add("edge_cases", "test", 2, "Edge case (missing or null field, casing)", "edge" in kinds, blocking=False,
        detail="add a case with kind: edge" if "edge" not in kinds else f"{kinds.count('edge')} edge")

    # 3/4 · Analyze
    level = doc.get("level")
    # Opt-in only (quality_gate.false_positive_levels, empty by default): a false-positive case is
    # required just for the levels a team lists; otherwise the check is not shown and costs no score.
    if level in gate.false_positive_levels:
        fp = kinds.count("false_positive")
        add("false_positive_cases", "analyze", 3, f"False-positive case (required for level {level})",
            fp > 0, blocking=True, detail=f"{fp} false_positive case(s)" if fp else "add a case with kind: false_positive")
    add("falsepositives_doc", "analyze", 3, "False positives documented (falsepositives)", bool(doc.get("falsepositives")),
        blocking=False)
    if has_exclusions:
        exercised = sum(r.exercises_filter for r in results)
        add("exclusion_tested", "analyze", 3, "Exclusion (filter) proven by a test case", exercised > 0,
            blocking=gate.require_filter_test,
            detail=f"{exercised} case(s) prove the exclusion" if exercised else "no no_match case depends on the filter")
    tags = [t for t in (doc.get("tags") or []) if isinstance(t, str)] if isinstance(doc.get("tags"), list) else []
    has_technique = any(t.startswith("attack.t") for t in tags)
    add("mitre", "analyze", 4, "Mapped to an ATT&CK technique", has_technique, blocking=gate.require_mitre,
        detail=", ".join(t[7:].upper() for t in tags if t.startswith("attack.t")) or "no attack.tXXXX tag")
    sups = [s for s in gov["suppressions"] if s["state"] != "orphan"]
    if sups:
        undocumented = [s["selection"] for s in sups if s["state"] == "undocumented"]
        add("suppressions_documented", "analyze", 3, "Every exclusion documented (vitrix.suppressions)", not undocumented,
            blocking=gate.require_suppression_reason,
            detail=f"no reason for: {', '.join(undocumented)}" if undocumented else f"{len(sups)} documented")
        expired = [s for s in sups if s["state"] == "expired"]
        add("suppressions_expired", "analyze", 3, "No expired exclusion", not expired, blocking=gate.block_expired_suppressions,
            detail="; ".join(f"{s['selection']} expired {s['expires']}" for s in expired)
            or (f"{len(sups)} active" if not any(s["expires"] for s in sups) else
                "next expiry " + min(s["expires"] for s in sups if s["expires"])))
    add("data_quality", "analyze", 2, "Test data without quality problems", not case_warnings, blocking=False,
        detail="; ".join(p.message for p in case_warnings[:2]))

    # 5 · Gate
    status = doc.get("status")
    add("status", "gate", 5, "Publishable status", status not in gate.blocked_status,
        detail=f"status {status}" if status else "no status")
    # without require_owner a missing owner is not scored (the Governance page lists unowned rules)
    add("owner", "gate", 5, "Has an owner (vitrix.owner)",
        True if gov["owner"] else (False if gate.require_owner else None), blocking=gate.require_owner,
        detail=gov["owner"] or "set vitrix.owner to the accountable team")
    if gov["review_by"]:
        add("review", "gate", 5, f"Review deadline {gov['review_by']}", gov["review_state"] != "overdue", blocking=False,
            detail={"overdue": "review overdue", "due_soon": "review due within 30 days"}.get(gov["review_state"], "on schedule"))
    elif gate.review_days:
        add("review", "gate", 5, f"Reviewed in the last {gate.review_days} days",
            None if age_days is None else age_days <= gate.review_days, blocking=False,
            detail="no Git history" if age_days is None else f"last changed {age_days:.0f} days ago")

    # Approval threshold: judged on the score of every other check, so it never feeds back into itself.
    score = health_score(checks)
    if gate.min_score:
        add("min_score", "gate", 5, f"Health score at least {gate.min_score}", score >= gate.min_score,
            detail=f"score {score}/100, {gate.min_score} required")

    blockers = [c for c in checks if c.blocking and c.passed is False]
    ready = not blockers
    return {
        "ready": ready,
        "score": score,
        "min_score": gate.min_score,
        "stages": _stages(checks, ready),
        "checks": [asdict(c) for c in checks],
        "blockers": [c.label for c in blockers],
        "answers": {q: _answer(checks, q, ready) for q in QUESTIONS},
    }


def health_score(checks: list[Check]) -> int:
    """Health score 0–100: applicable checks that pass, blocking ones weigh 3, recommendations 1.

    A blocked rule never scores above 69, so the score cannot hide a blocker.
    """
    applicable = [c for c in checks if c.passed is not None]
    if not applicable:
        return 0
    total = sum(3 if c.blocking else 1 for c in applicable)
    got = sum(3 if c.blocking else 1 for c in applicable if c.passed)
    score = round(100 * got / total)
    return min(score, 69) if any(c.blocking and not c.passed for c in applicable) else score


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
    """ok | warn | fail | skip | pending for each lifecycle stage."""
    states = {s: _stage_state([c for c in checks if c.stage == s]) for s in STAGES if s not in ("gate", "deploy")}
    gate_checks = [c for c in checks if c.stage == "gate"]
    states["gate"] = "fail" if not ready else ("warn" if any(c.passed is False for c in gate_checks) else "ok")
    # Deploy = validated by the real CI engine + merged. Pending until then.
    states["deploy"] = "pending" if ready else "skip"
    return states


def _answer(checks: list[Check], q: int, ready: bool) -> str:
    if q == 5:
        return "ok" if ready else "fail"
    return _stage_state([c for c in checks if c.question == q])
