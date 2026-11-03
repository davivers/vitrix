"""Sigma rule lint: minimal schema, condition consistency, metadata, regex and ATT&CK checks."""

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
# Sigma top-level fields; a key close to one of these is probably a typo.
SIGMA_FIELDS = {
    "title", "id", "related", "name", "taxonomy", "status", "description", "license", "author", "references", "date",
    "modified", "tags", "logsource", "detection", "fields", "falsepositives", "level", "scope", "vitrix",
}
# Sigma modifiers (specification 2.x). Anything else is rejected by pySigma.
SIGMA_MODIFIERS = {
    "contains", "startswith", "endswith", "all", "base64", "base64offset", "wide", "utf16le", "utf16be", "utf16",
    "windash", "re", "i", "m", "s", "cidr", "lt", "lte", "gt", "gte", "expand", "fieldref", "exists", "cased",
    "hour", "minute", "day", "week", "month", "year",
}
DATE = re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}$")
# A quantifier over a group that already has one: (a+)+, (\w*)*, (x+){2,} — catastrophic backtracking.
NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")
MAX_COMPARISONS = 50  # beyond this a rule gets expensive in the SIEM and hard to review


def _walk_fields(detection: dict):
    """(field spec, values) of every map selection (including lists of maps)."""
    for key, sel in detection.items():
        if key in ("condition", "timeframe"):
            continue
        for item in sel if isinstance(sel, list) else [sel]:
            if isinstance(item, dict):
                for spec, value in item.items():
                    yield str(spec), value if isinstance(value, list) else [value]


def _detection_checks(detection: dict, err, warn) -> None:
    """Modifiers, regex and complexity of a detection."""
    comparisons = 0
    for spec, values in _walk_fields(detection):
        field, *mods = spec.split("|")
        comparisons += max(1, len(values))
        unknown = [m for m in mods if m not in SIGMA_MODIFIERS]
        if unknown:
            hint = difflib.get_close_matches(unknown[0], SIGMA_MODIFIERS, n=1)
            err(f"unknown modifier '{unknown[0]}' on field {field}" + (f" (did you mean '{hint[0]}'?)" if hint else ""))
        if "re" in mods:
            for value in values:
                try:
                    re.compile(str(value))
                except re.error as exc:
                    err(f"invalid regex on field {field}: {exc}")
                    continue
                if NESTED_QUANTIFIER.search(str(value)):
                    warn(f"regex with a nested quantifier on field {field}: risk of catastrophic backtracking in the SIEM")
    if comparisons > MAX_COMPARISONS:
        warn(f"complex rule: {comparisons} comparisons (recommended limit {MAX_COMPARISONS}); consider splitting it")


def detection_fingerprint(doc: dict) -> str | None:
    """Fingerprint of the logic (logsource + detection) to find duplicate rules."""
    if not isinstance(doc.get("detection"), dict):
        return None
    payload = json.dumps({"logsource": doc.get("logsource"), "detection": doc["detection"]}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class Issue:
    severity: str  # "error" | "warning"
    rule: str  # file path
    message: str

    def __str__(self) -> str:
        return f"{self.severity}: {self.message}"


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
        err("the YAML document must be a mapping")
        return issues
    if "action" in doc or "correlation" in doc:
        return issues  # global/correlation documents skip the detection lint

    title = doc.get("title")
    if not isinstance(title, str) or not title.strip():
        err("missing required field: title")

    if "id" not in doc:
        err("missing required field: id")
    elif not _is_uuid(doc["id"]):
        err(f"id is not a valid UUID: {doc['id']!r}")

    if "status" not in doc:
        warn("missing recommended field: status")
    elif doc["status"] not in STATUSES:
        err(f"invalid status: {doc['status']!r} (use {', '.join(sorted(STATUSES))})")

    if "level" not in doc:
        warn("missing recommended field: level")
    elif doc["level"] not in LEVELS:
        err(f"invalid level: {doc['level']!r} (use {', '.join(sorted(LEVELS))})")

    logsource = doc.get("logsource")
    if not isinstance(logsource, dict) or not any(k in logsource for k in ("category", "product", "service")):
        err("logsource needs at least category, product or service")

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        err("missing required field: detection")
    elif "condition" not in detection:
        err("detection has no condition")
    else:
        selections = {k for k in detection if k not in ("condition", "timeframe")}
        if not selections:
            err("detection defines no selection")
        cond = detection["condition"]
        used_names: set[str] = set()
        used_patterns: set[str] = set()
        for c in cond if isinstance(cond, list) else [cond]:
            names, patterns = condition_refs(str(c))
            used_names |= names
            used_patterns |= patterns
        for name in sorted(used_names - selections):
            err(f"the condition references '{name}', which does not exist in detection")
        for pattern in sorted(used_patterns):
            if pattern.lower() != "them" and not any(fnmatch.fnmatchcase(s, pattern) for s in selections):
                err(f"the condition pattern '{pattern}' matches no selection")
        covered = set(used_names)
        for pattern in used_patterns:
            covered |= selections if pattern.lower() == "them" else {s for s in selections if fnmatch.fnmatchcase(s, pattern)}
        for name in sorted(selections - covered):
            warn(f"selection '{name}' is not used in the condition")
        _detection_checks(detection, err, warn)

    for key in doc:
        if key not in SIGMA_FIELDS:
            hint = difflib.get_close_matches(str(key), SIGMA_FIELDS, n=1, cutoff=0.8)
            if hint:
                warn(f"field '{key}' is not a Sigma field; did you mean '{hint[0]}'?")
    for key in ("tags", "falsepositives", "references"):
        if key in doc and not (isinstance(doc[key], list) and all(isinstance(v, str) for v in doc[key])):
            err(f"'{key}' must be a list of strings")
    for key in ("date", "modified"):
        if key in doc and not DATE.match(str(doc[key])):
            warn(f"'{key}' is not in YYYY-MM-DD format: {doc[key]!r}")

    for message in routing.problems(doc):
        err(message)
    if known_targets is not None:
        for name in routing.declared(doc) or []:
            if name not in known_targets:
                err(f"vitrix.target: unknown target '{name}' (available: {', '.join(sorted(known_targets))})")

    if not doc.get("description"):
        warn("missing recommended field: description")
    if not doc.get("falsepositives"):
        warn("missing recommended field: falsepositives")
    tags = [t for t in (doc.get("tags") or []) if isinstance(t, str)] if isinstance(doc.get("tags"), list) else []
    if not any(t.startswith("attack.t") for t in tags):
        warn("no MITRE technique tag (e.g. attack.t1059.001)")
    else:
        for tag in tags:
            if not tag.startswith("attack."):
                continue
            m = ATTACK_TAG.match(tag)
            if not m:
                warn(f"MITRE tag does not follow the pattern: {tag}")
            elif re.fullmatch(r"[a-z_]+", m.group(1)) and m.group(1) not in ATTACK_TACTICS:
                hint = difflib.get_close_matches(m.group(1), ATTACK_TACTICS, n=1)
                warn(f"unknown ATT&CK tactic: {tag}" + (f" (did you mean attack.{hint[0]}?)" if hint else ""))
        if not any(t[len("attack."):] in ATTACK_TACTICS for t in tags if t.startswith("attack.")):
            warn("MITRE technique without its tactic (e.g. attack.execution)")

    try:
        check_supported(doc)
    except UnsupportedError as exc:
        warn(f"the local evaluator does not cover this rule ({exc}); `vitrix test` cannot test it")

    return issues


def lint_files(files: list[RuleFile], known_targets: set[str] | None = None) -> list[Issue]:
    issues: list[Issue] = []
    seen: dict[str, str] = {}
    logic: dict[str, str] = {}
    for rf in files:
        if not rf.docs:
            issues.append(Issue("error", rf.rel, "empty file"))
            continue
        for doc in rf.docs:
            issues.extend(lint_doc(doc, rf.rel, known_targets))
            if isinstance(doc, dict) and "id" in doc and _is_uuid(doc["id"]):
                rid = str(doc["id"]).lower()
                if rid in seen and seen[rid] != rf.rel:
                    issues.append(Issue("error", rf.rel, f"duplicate id (already used in {seen[rid]})"))
                seen.setdefault(rid, rf.rel)
            fp = detection_fingerprint(doc) if isinstance(doc, dict) else None
            if fp:
                if fp in logic and logic[fp] != rf.rel:
                    issues.append(Issue("warning", rf.rel, f"detection logic identical to {logic[fp]} (redundant rule)"))
                logic.setdefault(fp, rf.rel)
    return issues
