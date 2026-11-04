"""Sigma rule lint: minimal schema, condition consistency, metadata, regex and ATT&CK checks."""

from __future__ import annotations

import difflib
import fnmatch
import hashlib
import json
import re
import uuid
from dataclasses import dataclass

import yaml

from . import attack, governance, routing
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


def _near(word: str, options, n: int = 3, cutoff: float = 0.6) -> list[str]:
    return difflib.get_close_matches(str(word), sorted(options), n=n, cutoff=cutoff)


def _walk_fields(detection: dict):
    """(field spec, values) of every map selection (including lists of maps)."""
    for _sel, spec, value in _walk_selected(detection):
        yield spec, value


def _walk_selected(detection: dict):
    """(selection name, field spec, values) of every map selection (including lists of maps)."""
    for key, sel in detection.items():
        if key in ("condition", "timeframe"):
            continue
        for item in sel if isinstance(sel, list) else [sel]:
            if isinstance(item, dict):
                for spec, value in item.items():
                    yield str(key), str(spec), value if isinstance(value, list) else [value]


def _detection_checks(detection: dict, add) -> None:  # noqa: ANN001
    """Modifiers, regex and complexity of a detection. `add(severity, code, msg, path, hint, fix, value)`."""
    comparisons = 0
    for sel, spec, values in _walk_selected(detection):
        field, *mods = spec.split("|")
        where = ("detection", sel, spec)
        comparisons += max(1, len(values))
        unknown = [m for m in mods if m not in SIGMA_MODIFIERS]
        if unknown:
            near = _near(unknown[0], SIGMA_MODIFIERS, n=1)
            fixed = "|".join([field, *[near[0] if m == unknown[0] else m for m in mods]]) if near else None
            add("error", "bad-modifier", f"unknown modifier '{unknown[0]}' on field {field}" + (f" (did you mean '{near[0]}'?)" if near else ""), where,
                (f"Rename `{spec}` to `{fixed}`. " if fixed else "") + f"Valid modifiers: {', '.join(sorted(SIGMA_MODIFIERS))}.",
                {"replace_path": ".".join(where), "snippet": fixed} if fixed else None)
        if "re" in mods:
            for value in values:
                try:
                    re.compile(str(value))
                except re.error as exc:
                    pos = f" at position {exc.pos}" if getattr(exc, "pos", None) is not None else ""
                    add("error", "bad-regex", f"invalid regex on field {field}: {exc}", where,
                        f"The regex fails{pos}: {exc.msg}. Fix or escape that part (a literal dot or bracket needs a backslash, e.g. `\\.`); "
                        "test it in the Regex Workbench.", None, True)
                    continue
                if NESTED_QUANTIFIER.search(str(value)):
                    add("warning", "regex-backtracking", f"regex with a nested quantifier on field {field}: risk of catastrophic backtracking in the SIEM", where,
                        "A quantifier on a group that already repeats, like `(a+)+`, can hang the SIEM. Drop the outer quantifier "
                        "(`a+`), or replace the regex with `|contains` / `|startswith` / `|endswith`.", None, True)
    if comparisons > MAX_COMPARISONS:
        add("warning", "complex-rule", f"complex rule: {comparisons} comparisons (recommended limit {MAX_COMPARISONS}); consider splitting it", ("detection",),
            "Split the rule by behaviour (one rule per technique variant) or fold long value lists into `|contains|all` / `|re` where it is still readable.")


def detection_fingerprint(doc: dict) -> str | None:
    """Fingerprint of the logic (logsource + detection) to find duplicate rules."""
    if not isinstance(doc.get("detection"), dict):
        return None
    payload = json.dumps({"logsource": doc.get("logsource"), "detection": doc["detection"]}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class Issue:
    """One finding. The first three fields are the original model; the rest (contract B3) say WHERE
    (`path`, 1-based `line`/`column`) and HOW to fix it (`hint`, optional `fix`). `file` is None for
    the rule's own YAML and "cases" when line/column point into the cases file."""

    severity: str  # "error" | "warning"
    rule: str  # file path
    message: str
    code: str | None = None  # stable id, e.g. "missing-field"
    path: str | None = None  # e.g. "detection.selection.Image|endswith"
    line: int | None = None
    column: int | None = None
    hint: str | None = None  # plain-English fix, may hold a YAML snippet in backticks
    fix: dict | None = None  # {"replace_path"?: str, "snippet"?: str}
    file: str | None = None

    def __str__(self) -> str:
        return f"{self.severity}: {self.message}"

    def where(self) -> str:
        return f"{self.line}:{self.column or 1}" if self.line else ""

    def to_dict(self) -> dict:
        return {"severity": self.severity, "rule": self.rule, "message": self.message, "code": self.code, "path": self.path,
                "line": self.line, "column": self.column, "hint": self.hint, "fix": self.fix, "file": self.file}

    @classmethod
    def from_dict(cls, d: dict, rule: str = "<editor>") -> Issue:
        return cls(d["severity"], rule, d["message"], d.get("code"), d.get("path"), d.get("line"), d.get("column"),
                   d.get("hint"), d.get("fix"), d.get("file"))


_NULL = "tag:yaml.org,2002:null"


class Locator:
    """Maps field paths to 1-based (line, column) in the YAML text, from the parser's node marks."""

    def __init__(self, root: yaml.Node | None):
        self.root = root

    @classmethod
    def for_text(cls, text: str) -> list[Locator]:
        """One locator per non-empty YAML document (same order as `yaml.safe_load_all` without Nones)."""
        try:
            nodes = [n for n in yaml.compose_all(text) if n is not None and not (isinstance(n, yaml.ScalarNode) and n.tag == _NULL)]
        except yaml.YAMLError:
            return []
        return [cls(n) for n in nodes]

    @staticmethod
    def _pos(node: yaml.Node) -> tuple[int, int]:
        return node.start_mark.line + 1, node.start_mark.column + 1

    def find(self, path: tuple = (), value: bool = False) -> tuple[int | None, int | None]:
        """Position of the key at `path` (or its value node with `value`); the closest existing
        ancestor when the path is absent (a missing field points at its parent)."""
        node = self.root
        if node is None:
            return None, None
        best = self._pos(node)
        for i, part in enumerate(path):
            nxt = None
            if isinstance(node, yaml.MappingNode):
                for k, v in node.value:
                    if isinstance(k, yaml.ScalarNode) and k.value == part:
                        nxt = v
                        best = self._pos(v) if (value and i == len(path) - 1) else self._pos(k)
                        break
            elif isinstance(node, yaml.SequenceNode):
                items = node.value  # a list of maps (selection alternatives): look in each item
                if isinstance(part, int) and part < len(items):
                    nxt, best = items[part], self._pos(items[part])
                else:
                    for item in items:
                        if isinstance(item, yaml.MappingNode):
                            for k, v in item.value:
                                if isinstance(k, yaml.ScalarNode) and k.value == part:
                                    nxt = v
                                    best = self._pos(v) if (value and i == len(path) - 1) else self._pos(k)
                                    break
                        if nxt is not None:
                            break
            if nxt is None:
                break
            node = nxt
        return best


def _is_uuid(value: object) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


def _vitrix_path(message: str) -> tuple[str, ...]:
    m = re.match(r"'?(vitrix(?:\.[A-Za-z_][\w-]*)*)", message)
    return tuple(m.group(1).split(".")) if m else ("vitrix",)


def _vitrix_hint(message: str) -> str:
    if "must be a mapping" in message and "suppressions" not in message:
        return "Write the block as a mapping, e.g.\n`vitrix:\n  owner: detection-team\n  target: splunk`."
    if "unknown key" in message:
        return "Remove or rename the key. Allowed under `vitrix`: target, owner, review_by, suppressions, kql_table."
    if "target" in message:
        return "Use a target name or a list, e.g. `target: splunk` or `target: [splunk, kql]`."
    if "owner" in message and "suppressions" not in message:
        return "Name a team or person, e.g. `owner: detection-engineering`."
    if "review_by" in message or "expires" in message:
        return "Use an ISO date, e.g. `review_by: 2027-06-30`."
    if "no selection named" in message:
        return "The key must be the name of a filter selection in `detection` (e.g. `filter_admin`); check the spelling."
    if "missing reason" in message:
        return "Explain why the exclusion exists, e.g. `reason: Patch tool run by IT ops`."
    return "Each suppression is `filter_name: {reason: ..., owner: ..., expires: YYYY-MM-DD, ticket: ...}`."


def _gov_code(message: str) -> str:
    return "bad-suppression" if "suppressions" in message else "bad-governance"


def lint_doc(doc: object, rel: str, known_targets: set[str] | None = None, locator: Locator | None = None) -> list[Issue]:
    """Lint one document. With `locator` (from the YAML text) every issue carries line/column."""
    issues: list[Issue] = []

    def add(severity: str, code: str, msg: str, path: tuple = (), hint: str | None = None, fix: dict | None = None,
            value: bool = False) -> None:
        line, col = locator.find(path, value) if locator else (None, None)
        issues.append(Issue(severity, rel, msg, code, ".".join(str(p) for p in path) or None, line, col, hint, fix))

    if not isinstance(doc, dict):
        add("error", "not-a-mapping", "the YAML document must be a mapping", (),
            "A Sigma rule is a set of `key: value` lines at the top level (title, logsource, detection...). Remove any leading `- ` or plain text.")
        return issues
    if "action" in doc or "correlation" in doc:
        return issues  # global/correlation documents skip the detection lint

    title = doc.get("title")
    if not isinstance(title, str) or not title.strip():
        add("error", "missing-field", "missing required field: title", ("title",),
            "Add a short, specific title, e.g. `title: Suspicious PowerShell Encoded Command`.",
            {"replace_path": "title", "snippet": "title: Suspicious PowerShell Encoded Command"})

    if "id" not in doc:
        new = uuid.uuid4()
        add("error", "missing-field", "missing required field: id", ("id",),
            f"Add a unique UUID, e.g. `id: {new}` (any UUID v4 generator works).", {"replace_path": "id", "snippet": f"id: {new}"})
    elif not _is_uuid(doc["id"]):
        new = uuid.uuid4()
        add("error", "invalid-uuid", f"id is not a valid UUID: {doc['id']!r}", ("id",),
            f"The id must be a UUID like `{new}`. Replace it with a freshly generated one.", {"replace_path": "id", "snippet": f"id: {new}"}, True)

    if "status" not in doc:
        add("warning", "missing-field", "missing recommended field: status", ("status",),
            "Add the maturity of the rule: `status: test` while tuning, `status: stable` once proven.",
            {"replace_path": "status", "snippet": "status: test"})
    elif doc["status"] not in STATUSES:
        near = _near(doc["status"], STATUSES, n=1)
        add("error", "invalid-status", f"invalid status: {doc['status']!r} (use {', '.join(sorted(STATUSES))})", ("status",),
            f"Use one of: {', '.join(sorted(STATUSES))}." + (f" Did you mean `status: {near[0]}`?" if near else ""),
            {"replace_path": "status", "snippet": f"status: {near[0] if near else 'test'}"}, True)

    if "level" not in doc:
        add("warning", "missing-field", "missing recommended field: level", ("level",),
            "Add the severity: `level: medium` (informational, low, medium, high or critical).", {"replace_path": "level", "snippet": "level: medium"})
    elif doc["level"] not in LEVELS:
        near = _near(doc["level"], LEVELS, n=1)
        add("error", "invalid-level", f"invalid level: {doc['level']!r} (use {', '.join(sorted(LEVELS))})", ("level",),
            f"Use one of: {', '.join(sorted(LEVELS))}." + (f" Did you mean `level: {near[0]}`?" if near else ""),
            {"replace_path": "level", "snippet": f"level: {near[0] if near else 'medium'}"}, True)

    logsource = doc.get("logsource")
    if not isinstance(logsource, dict) or not any(k in logsource for k in ("category", "product", "service")):
        add("error", "bad-logsource", "logsource needs at least category, product or service", ("logsource",),
            "Say where the events come from, e.g.\n`logsource:\n  category: process_creation\n  product: windows`.",
            {"replace_path": "logsource", "snippet": "logsource:\n  category: process_creation\n  product: windows"})

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        add("error", "missing-field", "missing required field: detection", ("detection",),
            "Add the matching logic, e.g.\n`detection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n  condition: selection`.",
            {"replace_path": "detection", "snippet": "detection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n  condition: selection"})
    elif "condition" not in detection:
        first = next((k for k in detection if k != "timeframe"), "selection")
        add("error", "missing-condition", "detection has no condition", ("detection",),
            f"Add `condition: {first}` under `detection` (combine selections with and / or / not, e.g. `selection and not filter`).",
            {"replace_path": "detection.condition", "snippet": f"condition: {first}"})
    else:
        selections = {k for k in detection if k not in ("condition", "timeframe")}
        if not selections:
            add("error", "no-selection", "detection defines no selection", ("detection",),
                "Add at least one named selection next to `condition`, e.g.\n`selection:\n    Image|endswith: '\\\\cmd.exe'`.")
        cond = detection["condition"]
        used_names: set[str] = set()
        used_patterns: set[str] = set()
        for c in cond if isinstance(cond, list) else [cond]:
            names, patterns = condition_refs(str(c))
            used_names |= names
            used_patterns |= patterns
        for name in sorted(used_names - selections):
            near = _near(name, selections, n=1)
            add("error", "unknown-selection", f"the condition references '{name}', which does not exist in detection", ("detection", "condition"),
                (f"Did you mean `{near[0]}`? " if near else "") + f"Selections defined: {', '.join(sorted(selections)) or 'none'}. "
                f"Either rename it in the condition or add a `{name}:` block under `detection`.", None, True)
        for pattern in sorted(used_patterns):
            if pattern.lower() != "them" and not any(fnmatch.fnmatchcase(s, pattern) for s in selections):
                add("error", "pattern-no-match", f"the condition pattern '{pattern}' matches no selection", ("detection", "condition"),
                    f"No selection name matches `{pattern}`. Defined: {', '.join(sorted(selections))}. Rename a selection to fit the pattern or fix the pattern.", None, True)
        covered = set(used_names)
        for pattern in used_patterns:
            covered |= selections if pattern.lower() == "them" else {s for s in selections if fnmatch.fnmatchcase(s, pattern)}
        for name in sorted(selections - covered):
            add("warning", "unused-selection", f"selection '{name}' is not used in the condition", ("detection", name),
                f"Use it (e.g. `condition: selection and not {name}` for an exclusion) or delete the `{name}:` block.")
        _detection_checks(detection, add)

    for key in doc:
        if key not in SIGMA_FIELDS:
            near = _near(str(key), SIGMA_FIELDS, n=1, cutoff=0.8)
            if near:
                add("warning", "unknown-field", f"field '{key}' is not a Sigma field; did you mean '{near[0]}'?", (str(key),),
                    f"Rename `{key}` to `{near[0]}`; Sigma ignores unknown keys, so a typo silently drops the data.",
                    {"replace_path": str(key), "snippet": near[0]})
    for key, example in (("tags", "tags:\n  - attack.execution\n  - attack.t1059.001"), ("falsepositives", "falsepositives:\n  - Administrator scripts"),
                         ("references", "references:\n  - https://attack.mitre.org/techniques/T1059/")):
        if key in doc and not (isinstance(doc[key], list) and all(isinstance(v, str) for v in doc[key])):
            add("error", "bad-list-field", f"'{key}' must be a list of strings", (key,),
                f"Write it as a list of plain strings, e.g.\n`{example}`.", {"replace_path": key, "snippet": example}, True)
    for key in ("date", "modified"):
        if key in doc and not DATE.match(str(doc[key])):
            add("warning", "bad-date", f"'{key}' is not in YYYY-MM-DD format: {doc[key]!r}", (key,),
                f"Use an ISO date, e.g. `{key}: 2026-11-03`.", {"replace_path": key, "snippet": f"{key}: 2026-11-03"}, True)

    for message in routing.problems(doc):
        add("error", "bad-vitrix-block", message, _vitrix_path(message), _vitrix_hint(message), None, True)
    for severity, message in governance.problems(doc):
        add(severity, _gov_code(message), message, _vitrix_path(message), _vitrix_hint(message), None, True)
    if known_targets is not None:
        for name in routing.declared(doc) or []:
            if name not in known_targets:
                near = _near(name, known_targets, n=1)
                add("error", "unknown-target", f"vitrix.target: unknown target '{name}' (available: {', '.join(sorted(known_targets))})", ("vitrix", "target"),
                    (f"Did you mean `{near[0]}`? " if near else "") + f"Available targets: {', '.join(sorted(known_targets))}.", None, True)

    if not doc.get("description"):
        add("warning", "missing-field", "missing recommended field: description", ("description",),
            "Say what the rule detects and why it matters, e.g. `description: Detects PowerShell started with an encoded command.`",
            {"replace_path": "description", "snippet": "description: Detects ..."})
    if not doc.get("falsepositives"):
        add("warning", "missing-field", "missing recommended field: falsepositives", ("falsepositives",),
            "List legitimate activity that may trigger it, e.g.\n`falsepositives:\n  - Administrator scripts`.",
            {"replace_path": "falsepositives", "snippet": "falsepositives:\n  - Administrator scripts"})
    tags = [t for t in (doc.get("tags") or []) if isinstance(t, str)] if isinstance(doc.get("tags"), list) else []
    if not any(t.startswith("attack.t") for t in tags):
        add("warning", "no-technique-tag", "no MITRE technique tag (e.g. attack.t1059.001)", ("tags",),
            "Add the ATT&CK technique and tactic under `tags`, e.g.\n`tags:\n  - attack.execution\n  - attack.t1059.001`.",
            {"replace_path": "tags", "snippet": "tags:\n  - attack.execution\n  - attack.t1059.001"})
    else:
        for tag in tags:
            if not tag.startswith("attack."):
                continue
            m = ATTACK_TAG.match(tag)
            if not m:
                add("warning", "bad-attack-tag", f"MITRE tag does not follow the pattern: {tag}", ("tags", doc["tags"].index(tag)),
                    "Tags look like `attack.t1059.001` (technique), `attack.execution` (tactic, lower case, underscores) or `attack.g0016` (group). "
                    "No spaces or upper case.")
            elif re.fullmatch(r"t\d{4}(\.\d{3})?", m.group(1)) and not attack.is_known_technique(m.group(1)):
                near = _near(m.group(1).upper(), attack.technique_ids(), n=3)
                add("warning", "unknown-technique", f"unknown ATT&CK technique: {tag} (not in ATT&CK Enterprise v{attack.catalog()['version']})", ("tags", doc["tags"].index(tag)),
                    "Check the id on attack.mitre.org." + (f" Closest known ids: {', '.join('attack.' + n.lower() for n in near)}." if near else ""),
                    {"replace_path": "tags", "snippet": f"attack.{near[0].lower()}"} if near else None)
            elif re.fullmatch(r"[a-z_]+", m.group(1)) and m.group(1) not in ATTACK_TACTICS:
                near = _near(m.group(1), ATTACK_TACTICS, n=1)
                add("warning", "unknown-tactic", f"unknown ATT&CK tactic: {tag}" + (f" (did you mean attack.{near[0]}?)" if near else ""), ("tags", doc["tags"].index(tag)),
                    (f"Use `attack.{near[0]}`. " if near else "") + f"Tactics: {', '.join(sorted(ATTACK_TACTICS))}.",
                    {"replace_path": "tags", "snippet": f"attack.{near[0]}"} if near else None)
        if not any(t[len("attack."):] in ATTACK_TACTICS for t in tags if t.startswith("attack.")):
            add("warning", "no-tactic-tag", "MITRE technique without its tactic (e.g. attack.execution)", ("tags",),
                f"Add the tactic next to the technique, e.g. `- attack.execution`. Tactics: {', '.join(sorted(ATTACK_TACTICS))}.")

    try:
        check_supported(doc)
    except UnsupportedError as exc:
        add("warning", "evaluator-unsupported", f"the local evaluator does not cover this rule ({exc}); `vitrix test` cannot test it", ("detection",),
            "This does not block the rule: it only means `vitrix test` and replay cannot run it locally. Use supported modifiers/conditions "
            "if you want local tests, otherwise test it in your SIEM.")

    return issues


def lint_files(files: list[RuleFile], known_targets: set[str] | None = None) -> list[Issue]:
    issues: list[Issue] = []
    seen: dict[str, tuple[str, int | None]] = {}
    logic: dict[str, str] = {}
    for rf in files:
        if not rf.docs:
            issues.append(Issue("error", rf.rel, "empty file", "empty-file", None, 1, 1,
                                "The file has no YAML document. Add a Sigma rule (title, logsource, detection...) or delete the file."))
            continue
        locators = Locator.for_text(rf.text)
        for idx, doc in enumerate(rf.docs):
            loc = locators[idx] if len(locators) == len(rf.docs) else None
            issues.extend(lint_doc(doc, rf.rel, known_targets, loc))
            if isinstance(doc, dict) and "id" in doc and _is_uuid(doc["id"]):
                rid = str(doc["id"]).lower()
                if rid in seen and seen[rid][0] != rf.rel:
                    line, col = loc.find(("id",), True) if loc else (None, None)
                    other, other_line = seen[rid]
                    issues.append(Issue("error", rf.rel, f"duplicate id (already used in {other})", "duplicate-id", "id", line, col,
                                        f"Two rules cannot share an id. Generate a new UUID (e.g. `id: {uuid.uuid4()}`) for this one; "
                                        f"the other rule is {other}" + (f" (line {other_line})." if other_line else "."),
                                        {"replace_path": "id", "snippet": f"id: {uuid.uuid4()}"}))
                seen.setdefault(rid, (rf.rel, loc.find(("id",))[0] if loc else None))
            fp = detection_fingerprint(doc) if isinstance(doc, dict) else None
            if fp:
                if fp in logic and logic[fp] != rf.rel:
                    line, col = loc.find(("detection",)) if loc else (None, None)
                    issues.append(Issue("warning", rf.rel, f"detection logic identical to {logic[fp]} (redundant rule)", "duplicate-logic", "detection", line, col,
                                        f"This rule matches exactly what {logic[fp]} matches. Delete one of them, or merge them and keep a single id."))
                logic.setdefault(fp, rf.rel)
    return issues
