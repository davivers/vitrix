"""Service layer: what the API (and any UI) consumes.

Everything here returns plain dicts, ready to become JSON. The CLI and the API share the same
engine functions, so the numbers on screen are the same as `vitrix check`.
"""

from __future__ import annotations

import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import routing
from .backends import ConversionError, available_targets, convert_text, load_extra_pipelines
from .cases import CaseResult, cases_path, parse_cases, run_cases, run_rule_cases
from .config import Config, ConfigError, parse_config_text
from .github import GitHubClient, GitHubConfig, GitHubError, branch_slug
from .lint import Issue, Locator, lint_doc, lint_files
from .loader import RULE_SUFFIXES, RuleFile, RuleLoadError, find_rule_files, load_rule

# MITRE ATT&CK tactics with the slug used in Sigma tags (attack.<slug>).
TACTICS = [
    ("initial_access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege_escalation", "Privilege Escalation"),
    ("defense_evasion", "Defense Evasion"),
    ("credential_access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral_movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command_and_control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
    ("reconnaissance", "Reconnaissance"),
    ("resource_development", "Resource Development"),
]
_TACTIC_SLUGS = {slug for slug, _ in TACTICS}
TACTIC_IDS = {
    "reconnaissance": "TA0043", "resource_development": "TA0042", "initial_access": "TA0001", "execution": "TA0002",
    "persistence": "TA0003", "privilege_escalation": "TA0004", "defense_evasion": "TA0005", "credential_access": "TA0006",
    "discovery": "TA0007", "lateral_movement": "TA0008", "collection": "TA0009", "command_and_control": "TA0011",
    "exfiltration": "TA0010", "impact": "TA0040",
}
_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


class ServiceError(Exception):
    """Configuration failure the UI must show (e.g. an invalid extra pipeline)."""


# --------------------------------------------------------------------------- helpers


def _issue(i: Issue) -> dict:
    return i.to_dict()


def yaml_error_issue(exc: yaml.YAMLError, rel: str = "<editor>") -> Issue:
    """The Issue for a YAML syntax error, located at the parser's mark."""
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or str(exc)
    return Issue("error", rel, f"invalid YAML: {exc}", "invalid-yaml", None, mark.line + 1 if mark else None, mark.column + 1 if mark else None,
                 f"The YAML cannot be parsed ({problem}). Check indentation (spaces, no tabs), a `:` after each key, and quote values that "
                 "contain `: `, `#` or start with `*`, `&`, `%` or `@` (single quotes keep backslashes literal, e.g. `'C:\\Windows'`).")


def _case(r: CaseResult) -> dict:
    return {"name": r.name, "expect": r.expect, "got": r.got, "passed": r.passed, "error": r.error,
            "kind": r.kind, "exercises_filter": r.exercises_filter, "event": r.event, "hint": r.hint}


def _state(issues: list[Issue], results: list[CaseResult], conversion_failed: bool = False) -> str:
    if conversion_failed or any(i.severity == "error" for i in issues) or any(not r.passed for r in results):
        return "fail"
    if any(i.severity == "warning" for i in issues):
        return "warn"
    return "ok"


def _extra_pipelines(cfg: Config) -> list:
    try:
        return load_extra_pipelines(cfg.extra_pipelines)
    except Exception as exc:
        raise ServiceError(f"could not load extra_pipelines: {exc}") from exc


def summarize(doc: object) -> dict:
    if not isinstance(doc, dict):
        return {"sigma_id": "", "title": "", "status": None, "level": None, "description": "", "tags": [], "tactics": [], "techniques": []}
    tags = [t for t in (doc.get("tags") or []) if isinstance(t, str)]
    tactics = sorted({t[len("attack."):] for t in tags if t.startswith("attack.") and t[len("attack."):] in _TACTIC_SLUGS})
    techniques = sorted({m.group(1).upper() for t in tags if (m := _TECHNIQUE.match(t))})
    return {
        "sigma_id": str(doc.get("id", "")),  # the rule UUID; "id" in responses is the path used in URLs
        "title": str(doc.get("title", "")),
        "status": doc.get("status"),
        "level": doc.get("level"),
        "description": str(doc.get("description", "")),
        "tags": tags,
        "tactics": tactics,
        "techniques": techniques,
    }


def _first_detection(docs: list) -> object:
    return next((d for d in docs if isinstance(d, dict) and "detection" in d), docs[0] if docs else None)


def rule_id(cfg: Config, path: Path) -> str:
    """Stable id used in URLs: path relative to the rules folder."""
    try:
        return path.resolve().relative_to(cfg.rules_dir.resolve()).as_posix()
    except ValueError:
        return path.name


def resolve_rule(cfg: Config, rid: str) -> Path | None:
    """Resolve an id to a file. Only rule files inside the rules folder are accepted."""
    base = cfg.rules_dir.resolve()
    candidate = (base / rid).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        return None
    if candidate.suffix not in RULE_SUFFIXES or not candidate.is_file():
        return None
    return candidate


def mark_conversions(conversions: dict, final: list[str]) -> list[dict]:
    """Tag every conversion `final` or preview. A failure in a preview language is `severity: "info"` (shown with its
    inline fix, never part of the gate or the score); in the final language it stays `"error"`.
    Returns the preview failures as issue-shaped dicts."""
    infos: list[dict] = []
    for name, c in conversions.items():
        c["final"] = name in final
        if c["ok"]:
            continue
        c["severity"] = "error" if c["final"] else "info"
        if not c["final"]:
            infos.append({"severity": "info", "target": name, "label": c.get("label"), "message": c.get("error", ""), "code": c.get("code") or "conversion-failed",
                          "path": c.get("path"), "line": c.get("line"), "hint": c.get("hint"), "fix": c.get("fix")})
    return infos


def final_language_view(chosen: routing.Resolved) -> dict:
    """The resolved final language(s) and why: source rule | folder | workspace | legacy-config | all."""
    return {"targets": chosen.targets, "source": chosen.source, "folder": chosen.folder}


def issue_counts(lint: list, conversions: dict) -> dict:
    """What the issue summary shows: errors = lint errors + conversion failures in the FINAL language;
    warnings = lint warnings; info = preview-language conversion failures (never errors or warnings)."""
    def sev(i: object) -> str:
        return i["severity"] if isinstance(i, dict) else i.severity

    return {"errors": sum(sev(i) == "error" for i in lint) + sum(1 for c in conversions.values() if not c["ok"] and c.get("final")),
            "warnings": sum(sev(i) == "warning" for i in lint),
            "info": sum(1 for c in conversions.values() if not c["ok"] and not c.get("final"))}


def convert_all(text: str, target_names: list[str], extra: list, kql: object = None) -> dict:
    registry = available_targets()
    out: dict[str, dict] = {}
    for name in target_names:
        target = registry.get(name)
        if target is None:
            out[name] = {"ok": False, "label": name, "error": "unknown target"}
            continue
        try:
            out[name] = {"ok": True, "label": target.label, "extension": target.extension,
                         "query": convert_text(text, target, extra, kql)}
        except ConversionError as exc:  # actionable: what is missing, where, and the YAML to add
            out[name] = {"ok": False, "label": target.label, "error": str(exc), **exc.details()}
        except Exception as exc:  # pySigma and third-party plugin errors
            message = " ".join(str(exc).split()) or type(exc).__name__
            out[name] = {"ok": False, "label": target.label, "error": f"{type(exc).__name__}: {message}"}
    return out


def _load_all(cfg: Config) -> tuple[list[RuleFile], dict[str, str]]:
    files: list[RuleFile] = []
    broken: dict[str, str] = {}
    for path in find_rule_files([], cfg):
        try:
            files.append(load_rule(path, cfg))
        except RuleLoadError as exc:
            broken[cfg.rel(path)] = str(exc)
    return files, broken


def _top_issues(issues: list[Issue], problems: list[Issue], results: list[CaseResult], conv: dict, limit: int = 3) -> list[dict]:
    """The problems that explain the rule state, errors first (for the to-do list)."""
    found: list[dict] = []
    for c in conv.values():
        if not c["ok"]:
            found.append({"severity": "error", "message": f"conversion failed ({c['label']}): {c.get('error', '')}",
                          "code": c.get("code") or "conversion-failed", "hint": c.get("hint"), "fix": c.get("fix")})
    for r in results:
        if not r.passed:
            detail = r.error or f"expected {r.expect}, got {r.got}"
            found.append({"severity": "error", "message": f"case “{r.name}”: {detail}", "code": "case-failed", "hint": r.hint})
    found.extend(_issue(i) for i in [*issues, *problems])
    found.sort(key=lambda i: i["severity"] != "error")
    return found[:limit]


# --------------------------------------------------------------------------- queries


def list_rules(cfg: Config) -> list[dict]:
    if not cfg.rules_dir.is_dir():
        return []
    files, broken = _load_all(cfg)
    extra = _extra_pipelines(cfg)
    known = set(available_targets())
    issues_by_rule: dict[str, list[Issue]] = {}
    for issue in lint_files(files, known):
        issues_by_rule.setdefault(issue.rule, []).append(issue)

    out: list[dict] = []
    for rf in files:
        issues = issues_by_rule.get(rf.rel, [])
        results, problems = run_rule_cases(cfg, rf)
        doc = routing.first_detection(rf.docs)
        chosen = routing.resolve(cfg, rule_id(cfg, rf.path), doc)
        conv = convert_all(rf.text, chosen.targets, extra, cfg.kql)
        ls = doc.get("logsource") if isinstance(doc, dict) and isinstance(doc.get("logsource"), dict) else {}
        out.append({
            "issues": _top_issues(issues, problems, results, conv),
            "id": rule_id(cfg, rf.path),
            "file": rf.rel,
            **summarize(_first_detection(rf.docs)),
            "logsource": " / ".join(str(ls[k]) for k in ("product", "category", "service") if ls.get(k)) or None,
            "targets": chosen.targets,  # final query language(s)
            "target_source": chosen.source,  # rule | folder | workspace | legacy-config | all
            "final_language": final_language_view(chosen),
            "conversion": {name: c["ok"] for name, c in conv.items()},
            "state": _state([*issues, *problems], results, any(not c["ok"] for c in conv.values())),
            "lint": {
                "errors": sum(i.severity == "error" for i in issues) + sum(not c["ok"] for c in conv.values()),  # + final-language conversion failures
                "warnings": sum(i.severity == "warning" for i in issues),
            },
            "tests": {"total": len(results), "passed": sum(r.passed for r in results)},
        })
    for rel, message in broken.items():
        out.append({
            "id": rel, "file": rel, "sigma_id": "", "title": rel, "status": None, "level": None, "description": "",
            "tags": [], "tactics": [], "techniques": [], "logsource": None, "targets": [], "target_source": None, "conversion": {},
            "state": "fail", "error": message, "issues": [{"severity": "error", "message": message, "code": "invalid-yaml", "hint": "Fix the YAML syntax of this file (indentation, `:` after keys, quotes)."}],
            "lint": {"errors": 1, "warnings": 0}, "tests": {"total": 0, "passed": 0},
        })
    return sorted(out, key=lambda r: r["id"])


def targets_view(cfg: Config) -> list[dict]:
    """Supported query languages: label, backend, plugin, status and how many rules use each as FINAL language."""
    from .backends import target_info

    used: Counter[str] = Counter()
    if cfg.rules_dir.is_dir():
        files, _ = _load_all(cfg)
        for rf in files:
            for t in routing.resolve(cfg, rule_id(cfg, rf.path), routing.first_detection(rf.docs)).targets:
                used[t] += 1
    return [
        {"name": name, "label": t.label, "extension": t.extension, "active": name in cfg.targets or name == "sigma",
         "default": name == (cfg.final_default or cfg.default_target), "pseudo": name == "sigma",
         **target_info(t), "used_by": used.get(name, 0)}
        for name, t in sorted(available_targets().items(), key=lambda kv: (kv[0] != "sigma", kv[0]))  # "Keep as Sigma" first
    ]


def rule_detail(cfg: Config, rid: str) -> dict:
    """Everything about one rule. Raises KeyError if the id does not exist."""
    path = resolve_rule(cfg, rid)
    if path is None:
        raise KeyError(rid)
    files, _ = _load_all(cfg)
    rf = next((f for f in files if f.path == path), None)
    if rf is None:
        try:
            rf = load_rule(path, cfg)
        except RuleLoadError as exc:
            return {"id": rid, "file": cfg.rel(path), "text": path.read_text(encoding="utf-8"), "summary": summarize(None),
                    "state": "fail", "lint": [{"severity": "error", "message": str(exc), "code": "invalid-yaml", "hint": "Fix the YAML syntax of this file (indentation, `:` after keys, quotes)."}], "conversions": {}, "targets": [], "target_source": None,
                    "tests": {"cases_file": None, "cases_text": None, "results": [], "problems": []}}
        files.append(rf)

    issues = [i for i in lint_files(files, set(available_targets())) if i.rule == rf.rel]
    results, problems = run_rule_cases(cfg, rf)
    cpath = cases_path(cfg, rf)
    chosen = routing.resolve(cfg, rid, routing.first_detection(rf.docs))
    # the final language comes first; the other active targets are previews
    conversions = convert_all(rf.text, list(dict.fromkeys([*chosen.targets, *cfg.targets])), _extra_pipelines(cfg), cfg.kql)
    conv_failed = any(not conversions[t]["ok"] for t in chosen.targets if t in conversions)
    preview_issues = mark_conversions(conversions, chosen.targets)
    return {
        "id": rid,
        "file": rf.rel,
        "text": rf.text,
        "summary": summarize(_first_detection(rf.docs)),
        "state": _state([*issues, *problems], results, conv_failed),
        "targets": chosen.targets,
        "target_source": chosen.source,
        "final_language": final_language_view(chosen),
        "lint": [_issue(i) for i in issues],
        "conversions": conversions,
        "preview_issues": preview_issues,
        "counts": issue_counts([_issue(i) for i in issues], conversions),
        "tests": {
            "cases_file": cfg.rel(cpath) if cpath.is_file() else None,
            "cases_text": cpath.read_text(encoding="utf-8") if cpath.is_file() else None,
            "results": [_case(r) for r in results],
            "problems": [_issue(p) for p in problems],
        },
    }


def validate_text(cfg: Config, text: str, cases_text: str | None = None, targets: list[str] | None = None, rule_rel: str | None = None) -> dict:
    """Validate an unsaved rule: lint, conversion and (optionally) test cases."""
    rel = "<editor>"
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        return {"state": "fail", "lint": [_issue(yaml_error_issue(exc))],
                "conversions": {}, "tests": None, "targets": [], "target_source": None}

    issues: list[Issue] = []
    if not docs:
        issues.append(Issue("error", rel, "empty document", "empty-file", None, 1, 1,
                            "Write a Sigma rule: title, logsource and detection (see the Editor templates)."))
    locators = Locator.for_text(text)
    for idx, doc in enumerate(docs):
        issues.extend(lint_doc(doc, rel, set(available_targets()), locators[idx] if len(locators) == len(docs) else None))

    chosen = routing.resolve(cfg, rule_rel, routing.first_detection(docs)) if docs else routing.Resolved(list(cfg.targets), "all")
    counted = list(targets) if targets else chosen.targets  # only the final language fails the rule
    names = list(dict.fromkeys([*counted, *([] if targets else cfg.targets)]))
    conversions = convert_all(text, names, _extra_pipelines(cfg), cfg.kql) if docs else {}

    tests = None
    results: list[CaseResult] = []
    problems: list[Issue] = []
    if cases_text is not None:
        cases, problems = parse_cases(cases_text, "cases", rel)
        results, problems = run_cases(cfg, rel, docs, cases, problems)
        tests = {"results": [_case(r) for r in results], "problems": [_issue(p) for p in problems]}

    failed_conversion = any(not conversions[t]["ok"] for t in counted if t in conversions)
    preview_issues = mark_conversions(conversions, counted)
    state = _state([*issues, *problems], results)
    if failed_conversion and state != "fail":
        state = "fail"
    return {"state": state, "targets": chosen.targets, "target_source": chosen.source, "final_language": final_language_view(chosen),
            "lint": [_issue(i) for i in issues], "conversions": conversions, "preview_issues": preview_issues,
            "counts": issue_counts([_issue(i) for i in issues], conversions), "tests": tests}


def repo_stats(cfg: Config) -> dict:
    """Numbers for the dashboards, all derived from the repository (no SIEM or CI data)."""
    rules = list_rules(cfg)
    tactic_counts: Counter[str] = Counter()
    techniques: set[str] = set()
    for r in rules:
        tactic_counts.update(r["tactics"])
        techniques.update(r["techniques"])

    tactics = [{"slug": slug, "id": TACTIC_IDS[slug], "name": name, "count": tactic_counts.get(slug, 0)} for slug, name in TACTICS]
    covered = [t for t in tactics if t["count"] > 0]
    parsed = [r for r in rules if "error" not in r]
    return {
        # pipeline stages, in `vitrix check` order
        "pipeline": {
            "parse": {"ok": len(parsed), "failed": len(rules) - len(parsed)},
            "validation": {s: sum(r["state"] == s for r in rules) for s in ("ok", "warn", "fail")},
            "conversion": {"ok": sum(all(r["conversion"].values()) for r in parsed),
                           "failed": sum(not all(r["conversion"].values()) for r in parsed)},
        },
        "rules": {
            "total": len(rules),
            "by_status": dict(Counter(r["status"] or "no status" for r in rules)),
            "by_level": dict(Counter(r["level"] or "no level" for r in rules)),
            "by_state": dict(Counter(r["state"] for r in rules)),
            "by_logsource": dict(Counter(r.get("logsource") or "(no logsource)" for r in rules)),
        },
        "mitre": {
            "tactics": sorted(tactics, key=lambda t: (-t["count"], t["name"])),
            "covered": len(covered),
            "total": len(TACTICS),
            "coverage_pct": round(100 * len(covered) / len(TACTICS)),
            "techniques": len(techniques),
            "uncovered": [t["name"] for t in tactics if t["count"] == 0],
        },
        "lint": {
            "errors": sum(r["lint"]["errors"] for r in rules),
            "warnings": sum(r["lint"]["warnings"] for r in rules),
        },
        "tests": {
            "total": sum(r["tests"]["total"] for r in rules),
            "passed": sum(r["tests"]["passed"] for r in rules),
            "rules_without_cases": sum(r["tests"]["total"] == 0 for r in rules),
            "rules_all_passing": sum(r["tests"]["total"] > 0 and r["tests"]["passed"] == r["tests"]["total"] for r in rules),
        },
        "targets": cfg.targets,
        "by_target": dict(Counter(t for r in rules for t in r["targets"])),
        "conversion_failures": sum(any(not ok for ok in r["conversion"].values()) for r in rules),
    }


# --------------------------------------------------------------------------- changes: CI first, then pull request

_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")


class ChangeError(Exception):
    """Invalid change request (bad path, failing rule). Becomes HTTP 422."""


def normalize_rule_path(path: str) -> str:
    """Validate the rule path inside rules/ (e.g. windows/my_rule.yml)."""
    raw = path.strip().replace("\\", "/")
    parts = [p for p in raw.split("/") if p]
    if not parts or raw.startswith("/") or any(not _SAFE_SEGMENT.match(p) for p in parts):
        raise ChangeError("invalid path: use folders and names with letters, digits, '.', '_' or '-' (e.g. windows/my_rule.yml)")
    if Path(parts[-1]).suffix not in RULE_SUFFIXES:
        raise ChangeError("the rule file must end in .yml or .yaml")
    return "/".join(parts)


def _require_github(cfg: Config) -> GitHubConfig:
    if cfg.github is None:
        raise GitHubError("GitHub is not connected: run `vitrix connect your-org/your-repo` in this folder (or set github.repo in vitrix.yml)", status=503)
    return cfg.github


def _change_body(summary: dict, validation: dict, quality: dict, rule_repo_path: str, cases_repo_path: str | None, is_new: bool) -> str:
    tests = validation.get("tests") or {"results": []}
    passed = sum(r["passed"] for r in tests["results"])
    warnings = [i["message"] for i in validation["lint"] if i["severity"] == "warning"]
    lines = [
        f"{'New rule' if is_new else 'Rule change'} submitted from the Vitrix UI.",
        "",
        f"- **Rule:** {summary['title'] or '(untitled)'} (`{rule_repo_path}`)",
        f"- **level:** `{summary['level'] or '—'}` · **status:** `{summary['status'] or '—'}`",
        f"- **ATT&CK:** {', '.join(summary['techniques']) or '—'}",
        f"- **Final language:** {', '.join(validation['targets']) or '—'}",
        f"- **Local tests:** {passed}/{len(tests['results'])}" + (f" (`{cases_repo_path}`)" if cases_repo_path else " (no cases)"),
        f"- **Local quality gate:** {'ready' if quality['ready'] else 'blocked'} · health {quality['score']}/100",
    ]
    if warnings:
        lines += ["", "**Lint warnings:**", *[f"- {w}" for w in warnings]]
    return "\n".join(lines)


def submit_rule(cfg: Config, path: str, rule_text: str, cases_text: str | None, title: str | None = None,
                client: GitHubClient | None = None, submitted_by: str = "", trailers: list[str] | None = None,
                is_new: bool | None = None, extra_files: dict[str, str] | None = None) -> dict:
    """Step 1: send the rule (and its cases) to a new branch so the real CI validates it.

    Rules blocked by the local quality gate are not sent: CI would fail them the same way.
    Nothing is written to the local disk and no pull request is opened yet.
    """
    from .flow import draft_quality

    gh = _require_github(cfg)
    rel = normalize_rule_path(path)
    cases = cases_text if cases_text and cases_text.strip() else None
    validation = validate_text(cfg, rule_text, cases)
    quality = draft_quality(cfg, validation, rule_text, cases is not None, rel)
    if validation["state"] == "fail" or not quality["ready"]:
        reasons = "; ".join(quality["blockers"][:3]) or "lint, conversion or test errors"
        raise ChangeError(f"the rule is blocked by the local quality gate ({reasons}); fix it before sending it to CI")

    docs = [d for d in yaml.safe_load_all(rule_text) if d is not None]
    summary = summarize(_first_detection(docs))
    rule_file = cfg.rules_dir / rel
    if is_new is None:
        is_new = not rule_file.is_file()
    rule_repo_path = gh.repo_path(cfg.rel(rule_file))
    files = {rule_repo_path: rule_text}
    for extra_rel, extra_text in (extra_files or {}).items():  # e.g. mappings.yml, when it changed locally
        files[gh.repo_path(extra_rel)] = extra_text
    cases_repo_path = None
    if cases:
        cases_repo_path = gh.repo_path(cfg.rel(cfg.cases_dir / rel))
        files[cases_repo_path] = cases

    name = summary["title"] or rel
    pr_title = ((title or "").strip() or f"{'feat' if is_new else 'tune'}: {'new rule' if is_new else 'update'} {name}")[:200]
    body = _change_body(summary, validation, quality, rule_repo_path, cases_repo_path, is_new)
    client = client or GitHubClient(gh)
    message = f"{pr_title}\n\n{body}" + (f"\n\n{submitted_by}" if submitted_by else "") + _trailer_block(trailers)
    pushed = client.push_branch(files, message, branch_slug(rel))
    return {**pushed, "title": pr_title, "files": sorted(files), "is_new": is_new, "mappings_included": bool(extra_files)}


def submit_mappings(cfg: Config, text: str, title: str | None = None, client: GitHubClient | None = None, submitted_by: str = "") -> dict:
    """Publish mappings.yml on its own (CI first, like every change)."""
    from . import mappings

    gh = _require_github(cfg)
    mappings.parse(text)  # an invalid file is never sent
    repo_path = gh.repo_path(mappings.FILE)
    pr_title = ((title or "").strip() or "chore: update query mappings")[:200]
    body = "Query mappings (`mappings.yml`) submitted from the Vitrix Editor."
    client = client or GitHubClient(gh)
    message = f"{pr_title}\n\n{body}" + (f"\n\n{submitted_by}" if submitted_by else "")
    pushed = client.push_branch({repo_path: text}, message, "mappings")
    return {**pushed, "title": pr_title, "files": [repo_path], "is_new": False, "mappings_included": True}


def _trailer_block(trailers: list[str] | None) -> str:
    return "\n\n" + "\n".join(trailers) if trailers else ""


class DraftsBlocked(ChangeError):
    """Some drafts fail the local quality gate; `blocked` = [{"id","path","reasons"}] (HTTP 422, nothing pushed)."""

    def __init__(self, blocked: list[dict]):
        super().__init__(f"{len(blocked)} draft{'s are' if len(blocked) != 1 else ' is'} blocked by the local quality gate")
        self.blocked = blocked


def submit_drafts(cfg: Config, drafts: list[dict], title: str | None = None, client: GitHubClient | None = None,
                  submitted_by: str = "", trailers: list[str] | None = None, extra_files: dict[str, str] | None = None) -> dict:
    """Publish several drafts (dicts with id, path, title, rule, cases) as ONE `vitrix/pack-...` branch.

    Every draft must have a path and pass validation plus the local quality gate, otherwise
    `DraftsBlocked` is raised before anything is pushed. Same two-step CI-first flow as `submit_rule`.
    """
    from .flow import draft_quality

    gh = _require_github(cfg)
    blocked: list[dict] = []
    files: dict[str, str] = {}
    lines: list[str] = []
    seen: set[str] = set()
    for d in drafts:
        reasons: list[str] = []
        rel = d["path"]
        cases = d["cases"] if d["cases"] and d["cases"].strip() else None
        if not rel:
            reasons.append("the draft has no path; open it in the Editor and set one")
        elif rel in seen:
            reasons.append("another draft in this batch has the same path")
        else:
            seen.add(rel)
            validation = validate_text(cfg, d["rule"], cases)
            quality = draft_quality(cfg, validation, d["rule"], cases is not None, rel)
            if validation["state"] == "fail" or not quality["ready"]:
                reasons = quality["blockers"][:5] or ["lint, conversion or test errors"]
        if reasons:
            blocked.append({"id": d["id"], "path": rel, "reasons": reasons})
            continue
        files[gh.repo_path(cfg.rel(cfg.rules_dir / rel))] = d["rule"]
        if cases:
            files[gh.repo_path(cfg.rel(cfg.cases_dir / rel))] = cases
        lines.append(f"- {d['title'] or rel} (`{rel}`)")
    if blocked:
        raise DraftsBlocked(blocked)

    for extra_rel, extra_text in (extra_files or {}).items():
        files[gh.repo_path(extra_rel)] = extra_text
    plural = "s" if len(drafts) != 1 else ""
    pr_title = ((title or "").strip() or f"feat: add {len(drafts)} rule{plural} from drafts")[:200]
    body = f"{len(drafts)} rule{plural} submitted from Vitrix drafts.\n\n" + "\n".join(lines)
    message = f"{pr_title}\n\n{body}" + (f"\n\n{submitted_by}" if submitted_by else "") + _trailer_block(trailers)
    client = client or GitHubClient(gh)
    pushed = client.push_branch(files, message, "pack-" + datetime.now(timezone.utc).strftime("%Y%m%d"))
    return {**pushed, "title": pr_title, "files": sorted(files), "is_new": True, "mappings_included": bool(extra_files)}


def submit_config(cfg: Config, text: str, title: str | None = None, client: GitHubClient | None = None, submitted_by: str = "") -> dict:
    """Step 1 for vitrix.yml: an invalid configuration is never sent."""
    gh = _require_github(cfg)
    check = validate_config_text(cfg, text)
    if not check["ok"]:
        raise ChangeError("invalid configuration: " + "; ".join(check["errors"]))
    repo_path = gh.repo_path(cfg.rel(cfg.path) if cfg.path else "vitrix.yml")
    pr_title = ((title or "").strip() or "chore: update vitrix.yml")[:200]
    body = "\n".join([
        "Change to `vitrix.yml` submitted from the Vitrix Settings page.",
        "",
        f"- **targets:** {', '.join(check['config']['targets'])}",
        f"- **default_target:** {check['config']['default_target'] or '—'}",
        f"- **routes:** {len(check['config']['routes'])}",
        *([""] + ["**Warnings:**"] + [f"- {w}" for w in check["warnings"]] if check["warnings"] else []),
    ])
    client = client or GitHubClient(gh)
    message = f"{pr_title}\n\n{body}" + (f"\n\n{submitted_by}" if submitted_by else "")
    pushed = client.push_branch({repo_path: text}, message, "config")
    return {**pushed, "title": pr_title, "files": [repo_path], "is_new": False}


def ci_status(cfg: Config, commit: str, client: GitHubClient | None = None) -> dict:
    """State of the real CI for one commit pushed by step 1."""
    return (client or GitHubClient(_require_github(cfg))).ci_status(commit)


def open_pull_request(cfg: Config, branch: str, commit: str, title: str | None = None, client: GitHubClient | None = None) -> dict:
    """Step 2: open the pull request, only if the real CI passed for that exact commit."""
    return (client or GitHubClient(_require_github(cfg))).open_validated_pull_request(branch, commit, (title or "").strip()[:200] or None)


def github_status(cfg: Config) -> dict:
    """What the UI needs to show (or hide) the CI and PR buttons. Never exposes the token."""
    from .gitremote import token

    found, token_source = token()
    gh = cfg.github
    return {"configured": gh is not None, "source": cfg.github_source, "repo": gh.repo if gh else None,
            "base": gh.base if gh else None, "workflow": gh.workflow if gh else None,
            "token": found is not None, "token_source": token_source}


# --------------------------------------------------------------------------- GitHub connector (read-only)

ACTIVITY_TTL = 60.0  # seconds; the GitHub API allows 5,000 calls/hour per token
_activity_cache: dict[tuple[str, str], tuple[float, dict]] = {}


def github_activity(cfg: Config, client: GitHubClient | None = None, refresh: bool = False) -> dict:
    """Open PRs, time to merge and CI runs from GitHub. Never raises: without configuration,
    token or on error it returns `available: false` and the reason."""
    if cfg.github is None:
        return {"available": False, "reason": "not_configured", "message": "configure the 'github' section in vitrix.yml"}
    key = (cfg.github.repo, cfg.github.base)
    cached = _activity_cache.get(key)
    if cached and not refresh and time.monotonic() - cached[0] < ACTIVITY_TTL:
        return cached[1]
    try:
        client = client or GitHubClient(cfg.github)
        data = {"available": True, **client.activity(), "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    except GitHubError as exc:
        reason = "no_token" if exc.status == 503 else "error"
        return {"available": False, "reason": reason, "message": str(exc)}
    _activity_cache[key] = (time.monotonic(), data)
    return data


# --------------------------------------------------------------------------- vitrix.yml from the UI


def config_view(cfg: Config) -> dict:
    """Effective configuration and the vitrix.yml text (for the Settings page)."""
    return {
        "path": cfg.rel(cfg.path) if cfg.path else None,
        "text": cfg.path.read_text(encoding="utf-8") if cfg.path else "",
        "targets": cfg.targets,
        "default_target": cfg.default_target,
        "routes": [{"match": m, "target": t} for m, t in cfg.routes],
        "rules_dir": cfg.rel(cfg.rules_dir),
        "cases_dir": cfg.rel(cfg.cases_dir),
        "output_dir": cfg.rel(cfg.output_dir),
        "datasets_dir": cfg.rel(cfg.datasets_dir) if cfg.datasets_dir else None,
        "extra_pipelines": [cfg.rel(p) for p in cfg.extra_pipelines],
        "require_cases": cfg.require_cases,
        "quality_gate": dict(vars(cfg.gate)),
        "github": {"repo": cfg.github.repo, "base": cfg.github.base, "path": cfg.github.path, "workflow": cfg.github.workflow}
        if cfg.github else None,
    }


def validate_config_text(cfg: Config, text: str) -> dict:
    """Validate an edited vitrix.yml as if it replaced the current one. Writes nothing."""
    try:
        new = parse_config_text(text, cfg.root)
    except ConfigError as exc:
        return {"ok": False, "errors": [str(exc)], "warnings": [], "config": None}
    errors: list[str] = []
    warnings: list[str] = []
    known = set(available_targets())
    unknown = sorted(routing.config_target_names(new) - known)
    if unknown:
        errors.append(f"unknown target: {', '.join(unknown)} (available: {', '.join(sorted(known))})")
    if new.default_target and new.default_target not in new.targets:
        warnings.append(f"default_target '{new.default_target}' is not in targets: it only applies to rules without a route")
    for p in new.extra_pipelines:
        if not p.is_file():
            errors.append(f"extra_pipelines: file not found: {new.rel(p)}")
    if not new.rules_dir.is_dir():
        warnings.append(f"rules_dir '{new.rel(new.rules_dir)}' does not exist in this repository")
    if new.github is None:
        warnings.append("no 'github' section: the UI cannot validate in CI, open pull requests or show CI data")
    view = config_view(new)
    view.pop("text")
    view.pop("path")
    return {"ok": not errors, "errors": errors, "warnings": warnings, "config": view}
