"""Detection catalog, dependency graph and governance across the repository.

- `catalog(cfg)`: every rule with its metadata and what it depends on (logsource, fields,
  pipelines, final targets, datasets), plus the reverse graph: which rules depend on a given
  logsource, field or target. Answers "if the CommandLine field mapping changes, what breaks?".
- `governance_report(cfg)`: owners, review deadlines (Detection SLA) and every suppression
  (exclusion) with its reason, owner and expiry.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date

from . import routing
from .config import Config
from .governance import rule_governance
from .lint import _walk_fields
from .replay import ReplayError, dataset_files, dataset_name, load_expectations
from .service import _first_detection, _load_all, rule_id, summarize


def _fields(docs: list) -> list[str]:
    found: set[str] = set()
    for doc in docs:
        detection = doc.get("detection") if isinstance(doc, dict) else None
        if not isinstance(detection, dict):
            continue
        for spec, _ in _walk_fields(detection):
            found.add(spec.split("|")[0])
        for key, sel in detection.items():
            if key not in ("condition", "timeframe") and isinstance(sel, list) and sel and not any(isinstance(x, dict) for x in sel):
                found.add("(keywords)")
    return sorted(found)


def _logsource(doc: object) -> dict:
    ls = doc.get("logsource") if isinstance(doc, dict) else None
    ls = ls if isinstance(ls, dict) else {}
    parts = {k: str(ls[k]) for k in ("product", "category", "service") if ls.get(k)}
    return {**parts, "key": "/".join(parts[k] for k in ("product", "category", "service") if k in parts) or "(none)"}


def _dataset_refs(cfg: Config) -> dict[str, list[str]]:
    refs: dict[str, list[str]] = defaultdict(list)
    for path in dataset_files(cfg):
        try:
            rules, _ = load_expectations(path)
        except ReplayError:
            continue
        for rid in rules:
            refs[rid].append(dataset_name(cfg, path))
    return refs


def catalog(cfg: Config) -> dict:
    files, broken = _load_all(cfg) if cfg.rules_dir.is_dir() else ([], {})
    datasets = _dataset_refs(cfg)
    pipelines = [p.name for p in cfg.extra_pipelines]
    rules = []
    for rf in files:
        rid = rule_id(cfg, rf.path)
        doc = _first_detection(rf.docs)
        s = summarize(doc)
        chosen = routing.resolve(cfg, routing.rules_rel(cfg, rf.path), doc)
        gov = rule_governance(doc)
        rules.append({
            "id": rid, "title": s["title"] or rid, "sigma_id": s["sigma_id"], "level": s["level"], "status": s["status"],
            "description": s["description"], "author": doc.get("author") if isinstance(doc, dict) else None,
            "owner": gov["owner"], "tactics": s["tactics"], "techniques": s["techniques"],
            "logsource": _logsource(doc), "fields": _fields(rf.docs),
            "targets": chosen.targets, "target_source": chosen.source, "pipelines": pipelines,
            "datasets": sorted(datasets.get(rid, [])),
            "exclusions": [x["selection"] for x in gov["suppressions"] if x["state"] != "orphan"],
        })
    rules.sort(key=lambda r: r["id"])

    def index(key) -> dict[str, list[str]]:
        out: dict[str, list[str]] = defaultdict(list)
        for r in rules:
            for value in key(r):
                out[value].append(r["id"])
        return out

    by_logsource = index(lambda r: [r["logsource"]["key"]])
    by_field = index(lambda r: r["fields"])
    by_target = index(lambda r: r["targets"])
    field_sources: dict[str, set[str]] = defaultdict(set)
    for r in rules:
        for f in r["fields"]:
            field_sources[f].add(r["logsource"]["key"])
    return {
        "rules": rules,
        "broken": sorted(broken),
        "graph": {
            "logsources": sorted(({"key": k, "rules": v} for k, v in by_logsource.items()), key=lambda x: (-len(x["rules"]), x["key"])),
            "fields": sorted(({"name": k, "rules": v, "logsources": sorted(field_sources[k])} for k, v in by_field.items()),
                             key=lambda x: (-len(x["rules"]), x["name"])),
            "targets": sorted(({"name": k, "rules": v} for k, v in by_target.items()), key=lambda x: x["name"]),
            "pipelines": pipelines,
        },
    }


def governance_report(cfg: Config, today: date | None = None) -> dict:
    files, _ = _load_all(cfg) if cfg.rules_dir.is_dir() else ([], {})
    today = today or date.today()
    rules, suppressions = [], []
    owners: dict[str, dict] = {}
    for rf in files:
        rid = rule_id(cfg, rf.path)
        doc = _first_detection(rf.docs)
        s = summarize(doc)
        gov = rule_governance(doc, today)
        rules.append({"id": rid, "title": s["title"] or rid, "level": s["level"], "status": s["status"], **gov})
        if gov["owner"]:
            o = owners.setdefault(gov["owner"], {"owner": gov["owner"], "rules": 0, "overdue": 0, "expired": 0})
            o["rules"] += 1
            o["overdue"] += gov["review_state"] == "overdue"
            o["expired"] += any(x["state"] == "expired" for x in gov["suppressions"])
        for x in gov["suppressions"]:
            suppressions.append({"rule": rid, "title": s["title"] or rid, **x})
    order = {"expired": 0, "undocumented": 1, "expiring": 2, "orphan": 3, "active": 4}
    suppressions.sort(key=lambda x: (order.get(x["state"], 9), x["expires"] or "9999", x["rule"]))
    review_order = {"overdue": 0, "due_soon": 1, "ok": 2, None: 3}
    rules.sort(key=lambda r: (review_order[r["review_state"]], r["review_by"] or "9999", r["id"]))

    def count(items, key) -> dict[str, int]:
        out: dict[str, int] = defaultdict(int)
        for it in items:
            out[str(it[key]) if it[key] else "none"] += 1
        return dict(out)

    return {
        "today": today.isoformat(),
        "summary": {
            "rules": len(rules),
            "owned": sum(1 for r in rules if r["owner"]),
            "unowned": sum(1 for r in rules if not r["owner"]),
            "reviews": {k: v for k, v in count(rules, "review_state").items()},
            "suppressions": count(suppressions, "state"),
        },
        "owners": sorted(owners.values(), key=lambda o: (-o["rules"], o["owner"])),
        "rules": rules,
        "suppressions": suppressions,
    }
