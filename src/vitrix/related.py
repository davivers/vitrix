"""Rules related to a rule: same log source, shared detection fields or ATT&CK techniques.

Built from the rule index (`catalog.catalog`), read-only. Answers "what else should I look at
when I change this rule?" in the Editor.
"""

from __future__ import annotations

import yaml

from .catalog import _fields, _logsource, catalog
from .config import Config
from .service import _first_detection, summarize

DEFAULT_LIMIT = 8


def _entry_from_text(text: str) -> dict | None:
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError:
        return None
    doc = _first_detection(docs)
    if not isinstance(doc, dict):
        return None
    s = summarize(doc)
    return {"id": None, "sigma_id": s["sigma_id"], "logsource": _logsource(doc), "fields": _fields(docs), "techniques": s["techniques"]}


def related_rules(cfg: Config, rid: str | None = None, text: str | None = None, limit: int = DEFAULT_LIMIT) -> list[dict]:
    """Up to `limit` rules, most related first. `rid`: a saved rule (404 is the caller's job: [] when unknown);
    `text`: an unsaved rule. Each item says why: `same_logsource`, `shared_fields`, `shared_techniques`, `why`."""
    rules = catalog(cfg)["rules"]
    me = next((r for r in rules if r["id"] == rid), None) if rid else None
    if me is None and text is not None:
        me = _entry_from_text(text)
    if me is None:
        return []
    my_fields = {f for f in me["fields"] if f != "(keywords)"}
    my_key = me["logsource"]["key"]
    my_tech = set(me["techniques"])
    out = []
    for r in rules:
        if r["id"] == rid or (me.get("sigma_id") and r["sigma_id"] == me["sigma_id"] and rid is None):
            continue
        same = my_key != "(none)" and r["logsource"]["key"] == my_key
        shared = sorted(my_fields & set(r["fields"]))
        techs = sorted(my_tech & set(r["techniques"]))
        score = (3 if same else 0) + len(shared) + 2 * len(techs)
        if score == 0:
            continue
        why = []
        if same:
            why.append(f"same log source ({my_key})")
        if shared:
            why.append("shares " + ", ".join(shared[:4]) + ("…" if len(shared) > 4 else ""))
        if techs:
            why.append("same technique " + ", ".join(techs[:3]))
        out.append((score, {"id": r["id"], "title": r["title"], "file": cfg.rel(cfg.rules_dir / r["id"]), "logsource": r["logsource"]["key"],
                            "shared_fields": shared, "shared_techniques": techs, "same_logsource": same, "level": r["level"],
                            "score": score, "why": "; ".join(why)}))
    out.sort(key=lambda x: (-x[0], x[1]["id"]))
    return [o for _, o in out[:max(1, min(limit, 50))]]
