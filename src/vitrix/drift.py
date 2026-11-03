"""Detection drift: does a rule still detect the same things it detected before?

Replays the repository datasets twice, once with the rules as they are now (working tree) and
once with the rules at a Git ref (the base branch by default), and compares the matches rule by
rule. The datasets are the current ones in both runs, so only rule changes cause drift:

    more     the rule now fires on more events (new coverage, or a broken exclusion)
    fewer    the rule fires on fewer events (tightened, or a regression)
    added    the rule does not exist at the ref
    removed  the rule exists at the ref but not now
    same     identical matches (`modified` says whether the text changed anyway)

Read-only: uses `git ls-tree` and `git cat-file`, never checks anything out.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .config import Config
from .history import HistoryError, _git, _read_blobs
from .loader import RULE_SUFFIXES, RuleFile
from .replay import ReplayError, dataset_files, dataset_name, load_events, replay
from .service import _load_all, rule_id

_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/~^@{}-]{0,199}$")


class DriftError(Exception):
    pass


def default_ref(cfg: Config) -> str:
    """origin/<base> when it exists, else <base>, else HEAD."""
    base = cfg.github.base if cfg.github else "main"
    for ref in (f"origin/{base}", base):
        try:
            _git(cfg, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
            return ref
        except (HistoryError, OSError):
            continue
    return "HEAD"


def rules_at(cfg: Config, ref: str) -> list[RuleFile]:
    """The rule files as they were at `ref` (without touching the working tree)."""
    if not _REF.match(ref) or ".." in ref:
        raise DriftError(f"invalid Git ref: {ref!r}")
    rules_rel = cfg.rel(cfg.rules_dir)
    try:
        _git(cfg, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
        names = _git(cfg, "ls-tree", "-r", "--name-only", ref, "--", rules_rel).decode("utf-8", "replace").splitlines()
        names = [n for n in names if Path(n).suffix in RULE_SUFFIXES]
        blobs = _read_blobs(cfg, [f"{ref}:./{n}" for n in names])
    except (HistoryError, OSError) as exc:
        raise DriftError(f"cannot read the rules at {ref}: {exc}") from exc
    out = []
    for name, blob in zip(names, blobs, strict=True):
        if blob is None:
            continue
        text = blob.decode("utf-8", "replace")
        try:
            docs = [d for d in yaml.safe_load_all(text) if d is not None]
        except yaml.YAMLError:
            continue
        out.append(RuleFile(cfg.root / name, name, text, docs))
    return out


def _state(before: int | None, after: int | None) -> str:
    if before is None:
        return "added"
    if after is None:
        return "removed"
    return "more" if after > before else "fewer" if after < before else "same"


def drift(cfg: Config, ref: str | None = None) -> dict:
    ref = ref or default_ref(cfg)
    old = rules_at(cfg, ref)
    try:
        sha = _git(cfg, "rev-parse", "--short", f"{ref}^{{commit}}").decode().strip()
    except (HistoryError, OSError):
        sha = ""
    new, _ = _load_all(cfg) if cfg.rules_dir.is_dir() else ([], {})
    old_ids = [(rule_id(cfg, rf.path), rf) for rf in old]
    new_ids = [(rule_id(cfg, rf.path), rf) for rf in new]
    old_text = {rid: rf.text for rid, rf in old_ids}
    new_text = {rid: rf.text for rid, rf in new_ids}

    datasets, totals = [], {}
    for path in dataset_files(cfg):
        name = dataset_name(cfg, path)
        try:
            events = load_events(path.read_text(encoding="utf-8"), path.name)
        except ReplayError as exc:
            datasets.append({"dataset": name, "error": str(exc), "events": 0, "rules": []})
            continue
        before = {r["rule"]: r for r in replay(old_ids, events)["rules"]}
        after = {r["rule"]: r for r in replay(new_ids, events)["rules"]}
        rows = []
        for rid in sorted(set(before) | set(after)):
            b, a = before.get(rid), after.get(rid)
            bm = b["matches"] if b and not b["error"] else (None if b is None else 0)
            am = a["matches"] if a and not a["error"] else (None if a is None else 0)
            rows.append({"rule": rid, "title": (a or b)["title"], "before": bm, "after": am,
                         "delta": (am or 0) - (bm or 0), "state": _state(bm, am), "error": (a or {}).get("error")})
            t = totals.setdefault(rid, {"rule": rid, "title": (a or b)["title"], "before": None, "after": None, "datasets_changed": 0})
            if bm is not None:
                t["before"] = (t["before"] or 0) + bm
            if am is not None:
                t["after"] = (t["after"] or 0) + am
            t["datasets_changed"] += rows[-1]["state"] != "same"
        rows.sort(key=lambda r: (r["state"] == "same", -abs(r["delta"]), r["rule"]))
        datasets.append({"dataset": name, "events": len(events), "rules": rows})

    for rid in set(old_text) | set(new_text):  # rules no dataset touched still count as added/removed
        totals.setdefault(rid, {"rule": rid, "title": rid, "before": 0 if rid in old_text else None,
                                "after": 0 if rid in new_text else None, "datasets_changed": 0})
    rules = []
    for t in totals.values():
        state = _state(t["before"], t["after"])
        rules.append({**t, "delta": (t["after"] or 0) - (t["before"] or 0), "state": state,
                      "modified": old_text.get(t["rule"]) != new_text.get(t["rule"])})
    rules.sort(key=lambda r: (r["state"] == "same", not r["modified"], -abs(r["delta"]), r["rule"]))
    counts = {s: sum(r["state"] == s for r in rules) for s in ("more", "fewer", "added", "removed", "same")}
    return {
        "ref": ref, "sha": sha, "datasets": datasets, "rules": rules,
        "summary": {**counts, "modified": sum(r["modified"] for r in rules), "drifted": counts["more"] + counts["fewer"]},
    }
