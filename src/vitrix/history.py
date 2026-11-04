"""Git repository history: time series and audit trail, without depending on GitHub.

Everything comes from the local `git log` (read-only):

- **coverage over time**: rules, ATT&CK tactics and techniques after every commit that touched
  rules/ (the state is rebuilt file by file with `git cat-file --batch`);
- **activity**: recent commits on rules, cases and datasets;
- **per rule**: creation, last change, authors and number of commits (audit trail, periodic
  review);
- **per author**: commits and rules created/changed.

Without Git, or outside a repository, returns `available: false`; never invents history.
"""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath

import yaml

from .config import Config
from .loader import RULE_SUFFIXES

MAX_COMMITS = 1000
CACHE_TTL = 30.0
_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_SEP = "\x1f"  # field separator in --format (never appears in commit messages)
_cache: dict[str, tuple[float, str, dict]] = {}


class HistoryError(Exception):
    pass


def _git(cfg: Config, *args: str, input: bytes | None = None) -> bytes:
    exe = shutil.which("git")
    if exe is None:
        raise HistoryError("git not found on PATH")
    proc = subprocess.run(  # nosec B603
        [exe, "-C", str(cfg.root), *args], input=input, capture_output=True, timeout=60, check=False,
    )
    if proc.returncode != 0:
        raise HistoryError(proc.stderr.decode("utf-8", "replace").strip()[:300] or f"git {args[0]} falhou")
    return proc.stdout


NO_COMMITS_MESSAGE = "This repository has no commits yet. Commit your rules to see their history."
NOT_A_REPO_MESSAGE = "This folder is not a Git repository, so there is no history to show."
GIT_MISSING_MESSAGE = "Git is not installed or not on PATH, so there is no history to show."


def repo_state(cfg: Config) -> dict | None:
    """None when the project is in a Git repository with at least one commit; otherwise
    `{state: "no_commits" | "not_a_repo" | "git_missing", message}` with a friendly message
    (never the raw git error)."""
    if shutil.which("git") is None:
        return {"state": "git_missing", "message": GIT_MISSING_MESSAGE}
    try:
        _git(cfg, "rev-parse", "--is-inside-work-tree")
    except (HistoryError, OSError, subprocess.TimeoutExpired):
        return {"state": "not_a_repo", "message": NOT_A_REPO_MESSAGE}
    try:
        _git(cfg, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
    except (HistoryError, OSError, subprocess.TimeoutExpired):
        return {"state": "no_commits", "message": NO_COMMITS_MESSAGE}
    return None


def unavailable(state: dict) -> dict:
    return {"available": False, "state": state["state"], "message": state["message"], "reason": state["message"]}


@dataclass
class _RuleState:
    tactics: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)


def _parse_rule(blob: bytes) -> _RuleState:
    try:
        docs = [d for d in yaml.safe_load_all(blob.decode("utf-8", "replace")) if isinstance(d, dict)]
    except yaml.YAMLError:
        return _RuleState()
    tags = [t for d in docs for t in (d.get("tags") or []) if isinstance(t, str)]
    from .lint import ATTACK_TACTICS

    return _RuleState(
        tactics={t[7:] for t in tags if t.startswith("attack.") and t[7:] in ATTACK_TACTICS},
        techniques={m.group(1).upper() for t in tags if (m := _TECHNIQUE.match(t))},
    )


def _read_blobs(cfg: Config, specs: list[str]) -> list[bytes | None]:
    """Content of several `sha:path` specs in a single process (git cat-file --batch)."""
    if not specs:
        return []
    out = _git(cfg, "cat-file", "--batch", input=("\n".join(specs) + "\n").encode())
    blobs: list[bytes | None] = []
    pos = 0
    for _ in specs:
        end = out.index(b"\n", pos)
        header = out[pos:end].decode()
        pos = end + 1
        if header.endswith("missing") or header.endswith("ambiguous"):
            blobs.append(None)
            continue
        size = int(header.split()[2])
        blobs.append(out[pos:pos + size])
        pos += size + 1
    return blobs


def _commits(cfg: Config, rules_rel: str, cases_rel: str, datasets_rel: str) -> list[dict]:
    """Commits (oldest first) that touched rules, cases or datasets, with their files."""
    fmt = _SEP.join(["%H", "%at", "%an", "%s"])
    raw = _git(
        cfg, "log", "--reverse", f"--max-count={MAX_COMMITS}", "--no-renames", "--relative", "--name-status",
        f"--format=@@{fmt}", "--", rules_rel, cases_rel, datasets_rel,
    ).decode("utf-8", "replace")
    commits: list[dict] = []
    for line in raw.splitlines():
        if line.startswith("@@"):
            sha, ts, author, subject = (line[2:].split(_SEP) + ["", "", "", ""])[:4]
            commits.append({"sha": sha, "ts": int(ts), "author": author, "subject": subject, "files": []})
        elif line.strip() and commits:
            status, _, path = line.partition("\t")
            commits[-1]["files"].append({"status": status[:1], "path": path})
    return commits


def build_history(cfg: Config) -> dict:
    rules_rel = cfg.rel(cfg.rules_dir)
    cases_rel = cfg.rel(cfg.cases_dir)
    datasets_rel = cfg.rel(cfg.datasets_dir) if cfg.datasets_dir else "datasets"
    prefix = _git(cfg, "rev-parse", "--show-prefix").decode().strip()
    commits = _commits(cfg, rules_rel, cases_rel, datasets_rel)

    def rule_id(path: str) -> str | None:
        p = PurePosixPath(path)
        if p.suffix not in RULE_SUFFIXES or not path.startswith(rules_rel.rstrip("/") + "/"):
            return None
        return path[len(rules_rel.rstrip("/")) + 1:]

    # rule content at every commit that changed it, in a single process
    specs = [f"{c['sha']}:{prefix}{f['path']}" for c in commits for f in c["files"] if f["status"] in "AM" and rule_id(f["path"])]
    blobs = iter(_read_blobs(cfg, specs))

    state: dict[str, _RuleState] = {}
    per_rule: dict[str, dict] = {}
    authors: dict[str, Counter] = {}
    timeline: dict[str, dict] = {}
    for c in commits:
        when = datetime.fromtimestamp(c["ts"], timezone.utc)
        a = authors.setdefault(c["author"], Counter())
        a["commits"] += 1
        for f in c["files"]:
            rid = rule_id(f["path"])
            if rid is None:
                continue
            if f["status"] == "D":
                state.pop(rid, None)
                a["rules_deleted"] += 1
                if rid in per_rule:
                    per_rule[rid]["deleted"] = True
                continue
            blob = next(blobs)
            state[rid] = _parse_rule(blob) if blob is not None else _RuleState()
            info = per_rule.setdefault(rid, {"created": when.isoformat(), "created_by": c["author"], "commits": 0, "authors": set(), "log": []})
            info.update(modified=when.isoformat(), modified_by=c["author"], deleted=False)
            info["commits"] += 1
            info["authors"].add(c["author"])
            info["log"].append({"sha": c["sha"][:7], "date": when.isoformat(), "author": c["author"], "subject": c["subject"],
                                "change": "created" if f["status"] == "A" else "modified"})
            a["rules_created" if f["status"] == "A" else "rules_changed"] += 1
        tactics = set().union(*(s.tactics for s in state.values())) if state else set()
        techniques = set().union(*(s.techniques for s in state.values())) if state else set()
        timeline[when.date().isoformat()] = {"date": when.date().isoformat(), "sha": c["sha"][:7], "rules": len(state),
                                             "tactics": len(tactics), "techniques": len(techniques)}

    now = time.time()
    weeks: Counter[str] = Counter()
    for c in commits:
        if now - c["ts"] <= 7 * 24 * 3600 * 12:
            y, w, _ = datetime.fromtimestamp(c["ts"], timezone.utc).isocalendar()
            weeks[f"{y}-S{w:02d}"] += 1
    activity = [
        {"sha": c["sha"][:7], "date": datetime.fromtimestamp(c["ts"], timezone.utc).isoformat(), "author": c["author"],
         "subject": c["subject"], "files": c["files"][:20], "more_files": max(0, len(c["files"]) - 20)}
        for c in reversed(commits[-30:])
    ]
    for info in per_rule.values():
        info["authors"] = sorted(info["authors"])
        info["log"] = list(reversed(info["log"]))[:50]
        info["age_days"] = round((now - datetime.fromisoformat(info["modified"]).timestamp()) / 86400, 1)
    return {
        "available": True,
        "commits": len(commits),
        "truncated": len(commits) >= MAX_COMMITS,
        "timeline": list(timeline.values()),
        "weekly": [{"week": k, "commits": v} for k, v in sorted(weeks.items())],
        "activity": activity,
        "rules": per_rule,
        "authors": sorted(
            ({"name": n, **{k: v for k, v in cnt.items()}} for n, cnt in authors.items()),
            key=lambda x: -x.get("commits", 0),
        ),
    }


def history(cfg: Config) -> dict:
    """History with a short cache (per HEAD). Never raises."""
    state = repo_state(cfg)
    if state:
        return unavailable(state)
    try:
        head = _git(cfg, "rev-parse", "HEAD").decode().strip()
    except (HistoryError, OSError, subprocess.TimeoutExpired):
        return unavailable({"state": "no_commits", "message": NO_COMMITS_MESSAGE})
    key = str(cfg.root)
    cached = _cache.get(key)
    if cached and cached[1] == head and time.monotonic() - cached[0] < CACHE_TTL:
        return cached[2]
    try:
        data = build_history(cfg)
    except (HistoryError, OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return {"available": False, "state": "error", "message": "The Git history could not be read.", "reason": str(exc)}
    data["head"] = head[:7]
    _cache[key] = (time.monotonic(), head, data)
    return data


def rule_history(cfg: Config, rid: str) -> dict:
    h = history(cfg)
    if not h.get("available"):
        return {k: v for k, v in h.items() if k != "rules"}
    info = h["rules"].get(rid)
    return {"available": True, "tracked": info is not None, **(info or {})}
