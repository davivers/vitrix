"""Where is each rule: merged on the base branch, only local, pushed to a vitrix/* branch, or in a PR?

Read-only, from git (ADR 0007 point 6). Nothing here fetches or writes; `sync.py` brings `origin/*`
up to date and this module only compares the working tree with those refs.

- `published`: rule (and cases) equal to `origin/<base>` (no remote: `HEAD`);
- `local`: differs from base (`change`: added | modified). `git`: untracked | modified | committed;
- `pushed`: a fetched `origin/vitrix/*` branch holds exactly this content, no open PR known;
- `in_pr`: as `pushed`, and the (cached) GitHub activity lists an open PR from that branch;
- `unknown`: no git / no commits / no base ref and the file is clean.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess  # nosec B404
import threading
import time
from pathlib import Path

from . import gitremote
from .config import Config
from .sync import default_runner

CACHE_TTL = 5.0
MAX_BRANCHES = 50
_SUFFIXES = {".yml", ".yaml"}
_ENV = {"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}
NL = chr(10)
LF = b"\n"
CRLF = b"\r\n"
_lock = threading.Lock()
_cache: dict[str, tuple[float, tuple, dict]] = {}


def invalidate() -> None:
    with _lock:
        _cache.clear()


def _git(top: Path, *args: str) -> tuple[int, bytes]:
    r = default_runner(list(args), cwd=top, env=_ENV, timeout=15)
    return r.rc, r.out


def _text(top: Path, *args: str) -> str | None:
    rc, out = _git(top, *args)
    return out.decode("utf-8", "replace").strip() if rc == 0 else None


def _blob_hash(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()  # nosec B324 - git object id, not security


def _toplevel(cfg: Config) -> Path | None:
    top = _text(cfg.root, "rev-parse", "--show-toplevel")
    return Path(top) if top else None


def _base_name(cfg: Config, top: Path) -> str | None:
    if cfg.github and cfg.github.base:
        return cfg.github.base
    det = gitremote.detect(cfg.root)
    return (det.base if det else None) or _text(top, "branch", "--show-current")


def _base_ref(cfg: Config, top: Path) -> tuple[str | None, bool]:
    """(ref to compare with, is it origin/<base>)."""
    base = _base_name(cfg, top)
    if base and _text(top, "rev-parse", "--verify", "-q", f"refs/remotes/origin/{base}"):
        return f"origin/{base}", True
    if _text(top, "rev-parse", "--verify", "-q", "HEAD"):
        return "HEAD", False
    return None, False


def _rule_files(cfg: Config) -> list[str]:
    if not cfg.rules_dir.is_dir():
        return []
    return sorted(p.relative_to(cfg.rules_dir).as_posix() for p in cfg.rules_dir.rglob("*") if p.is_file() and p.suffix.lower() in _SUFFIXES)


def _repo_rel(top: Path, path: Path) -> str | None:
    try:
        return path.resolve().relative_to(top.resolve()).as_posix()
    except ValueError:
        return None


def in_base(cfg: Config, rid: str) -> bool | None:
    """True when the rule file exists in the published base (`origin/<base>`, else `HEAD`);
    None when there is nothing to compare with (no git, no commits)."""
    top = _toplevel(cfg)
    if top is None:
        return None
    ref, _ = _base_ref(cfg, top)
    rel = _repo_rel(top, cfg.rules_dir / rid)
    if ref is None or rel is None:
        return None
    rc, _ = _git(top, "cat-file", "-e", f"{ref}:{rel}")
    return rc == 0


def base_versions(cfg: Config, path: Path) -> tuple[str | None, str | None, bool]:
    """(text of the file in origin/<base>, text at the merge-base of HEAD and origin/<base>, comparable).
    `comparable` is False when there is no origin/<base> to compare with (no git, no remote)."""
    top = _toplevel(cfg)
    rel = _repo_rel(top, path) if top else None
    if top is None or rel is None:
        return None, None, False
    ref, remote = _base_ref(cfg, top)
    if ref is None or not remote:
        return None, None, False

    def show(rev: str) -> str | None:
        rc, out = _git(top, "show", f"{rev}:{rel}")
        return out.decode("utf-8", "replace") if rc == 0 else None

    theirs = show(ref)
    mb = _text(top, "merge-base", "HEAD", ref)
    return theirs, (show(mb) if mb else None), True


def _status(top: Path, prefixes: list[str]) -> dict[str, str]:
    rc, out = _git(top, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--", *prefixes)
    parts = out.decode("utf-8", "replace").split("\0") if rc == 0 else []
    res: dict[str, str] = {}
    i = 0
    while i < len(parts):
        entry = parts[i]
        i += 1
        if len(entry) < 4:
            continue
        res[entry[3:]] = entry[:2]
        if "R" in entry[:2] or "C" in entry[:2]:
            i += 1
    return res


def _differs(top: Path, ref: str, prefixes: list[str]) -> dict[str, str]:
    """Tracked paths whose working-tree content differs from `ref` -> A | M | D."""
    rc, out = _git(top, "diff", "--name-status", "-z", "--no-renames", ref, "--", *prefixes)
    parts = out.decode("utf-8", "replace").split("\0") if rc == 0 else []
    return {parts[i + 1]: parts[i][:1] for i in range(0, len(parts) - 1, 2) if parts[i]}


def _tree(top: Path, ref: str, prefixes: list[str]) -> dict[str, str]:
    rc, out = _git(top, "ls-tree", "-r", "-z", ref, "--", *prefixes)
    res: dict[str, str] = {}
    if rc == 0:
        for rec in out.decode("utf-8", "replace").split("\0"):
            meta, _, path = rec.partition("\t")
            bits = meta.split()
            if len(bits) == 3:
                res[path] = bits[2]
    return res


def _open_prs() -> dict[str, dict]:
    """head branch -> {number, url} from the cached GitHub activity (never fetches)."""
    from . import service

    prs: dict[str, dict] = {}
    for _, data in list(service._activity_cache.values()):  # noqa: SLF001
        for item in (data.get("pulls") or {}).get("items", []):
            if item.get("branch"):
                prs[item["branch"]] = {"number": item.get("number"), "url": item.get("url")}
    return prs


def publication_map(cfg: Config, only: str | None = None) -> dict[str, dict]:
    """rule id -> publication info, for every rule file under rules_dir (or just `only`)."""
    ids = _rule_files(cfg)
    if only is not None:
        ids = [i for i in ids if i == only]
    top = _toplevel(cfg)
    if top is None:
        return {rid: _info("unknown", reason="not a git repository") for rid in ids}
    ref, remote = _base_ref(cfg, top)
    status_prefixes = [p for p in (_repo_rel(top, cfg.rules_dir), _repo_rel(top, cfg.cases_dir)) if p]
    prefixes = status_prefixes or ["."]
    head = _text(top, "rev-parse", "--verify", "-q", "HEAD") or ""
    refs_out = _text(top, "for-each-ref", "--format=%(objectname) %(refname)", "refs/remotes/origin") or ""
    status = _status(top, prefixes)
    key = (str(top), head, hashlib.sha1(refs_out.encode(), usedforsecurity=False).hexdigest(), tuple(sorted(status.items())), tuple(ids))  # nosec B324
    with _lock:
        hit = _cache.get(f"{top}|{only}")
        if hit and hit[1] == key and time.monotonic() - hit[0] < CACHE_TTL:
            return hit[2]
    out = _compute(cfg, top, ids, ref, remote, status, prefixes, bool(head))
    with _lock:
        _cache[f"{top}|{only}"] = (time.monotonic(), key, out)
    return out


def file_publication(cfg: Config, path: Path) -> dict:
    """Publication info of ONE repo file (e.g. mappings.yml): same states as a rule; `absent` when the file does not exist."""
    if not path.is_file():
        return _info("absent", reason="the file does not exist yet")
    top = _toplevel(cfg)
    rel = _repo_rel(top, path) if top else None
    if top is None or rel is None:
        return _info("unknown", reason="not a git repository")
    ref, remote = _base_ref(cfg, top)
    status = _status(top, [rel])
    has_commit = bool(_text(top, "rev-parse", "--verify", "-q", "HEAD"))
    return _compute(cfg, top, [rel], ref, remote, status, [rel], has_commit, paths_of=lambda _rid: [rel])[rel]


def _info(state: str, *, change: str | None = None, git: str | None = None, branch: str | None = None, pr: dict | None = None,
          base_ref: str | None = None, reason: str | None = None) -> dict:
    return {"state": state, "change": change, "git": git, "branch": branch, "pr": pr, "base_ref": base_ref, "reason": reason}


def _compute(cfg: Config, top: Path, ids: list[str], ref: str | None, remote: bool, status: dict[str, str],
             prefixes: list[str], has_commit: bool, paths_of=None) -> dict[str, dict]:  # noqa: ANN001
    base_ref = ref if remote else None
    base_tree = _tree(top, ref, prefixes) if ref else {}
    differs = _differs(top, ref, prefixes) if ref else {}
    reason = None if remote else ("no commits yet" if not has_commit else "no GitHub remote")
    result: dict[str, dict] = {}
    local: dict[str, tuple[list[str], str, str]] = {}
    for rid in ids:
        paths = paths_of(rid) if paths_of else [p for p in (_repo_rel(top, cfg.rules_dir / rid), _repo_rel(top, cfg.cases_dir / rid)) if p]
        rule_path = paths[0] if paths else None
        existing = [p for p in paths if (top / p).is_file()]
        untracked = any(status.get(p) == "??" for p in existing)
        dirty = any(status.get(p, "  ") not in ("  ", "??") for p in existing)
        changed = any(p in differs for p in existing) or any(p not in base_tree for p in existing) or (ref is None)
        if not (untracked or dirty or changed):
            result[rid] = _info("published" if remote else "unknown", base_ref=base_ref, reason=reason, git="clean")
            continue
        if not remote and not (untracked or dirty):
            # clean tree, but there is no origin/<base> to compare with: nothing to say
            result[rid] = _info("unknown", base_ref=base_ref, reason=reason, git="clean")
            continue
        git_state = "untracked" if untracked else "modified" if dirty else "committed"
        added = rule_path is not None and rule_path not in base_tree
        info = _info("local", change="added" if added else "modified", git=git_state, base_ref=base_ref, reason=None)
        result[rid] = info
        local[rid] = (existing, git_state, rule_path or "")
    if local:
        _match_branches(top, prefixes, local, result, status)
    return result


def _batch_check(top: Path, specs: list[str]) -> list[str | None]:
    """Blob id of every `<ref>:<path>` spec (None when missing) with ONE git process."""
    exe = shutil.which("git")
    if not exe or not specs:
        return [None] * len(specs)
    try:
        proc = subprocess.run([exe, "-C", str(top), "cat-file", "--batch-check"], input=(NL.join(specs) + NL).encode(),  # nosec B603
                              capture_output=True, timeout=30, env={**os.environ, **_ENV}, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return [None] * len(specs)
    lines = proc.stdout.decode("utf-8", "replace").splitlines()
    out: list[str | None] = []
    for line in lines[:len(specs)]:
        bits = line.split()
        out.append(bits[0] if len(bits) == 3 and bits[1] == "blob" else None)
    return out + [None] * (len(specs) - len(out))


def _match_branches(top: Path, prefixes: list[str], local: dict[str, tuple[list[str], str, str]], result: dict[str, dict],
                    status: dict[str, str]) -> None:
    """Which fetched `origin/vitrix/*` branch holds exactly the working content of a local rule.
    Constant number of git processes: one for-each-ref and one cat-file --batch-check for all branches and files."""
    out = _text(top, "for-each-ref", "--sort=-committerdate", f"--count={MAX_BRANCHES}", "--format=%(refname:short)", "refs/remotes/origin/vitrix/")
    branches = [b for b in (out or "").splitlines() if b]
    if not branches:
        return
    work: dict[str, set[str]] = {}
    for _rid, (existing, _, _) in local.items():
        for p in existing:
            try:
                data = (top / p).read_bytes()
            except OSError:
                continue
            # git stores LF: a CRLF checkout (autocrlf) hashes like its LF form
            work[p] = {_blob_hash(data), _blob_hash(data.replace(CRLF, LF))}
    rids = sorted(local)[:500]
    specs = [f"{b}:{p}" for b in branches for rid in rids for p in local[rid][0]]
    blobs = iter(_batch_check(top, specs))
    found: dict[tuple[str, str], str | None] = {(b, p): next(blobs) for b in branches for rid in rids for p in local[rid][0]}
    prs = _open_prs()
    pending = set(rids)
    for branch in branches:
        for rid in sorted(pending):
            existing = local[rid][0]
            if existing and all(found.get((branch, p)) in work.get(p, ()) for p in existing):
                short = branch.split("/", 1)[1]
                pr = prs.get(short)
                result[rid].update(state="in_pr" if pr else "pushed", branch=short, pr=pr)
                pending.discard(rid)
