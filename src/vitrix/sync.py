"""GitHub sync (ADR 0006): a throttled `git fetch` and a safe fast-forward of the base branch.

The app runs exactly these mutating git commands and nothing else: `git fetch`, `git merge --ff-only`,
and the clean-up of files whose content already equals what GitHub brings (`git restore` / unlink).
Local work is never overwritten: any incoming path that is dirty locally with different content is a
conflict and nothing changes at all. The token only travels in the environment of the one fetch
subprocess (`GIT_CONFIG_*` extraheader scoped to https://github.com/); it is never on argv, disk, a log
or a response.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess  # nosec B404
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import gitremote

REPO_LOCK = threading.RLock()  # also held by local rule writes (ADR 0007): a save never interleaves with a merge

FETCH_TIMEOUT = 60
READ_TIMEOUT = 15
MAX_RULES = 200
MIN_FORCE_SECONDS = 5
_HTTPS_GITHUB = re.compile(r"^https://(?:[^@/\s]+@)?github\.com/", re.IGNORECASE)
_USERINFO = re.compile(r"https://[^@/\s]+@")
_RULE_SUFFIXES = {".yml", ".yaml"}
_IN_PROGRESS = ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply")


@dataclass
class Result:
    rc: int
    out: bytes = b""
    err: str = ""

    @property
    def text(self) -> str:
        return self.out.decode("utf-8", "replace").strip()


Runner = Callable[..., Result]


def default_runner(args: list[str], *, cwd: Path, env: dict[str, str], timeout: float) -> Result:
    """Run `git <args>` in `cwd`: fixed executable, argument list, no shell, hard timeout."""
    exe = shutil.which("git")
    if not exe:
        return Result(127, b"", "git is not installed")
    try:
        proc = subprocess.run([exe, "-C", str(cwd), *args], capture_output=True, timeout=timeout,  # nosec B603
                              env={**os.environ, **env}, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return Result(124, b"", f"git timed out after {int(timeout)} s")
    except OSError as exc:
        return Result(126, b"", str(exc))
    return Result(proc.returncode, proc.stdout, proc.stderr.decode("utf-8", "replace"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SyncManager:
    def __init__(self, cfg_holder, clock: Callable[[], float] = time.monotonic, runner: Runner = default_runner,  # noqa: ANN001
                 audit: Callable[[str, str], None] | None = None):
        self.holder, self._clock, self._run = cfg_holder, clock, runner
        self.audit = audit
        self.on_change: list[Callable[[], None]] = []  # extra caches to clear after a fast-forward (ADR 0007 publication cache)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._fetching = False
        self._last_attempt_mono: float | None = None
        self._last_attempt: str | None = None
        self._last_fetch: str | None = None
        self._last_error: str | None = None
        self._failures = 0
        self._changed_rules: list[dict] = []
        self._last_pull: str | None = None
        self._config_changed = False
        self._audited_conflict: str | None = None
        self._token_value: str | None = None  # only for masking messages of the current fetch

    # ------------------------------------------------------------------ git plumbing

    @staticmethod
    def _env(read: bool) -> dict[str, str]:
        env = {"GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never", "LC_ALL": "C"}
        if "GIT_SSH_COMMAND" not in os.environ:
            env["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes"
        if read:
            env["GIT_OPTIONAL_LOCKS"] = "0"
        return env

    def _git(self, root: Path, *args: str, read: bool = True, env: dict[str, str] | None = None, timeout: float = READ_TIMEOUT) -> Result:
        return self._run(list(args), cwd=root, env={**self._env(read), **(env or {})}, timeout=timeout)

    def _mask(self, text: str, token: str | None) -> str:
        text = _USERINFO.sub("https://***@", text)
        if token:
            text = text.replace(base64.b64encode(f"x-access-token:{token}".encode()).decode(), "***").replace(token, "***")
        return text.strip()[-500:]

    # ------------------------------------------------------------------ local state

    def _repo(self, cfg) -> tuple[Path | None, str | None]:  # noqa: ANN001
        r = self._git(cfg.root, "rev-parse", "--show-toplevel")
        if r.rc == 0 and r.text:
            return Path(r.text), None
        if "dubious ownership" in r.err:
            return None, "git refuses this folder (dubious ownership). Run: git config --global --add safe.directory <this folder>"
        return None, None

    def _base(self, cfg, top: Path, branch: str | None) -> str | None:  # noqa: ANN001
        if cfg.github and cfg.github.base:
            return cfg.github.base
        det = gitremote.detect(cfg.root)
        return (det.base if det else None) or branch

    def _rev(self, top: Path, ref: str) -> str | None:
        r = self._git(top, "rev-parse", "--verify", "-q", ref)
        return r.text if r.rc == 0 and r.text else None

    def _in_progress(self, top: Path) -> bool:
        r = self._git(top, "rev-parse", "--absolute-git-dir")
        gd = Path(r.text) if r.rc == 0 and r.text else top / ".git"
        return any((gd / name).exists() for name in _IN_PROGRESS)

    def _rule_of(self, cfg, top: Path, rel: str) -> str | None:  # noqa: ANN001
        for base in (cfg.rules_dir, cfg.cases_dir):
            try:
                inside = (top / rel).resolve().relative_to(base.resolve())
            except ValueError:
                continue
            if PurePosixPath(rel).suffix in _RULE_SUFFIXES:
                return inside.as_posix()
        return None

    def _incoming(self, top: Path, ref: str) -> list[tuple[str, str]]:
        r = self._git(top, "diff", "--name-status", "-z", "--no-renames", "HEAD", ref)
        if r.rc != 0:
            return []
        parts = r.out.decode("utf-8", "replace").split("\0")
        return [(parts[i][:1], parts[i + 1]) for i in range(0, len(parts) - 1, 2) if parts[i] and parts[i + 1]]

    def _dirty(self, top: Path) -> dict[str, str]:
        r = self._git(top, "status", "--porcelain=v1", "-z", "--untracked-files=all")
        parts = r.out.decode("utf-8", "replace").split("\0")
        out: dict[str, str] = {}
        i = 0
        while i < len(parts):
            entry = parts[i]
            i += 1
            if len(entry) < 4:
                continue
            xy, path = entry[:2], entry[3:]
            out[path] = xy
            if "R" in xy or "C" in xy:
                i += 1  # the original path follows
        return out

    def _plan(self, cfg, top: Path, ref: str) -> tuple[list[tuple[str, str]], list[dict], list[tuple[str, str | None]]]:  # noqa: ANN001
        """(incoming changes, conflicts, resolvable [(path, incoming blob sha or None)])."""
        incoming = self._incoming(top, ref)
        dirty = self._dirty(top)
        conflicts: list[dict] = []
        resolvable: list[tuple[str, str | None]] = []
        for change, rel in incoming:
            if rel.startswith("/") or ".." in PurePosixPath(rel).parts:
                continue
            file = top / rel
            xy = dirty.get(rel)
            if xy is None:
                if change != "A" or not file.is_file():
                    continue
                xy = "!!"  # present but not listed by status: an ignored file
            blob = None if change == "D" else self._rev(top, f"{ref}:{rel}")
            if file.is_file():
                h = self._git(top, "hash-object", f"--path={rel}", "--", str(file))
                same = blob is not None and h.rc == 0 and h.text == blob
            else:
                same = blob is None  # deleted locally and on GitHub
            if same:
                resolvable.append((rel, blob))
                continue
            reason = ("deleted on GitHub, changed locally" if change == "D" else
                      "untracked file differs" if xy == "??" else
                      "ignored file differs" if xy == "!!" else "modified locally")
            conflicts.append({"path": rel, "rule": self._rule_of(cfg, top, rel), "reason": reason})
        return incoming, conflicts, resolvable

    def _rules(self, cfg, top: Path, incoming: list[tuple[str, str]]) -> list[dict]:  # noqa: ANN001
        names = {"A": "added", "M": "modified", "T": "modified", "D": "deleted"}
        out = []
        for change, rel in incoming:
            rid = self._rule_of(cfg, top, rel)
            if rid and not self._is_case(cfg, top, rel):
                out.append({"rule": rid, "change": names.get(change, "modified")})
        return out[:MAX_RULES]

    @staticmethod
    def _is_case(cfg, top: Path, rel: str) -> bool:  # noqa: ANN001
        try:
            (top / rel).resolve().relative_to(cfg.cases_dir.resolve())
            return True
        except ValueError:
            return False

    def _interval(self, cfg) -> int:  # noqa: ANN001
        base = cfg.sync_interval
        return min(600, base * 4) if self._failures >= 3 else base

    def status(self, cfg) -> dict:  # noqa: ANN001
        """Local state only: never touches the network."""
        with self._lock:
            fetching, attempt_mono = self._fetching, self._last_attempt_mono
            st = {"last_fetch": self._last_fetch, "last_attempt": self._last_attempt, "last_error": self._last_error,
                  "changed_rules": list(self._changed_rules), "last_pull": self._last_pull, "config_changed": self._config_changed}
        due = 0
        if attempt_mono is not None:
            due = max(0, int(-(-(attempt_mono + self._interval(cfg) - self._clock()) // 1)))
        out: dict = {"enabled": True, "reason": None, "state": "synced", "branch": None, "base": None, "on_base": False, "head": None,
                     "remote_head": None, "behind": 0, "ahead": 0, "fetching": fetching, "next_fetch_in": due,
                     "blocked": None, "conflicts": [], "incoming_rules": [], **st}
        if not cfg.sync_enabled:
            return {**out, "enabled": False, "reason": "sync is turned off (sync.enabled: false)", "state": "disabled"}
        top, problem = self._repo(cfg)
        if top is None:
            return {**out, "state": "error" if problem else "not_a_repo", "last_error": problem or out["last_error"]}
        url = self._git(top, "remote", "get-url", "origin")
        branch_r = self._git(top, "symbolic-ref", "-q", "--short", "HEAD")
        branch = branch_r.text if branch_r.rc == 0 and branch_r.text else None
        base = self._base(cfg, top, branch)
        head = self._rev(top, "HEAD")
        out.update(branch=branch, base=base, on_base=bool(branch and branch == base), head=head)
        if url.rc != 0:
            return {**out, "state": "no_remote"}
        ref = f"refs/remotes/origin/{base}" if base else None
        remote_head = self._rev(top, ref) if ref else None
        out["remote_head"] = remote_head
        if head is None:
            return {**out, "state": "no_commits", "blocked": "no commits yet",
                    "last_error": out["last_error"], "hint": "Repository has no commits yet — run `git pull` once"}
        if remote_head is None:
            return {**out, "state": "error" if out["last_error"] else "synced"}
        counts = self._git(top, "rev-list", "--left-right", "--count", f"HEAD...{ref}")
        try:
            ahead, behind = (int(x) for x in counts.text.split())
        except ValueError:
            ahead = behind = 0
        out.update(ahead=ahead, behind=behind, state="diverged" if ahead and behind else "behind" if behind else "ahead" if ahead else "synced")
        if behind:
            incoming, conflicts, _ = self._plan(cfg, top, ref)
            out.update(conflicts=conflicts, incoming_rules=self._rules(cfg, top, incoming))
            out["blocked"] = self._blocked(cfg, top, branch, base, bool(conflicts))
        return out

    def _blocked(self, cfg, top: Path, branch: str | None, base: str | None, conflicts: bool) -> str | None:  # noqa: ANN001
        if not cfg.sync_fast_forward:
            return "fast_forward is off"
        if branch is None:
            return "detached HEAD"
        if branch != base:
            return f"not on the base branch (on {branch})"
        if self._in_progress(top):
            return "a merge is in progress"
        if conflicts:
            return "local changes conflict with GitHub"
        return None

    # ------------------------------------------------------------------ trigger

    def trigger(self, cfg, force: bool = False) -> dict:  # noqa: ANN001
        if cfg.sync_enabled:
            with self._lock:
                wait = MIN_FORCE_SECONDS if force else self._interval(cfg)
                due = self._last_attempt_mono is None or self._clock() - self._last_attempt_mono >= wait
                if not self._fetching and due:
                    self._fetching = True
                    self._last_attempt_mono = self._clock()
                    self._last_attempt = _now_iso()
                    self._thread = threading.Thread(target=self._job, args=(cfg,), name="vitrix-sync", daemon=True)
                    self._thread.start()
        return self.status(cfg)

    def wait(self, timeout: float = 30) -> None:
        """Wait for the background fetch (tests)."""
        t = self._thread
        if t is not None:
            t.join(timeout)

    def _job(self, cfg) -> None:  # noqa: ANN001
        try:
            self._sync(cfg)
        except Exception as exc:  # never let the thread die silently with `fetching` stuck
            with self._lock:
                self._last_error = self._mask(f"{type(exc).__name__}: {exc}", self._token_value)
                self._failures += 1
        finally:
            self._token_value = None
            with self._lock:
                self._fetching = False

    def _sync(self, cfg) -> None:  # noqa: ANN001
        top, problem = self._repo(cfg)
        if top is None:
            with self._lock:
                self._last_error = problem
            return
        url = self._git(top, "remote", "get-url", "origin")
        if url.rc != 0:
            return
        env: dict[str, str] = {}
        token = None
        if _HTTPS_GITHUB.match(url.text):
            token, _ = gitremote.token()
            if token:
                self._token_value = token
                cred = base64.b64encode(f"x-access-token:{token}".encode()).decode()
                env = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                       "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {cred}"}
        r = self._git(top, "-c", "credential.interactive=never", "fetch", "--prune", "--no-tags", "--no-recurse-submodules", "origin",
                      read=False, env=env, timeout=FETCH_TIMEOUT)
        with self._lock:
            if r.rc != 0:
                self._failures += 1
                msg = self._mask(r.err, token) or f"git fetch failed ({r.rc})"
                if "index.lock" in r.err:
                    msg = "git is busy, retrying"
                if "dubious ownership" in r.err:
                    msg = "git refuses this folder (dubious ownership). Run: git config --global --add safe.directory <this folder>"
                self._last_error = msg
                return
            self._failures = 0
            self._last_error = None
            self._last_fetch = _now_iso()
        self._fast_forward(cfg, top)

    # ------------------------------------------------------------------ the fast-forward

    def _fast_forward(self, cfg, top: Path) -> None:  # noqa: ANN001
        if not cfg.sync_fast_forward:
            return
        with REPO_LOCK:
            branch_r = self._git(top, "symbolic-ref", "-q", "--short", "HEAD")
            branch = branch_r.text if branch_r.rc == 0 and branch_r.text else None
            base = self._base(cfg, top, branch)
            head = self._rev(top, "HEAD")
            if not base or not head or branch != base or self._in_progress(top):
                return
            ref = f"refs/remotes/origin/{base}"
            remote = self._rev(top, ref)
            if not remote or remote == head:
                return
            if self._git(top, "merge-base", "--is-ancestor", "HEAD", ref).rc != 0:
                return  # ahead or diverged: never touched
            incoming, conflicts, resolvable = self._plan(cfg, top, ref)
            if conflicts:
                if self._audited_conflict != remote:
                    self._audited_conflict = remote
                    self._log("sync.conflict", f"{len(conflicts)} local file(s) differ from origin/{base} @ {remote[:7]}: "
                              + ", ".join(c["path"] for c in conflicts[:5]))
                return
            backup: dict[str, bytes] = {}
            for rel, _ in resolvable:
                f = top / rel
                if f.is_file():
                    backup[rel] = f.read_bytes()
                tracked = self._git(top, "ls-files", "--error-unmatch", "--", rel).rc == 0
                if tracked:
                    self._git(top, "restore", "--staged", "--worktree", "--source=HEAD", "--", rel, read=False)
                elif f.is_file():
                    f.unlink()
            m = self._git(top, "merge", "--ff-only", ref, read=False, timeout=60)
            if m.rc != 0:
                for rel, data in backup.items():  # put the user's files back exactly as they were
                    f = top / rel
                    f.parent.mkdir(parents=True, exist_ok=True)
                    f.write_bytes(data)
                with self._lock:
                    self._last_error = "index.lock" in m.err and "git is busy, retrying" or self._mask(m.err, None) or "fast-forward failed"
                return
            rules = self._rules(cfg, top, incoming)
            cfg_rel = None
            if cfg.path is not None:
                try:
                    cfg_rel = cfg.path.resolve().relative_to(top.resolve()).as_posix()
                except ValueError:
                    cfg_rel = None
            with self._lock:
                self._changed_rules = rules
                self._last_pull = _now_iso()
                self._config_changed = bool(cfg_rel and any(p == cfg_rel for _, p in incoming))
        self._after_change()
        self._log("sync.fast_forward", f"{base} {head[:7]} → {remote[:7]} ({len(incoming)} file(s))")

    def _after_change(self) -> None:
        """Caches that could still describe the old tree."""
        from . import service

        try:
            self.holder.refresh()
        except Exception:  # nosec B110 - a bad vitrix.yml is reported by ConfigHolder.reload_error
            pass
        gitremote._cache.clear()
        service._activity_cache.clear()
        for fn in self.on_change:
            fn()

    def _log(self, action: str, detail: str) -> None:
        if self.audit is not None:
            try:
                self.audit(action, detail)
            except Exception:  # nosec B110 - auditing must never break a sync
                pass
