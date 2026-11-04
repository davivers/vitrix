"""GitHub sync (ADR 0006): throttled fetch + safe fast-forward, against temporary bare repos as `origin`."""

from __future__ import annotations

import base64
import os
import subprocess
import time
from pathlib import Path

import pytest

from vitrix import sync as sync_mod
from vitrix.config import ConfigHolder
from vitrix.sync import SyncManager

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
           "GIT_CONFIG_NOSYSTEM": "1"}
YML = "schema_version: 1\ngithub: false\nauth:\n  enabled: false\n"


def git(cwd: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, env={**os.environ, **GIT_ENV}, check=True)
    return r.stdout.strip()


def commit_all(repo: Path, msg: str) -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def plain_runner(extra: dict | None = None):  # noqa: ANN201
    def run(args, *, cwd, env, timeout):  # noqa: ANN001
        return sync_mod.default_runner(args, cwd=cwd, env={**GIT_ENV, **(extra or {}), **env}, timeout=timeout)

    return run


class World:
    pass


@pytest.fixture
def world(tmp_path):
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    work, other = tmp_path / "work", tmp_path / "other"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    (work / "vitrix.yml").write_text(YML, encoding="utf-8")
    (work / "rules").mkdir()
    (work / "rules" / "a.yml").write_text("title: a\n", encoding="utf-8")
    commit_all(work, "init")
    git(work, "remote", "add", "origin", str(origin))
    git(work, "push", "-q", "-u", "origin", "main")
    subprocess.run(["git", "clone", "-q", str(origin), str(other)], check=True)

    def publish(files: dict[str, str | None], msg: str = "upstream") -> None:
        git(other, "pull", "-q", "--ff-only", "origin", "main")
        for rel, text in files.items():
            f = other / rel
            if text is None:
                f.unlink()
            else:
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(text, encoding="utf-8")
        commit_all(other, msg)
        git(other, "push", "-q", "origin", "main")

    holder = ConfigHolder(work / "vitrix.yml")
    clock, calls = Clock(), []

    def recording(args, *, cwd, env, timeout):  # noqa: ANN001
        calls.append((list(args), dict(env)))
        return sync_mod.default_runner(args, cwd=cwd, env={**GIT_ENV, **env}, timeout=timeout)

    mgr = SyncManager(holder, clock=clock, runner=recording)
    w = World()
    w.work, w.other, w.origin, w.publish, w.holder, w.clock, w.calls, w.mgr = work, other, origin, publish, holder, clock, calls, mgr

    def sync(force: bool = False) -> dict:
        mgr.trigger(holder.get(), force=force)
        mgr.wait()
        return mgr.status(holder.get())

    w.sync = sync
    w.fetches = lambda: sum("fetch" in c[0] for c in calls)
    return w


def test_behind_fast_forwards(world):
    world.publish({"rules/new.yml": "title: new\n", "rules/a.yml": "title: a2\n"})
    st = world.sync()
    assert st["state"] == "synced" and st["behind"] == 0
    assert (world.work / "rules" / "new.yml").read_text() == "title: new\n"
    assert {(r["rule"], r["change"]) for r in st["changed_rules"]} == {("new.yml", "added"), ("a.yml", "modified")}
    assert st["last_fetch"] and st["last_pull"] and st["last_error"] is None
    assert st["config_changed"] is False


def test_status_never_fetches(world):
    world.publish({"rules/new.yml": "title: new\n"})
    st = world.mgr.status(world.holder.get())
    assert st["state"] == "synced"  # nothing fetched yet, so origin/main is still the old commit
    assert world.fetches() == 0


def test_vitrix_yml_change_is_picked_up(world):
    world.publish({"vitrix.yml": YML + "sync:\n  interval_seconds: 99\n"})
    st = world.sync()
    assert st["config_changed"] is True
    assert world.holder.get().sync_interval == 99


def test_diverged_is_not_touched(world):
    (world.work / "rules" / "local.yml").write_text("title: l\n", encoding="utf-8")
    commit_all(world.work, "local")
    world.publish({"rules/up.yml": "title: u\n"})
    head = git(world.work, "rev-parse", "HEAD")
    st = world.sync()
    assert st["state"] == "diverged" and (st["ahead"], st["behind"]) == (1, 1)
    assert git(world.work, "rev-parse", "HEAD") == head
    assert not (world.work / "rules" / "up.yml").exists()


def test_untracked_conflicting_file_is_reported_and_untouched(world):
    world.publish({"rules/new.yml": "title: upstream\n"})
    mine = world.work / "rules" / "new.yml"
    mine.write_text("title: MINE\n", encoding="utf-8")
    st = world.sync()
    assert st["state"] == "behind" and st["blocked"] == "local changes conflict with GitHub"
    assert st["conflicts"] == [{"path": "rules/new.yml", "rule": "new.yml", "reason": "untracked file differs"}]
    assert st["incoming_rules"] == [{"rule": "new.yml", "change": "added"}]
    assert mine.read_text() == "title: MINE\n"


def test_modified_tracked_conflict_changes_nothing_else(world):
    world.publish({"rules/a.yml": "title: upstream\n", "rules/b.yml": "title: b\n"})
    (world.work / "rules" / "a.yml").write_text("title: local edit\n", encoding="utf-8")
    st = world.sync()
    assert [c["reason"] for c in st["conflicts"]] == ["modified locally"]
    assert not (world.work / "rules" / "b.yml").exists()
    assert (world.work / "rules" / "a.yml").read_text() == "title: local edit\n"


def test_deleted_on_github_changed_locally(world):
    world.publish({"rules/a.yml": None})
    (world.work / "rules" / "a.yml").write_text("title: keep me\n", encoding="utf-8")
    st = world.sync()
    assert st["conflicts"][0]["reason"] == "deleted on GitHub, changed locally"
    assert (world.work / "rules" / "a.yml").read_text() == "title: keep me\n"


def test_identical_untracked_content_is_reconciled(world):
    (world.work / "rules" / "new.yml").write_text("title: new\n", encoding="utf-8")  # saved locally, published, merged
    world.publish({"rules/new.yml": "title: new\n"})
    st = world.sync()
    assert st["state"] == "synced" and st["conflicts"] == []
    assert (world.work / "rules" / "new.yml").read_text() == "title: new\n"
    assert git(world.work, "status", "--porcelain") == ""


def test_identical_modified_tracked_content_is_reconciled(world):
    (world.work / "rules" / "a.yml").write_text("title: a2\n", encoding="utf-8")
    world.publish({"rules/a.yml": "title: a2\n"})
    st = world.sync()
    assert st["state"] == "synced" and git(world.work, "status", "--porcelain") == ""


def test_not_on_base_branch_is_blocked(world):
    (world.work / "vitrix.yml").write_text("schema_version: 1\ngithub:\n  repo: acme/x\n  base: main\nauth:\n  enabled: false\n", encoding="utf-8")
    commit_all(world.work, "pin base")
    git(world.work, "push", "-q", "origin", "main")
    git(world.work, "checkout", "-q", "-b", "feature")
    holder = ConfigHolder(world.work / "vitrix.yml")  # `github` is read at startup
    mgr = SyncManager(holder, runner=plain_runner())
    world.publish({"rules/new.yml": "title: n\n"})
    mgr.trigger(holder.get())
    mgr.wait()
    st = mgr.status(holder.get())
    assert st["state"] == "behind" and st["on_base"] is False
    assert st["blocked"] == "not on the base branch (on feature)"
    assert not (world.work / "rules" / "new.yml").exists()


def test_fast_forward_off_only_reports(world):
    (world.work / "vitrix.yml").write_text(YML + "sync:\n  fast_forward: false\n", encoding="utf-8")
    commit_all(world.work, "ff off")
    git(world.work, "push", "-q", "origin", "main")
    world.holder.refresh()
    world.publish({"rules/new.yml": "title: n\n"})
    st = world.sync()
    assert st["state"] == "behind" and st["blocked"] == "fast_forward is off"
    assert not (world.work / "rules" / "new.yml").exists()


def test_no_remote(world):
    git(world.work, "remote", "remove", "origin")
    st = world.sync()
    assert st["state"] == "no_remote"
    assert world.fetches() == 0


def test_no_commits(tmp_path):
    repo = tmp_path / "empty"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "remote", "add", "origin", str(tmp_path / "nowhere.git"))
    (repo / "vitrix.yml").write_text("schema_version: 1\ngithub: false\n", encoding="utf-8")
    holder = ConfigHolder(repo / "vitrix.yml")
    mgr = SyncManager(holder, runner=plain_runner())
    mgr.trigger(holder.get())
    mgr.wait()
    st = mgr.status(holder.get())
    assert st["state"] == "no_commits" and st["blocked"] == "no commits yet"


def test_not_a_repo(tmp_path):
    (tmp_path / "vitrix.yml").write_text("schema_version: 1\ngithub: false\n", encoding="utf-8")
    holder = ConfigHolder(tmp_path / "vitrix.yml")
    mgr = SyncManager(holder, runner=plain_runner({"GIT_CEILING_DIRECTORIES": str(tmp_path.parent)}))
    assert mgr.status(holder.get())["state"] == "not_a_repo"


def test_disabled(world):
    (world.work / "vitrix.yml").write_text("schema_version: 1\ngithub: false\nsync: false\nauth:\n  enabled: false\n", encoding="utf-8")
    world.holder.refresh()
    st = world.sync()
    assert st["state"] == "disabled" and st["enabled"] is False
    assert world.fetches() == 0


def test_throttle_and_force(world):
    world.sync()
    assert world.fetches() == 1
    world.clock.now += 5
    world.sync()
    assert world.fetches() == 1  # inside the 30 s interval
    world.sync(force=True)
    assert world.fetches() == 2  # force only needs 5 s
    world.sync(force=True)
    assert world.fetches() == 2  # ... since the last attempt
    world.clock.now += 31
    st = world.sync()
    assert world.fetches() == 3 and st["next_fetch_in"] > 0


def test_fetch_failure_is_reported(world):
    git(world.work, "remote", "set-url", "origin", str(world.work.parent / "gone.git"))
    git(world.work, "update-ref", "-d", "refs/remotes/origin/main")
    st = world.sync()
    assert st["state"] == "error" and st["last_error"] and st["last_fetch"] is None


def test_token_only_in_env_never_argv(world, monkeypatch):
    secret = "ghp_SECRETTOKEN123"
    monkeypatch.setenv("VITRIX_GITHUB_TOKEN", secret)
    git(world.work, "remote", "set-url", "origin", "https://github.com/acme/none.git")
    seen = []

    def runner(args, *, cwd, env, timeout):  # noqa: ANN001
        seen.append((list(args), dict(env)))
        if "fetch" in args:
            return sync_mod.Result(128, b"", f"fatal: unable to access 'https://x-access-token:{secret}@github.com/acme/none.git/': {secret} denied")
        return sync_mod.default_runner(args, cwd=cwd, env={**GIT_ENV, **env}, timeout=timeout)

    mgr = SyncManager(world.holder, clock=world.clock, runner=runner)
    mgr.trigger(world.holder.get())
    mgr.wait()
    st = mgr.status(world.holder.get())
    fetch = next(s for s in seen if "fetch" in s[0])
    assert all(secret not in a for args, _ in seen for a in args)
    assert fetch[1]["GIT_CONFIG_COUNT"] == "1" and fetch[1]["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
    assert fetch[1]["GIT_CONFIG_VALUE_0"].startswith("AUTHORIZATION: basic ")
    assert fetch[1]["GIT_TERMINAL_PROMPT"] == "0" and fetch[1]["GCM_INTERACTIVE"] == "never"
    assert not any("GIT_CONFIG_COUNT" in e for args, e in seen if "fetch" not in args)
    err = st["last_error"] or ""
    assert secret not in err and "***" in err
    assert base64.b64encode(f"x-access-token:{secret}".encode()).decode() not in err


def test_non_github_remote_gets_no_token(world, monkeypatch):
    monkeypatch.setenv("VITRIX_GITHUB_TOKEN", "ghp_x")
    world.sync()
    assert world.fetches() == 1
    assert all("GIT_CONFIG_COUNT" not in e for _, e in world.calls)


def test_api_get_and_post(world, monkeypatch):
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    world.publish({"rules/new.yml": "title: n\n"})
    git(world.work, "fetch", "-q")
    app = create_app(str(world.work / "vitrix.yml"))
    client = TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 5000))
    st = client.get("/api/sync").json()
    assert st["state"] == "behind" and st["enabled"] is True and st["incoming_rules"] == [{"rule": "new.yml", "change": "added"}]
    assert client.post("/api/sync", json={}).status_code == 200
    for _ in range(100):
        if not client.get("/api/sync").json()["fetching"]:
            break
        time.sleep(0.1)
    assert client.get("/api/sync").json()["state"] == "synced"
    assert (world.work / "rules" / "new.yml").exists()
    outside = TestClient(app, base_url="http://127.0.0.1:8000", client=("203.0.113.9", 5000))
    assert outside.post("/api/sync", json={}).status_code == 403
    assert outside.get("/api/sync").json()["enabled"] is False
