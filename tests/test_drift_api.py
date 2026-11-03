"""GET /api/drift: per-rule matches now vs at a Git ref."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from vitrix.api import create_app

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def git(root, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "A", "GIT_AUTHOR_EMAIL": "a@example.com",
           "GIT_COMMITTER_NAME": "A", "GIT_COMMITTER_EMAIL": "a@example.com"}
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)


def client(cfg_path):
    return TestClient(create_app(str(cfg_path)), base_url="http://127.0.0.1:8000")


def test_not_a_git_repo_is_409(user_repo):
    r = client(user_repo).get("/api/drift")
    assert r.status_code == 409 and "Git repository" in r.json()["detail"]


def test_drift_states_and_errors(user_repo):
    root = user_repo.parent
    git(root, "init", "-q", "-b", "main")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "base")
    c = client(user_repo)

    same = c.get("/api/drift?ref=HEAD").json()
    assert same["summary"]["drifted"] == 0 and same["summary"]["added"] == 0 and same["rules"]
    assert all(r["state"] == "same" for r in same["rules"])
    assert c.get("/api/drift").status_code == 200  # default ref falls back to HEAD

    rules = sorted((root / "rules").rglob("*.yml"))
    first = rules[0]
    text = first.read_text(encoding="utf-8")
    first.write_text(text.replace("condition: ", "condition: 1 of nothing_* or ", 1) if False else text + "\n# edited\n", encoding="utf-8")
    (root / "rules" / "brand_new.yml").write_text(text, encoding="utf-8")
    body = c.get("/api/drift?ref=HEAD").json()
    states = {r["rule"]: r for r in body["rules"]}
    assert states["brand_new.yml"]["state"] == "added"
    assert states[first.relative_to(root / "rules").as_posix()]["modified"] is True
    assert body["summary"]["added"] >= 1 and body["ref"] == "HEAD" and body["sha"]
    assert body["datasets"] and "rules" in body["datasets"][0]

    first.unlink()
    removed = c.get("/api/drift?ref=HEAD").json()
    assert any(r["state"] == "removed" for r in removed["rules"])


def test_drift_bad_refs_are_422(user_repo):
    root = user_repo.parent
    git(root, "init", "-q", "-b", "main")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "base")
    c = client(user_repo)
    missing = c.get("/api/drift?ref=nope")
    assert missing.status_code == 422 and "not found" in missing.json()["detail"]
    assert c.get("/api/drift?ref=--upload-pack=x").status_code == 422
    assert c.get("/api/drift?ref=a..b").status_code == 422


def committed(user_repo):
    root = user_repo.parent
    git(root, "init", "-q", "-b", "main")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "base")
    return root


def test_drift_rule_filter_and_cache(user_repo, monkeypatch):
    import threading

    from vitrix import drift as drift_mod

    drift_mod._cache.clear()
    root = committed(user_repo)
    calls = []
    real = drift_mod._drift
    monkeypatch.setattr(drift_mod, "_drift", lambda *a, **k: (calls.append(a[2]), real(*a, **k))[1])
    c = client(user_repo)

    full = c.get("/api/drift?ref=HEAD").json()
    one = sorted(root.joinpath("rules").rglob("*.yml"))[0].relative_to(root / "rules").as_posix()
    only = c.get(f"/api/drift?ref=HEAD&rule={one}").json()
    assert [r["rule"] for r in only["rules"]] == [one] and len(full["rules"]) >= 1
    assert all(r["rule"] == one for d_ in only["datasets"] for r in d_["rules"])
    assert c.get("/api/drift?ref=HEAD&rule=nope.yml").json()["rules"] == []
    assert calls == [None, one, "nope.yml"]

    c.get("/api/drift?ref=HEAD")  # served from the cache
    c.get(f"/api/drift?ref=HEAD&rule={one}")
    assert len(calls) == 3

    # concurrent identical requests compute once
    drift_mod._cache.clear()
    calls.clear()
    out = []
    ts = [threading.Thread(target=lambda: out.append(c.get("/api/drift?ref=HEAD").status_code)) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert out == [200] * 4 and len(calls) == 1

    # editing a rule invalidates the entry
    (root / "rules" / one).write_text((root / "rules" / one).read_text(encoding="utf-8") + "\n# x\n", encoding="utf-8")
    assert c.get("/api/drift?ref=HEAD").json()["summary"]["modified"] == 1 and len(calls) == 2


def test_drift_cache_expires_after_60s(user_repo, monkeypatch):
    from vitrix import drift as drift_mod
    from vitrix.config import load_config

    drift_mod._cache.clear()
    committed(user_repo)
    cfg = load_config(str(user_repo))
    n = []
    real = drift_mod._drift
    monkeypatch.setattr(drift_mod, "_drift", lambda *a, **k: (n.append(1), real(*a, **k))[1])
    t = [0.0]
    drift_mod.drift(cfg, "HEAD", clock=lambda: t[0])
    t[0] = 30
    drift_mod.drift(cfg, "HEAD", clock=lambda: t[0])
    assert len(n) == 1
    t[0] = 61
    drift_mod.drift(cfg, "HEAD", clock=lambda: t[0])
    assert len(n) == 2
