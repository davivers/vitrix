"""Local rules as files (ADR 0007): writer guards, optimistic sha, publication flag from git, publish from file."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest
from test_engine import CASES_OK, RULE_OK, make_project

from vitrix import local_rules, publication
from vitrix.config import load_config

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from vitrix.api import create_app  # noqa: E402

BASE = "http://127.0.0.1:8000"
LOOPBACK = ("127.0.0.1", 50000)
HAS_GIT = shutil.which("git") is not None


def git(root, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "A", "GIT_AUTHOR_EMAIL": "a@x", "GIT_COMMITTER_NAME": "A", "GIT_COMMITTER_EMAIL": "a@x"}
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env, text=True).stdout


def client(tmp_path, monkeypatch, extra="", **kw):
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    publication.invalidate()
    return TestClient(create_app(make_project(tmp_path, extra_cfg=extra, **kw)), base_url=BASE, client=LOOPBACK)


NEW = RULE_OK.replace("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "dddddddd-dddd-4ddd-8ddd-dddddddddddd")


# --------------------------------------------------------------------------- writer


def test_create_update_delete_roundtrip_with_sha_lock(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    r = c.post("/api/rules", json={"path": "windows/new.yml", "rule": NEW, "cases": CASES_OK})
    assert r.status_code == 201, r.text
    made = r.json()
    assert made["id"] == "windows/new.yml" and len(made["sha"]) == 64 and len(made["cases_sha"]) == 64
    assert (tmp_path / "rules" / "windows" / "new.yml").read_bytes().endswith(b"\n") and b"\r" not in (tmp_path / "cases" / "windows" / "new.yml").read_bytes()
    assert c.post("/api/rules", json={"path": "windows/new.yml", "rule": NEW}).status_code == 409
    assert c.post("/api/rules", json={"path": "windows/NEW.yml", "rule": NEW}).status_code in (201, 409)  # case-insensitive FS: 409
    # update needs the sha we loaded
    body = {"rule": NEW + "# v2\n", "sha": made["sha"], "cases_sha": made["cases_sha"]}
    u = c.put("/api/rules/windows/new.yml", json=body)
    assert u.status_code == 200 and u.json()["sha"] != made["sha"] and "# v2" in (tmp_path / "rules" / "windows" / "new.yml").read_text()
    assert c.put("/api/rules/windows/new.yml", json=body).status_code == 409  # stale sha
    assert c.put("/api/rules/missing.yml", json=body).status_code == 404
    # cases: null leaves them alone, remove_cases deletes
    fresh = u.json()
    keep = c.put("/api/rules/windows/new.yml", json={"rule": NEW, "sha": fresh["sha"], "cases": None})
    assert keep.status_code == 200 and (tmp_path / "cases" / "windows" / "new.yml").is_file()
    gone = c.put("/api/rules/windows/new.yml", json={"rule": NEW, "sha": keep.json()["sha"], "remove_cases": True, "cases_sha": keep.json()["cases_sha"]})
    assert gone.status_code == 200 and gone.json()["cases_sha"] is None and not (tmp_path / "cases" / "windows" / "new.yml").exists()
    # delete (unpublished): sha required, 204
    assert c.delete("/api/rules/windows/new.yml?sha=" + "0" * 64).status_code == 409
    assert c.delete("/api/rules/windows/new.yml?sha=" + gone.json()["sha"]).status_code == 204
    assert not (tmp_path / "rules" / "windows" / "new.yml").exists()
    assert not list((tmp_path / "rules").rglob("*.tmp"))


@pytest.mark.parametrize("path", ["../x.yml", "/abs.yml", "a/../../x.yml", "x.txt", ".hidden.yml", "con.yml", "a/nul.yaml", "x.yml.", "a/b/c/d/e/f/g/h/i.yml", "y" * 301 + ".yml"])
def test_bad_paths_are_422(tmp_path, monkeypatch, path):
    c = client(tmp_path, monkeypatch)
    assert c.post("/api/rules", json={"path": path, "rule": NEW}).status_code == 422
    assert not any(p.name.endswith(".tmp") for p in tmp_path.rglob("*"))


def test_invalid_yaml_and_size_limits(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    r = c.post("/api/rules", json={"path": "bad.yml", "rule": "title: [unclosed\n"})
    assert r.status_code == 422 and r.json()["detail"]["issues"] and "not valid YAML" in r.json()["detail"]["message"]
    assert c.post("/api/rules", json={"path": "list.yml", "rule": "- a\n- b\n"}).status_code == 422  # not a mapping
    assert c.post("/api/rules", json={"path": "ok.yml", "rule": NEW, "cases": "a: [\n"}).status_code == 422
    big = "title: x\n" + "# " + "a" * 300_000 + "\n"
    assert c.post("/api/rules", json={"path": "big.yml", "rule": big}).status_code == 422
    assert not (tmp_path / "rules" / "bad.yml").exists()
    # lint errors do not block saving (they block publishing)
    assert c.post("/api/rules", json={"path": "lintbad.yml", "rule": "title: only a title\n"}).status_code == 201


def test_symlink_components_are_refused(tmp_path, monkeypatch):
    cfg = load_config(make_project(tmp_path))
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, tmp_path / "rules" / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    with pytest.raises(local_rules.LocalRuleError) as e:
        local_rules.create(cfg, "link/x.yml", NEW, None)
    assert "links are not allowed" in str(e.value)
    assert not (outside / "x.yml").exists()


def test_off_when_disabled_or_remote_client(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch, extra="local_rules:\n  enabled: false\n")
    r = c.post("/api/rules", json={"path": "a.yml", "rule": NEW})
    assert r.status_code == 403 and "local_rules.enabled" in r.json()["detail"]
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    remote = TestClient(create_app(make_project(tmp_path / "x" if False else tmp_path)), base_url=BASE, client=("203.0.113.9", 4000))
    assert remote.post("/api/rules", json={"path": "a.yml", "rule": NEW}).status_code == 403


def test_readonly_filesystem_is_503(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)

    def boom(*a, **k):
        raise PermissionError("read-only")

    monkeypatch.setattr(local_rules.os, "replace", boom)
    r = c.post("/api/rules", json={"path": "ro.yml", "rule": NEW})
    assert r.status_code == 503 and r.json()["detail"] == "the rules folder is not writable"


# --------------------------------------------------------------------------- publication from git


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_publication_states_against_a_bare_origin(tmp_path, monkeypatch):
    origin = tmp_path / "origin.git"
    work = tmp_path / "work"
    work.mkdir()
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    c = client(work, monkeypatch)
    git(work, "init", "-q", "-b", "main")
    # no commits yet: rules are local (untracked) and nothing is invented
    pm = c.get("/api/rules").json()
    assert pm[0]["publication"]["state"] == "local" and pm[0]["publication"]["git"] == "untracked"
    git(work, "add", ".")
    git(work, "commit", "-q", "-m", "init")
    git(work, "remote", "add", "origin", str(origin))
    git(work, "push", "-q", "origin", "main")
    git(work, "fetch", "-q", "origin")
    publication.invalidate()
    one = c.get("/api/rules/r.yml").json()
    assert one["publication"]["state"] == "published" and one["publication"]["base_ref"] == "origin/main" and one["sha"]
    # a new local rule, then an edit of a published one
    made = c.post("/api/rules", json={"path": "n.yml", "rule": NEW, "cases": CASES_OK}).json()
    assert made["publication"]["state"] == "local" and made["publication"]["change"] == "added" and made["publication"]["git"] == "untracked"
    edit = c.put("/api/rules/r.yml", json={"rule": RULE_OK + "# tweak\n", "sha": one["sha"], "cases_sha": one["cases_sha"]}).json()
    assert edit["publication"]["state"] == "local" and edit["publication"]["change"] == "modified" and edit["publication"]["git"] == "modified"
    assert {r["id"] for r in c.get("/api/rules?publication=local").json()} == {"n.yml", "r.yml"}
    assert {r["id"] for r in c.get("/api/rules?publication=unmerged").json()} == {"n.yml", "r.yml"}
    # committed locally but not on origin
    git(work, "add", "n.yml".replace("n.yml", "rules/n.yml"), "cases/n.yml")
    git(work, "commit", "-q", "-m", "local")
    publication.invalidate()
    assert c.get("/api/rules/n.yml").json()["publication"]["git"] == "committed"
    # pushed to a vitrix/* branch (fetched): "pushed", and "in_pr" when the cached activity knows the PR
    git(work, "push", "-q", "origin", "main:refs/heads/vitrix/n-abc123")
    git(work, "fetch", "-q", "origin")
    publication.invalidate()
    p = c.get("/api/rules/n.yml").json()["publication"]
    assert p["state"] == "pushed" and p["branch"] == "vitrix/n-abc123" and p["pr"] is None
    from vitrix import service

    service._activity_cache[("o/r", "main")] = (0.0, {"pulls": {"items": [{"branch": "vitrix/n-abc123", "number": 7, "url": "https://github.com/o/r/pull/7"}]}})
    publication.invalidate()
    try:
        p = c.get("/api/rules/n.yml").json()["publication"]
        assert p["state"] == "in_pr" and p["pr"]["number"] == 7
    finally:
        service._activity_cache.clear()
    # published rules cannot be deleted; unpublished (r.yml modified is still published in base)
    sha = c.get("/api/rules/r.yml").json()["sha"]
    d = c.delete(f"/api/rules/r.yml?sha={sha}")
    assert d.status_code == 409 and d.json()["detail"] == "Published rules are removed through a pull request."
    assert (work / "rules" / "r.yml").is_file()


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_not_a_repo_is_unknown_with_reason(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    pub = c.get("/api/rules").json()[0]["publication"]
    assert pub["state"] == "unknown" and pub["reason"] == "not a git repository"
    # the app never stages or commits
    assert not (tmp_path / ".git").exists()


# --------------------------------------------------------------------------- publish from the saved file


def test_publish_source_file_checks_sha_and_reads_disk(tmp_path, monkeypatch):
    from test_github import GITHUB_CFG, FakeGitHub, client_for

    c = client(tmp_path, monkeypatch, extra=GITHUB_CFG)
    saved = c.post("/api/rules", json={"path": "n.yml", "rule": NEW, "cases": CASES_OK}).json()
    fake = FakeGitHub()
    from vitrix import service

    cfg = load_config(str(tmp_path / "vitrix.yml"))
    monkeypatch.setattr(service, "GitHubClient", lambda gh: client_for(cfg, fake))
    bad = c.post("/api/ci/rules", json={"source": "file", "path": "n.yml", "sha": "0" * 64, "cases_sha": saved["cases_sha"]})
    assert bad.status_code == 409
    both = c.post("/api/ci/rules", json={"source": "file", "path": "n.yml", "sha": saved["sha"], "rule": NEW})
    assert both.status_code == 422
    ok = c.post("/api/ci/rules", json={"source": "file", "path": "n.yml", "sha": saved["sha"], "cases_sha": saved["cases_sha"]})
    assert ok.status_code == 201, ok.text
    assert ok.json()["sha"] == saved["sha"] and ok.json()["is_new"] is True
    assert c.post("/api/ci/rules", json={"path": "n.yml"}).status_code == 422  # text mode needs rule


def test_batch_publish_local_rules_and_blocked_422(tmp_path, monkeypatch):
    from test_github import GITHUB_CFG, FakeGitHub, client_for

    from vitrix import service

    c = client(tmp_path, monkeypatch, extra=GITHUB_CFG)
    cfg = load_config(str(tmp_path / "vitrix.yml"))
    monkeypatch.setattr(service, "GitHubClient", lambda gh: client_for(cfg, FakeGitHub()))
    c.post("/api/rules", json={"path": "n.yml", "rule": NEW, "cases": CASES_OK})
    c.post("/api/rules", json={"path": "bad.yml", "rule": "title: only a title\n"})
    blocked = c.post("/api/ci/local-rules", json={"paths": ["n.yml", "bad.yml"]})
    assert blocked.status_code == 422 and blocked.json()["blocked"][0]["id"] == "bad.yml"
    ok = c.post("/api/ci/local-rules", json={"paths": ["n.yml"]})
    assert ok.status_code == 201 and any(f.endswith("n.yml") for f in ok.json()["files"])
    assert c.post("/api/ci/local-rules", json={"paths": ["nope.yml"]}).status_code == 404


def test_python_version_marker():
    assert sys.version_info >= (3, 10)


# --------------------------------------------------------------------------- code review S4-2 .. S4-6


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_many_vitrix_branches_cost_a_constant_number_of_git_processes(tmp_path, monkeypatch):
    origin = tmp_path / "origin.git"
    work = tmp_path / "work"
    work.mkdir()
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    c = client(work, monkeypatch)
    git(work, "init", "-q", "-b", "main")
    git(work, "add", ".")
    git(work, "commit", "-q", "-m", "init")
    git(work, "remote", "add", "origin", str(origin))
    git(work, "push", "-q", "origin", "main")
    made = c.post("/api/rules", json={"path": "n.yml", "rule": NEW, "cases": CASES_OK}).json()
    git(work, "add", "rules/n.yml", "cases/n.yml")
    git(work, "commit", "-q", "-m", "n")
    for i in range(40):
        git(work, "push", "-q", "origin", f"main:refs/heads/vitrix/b{i:02}")
    git(work, "fetch", "-q", "origin")
    publication.invalidate()
    calls = []
    real_run = subprocess.run

    def counting(*a, **k):
        calls.append(a[0])
        return real_run(*a, **k)

    monkeypatch.setattr(subprocess, "run", counting)
    p = c.get("/api/rules/n.yml").json()["publication"]
    assert p["state"] == "pushed" and p["branch"].startswith("vitrix/b")
    assert made["sha"] and len(calls) < 25, len(calls)  # was ~2 per branch (80+)
    calls.clear()
    publication.invalidate()
    assert {r["id"]: r["publication"]["state"] for r in c.get("/api/rules").json()}["n.yml"] == "pushed"
    assert len(calls) < 30, len(calls)


def test_create_without_cases_refuses_a_leftover_cases_file(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    (tmp_path / "cases" / "w").mkdir(parents=True)
    (tmp_path / "cases" / "w" / "n.yml").write_text("garbage: [\n", encoding="utf-8")
    r = c.post("/api/rules", json={"path": "w/n.yml", "rule": NEW})
    assert r.status_code == 409 and "already exists" in r.json()["detail"]
    assert not (tmp_path / "rules" / "w" / "n.yml").exists()


def test_publishing_checks_that_cases_on_disk_are_yaml(tmp_path, monkeypatch):
    from test_github import GITHUB_CFG

    c = client(tmp_path, monkeypatch, extra=GITHUB_CFG)
    saved = c.post("/api/rules", json={"path": "n.yml", "rule": NEW, "cases": CASES_OK}).json()
    (tmp_path / "cases" / "n.yml").write_text("garbage: [\n", encoding="utf-8")  # edited outside the app
    cases_sha = local_rules.sha_of((tmp_path / "cases" / "n.yml").read_bytes())
    r = c.post("/api/ci/rules", json={"source": "file", "path": "n.yml", "sha": saved["sha"], "cases_sha": cases_sha})
    assert r.status_code == 422 and "cases" in r.json()["detail"]["message"]
    assert c.post("/api/ci/local-rules", json={"paths": ["n.yml"]}).status_code == 422


def test_case_only_folder_collision_is_refused_with_the_real_path(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    assert c.post("/api/rules", json={"path": "windows/a.yml", "rule": NEW}).status_code == 201
    r = c.post("/api/rules", json={"path": "Windows/b.yml", "rule": NEW})
    assert r.status_code == 409 and "rules/windows" in r.json()["detail"]
    assert [p.name for p in (tmp_path / "rules").iterdir() if p.is_dir()] == ["windows"]
    assert c.post("/api/rules", json={"path": "windows/b.yml", "rule": NEW}).status_code == 201


@pytest.mark.parametrize("key", ["rules_dir", "cases_dir", "datasets_dir", "output_dir"])
@pytest.mark.parametrize("value", ["../elsewhere", "a/../../x", "C:/Users/svc/.ssh", "/etc"])
def test_configured_folders_must_stay_inside_the_project(tmp_path, key, value):
    from vitrix.config import ConfigError

    cfg_path = tmp_path / "vitrix.yml"
    cfg_path.write_text(f"schema_version: 1\n{key}: '{value}'\n", encoding="utf-8")
    with pytest.raises(ConfigError) as e:
        load_config(str(cfg_path))
    assert "inside the project" in str(e.value)
    cfg_path.write_text(f"schema_version: 1\n{key}: sub/dir\n", encoding="utf-8")
    assert load_config(str(cfg_path))


def test_cancel_event_names_the_real_actor(tmp_path):
    from vitrix.reviews import ReviewStore

    s = ReviewStore(tmp_path / "r.db")
    me, you, admin = ({"id": 1, "email": "a@x", "name": "Ana"}, {"id": 2, "email": "b@x", "name": "Bia"}, {"id": 3, "email": "c@x", "name": "Admin Cris"})
    r = s.request(kind="rule", ref="a.yml", title="T", target_hash="h", target_version=None, requester=me, reviewer=you, note=None)
    s.cancel(r["id"], version=1, actor=admin)
    last = s.events(r["id"])[-1]
    assert last["type"] == "cancelled" and last["actor_name"] == "Admin Cris" and "Admin Cris cancelled" in last["text"]


def test_pack_import_audit_names_the_job_starter_not_the_poller(tmp_path):
    from fastapi import FastAPI

    from vitrix import packs_api
    from vitrix.pack_jobs import PackJobs

    logged = []
    jobs = PackJobs()
    cfg = load_config(make_project(tmp_path))
    app = FastAPI()
    app.include_router(packs_api.build_router(cfg, off=lambda r: None, auth_on=False, jobs=jobs, audit=lambda who, action, detail: logged.append((who, action, detail))))
    job = jobs.start("import", {"id": 5, "email": "starter@x", "name": "Starter"}, lambda j: setattr(j, "result", {"audit": "1 rules into rules/x"}), background=False)
    TestClient(app, base_url=BASE, client=LOOPBACK).get(f"/api/packs/jobs/{job.id}")
    assert logged == [("Starter", "packs.imported_local", "1 rules into rules/x")]
