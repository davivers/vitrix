"""POST /api/ci/drafts: publish several drafts as one `vitrix/pack-...` branch (fake GitHub transport)."""

from __future__ import annotations

import pytest
from test_auth import invite_token, register
from test_engine import CASES_OK, RULE_OK, make_project
from test_github import GITHUB_CFG, FakeGitHub

from vitrix import service
from vitrix.github import GitHubClient

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from vitrix.api import create_app  # noqa: E402

BASE = "http://127.0.0.1:8000"
LOOPBACK = ("127.0.0.1", 50000)


def rule(n: int) -> str:
    return RULE_OK.replace("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", f"aaaaaaaa-aaaa-4aaa-8aaa-{n:012d}")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    fake = FakeGitHub()
    monkeypatch.setattr(service, "GitHubClient", lambda gh: GitHubClient(gh, transport=fake))
    monkeypatch.setenv("VITRIX_GITHUB_TOKEN", "test-secret")
    client = TestClient(create_app(make_project(tmp_path, extra_cfg=GITHUB_CFG)), base_url=BASE, client=LOOPBACK)
    return client, fake


def save(client, path, text=None, cases=CASES_OK, n=1) -> str:
    r = client.post("/api/drafts", json={"path": path, "rule": text or rule(n), "cases": cases})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_batch_publish_one_pack_branch_without_a_pr(env):
    client, fake = env
    ids = [save(client, "windows/a.yml", n=1), save(client, "windows/b.yml", n=2)]
    r = client.post("/api/ci/drafts", json={"draft_ids": ids, "title": "feat: two rules"})
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["branch"].startswith("vitrix/pack-") and out["title"] == "feat: two rules"
    assert len(out["files"]) == 4 and not fake.posted("/pulls")
    tree = fake.body_of("/git/trees")["tree"]
    assert {t["path"] for t in tree} == set(out["files"])
    assert sum(1 for m, u, _ in fake.calls if m == "POST" and u.endswith("/git/commits")) == 1


def test_one_blocked_draft_blocks_the_whole_batch(env):
    client, fake = env
    good = save(client, "windows/a.yml")
    bad = save(client, "windows/b.yml", text="title: nope\n", n=2)
    nopath = client.post("/api/drafts", json={"rule": rule(3)}).json()["id"]
    r = client.post("/api/ci/drafts", json={"draft_ids": [good, bad, nopath]})
    assert r.status_code == 422
    body = r.json()
    assert body["detail"] == "2 drafts are blocked by the local quality gate"
    assert {b["id"] for b in body["blocked"]} == {bad, nopath} and all(b["reasons"] for b in body["blocked"])
    assert not fake.calls  # nothing pushed (not even a read)


def test_same_path_twice_is_blocked(env):
    client, _ = env
    ids = [save(client, "windows/a.yml", n=1), save(client, "windows/a.yml", n=2)]
    r = client.post("/api/ci/drafts", json={"draft_ids": ids})
    assert r.status_code == 422 and len(r.json()["blocked"]) == 1


def test_validation_limits_and_unknown_draft(env):
    client, _ = env
    assert client.post("/api/ci/drafts", json={"draft_ids": []}).status_code == 422
    assert client.post("/api/ci/drafts", json={"draft_ids": ["a" * 32] * 51}).status_code == 422
    assert client.post("/api/ci/drafts", json={"draft_ids": ["not-an-id"]}).status_code == 422
    assert client.post("/api/ci/drafts", json={"draft_ids": ["a" * 32]}).status_code == 404


def test_without_github_nothing_is_sent(tmp_path, monkeypatch):
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    client = TestClient(create_app(make_project(tmp_path)), base_url=BASE, client=LOOPBACK)
    i = save(client, "windows/a.yml")
    assert client.post("/api/ci/drafts", json={"draft_ids": [i]}).status_code == 503


def _team_with_github(tmp_path, monkeypatch):
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    fake = FakeGitHub()
    monkeypatch.setattr(service, "GitHubClient", lambda gh: GitHubClient(gh, transport=fake))
    monkeypatch.setenv("VITRIX_GITHUB_TOKEN", "test-secret")
    owner = TestClient(create_app(make_project(tmp_path, extra_cfg=GITHUB_CFG + "auth:\n  enabled: true\n")), base_url=BASE)
    assert register(owner).status_code == 201
    out = {"owner": owner}
    for name in ("ed1", "ed2"):
        c = TestClient(owner.app, base_url=BASE)
        email = f"{name}@example.com"
        assert register(c, email=email, name=name, invite=invite_token(owner, email, "editor")).status_code == 201
        out[name] = c
    ids = {m["email"].split("@")[0]: m["id"] for m in owner.get("/api/workspace").json()["members"]}
    return out, ids, fake


def test_drafts_of_another_author_cannot_be_submitted(tmp_path, monkeypatch):
    t, ids, fake = _team_with_github(tmp_path, monkeypatch)  # drafts are private (ADR 0007): no cross-author batches
    a = save(t["ed1"], "windows/a.yml", n=1)
    b = save(t["ed2"], "windows/b.yml", n=2)
    assert t["owner"].post("/api/ci/drafts", json={"draft_ids": [a, b]}).status_code == 404
    assert t["ed1"].post("/api/ci/drafts", json={"draft_ids": [a, b]}).status_code == 404
    assert t["ed1"].post("/api/ci/drafts", json={"draft_ids": [a]}).status_code == 201
