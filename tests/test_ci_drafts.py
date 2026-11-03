"""POST /api/ci/drafts: publish several drafts as one `vitrix/pack-...` branch (fake GitHub transport)."""

from __future__ import annotations

import pytest
from test_auth import PW, invite_token, register
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


def test_reviewed_by_trailer_for_approved_reviews(tmp_path, monkeypatch):
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    fake = FakeGitHub()
    monkeypatch.setattr(service, "GitHubClient", lambda gh: GitHubClient(gh, transport=fake))
    monkeypatch.setenv("VITRIX_GITHUB_TOKEN", "test-secret")
    owner = TestClient(create_app(make_project(tmp_path, extra_cfg=GITHUB_CFG + "auth:\n  enabled: true\n")), base_url=BASE)
    assert register(owner).status_code == 201
    rev = TestClient(owner.app, base_url=BASE)
    assert register(rev, email="rev@example.com", name="Rita Reviewer", invite=invite_token(owner, "rev@example.com")).status_code == 201
    rev_id = next(m["id"] for m in owner.get("/api/workspace").json()["members"] if m["email"] == "rev@example.com")
    a = save(owner, "windows/a.yml", n=1)
    b = save(owner, "windows/b.yml", n=2)
    r = owner.post("/api/reviews", json={"target_kind": "draft", "target_ref": a, "reviewer_id": rev_id})
    assert r.status_code == 201, r.text
    rid, ver = r.json()["id"], r.json()["version"]
    assert rev.post(f"/api/reviews/{rid}/decision", json={"decision": "approved", "version": ver}).status_code == 200
    assert owner.post("/api/ci/drafts", json={"draft_ids": [a, b]}).status_code == 201
    message = fake.body_of("/git/commits")["message"]
    assert message.count("Reviewed-by: Rita Reviewer <rev@example.com>") == 1
    assert "Submitted-by: Olivia Owner" in message

    # changing the draft after approval drops the trailer
    d = owner.get(f"/api/drafts/{a}").json()
    owner.put(f"/api/drafts/{a}", json={"path": d["path"], "rule": d["rule"] + "\n# edited\n", "cases": d["cases"], "version": d["version"]})
    fake.calls.clear()
    assert owner.post("/api/ci/drafts", json={"draft_ids": [a]}).status_code == 201
    assert "Reviewed-by" not in fake.body_of("/git/commits")["message"]
    assert PW  # keep the shared import used


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


def test_co_authored_by_other_draft_authors_only_when_github_linked(tmp_path, monkeypatch):
    from vitrix.auth import AuthStore
    from vitrix.config import load_config

    t, ids, fake = _team_with_github(tmp_path, monkeypatch)
    a = save(t["ed1"], "windows/a.yml", n=1)
    b = save(t["ed2"], "windows/b.yml", n=2)
    c = save(t["owner"], "windows/c.yml", n=3)
    cfg = load_config(str(tmp_path / "vitrix.yml"))
    AuthStore(cfg.data_dir / "vitrix.db", cfg.auth).link_github(ids["ed1"], {"id": 4242, "login": "ed1-gh"})
    assert t["owner"].post("/api/ci/drafts", json={"draft_ids": [a, b, c]}).status_code == 201
    msg = fake.body_of("/git/commits")["message"]
    assert msg.count("Co-authored-by:") == 1 and "<4242+ed1-gh@users.noreply.github.com>" in msg  # ed2 is unlinked: no trailer
    assert "ed2@example.com" not in msg.replace("Submitted-by", "")


def test_rules_publish_keeps_draft_review_trailer(tmp_path, monkeypatch):
    t, ids, fake = _team_with_github(tmp_path, monkeypatch)
    d = save(t["ed1"], "windows/a.yml", n=1)
    r = t["ed1"].post("/api/reviews", json={"target_kind": "draft", "target_ref": d, "reviewer_id": ids["ed2"]}).json()
    assert t["ed2"].post(f"/api/reviews/{r['id']}/decision", json={"decision": "approved", "version": r["version"]}).status_code == 200
    body = {"path": "windows/a.yml", "rule": rule(1), "cases": CASES_OK}
    assert t["ed1"].post("/api/ci/rules", json=body).status_code == 201
    assert "Reviewed-by" not in fake.body_of("/git/commits")["message"]
    fake.calls.clear()
    assert t["ed1"].post("/api/ci/rules", json={**body, "draft_id": d}).status_code == 201
    assert "Reviewed-by: ed2 <ed2@example.com>" in fake.body_of("/git/commits")["message"]
