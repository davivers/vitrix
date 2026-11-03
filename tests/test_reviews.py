"""Workspace reviews and comments (ADR 0005): store, routes, roles, staleness, auth-off behaviour."""

from __future__ import annotations

import pytest
from test_auth import invite_token, register
from test_engine import RULE_OK, make_project

from vitrix.reviews import MAX_COMMENTS_PER_TARGET, MAX_OPEN_PER_REQUESTER, ReviewError, ReviewStore

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from vitrix.api import create_app  # noqa: E402

BASE = "http://127.0.0.1:8000"
AUTH_ON = "auth:\n  enabled: true\n"
RULE_ID = "r.yml"  # make_project writes rules/r.yml
ME = {"id": 1, "email": "a@x", "name": "A"}
YOU = {"id": 2, "email": "b@x", "name": "B"}


def team(tmp_path, extra: str = AUTH_ON):
    owner = TestClient(create_app(make_project(tmp_path, extra_cfg=extra)), base_url=BASE)
    assert register(owner).status_code == 201
    out = {"owner": owner}
    for name, role in (("ed1", "editor"), ("ed2", "editor"), ("view", "viewer")):
        email = f"{name}@example.com"
        c = TestClient(owner.app, base_url=BASE)
        assert register(c, email=email, name=name.title(), invite=invite_token(owner, email, role)).status_code == 201
        out[name] = c
    ids = {m["email"].split("@")[0]: m["id"] for m in owner.get("/api/workspace").json()["members"]}
    return out, ids


def request_review(c, ids, reviewer="ed2", kind="rule", ref=RULE_ID, note=None):
    return c.post("/api/reviews", json={"target_kind": kind, "target_ref": ref, "reviewer_id": ids[reviewer], "note": note})


def new_draft(c, text=RULE_OK, path="windows/d.yml"):
    r = c.post("/api/drafts", json={"path": path, "rule": text})
    assert r.status_code == 201, r.text
    return r.json()


def edit_rule(tmp_path):
    (tmp_path / "rules" / "r.yml").write_text(RULE_OK + "\n# edited\n", encoding="utf-8")


def store_request(s, ref="a.yml"):
    return s.request(kind="rule", ref=ref, title="T", target_hash="h1", target_version=None, requester=ME, reviewer=YOU, note=None)


# --------------------------------------------------------------------------- store


def test_store_is_lazy_and_transitions(tmp_path):
    db = tmp_path / "x" / "reviews.db"
    s = ReviewStore(db)
    assert s.list() == [] and s.comments("rule", "a") == [] and s.counts(1) == {"to_review": 0, "requested": 0} and not db.exists()
    r = store_request(s)
    assert db.is_file() and r["state"] == "pending" and r["version"] == 1
    with pytest.raises(ReviewError) as e:
        store_request(s)
    assert e.value.status == 409
    with pytest.raises(ReviewError) as e:
        s.decide(r["id"], decision="approved", note=None, version=1, current_hash="other")
    assert e.value.status == 409 and "changed" in str(e.value)
    with pytest.raises(ReviewError):
        s.decide(r["id"], decision="approved", note=None, version=7, current_hash="h1")
    done = s.decide(r["id"], decision="approved", note="ok", version=1, current_hash="h1")
    assert done["state"] == "approved" and done["version"] == 2 and done["decided_at"]
    assert [x["reviewer_email"] for x in s.approved("rule", "a.yml", "h1")] == ["b@x"] and s.approved("rule", "a.yml", "zz") == []
    with pytest.raises(ReviewError):
        s.decide(r["id"], decision="approved", note=None, version=2, current_hash="h1")  # no longer pending


def test_store_open_request_limit(tmp_path):
    s = ReviewStore(tmp_path / "r.db")
    for i in range(MAX_OPEN_PER_REQUESTER):
        store_request(s, f"{i}.yml")
    with pytest.raises(ReviewError) as e:
        store_request(s, "over.yml")
    assert e.value.status == 409
    assert s.counts(1)["requested"] == MAX_OPEN_PER_REQUESTER and s.counts(2)["to_review"] == MAX_OPEN_PER_REQUESTER


def test_store_comment_limit(tmp_path):
    s = ReviewStore(tmp_path / "r.db")
    for _ in range(MAX_COMMENTS_PER_TARGET):
        s.add_comment(kind="rule", ref="a.yml", body="x", author=ME, target_hash=None)
    with pytest.raises(ReviewError) as e:
        s.add_comment(kind="rule", ref="a.yml", body="x", author=ME, target_hash=None)
    assert e.value.status == 409


# --------------------------------------------------------------------------- availability


def test_auth_off_lists_disabled_and_writes_403(tmp_path, monkeypatch):
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    c = TestClient(create_app(make_project(tmp_path)), base_url=BASE)
    for url, key in (("/api/reviews", "reviews"), ("/api/comments?kind=rule&ref=r.yml", "comments")):
        j = c.get(url).json()
        assert j["enabled"] is False and "accounts" in j["reason"] and j[key] == []
    assert c.get("/api/reviews/counts").json()["enabled"] is False
    assert c.post("/api/comments", json={"target_kind": "rule", "target_ref": RULE_ID, "body": "x"}).status_code == 403
    assert c.post("/api/reviews", json={"target_kind": "rule", "target_ref": RULE_ID, "reviewer_id": 1}).status_code == 403
    assert c.get("/api/reviews/reviewers").status_code == 403
    assert not (tmp_path / ".vitrix" / "reviews.db").exists()


def test_reviews_disabled_in_config(tmp_path):
    c = TestClient(create_app(make_project(tmp_path, extra_cfg=AUTH_ON + "reviews:\n  enabled: false\n")), base_url=BASE)
    assert register(c).status_code == 201
    j = c.get("/api/reviews").json()
    assert j["enabled"] is False and "reviews.enabled" in j["reason"]
    assert c.post("/api/comments", json={"target_kind": "rule", "target_ref": RULE_ID, "body": "x"}).status_code == 403


# --------------------------------------------------------------------------- reviews


def test_full_review_flow_on_a_rule(tmp_path):
    t, ids = team(tmp_path)
    assert {r["email"] for r in t["ed1"].get("/api/reviews/reviewers").json()} == {"owner@example.com", "ed2@example.com"}  # editors+, not me
    r = request_review(t["ed1"], ids, note="please look")
    assert r.status_code == 201, r.text
    rev = r.json()
    assert rev["state"] == "pending" and rev["mine_requested"] and not rev["mine_to_review"] and rev["stale"] is False
    assert rev["target"]["kind"] == "rule" and rev["target"]["missing"] is False and rev["governance"]["owner"] is None
    assert t["ed2"].get("/api/reviews/counts").json() == {"enabled": True, "reason": None, "to_review": 1, "requested": 0}
    assert t["ed1"].get("/api/reviews/counts").json()["requested"] == 1
    assert [x["id"] for x in t["ed2"].get("/api/reviews").json()["reviews"]] == [rev["id"]]
    assert t["ed1"].get("/api/reviews").json()["reviews"] == []
    assert [x["id"] for x in t["ed1"].get("/api/reviews?scope=requested").json()["reviews"]] == [rev["id"]]
    assert [x["id"] for x in t["view"].get(f"/api/reviews?scope=all&kind=rule&ref={RULE_ID}").json()["reviews"]] == [rev["id"]]
    assert t["view"].get(f"/api/reviews/{rev['id']}").json()["comments"] == []

    d = f"/api/reviews/{rev['id']}/decision"
    assert t["ed1"].post(d, json={"decision": "approved", "version": 1}).status_code == 403  # not the reviewer
    assert t["owner"].post(d, json={"decision": "approved", "version": 1}).status_code == 403
    assert t["ed2"].post(d, json={"decision": "approved", "version": 9}).status_code == 409
    done = t["ed2"].post(d, json={"decision": "changes_requested", "note": "fix it", "version": 1})
    assert done.status_code == 200 and done.json()["state"] == "changes_requested" and done.json()["decision_note"] == "fix it"
    assert t["ed2"].get("/api/reviews/counts").json()["to_review"] == 0 and t["ed1"].get("/api/reviews/counts").json()["requested"] == 1
    assert t["ed2"].post(f"/api/reviews/{rev['id']}/rerequest", json={"version": 2}).status_code == 403
    again = t["ed1"].post(f"/api/reviews/{rev['id']}/rerequest", json={"version": 2})
    assert again.status_code == 200 and again.json()["state"] == "pending" and again.json()["decision_note"] is None
    ok = t["ed2"].post(d, json={"decision": "approved", "version": 3})
    assert ok.status_code == 200 and ok.json()["state"] == "approved"
    assert t["ed1"].post(f"/api/reviews/{rev['id']}/cancel", json={"version": 4}).status_code == 409  # approved is final


def test_cannot_request_own_review_or_a_viewer_and_duplicates(tmp_path):
    t, ids = team(tmp_path)
    mine = t["ed1"].post("/api/reviews", json={"target_kind": "rule", "target_ref": RULE_ID, "reviewer_id": ids["ed1"]})
    assert mine.status_code == 422 and mine.json()["detail"] == "You cannot review your own request."
    viewer = request_review(t["ed1"], ids, reviewer="view")
    assert viewer.status_code == 422 and "editor" in viewer.json()["detail"]
    assert t["ed1"].post("/api/reviews", json={"target_kind": "rule", "target_ref": RULE_ID, "reviewer_id": 9999}).status_code == 422
    assert request_review(t["ed1"], ids).status_code == 201
    assert request_review(t["ed1"], ids).status_code == 409
    assert request_review(t["ed1"], ids, ref="missing.yml").status_code == 404
    assert request_review(t["ed1"], ids, ref="../etc/passwd").status_code == 404
    assert request_review(t["ed1"], ids, kind="draft", ref="a" * 32).status_code == 404
    assert t["view"].post("/api/reviews", json={"target_kind": "rule", "target_ref": RULE_ID, "reviewer_id": ids["ed2"]}).status_code == 403


def test_decision_on_a_changed_rule_is_409_then_rerequest_refreshes(tmp_path):
    t, ids = team(tmp_path)
    rev = request_review(t["ed1"], ids).json()
    edit_rule(tmp_path)
    assert t["ed1"].get(f"/api/reviews/{rev['id']}").json()["stale"] is True
    r = t["ed2"].post(f"/api/reviews/{rev['id']}/decision", json={"decision": "approved", "version": 1})
    assert r.status_code == 409 and "changed" in r.json()["detail"]
    fresh = t["ed1"].post(f"/api/reviews/{rev['id']}/rerequest", json={"version": 1}).json()
    assert fresh["stale"] is False
    assert t["ed2"].post(f"/api/reviews/{rev['id']}/decision", json={"decision": "approved", "version": fresh["version"]}).status_code == 200


def test_draft_reviews_cancel_and_missing_target(tmp_path):
    t, ids = team(tmp_path)
    d = new_draft(t["ed1"])
    rev = request_review(t["ed1"], ids, kind="draft", ref=d["id"]).json()
    assert rev["target"]["title"] == d["title"] and rev["governance"] is None
    assert t["ed2"].post(f"/api/reviews/{rev['id']}/cancel", json={"version": 1}).status_code == 403
    t["ed1"].delete(f"/api/drafts/{d['id']}")
    j = t["ed2"].get(f"/api/reviews/{rev['id']}").json()
    assert j["target"]["missing"] is True and j["state"] == "pending"
    assert t["owner"].post(f"/api/reviews/{rev['id']}/cancel", json={"version": 1}).status_code == 200  # admin+
    assert t["ed2"].get("/api/reviews").json()["reviews"] == []  # the default "open" filter hides cancelled
    assert len(t["ed2"].get("/api/reviews?state=cancelled").json()["reviews"]) == 1


def test_validation(tmp_path):
    t, ids = team(tmp_path)
    assert t["ed1"].get("/api/reviews/" + "a" * 32).status_code == 404
    assert t["ed1"].post("/api/reviews", json={"target_kind": "other", "target_ref": "x", "reviewer_id": 1}).status_code == 422
    assert t["ed1"].post("/api/reviews", json={"target_kind": "rule", "target_ref": "x" * 301, "reviewer_id": 1}).status_code == 422
    too_long = {"target_kind": "rule", "target_ref": RULE_ID, "reviewer_id": ids["ed2"], "note": "n" * 2001}
    assert t["ed1"].post("/api/reviews", json=too_long).status_code == 422
    assert t["ed1"].get("/api/reviews?scope=bogus").status_code == 422


# --------------------------------------------------------------------------- comments


def test_comments_roles_edit_delete_and_outdated(tmp_path):
    t, ids = team(tmp_path)
    body = {"target_kind": "rule", "target_ref": RULE_ID, "body": "false positive on backups?"}
    c = t["view"].post("/api/comments", json=body)  # viewers may comment
    assert c.status_code == 201, c.text
    cj = c.json()
    assert cj["mine"] and cj["outdated"] is False and cj["review_id"] is None
    assert t["ed1"].post("/api/comments", json={**body, "target_ref": "nope.yml"}).status_code == 404
    assert t["ed1"].post("/api/comments", json={**body, "body": ""}).status_code == 422
    assert t["ed1"].post("/api/comments", json={**body, "body": "x" * 5001}).status_code == 422
    listed = t["ed1"].get(f"/api/comments?kind=rule&ref={RULE_ID}").json()["comments"]
    assert [x["id"] for x in listed] == [cj["id"]] and listed[0]["mine"] is False
    assert t["ed1"].patch(f"/api/comments/{cj['id']}", json={"body": "hijack"}).status_code == 403
    edited = t["view"].patch(f"/api/comments/{cj['id']}", json={"body": "edited"})
    assert edited.status_code == 200 and edited.json()["body"] == "edited" and edited.json()["edited_at"]
    edit_rule(tmp_path)
    assert t["ed1"].get(f"/api/comments?kind=rule&ref={RULE_ID}").json()["comments"][0]["outdated"] is True
    assert t["ed2"].delete(f"/api/comments/{cj['id']}").status_code == 403
    assert t["owner"].delete(f"/api/comments/{cj['id']}").status_code == 204  # admin+
    gone = t["ed1"].get(f"/api/comments?kind=rule&ref={RULE_ID}").json()["comments"][0]
    assert gone["deleted"] is True and gone["body"] == ""
    assert t["view"].patch(f"/api/comments/{cj['id']}", json={"body": "again"}).status_code == 404
    assert t["view"].delete("/api/comments/" + "b" * 32).status_code == 404
    assert t["ed1"].get("/api/comments").status_code == 422  # kind and ref are required


def test_comment_on_a_review_thread(tmp_path):
    t, ids = team(tmp_path)
    rev = request_review(t["ed1"], ids).json()
    c = t["ed2"].post("/api/comments", json={"target_kind": "rule", "target_ref": RULE_ID, "body": "question", "review_id": rev["id"]})
    assert c.status_code == 201 and c.json()["review_id"] == rev["id"]
    t["ed1"].post("/api/comments", json={"target_kind": "rule", "target_ref": RULE_ID, "body": "unrelated"})
    assert [x["body"] for x in t["ed1"].get(f"/api/reviews/{rev['id']}").json()["comments"]] == ["question"]
    other = {"target_kind": "draft", "target_ref": new_draft(t["ed2"])["id"], "body": "x", "review_id": rev["id"]}
    assert t["ed2"].post("/api/comments", json=other).status_code == 422
    assert t["ed2"].post("/api/comments", json={"target_kind": "rule", "target_ref": RULE_ID, "body": "x", "review_id": "z" * 32}).status_code == 422


def test_crlf_and_bom_do_not_make_a_review_stale(tmp_path):
    from vitrix.drafts import content_hash

    assert content_hash("a\r\nb\rc") == content_hash("a\nb\nc") == content_hash("\ufeffa\nb\nc")
    t, ids = team(tmp_path)
    rev = request_review(t["ed1"], ids).json()
    (tmp_path / "rules" / "r.yml").write_bytes(b"\xef\xbb\xbf" + RULE_OK.replace("\n", "\r\n").encode())
    assert t["ed1"].get(f"/api/reviews/{rev['id']}").json()["stale"] is False
    assert t["ed2"].post(f"/api/reviews/{rev['id']}/decision", json={"decision": "approved", "version": 1}).status_code == 200
