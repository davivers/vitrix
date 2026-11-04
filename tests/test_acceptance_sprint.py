"""Sprint acceptance (G1, G3, G4, G5, G6) driven end to end through the HTTP API with accounts on."""

from __future__ import annotations

import time

import pytest
from test_auth import invite_token, login, make_client, register
from test_engine import RULE_OK

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

DRAFT = {"path": None, "title": "mine", "rule": RULE_OK, "cases": None}


def uid_of(owner, email):
    return next(m["id"] for m in owner.get("/api/workspace").json()["members"] if m["email"] == email)


def join(owner, tmp_path, email, role):
    from test_auth import second_client

    browser = second_client(tmp_path, owner)
    assert register(browser, email, email.split("@")[0], invite=invite_token(owner, email, role)).status_code == 201
    return browser


def test_g6_registration_is_owner_bootstrap_then_invite_only(tmp_path):
    owner = make_client(tmp_path)
    assert owner.get("/api/auth/config").json()["registration"] == "owner-bootstrap"
    assert register(owner).status_code == 201
    cfg = owner.get("/api/auth/config").json()
    assert cfg["registration"] == "invite-only" and "allow_signup" not in cfg and cfg["bootstrap"] is False
    from test_auth import second_client

    stranger = second_client(tmp_path, owner)
    assert register(stranger, "x@example.com", "X").status_code == 403
    assert register(stranger, "x@example.com", "X", invite="not-a-real-token").status_code in (400, 403, 404, 422)
    # an invite is bound to its email
    token = invite_token(owner, "right@example.com", "editor")
    assert register(stranger, "wrong@example.com", "W", invite=token).status_code in (400, 403)
    assert register(stranger, "right@example.com", "R", invite=token).status_code == 201
    # and single use
    assert register(second_client(tmp_path, owner), "right2@example.com", "R2", invite=token).status_code in (400, 403)


def test_g5_g3_g4_role_change_lifecycle(tmp_path):
    owner = make_client(tmp_path)
    assert register(owner).status_code == 201
    ed = join(owner, tmp_path, "ed@example.com", "editor")
    cookie = ed.cookies.get("vitrix_session")
    uid = uid_of(owner, "ed@example.com")
    assert ed.post("/api/drafts", json=DRAFT).status_code == 201
    # downgrade to viewer: same cookie, still signed in
    assert owner.patch(f"/api/workspace/members/{uid}", json={"role": "viewer"}).status_code == 200
    assert ed.cookies.get("vitrix_session") == cookie
    assert ed.get("/api/auth/me").json()["user"]["role"] == "viewer"
    assert ed.get("/api/drafts").status_code == 200  # may read
    assert ed.post("/api/drafts", json=DRAFT).status_code == 403
    assert ed.post("/api/regex", json={"pattern": "a+", "samples": ["aa"]}).status_code == 200
    r = ed.post("/api/replay/draft", json={"rule": RULE_OK})
    assert r.status_code not in (401, 403)
    assert ed.get("/api/replay/datasets").status_code == 200
    assert ed.post("/api/ci/rules", json={"path": "x.yml", "rule": RULE_OK}).status_code == 403
    # upgrade back: draft saving works again, no re-login
    assert owner.patch(f"/api/workspace/members/{uid}", json={"role": "editor"}).status_code == 200
    assert ed.cookies.get("vitrix_session") == cookie
    assert ed.post("/api/drafts", json=DRAFT).status_code == 201


def test_g4_draft_ownership_admin_delete_and_removal(tmp_path):
    owner = make_client(tmp_path)
    register(owner)
    ed1, ed2 = join(owner, tmp_path, "ed1@example.com", "editor"), join(owner, tmp_path, "ed2@example.com", "editor")
    admin = join(owner, tmp_path, "adm@example.com", "admin")
    d = ed1.post("/api/drafts", json=DRAFT).json()
    assert d["mine"] is True
    assert ed2.get(f"/api/drafts/{d['id']}").status_code == 404  # private scratch (ADR 0007)
    assert ed2.put(f"/api/drafts/{d['id']}", json={**DRAFT, "version": d["version"]}).status_code == 404
    assert ed2.delete(f"/api/drafts/{d['id']}").status_code == 404
    assert admin.put(f"/api/drafts/{d['id']}", json={**DRAFT, "version": 1}).status_code == 404  # nobody edits others' drafts
    assert ed1.put(f"/api/drafts/{d['id']}", json={**DRAFT, "title": "v2", "version": 1}).json()["version"] == 2
    assert ed1.put(f"/api/drafts/{d['id']}", json={**DRAFT, "version": 1}).status_code == 409  # stale version
    assert admin.delete(f"/api/drafts/{d['id']}").status_code == 404  # not even admins see it
    assert ed1.delete(f"/api/drafts/{d['id']}").status_code == 204
    assert ed1.get(f"/api/drafts/{d['id']}").status_code == 404
    # removal revokes the session
    assert owner.delete(f"/api/workspace/members/{uid_of(owner, 'ed1@example.com')}").status_code == 200
    assert ed1.get("/api/drafts").status_code == 401
    assert login(ed1, "ed1@example.com").status_code == 401


def test_g3_anonymous_cannot_use_compute_or_drafts(tmp_path):
    owner = make_client(tmp_path)
    register(owner)
    from test_auth import second_client

    anon = second_client(tmp_path, owner)
    for method, path, body in (
        ("post", "/api/regex", {"pattern": "a", "samples": ["a"]}),
        ("post", "/api/replay/draft", {"rule": RULE_OK}),
        ("post", "/api/drafts", DRAFT),
        ("get", "/api/replay/datasets", None),
    ):
        assert getattr(anon, method)(path, **({"json": body} if body is not None else {})).status_code == 401, path


def test_g3_viewer_regex_timeout_is_still_enforced(tmp_path):
    owner = make_client(tmp_path)
    register(owner)
    viewer = join(owner, tmp_path, "v@example.com", "viewer")
    t0 = time.monotonic()
    r = viewer.post("/api/regex", json={"pattern": "(a|aa)+$", "samples": ["a" * 40 + "!"]})
    assert time.monotonic() - t0 < 15
    assert r.status_code == 200
    body = r.json()
    assert body["timeout"] is True or any(s.get("timeout") for s in body.get("samples", []) if isinstance(s, dict))
    # viewers still cannot reach admin-only writes
    assert viewer.post("/api/ci/config", json={"text": "targets: [splunk]"}).status_code == 403


def test_g1_replay_draft_reports_errors_not_silent_pass(tmp_path):
    owner = make_client(tmp_path)
    register(owner)
    viewer = join(owner, tmp_path, "v@example.com", "viewer")
    assert viewer.post("/api/replay/draft", json={"rule": "not: [valid"}).status_code == 422
    assert viewer.post("/api/replay/draft", json={"rule": "title: x\n"}).status_code == 422
    assert viewer.post("/api/replay/draft", json={"rule": RULE_OK, "datasets": ["../../etc/passwd"]}).status_code == 422
