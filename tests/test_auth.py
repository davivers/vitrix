"""Accounts, workspace roles, invites, GitHub sign-in and the session guard."""

from __future__ import annotations

import re
import sqlite3
import urllib.parse

import pytest
from test_engine import CASES_OK, RULE_OK, make_project
from test_github import REPO, SHA, FakeGitHub

from vitrix import auth, auth_api, service
from vitrix.auth import AuthError, AuthStore, GitHubOAuth, check_password_policy, hash_password, verify_password
from vitrix.config import AuthConfig, ConfigError, load_config
from vitrix.github import GitHubClient

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from vitrix.api import create_app  # noqa: E402

PW = "correct horse battery"
AUTH_ON = "auth:\n  enabled: true\n"


def make_client(tmp_path, extra: str = AUTH_ON, monkeypatch=None, oauth=None):
    if oauth is not None and monkeypatch is not None:
        monkeypatch.setattr(auth_api, "github_oauth_from_env", lambda: oauth)
    return TestClient(create_app(make_project(tmp_path, extra_cfg=extra)), base_url="http://127.0.0.1:8000")


def register(client, email="owner@example.com", name="Olivia Owner", password=PW, invite=None):
    return client.post("/api/auth/register", json={"email": email, "name": name, "password": password, "invite": invite})


def login(client, email, password=PW):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def second_client(tmp_path, first: TestClient) -> TestClient:
    """A browser of its own (separate cookie jar) talking to the same server."""
    return TestClient(first.app, base_url="http://127.0.0.1:8000")


def invite_token(client, email, role="editor") -> str:
    link = client.post("/api/workspace/invites", json={"email": email, "role": role}).json()["link"]
    return urllib.parse.parse_qs(urllib.parse.urlparse(link).query)["invite"][0]


# --------------------------------------------------------------------------- passwords


def test_password_hashing_is_salted_scrypt_and_verifies():
    a, b = hash_password(PW), hash_password(PW)
    assert a != b and a.startswith("scrypt$") and PW not in a
    assert verify_password(PW, a) and not verify_password("wrong password!", a)
    assert not verify_password(PW, None) and not verify_password(PW, "garbage")


@pytest.mark.parametrize("bad", ["short", "aaaaaaaaaaaaaaaa", "x" * 300])
def test_password_policy(bad):
    with pytest.raises(AuthError):
        check_password_policy(bad)


# --------------------------------------------------------------------------- registration policy


def test_first_account_is_the_owner_and_gets_a_session(tmp_path):
    c = make_client(tmp_path)
    assert c.get("/api/auth/config").json()["bootstrap"] is True
    r = register(c)
    assert r.status_code == 201 and r.json()["user"]["role"] == "owner" and "vitrix_session" in c.cookies
    assert c.get("/api/auth/me").json()["authenticated"] is True
    assert c.get("/api/auth/config").json()["bootstrap"] is False


def test_registration_is_closed_after_the_first_account(tmp_path):
    c = make_client(tmp_path)
    register(c)
    other = second_client(tmp_path, c)
    r = register(other, "stranger@example.com", "Stranger")
    assert r.status_code == 403 and "invitation" in r.json()["detail"]
    assert "vitrix_session" not in other.cookies


def test_second_registration_needs_an_invite(tmp_path):
    c = make_client(tmp_path)
    assert c.get("/api/auth/config").json()["registration"] == "owner-bootstrap"
    register(c)
    assert c.get("/api/auth/config").json()["registration"] == "invite-only"
    assert register(second_client(tmp_path, c), "no-invite@example.com", "No Invite").status_code == 403
    token = invite_token(c, "new@example.com", "viewer")
    assert register(second_client(tmp_path, c), "new@example.com", "New Person", invite=token).json()["user"]["role"] == "viewer"


def test_local_registration_with_an_invited_email_but_no_token_is_refused(tmp_path):
    c = make_client(tmp_path)
    register(c)
    invite_token(c, "bob@example.com", "admin")
    thief = second_client(tmp_path, c)
    assert register(thief, "bob@example.com", "Thief").status_code == 403
    assert "vitrix_session" not in thief.cookies


def test_retired_signup_keys_are_ignored_not_fatal(tmp_path):
    with pytest.warns(UserWarning, match="allow_signup"):
        c = make_client(tmp_path, "auth:\n  enabled: true\n  allow_signup: true\n  signup_role: editor\n")
    register(c)
    assert register(second_client(tmp_path, c), "new@example.com", "New Person").status_code == 403  # still closed


def test_invalid_registrations_and_duplicate_emails(tmp_path):
    c = make_client(tmp_path)
    assert register(c, "not-an-email", "X").status_code == 422
    assert register(c, "ok@example.com", "X", password="short").status_code == 422
    assert register(c, "ok2@example.com", "  ").status_code == 422
    assert c.get("/api/auth/config").json()["bootstrap"] is True  # nothing was created
    register(c)
    token = invite_token(c, "ana@example.com")
    assert register(second_client(tmp_path, c), "ana@example.com", "Ana", invite=token).status_code == 201
    assert c.post("/api/workspace/invites", json={"email": "OWNER@example.com", "role": "viewer"}).status_code == 409  # emails are case-insensitive


@pytest.mark.parametrize("bad", ["auth: 1\n", "auth:\n  nope: true\n", "auth:\n  enabled: maybe\n", "auth:\n  session_days: 0\n"])
def test_invalid_auth_config(tmp_path, bad):
    with pytest.raises(ConfigError):
        load_config(make_project(tmp_path, extra_cfg=bad))


# --------------------------------------------------------------------------- login, sessions, throttling


def test_login_logout_and_session_revocation(tmp_path):
    c = make_client(tmp_path)
    register(c)
    c.post("/api/auth/logout", json={})
    assert c.get("/api/rules").status_code == 401
    assert login(c, "owner@example.com").status_code == 200 and c.get("/api/rules").status_code == 200
    stolen = c.cookies.get("vitrix_session")
    c.post("/api/auth/logout", json={})
    thief = second_client(tmp_path, c)
    thief.cookies.set("vitrix_session", stolen)
    assert thief.get("/api/rules").status_code == 401  # logout revoked the server-side session


def test_login_errors_are_generic_and_do_not_reveal_accounts(tmp_path):
    c = make_client(tmp_path)
    register(c)
    other = second_client(tmp_path, c)
    wrong = login(other, "owner@example.com", "wrong password!!")
    unknown = login(other, "nobody@example.com", "wrong password!!")
    assert wrong.status_code == unknown.status_code == 401 and wrong.json() == unknown.json()


def test_brute_force_lockout_by_email_and_ip():
    clock = [1000.0]
    store = AuthStore(":memory:", AuthConfig(enabled=True), clock=lambda: clock[0])
    store.create_user("a@example.com", "A", PW, "owner")
    for _ in range(auth.MAX_FAILURES):
        with pytest.raises(AuthError, match="Wrong email"):
            store.verify_login("a@example.com", "nope nope nope", "1.2.3.4")
    with pytest.raises(AuthError) as locked:
        store.verify_login("a@example.com", PW, "1.2.3.4")  # even the right password is refused while locked
    assert locked.value.status == 429
    assert store.verify_login("a@example.com", PW, "5.6.7.8")  # another address is not locked
    clock[0] += auth.LOCKOUT_S + 1
    assert store.verify_login("a@example.com", PW, "1.2.3.4")


def test_session_expiry():
    clock = [1000.0]
    store = AuthStore(":memory:", AuthConfig(enabled=True, session_days=1), clock=lambda: clock[0])
    uid = store.create_user("a@example.com", "A", PW, "owner")
    token = store.create_session(uid)
    assert store.identify(token) is not None
    clock[0] += 86400 + 1
    assert store.identify(token) is None


def test_cookie_flags_and_no_raw_token_in_the_database(tmp_path, monkeypatch):
    c = make_client(tmp_path)
    r = register(c)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "secure" not in cookie
    token = c.cookies.get("vitrix_session")
    rows = sqlite3.connect(tmp_path / ".vitrix" / "vitrix.db").execute("SELECT token_hash FROM sessions").fetchall()
    assert rows and all(token != h for (h,) in rows) and re.fullmatch(r"[0-9a-f]{64}", rows[0][0])
    monkeypatch.setenv("VITRIX_COOKIE_SECURE", "1")
    assert "secure" in login(c, "owner@example.com").headers["set-cookie"].lower()


def test_each_login_gets_a_new_token(tmp_path):
    c = make_client(tmp_path)
    register(c)
    first = c.cookies.get("vitrix_session")
    login(c, "owner@example.com")
    assert c.cookies.get("vitrix_session") != first


def test_password_change_revokes_the_other_sessions(tmp_path):
    c = make_client(tmp_path)
    register(c)
    other = second_client(tmp_path, c)
    login(other, "owner@example.com")
    assert c.post("/api/auth/password", json={"current": "wrong password!!", "new": "another long password"}).status_code == 403
    assert c.post("/api/auth/password", json={"current": PW, "new": "another long password"}).status_code == 200
    assert c.get("/api/rules").status_code == 200 and other.get("/api/rules").status_code == 401
    assert login(c, "owner@example.com", PW).status_code == 401 and login(c, "owner@example.com", "another long password").status_code == 200


# --------------------------------------------------------------------------- the guard


def test_everything_except_the_public_routes_needs_a_session(tmp_path):
    c = make_client(tmp_path)
    for path in ("/api/rules", "/api/config", "/api/quality", "/api/report", "/api/workspace", "/api/github"):
        assert c.get(path).status_code == 401, path
    assert c.get("/api/health").status_code == 200
    assert c.get("/api/auth/config").json()["enabled"] is True
    me = c.get("/api/auth/me")
    assert me.json()["authenticated"] is False and me.headers["cache-control"] == "no-store"


def test_auth_off_keeps_the_local_mode_unchanged(tmp_path):
    c = make_client(tmp_path, extra="")
    assert c.get("/api/rules").status_code == 200
    assert c.get("/api/auth/config").json() == {"enabled": False, "enabled_source": "default", "setup_token_required": False}
    assert c.get("/api/auth/me").json()["authenticated"] is True
    assert c.post("/api/auth/login", json={"email": "a@b.co", "password": "x"}).status_code in (404, 405)


def test_login_still_obeys_the_csrf_guard(tmp_path):
    c = make_client(tmp_path)
    body = '{"email": "a@example.com", "password": "x"}'
    assert c.post("/api/auth/login", content=body, headers={"Content-Type": "text/plain"}).status_code == 415
    assert c.post("/api/auth/login", content=body, headers={"Content-Type": "application/json", "Origin": "https://evil.example"}).status_code == 403


# --------------------------------------------------------------------------- roles


def join(c, tmp_path, email, role):
    token = invite_token(c, email, role)
    browser = second_client(tmp_path, c)
    assert register(browser, email, email.split("@")[0], invite=token).status_code == 201
    return browser


def test_role_matrix(tmp_path):
    owner = make_client(tmp_path)
    register(owner)
    viewer, editor, admin = (join(owner, tmp_path, f"{r}@example.com", r) for r in ("viewer", "editor", "admin"))
    body = {"rule": RULE_OK, "cases": CASES_OK}
    # reading: everyone; computing/publishing rules: editor+; config, members, audit: admin+
    assert viewer.get("/api/rules").status_code == editor.get("/api/rules").status_code == 200
    # pure-compute POSTs are open to viewers; anything that writes needs editor+
    assert viewer.post("/api/validate", json=body).status_code == 200
    assert editor.post("/api/validate", json=body).status_code == 200
    assert viewer.post("/api/regex", json={"pattern": "a", "samples": ["a"]}).status_code == 200
    assert viewer.post("/api/replay", json={"events": "[]"}).status_code != 403
    assert viewer.post("/api/config/validate", json={"text": "targets: [splunk]"}).status_code == 200
    assert viewer.post("/api/ci/rules", json={"path": "x.yml", "rule": RULE_OK}).status_code == 403
    assert viewer.post("/api/pull-requests", json={"branch": "b", "commit": "c", "title": "t"}).status_code == 403
    assert viewer.post("/api/ci/config", json={"text": "targets: [splunk]"}).status_code == 403
    assert editor.post("/api/ci/config", json={"text": "targets: [splunk]"}).status_code == 403
    assert admin.post("/api/ci/config", json={"text": "targets: [splunk]"}).status_code != 403
    for who, expected in ((viewer, 403), (editor, 403), (admin, 200), (owner, 200)):
        assert who.get("/api/workspace/audit").status_code == expected
    assert "members" not in viewer.get("/api/workspace").json() and "members" in admin.get("/api/workspace").json()
    assert editor.post("/api/workspace/invites", json={"email": "x@example.com", "role": "viewer"}).status_code == 403


@pytest.mark.parametrize("path", ["/api/regex", "/api/validate", "/api/impact", "/api/replay", "/api/replay/draft", "/api/config/validate"])
def test_compute_posts_are_viewer_level(path):
    assert auth_api.required_role("POST", path) == "viewer"


@pytest.mark.parametrize("path", ["/api/ci/rules", "/api/pull-requests", "/api/drafts"])
def test_publishing_posts_are_editor_level(path):
    assert auth_api.required_role("POST", path) == "editor"


def test_draft_routes_are_classified():
    assert auth_api.required_role("GET", "/api/drafts") == auth_api.required_role("GET", "/api/drafts/abc") == "viewer"
    assert auth_api.required_role("PUT", "/api/drafts/abc") == auth_api.required_role("DELETE", "/api/drafts/abc") == "editor"


def test_unclassified_writes_default_to_admin():
    assert auth_api.required_role("POST", "/api/something-new") == "admin"
    assert auth_api.required_role("DELETE", "/api/rules/x") == "admin"
    assert auth_api.required_role("GET", "/api/rules") == "viewer"


def test_owner_rules_and_the_last_owner(tmp_path):
    owner = make_client(tmp_path)
    register(owner)
    admin = join(owner, tmp_path, "admin@example.com", "admin")
    members = {m["email"]: m["id"] for m in owner.get("/api/workspace").json()["members"]}
    assert admin.patch(f"/api/workspace/members/{members['admin@example.com']}", json={"role": "owner"}).status_code == 403  # admins cannot mint owners
    assert admin.patch(f"/api/workspace/members/{members['owner@example.com']}", json={"role": "viewer"}).status_code == 403
    assert admin.delete(f"/api/workspace/members/{members['owner@example.com']}").status_code == 409
    assert owner.patch(f"/api/workspace/members/{members['owner@example.com']}", json={"role": "admin"}).status_code == 409  # last owner
    assert owner.delete(f"/api/workspace/members/{members['owner@example.com']}").status_code == 409
    assert owner.patch(f"/api/workspace/members/{members['admin@example.com']}", json={"role": "owner"}).status_code == 200
    assert owner.patch(f"/api/workspace/members/{members['owner@example.com']}", json={"role": "editor"}).status_code == 200  # a second owner exists now


def test_role_change_keeps_the_session_and_applies_at_once(tmp_path):
    owner = make_client(tmp_path)
    register(owner)
    editor = join(owner, tmp_path, "editor@example.com", "editor")
    token = editor.cookies.get("vitrix_session")
    uid = next(m["id"] for m in owner.get("/api/workspace").json()["members"] if m["email"] == "editor@example.com")
    assert editor.post("/api/ci/rules", json={"path": "x.yml", "rule": RULE_OK}).status_code != 403
    assert owner.patch(f"/api/workspace/members/{uid}", json={"role": "viewer"}).status_code == 200  # downgrade
    assert editor.cookies.get("vitrix_session") == token and editor.get("/api/rules").status_code == 200  # no logout
    assert editor.get("/api/auth/me").json()["user"]["role"] == "viewer"
    assert editor.post("/api/ci/rules", json={"path": "x.yml", "rule": RULE_OK}).status_code == 403  # lost editor writes
    assert editor.post("/api/regex", json={"pattern": "a", "samples": ["a"]}).status_code == 200  # still computes
    assert owner.patch(f"/api/workspace/members/{uid}", json={"role": "admin"}).status_code == 200  # upgrade
    assert editor.get("/api/auth/me").json()["user"]["role"] == "admin" and editor.get("/api/workspace/audit").status_code == 200


def test_removing_a_member_ends_their_sessions(tmp_path):
    owner = make_client(tmp_path)
    register(owner)
    editor = join(owner, tmp_path, "editor@example.com", "editor")
    uid = next(m["id"] for m in owner.get("/api/workspace").json()["members"] if m["email"] == "editor@example.com")
    assert owner.delete(f"/api/workspace/members/{uid}").status_code == 200
    assert editor.get("/api/rules").status_code == 401
    assert login(editor, "editor@example.com").status_code == 401


# --------------------------------------------------------------------------- invites


def test_invites_are_bound_to_an_email_single_use_and_revocable(tmp_path):
    owner = make_client(tmp_path)
    register(owner)
    token = invite_token(owner, "ana@example.com", "editor")
    stranger = second_client(tmp_path, owner)
    assert register(stranger, "evil@example.com", "Evil", invite=token).status_code == 403  # wrong email
    assert register(stranger, "ana@example.com", "Ana", invite=token).json()["user"]["role"] == "editor"
    assert register(second_client(tmp_path, owner), "ana2@example.com", "Ana", invite="not-a-token").status_code == 403
    again = invite_token(owner, "bob@example.com", "viewer")
    invites = owner.get("/api/workspace").json()["invites"]
    assert [i["email"] for i in invites] == ["bob@example.com"]
    assert owner.delete(f"/api/workspace/invites/{invites[0]['id']}").status_code == 200
    assert register(second_client(tmp_path, owner), "bob@example.com", "Bob", invite=again).status_code == 403  # revoked
    assert "ana@example.com" not in {i["email"] for i in owner.get("/api/workspace").json()["invites"]}  # used


def test_invites_expire_and_are_stored_hashed(tmp_path):
    clock = [1000.0]
    store = AuthStore(":memory:", AuthConfig(enabled=True), clock=lambda: clock[0])
    owner = auth.Identity(store.create_user("o@example.com", "O", PW, "owner"), "o@example.com", "O", "owner", None, None)
    token = store.create_invite(owner, "x@example.com", "editor")
    assert store.find_invite(token) is not None
    assert token not in str(store._q("SELECT * FROM invites")[0].keys()) and store._q("SELECT token_hash FROM invites")[0][0] != token
    clock[0] += auth.INVITE_DAYS * 86400 + 1
    assert store.find_invite(token) is None


def test_inviting_an_existing_member_or_with_a_higher_role_is_refused(tmp_path):
    owner = make_client(tmp_path)
    register(owner)
    admin = join(owner, tmp_path, "admin@example.com", "admin")
    assert owner.post("/api/workspace/invites", json={"email": "admin@example.com", "role": "viewer"}).status_code == 409
    assert admin.post("/api/workspace/invites", json={"email": "new@example.com", "role": "owner"}).status_code == 403
    assert owner.post("/api/workspace/invites", json={"email": "new@example.com", "role": "emperor"}).status_code == 403


# --------------------------------------------------------------------------- GitHub sign-in


def fake_github(user_id=42, login="octocat", emails=None, token_ok=True):
    emails = [{"email": "Octo@Example.com", "primary": True, "verified": True}] if emails is None else emails

    def http(method, url, headers, body):
        if url == "https://github.com/login/oauth/access_token":
            return 200, ({"access_token": "gho_secret"} if token_ok else {"error": "bad_verification_code"})
        if url == "https://api.github.com/user":
            return 200, {"id": user_id, "login": login, "name": "Octo Cat", "avatar_url": "https://avatars.example/x.png"}
        if url == "https://api.github.com/user/emails":
            return 200, emails
        raise AssertionError(url)

    return GitHubOAuth("client-id", "client-secret", http)


def github_flow(client, state=None, code="abc"):
    start = client.get("/api/auth/github/start", follow_redirects=False)
    assert start.status_code == 302 and start.headers["location"].startswith("https://github.com/login/oauth/authorize?")
    sent = urllib.parse.parse_qs(urllib.parse.urlparse(start.headers["location"]).query)
    assert sent["client_id"] == ["client-id"] and sent["scope"] == ["read:user user:email"] and sent["redirect_uri"][0].endswith("/api/auth/github/callback")
    return client.get(f"/api/auth/github/callback?code={code}&state={state or sent['state'][0]}", follow_redirects=False)


def test_github_button_only_when_configured(tmp_path, monkeypatch):
    monkeypatch.delenv("VITRIX_GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("VITRIX_GITHUB_CLIENT_SECRET", raising=False)
    c = make_client(tmp_path)
    assert c.get("/api/auth/config").json()["github"] is False
    assert c.get("/api/auth/github/start", follow_redirects=False).status_code == 404


def test_github_first_account_becomes_the_owner(tmp_path, monkeypatch):
    c = make_client(tmp_path, monkeypatch=monkeypatch, oauth=fake_github())
    assert c.get("/api/auth/config").json()["github"] is True
    r = github_flow(c)
    assert r.status_code == 302 and r.headers["location"] == "/" and "vitrix_session" in c.cookies
    me = c.get("/api/auth/me").json()["user"]
    assert me["role"] == "owner" and me["email"] == "octo@example.com" and me["github_login"] == "octocat" and me["name"] == "Octo Cat"
    row = sqlite3.connect(tmp_path / ".vitrix" / "vitrix.db").execute("SELECT password_hash FROM users").fetchone()
    assert row[0] is None  # no password: GitHub-only account
    assert login(second_client(tmp_path, c), "octo@example.com", "anything at all").status_code == 401


def test_github_state_mismatch_is_rejected(tmp_path, monkeypatch):
    c = make_client(tmp_path, monkeypatch=monkeypatch, oauth=fake_github())
    r = github_flow(c, state="forged-state")
    assert r.status_code == 302 and "auth_error" in r.headers["location"] and "vitrix_session" not in c.cookies
    no_cookie = second_client(tmp_path, c).get("/api/auth/github/callback?code=abc&state=anything", follow_redirects=False)
    assert "auth_error" in no_cookie.headers["location"]


def test_github_bad_code_creates_nothing(tmp_path, monkeypatch):
    c = make_client(tmp_path, monkeypatch=monkeypatch, oauth=fake_github(token_ok=False))
    assert "auth_error" in github_flow(c).headers["location"]
    assert c.get("/api/auth/config").json()["bootstrap"] is True


def test_github_links_an_existing_account_only_through_a_verified_email(tmp_path, monkeypatch):
    c = make_client(tmp_path)
    register(c, "octo@example.com", "Octo")  # an existing local owner account
    cfg = str(tmp_path / "vitrix.yml")
    monkeypatch.setattr(auth_api, "github_oauth_from_env", lambda: fake_github(emails=[{"email": "octo@example.com", "primary": True, "verified": False}]))
    attacker = TestClient(create_app(cfg), base_url="http://127.0.0.1:8000")
    assert "auth_error" in github_flow(attacker).headers["location"] and "vitrix_session" not in attacker.cookies  # unverified: no takeover
    monkeypatch.setattr(auth_api, "github_oauth_from_env", lambda: fake_github())
    owner = TestClient(create_app(cfg), base_url="http://127.0.0.1:8000")
    assert github_flow(owner).headers["location"] == "/"
    me = owner.get("/api/auth/me").json()["user"]
    assert me["role"] == "owner" and me["github_login"] == "octocat"  # linked to the existing account, not a new one
    assert len(owner.get("/api/workspace").json()["members"]) == 1


def test_github_sign_up_follows_the_invite_policy(tmp_path, monkeypatch):
    owner = make_client(tmp_path, monkeypatch=monkeypatch, oauth=fake_github(user_id=1, login="boss", emails=[{"email": "boss@example.com", "primary": True, "verified": True}]))
    github_flow(owner)  # first account: owner
    monkeypatch.setattr(auth_api, "github_oauth_from_env", lambda: fake_github(user_id=2, login="newbie", emails=[{"email": "newbie@example.com", "primary": True, "verified": True}]))
    newbie = TestClient(create_app(str(tmp_path / "vitrix.yml")), base_url="http://127.0.0.1:8000")
    assert "invitation" in urllib.parse.unquote_plus(github_flow(newbie).headers["location"])  # closed: un-invited email refused
    assert newbie.get("/api/auth/me").json()["authenticated"] is False
    assert len(owner.get("/api/workspace").json()["members"]) == 1
    token = invite_token(owner, "newbie@example.com", "editor")
    assert register(second_client(tmp_path, owner), "newbie@example.com", "Local").status_code == 403  # no token locally
    start = newbie.get(f"/api/auth/github/start?invite={urllib.parse.quote(token)}", follow_redirects=False)
    state = urllib.parse.parse_qs(urllib.parse.urlparse(start.headers["location"]).query)["state"][0]
    assert newbie.get(f"/api/auth/github/callback?code=abc&state={state}", follow_redirects=False).headers["location"] == "/"
    assert newbie.get("/api/auth/me").json()["user"]["role"] == "editor"


def test_github_without_any_verified_email_is_refused(tmp_path, monkeypatch):
    c = make_client(tmp_path, monkeypatch=monkeypatch, oauth=fake_github(emails=[{"email": "x@example.com", "primary": True, "verified": False}]))
    assert "verified" in urllib.parse.unquote_plus(github_flow(c).headers["location"])


def test_oauth_client_only_talks_to_github():
    from vitrix.auth import _http

    for url in ("http://github.com/login", "https://evil.example/", "https://github.com.evil.example/x", "file:///etc/passwd"):
        with pytest.raises(AuthError):
            _http("GET", url, {}, None)


# --------------------------------------------------------------------------- audit and attribution


def test_audit_trail_records_who_did_what(tmp_path):
    owner = make_client(tmp_path)
    register(owner)
    token = invite_token(owner, "ana@example.com", "editor")
    login(second_client(tmp_path, owner), "owner@example.com", "wrong password!!")
    actions = [(a["action"], a["actor"]) for a in owner.get("/api/workspace/audit").json()]
    assert ("invite.created", "Olivia Owner") in actions and ("account.register", "Olivia Owner") in actions
    assert any(a == "login.failed" for a, _ in actions)
    assert token not in str(owner.get("/api/workspace/audit").json())  # secrets never reach the log


def test_commits_sent_to_ci_credit_the_person(tmp_path, monkeypatch):
    fake = FakeGitHub()
    monkeypatch.setattr(service, "GitHubClient", lambda gh: GitHubClient(gh, transport=fake))
    monkeypatch.setenv("VITRIX_GITHUB_TOKEN", "test-secret")
    c = make_client(tmp_path, extra=AUTH_ON + f"github:\n  repo: {REPO}\n  base: main\n")
    register(c)
    r = c.post("/api/ci/rules", json={"path": "windows/new.yml", "rule": RULE_OK, "cases": CASES_OK})
    assert r.status_code == 201
    message = fake.body_of("/git/commits")["message"]
    assert "Submitted-by: Olivia Owner (owner@example.com) via Vitrix" in message and "Co-authored-by" not in message  # local email is unverified
    assert any(a["action"] == "rule.ci_submitted" and SHA[:7] in a["detail"] for a in c.get("/api/workspace/audit").json())


def test_attribution_never_injects_header_lines():
    evil = "Eve" + chr(10) + "Co-authored-by: Boss <boss@x.io>"
    ident = auth.Identity(1, "a@example.com", evil, "editor", "eve", None, 99)
    lines = auth.attribution(ident).splitlines()
    assert len(lines) == 2 and lines[0].startswith("Submitted-by: ") and lines[1].endswith("<99+eve@users.noreply.github.com>")
    assert "<boss@x.io>" not in chr(10).join(lines)


# --------------------------------------------------------------------------- S2: VITRIX_AUTH + setup token (ADR 0002)


def _d(tmp_path, name):
    (tmp_path / name).mkdir()
    return tmp_path / name


def _cfg(tmp_path, extra=""):
    return load_config(make_project(tmp_path, extra_cfg=extra))


def test_env_beats_file_beats_default(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("VITRIX_AUTH", raising=False)
    assert _cfg(_d(tmp_path, "a")).auth.enabled is False
    assert _cfg(_d(tmp_path, "a2")).auth.enabled_source == "default"
    assert _cfg(_d(tmp_path, "b"), AUTH_ON).auth.enabled_source == "config"
    monkeypatch.setenv("VITRIX_AUTH", "ON")
    c = _cfg(_d(tmp_path, "c"))
    assert c.auth.enabled is True and c.auth.enabled_source == "env"
    monkeypatch.setenv("VITRIX_AUTH", "off")
    d = _cfg(_d(tmp_path, "d"), AUTH_ON)  # operator decision, with a warning
    assert d.auth.enabled is False and d.auth.enabled_source == "env"
    assert "overrides auth.enabled" in capsys.readouterr().err
    monkeypatch.setenv("VITRIX_AUTH", "")  # empty = unset
    assert _cfg(_d(tmp_path, "e"), AUTH_ON).auth.enabled_source == "config"


@pytest.mark.parametrize("bad", ["maybe", "2", "enabled"])
def test_invalid_vitrix_auth_is_a_config_error(tmp_path, monkeypatch, bad):
    monkeypatch.setenv("VITRIX_AUTH", bad)
    with pytest.raises(ConfigError, match="VITRIX_AUTH"):
        _cfg(tmp_path)


def test_vitrix_auth_env_turns_accounts_on_and_reports_the_source(tmp_path, monkeypatch):
    monkeypatch.setenv("VITRIX_AUTH", "on")
    c = make_client(tmp_path, extra="")
    cfg = c.get("/api/auth/config").json()
    assert cfg["enabled"] is True and cfg["enabled_source"] == "env" and cfg["setup_token_required"] is False
    assert c.get("/api/rules").status_code == 401


def test_short_explicit_bootstrap_token_is_a_config_error(tmp_path, monkeypatch):
    monkeypatch.setenv("VITRIX_BOOTSTRAP_TOKEN", "short")
    with pytest.raises(ConfigError, match="VITRIX_BOOTSTRAP_TOKEN"):
        _cfg(tmp_path, AUTH_ON)


EXPLICIT = "an-explicit-setup-token-123"


def _first(c, token=None):
    return c.post("/api/auth/register", json={"email": "o@example.com", "name": "O", "password": PW, "setup_token": token})


def test_setup_token_gates_the_first_account(tmp_path, monkeypatch):
    monkeypatch.setenv("VITRIX_BOOTSTRAP_TOKEN", EXPLICIT)
    c = make_client(tmp_path)
    assert c.get("/api/auth/config").json()["setup_token_required"] is True
    for token in (None, "wrong", EXPLICIT[:-1]):
        assert _first(c, token).status_code == 403
    assert c.get("/api/auth/config").json()["bootstrap"] is True  # nothing was created
    r = _first(c, EXPLICIT)
    assert r.status_code == 201 and r.json()["user"]["role"] == "owner"
    # once the owner exists the token is irrelevant: an invitation is all a second person needs
    assert c.get("/api/auth/config").json()["setup_token_required"] is False
    token = invite_token(c, "e@example.com")
    assert register(second_client(tmp_path, c), "e@example.com", "E", invite=token).status_code == 201


def test_setup_token_failures_are_delayed_not_locked_out(tmp_path, monkeypatch):
    """Behind Docker all clients share one IP: bad guesses must never lock the real owner out."""
    monkeypatch.setenv("VITRIX_BOOTSTRAP_TOKEN", EXPLICIT)
    monkeypatch.setattr(auth, "SETUP_FAIL_DELAY_S", 0.01)
    c = make_client(tmp_path)
    assert [_first(c, f"guess-{i}").status_code for i in range(auth.MAX_FAILURES * 2)] == [403] * (auth.MAX_FAILURES * 2)
    assert _first(c, EXPLICIT).status_code == 201


def test_setup_token_failure_waits_a_fixed_delay(tmp_path, monkeypatch):
    monkeypatch.setenv("VITRIX_BOOTSTRAP_TOKEN", EXPLICIT)
    slept = []
    monkeypatch.setattr(auth.time, "sleep", slept.append)
    _first(make_client(tmp_path), "nope")
    assert slept == [auth.SETUP_FAIL_DELAY_S]


def test_auto_token_is_generated_per_start_and_announced_on_stderr(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VITRIX_BOOTSTRAP_TOKEN", "auto")
    monkeypatch.setenv("VITRIX_SERVE_URL", "http://localhost:8123")
    c = make_client(tmp_path)
    token = c.app.state.setup_token
    assert len(token) >= 24 and token != "auto"
    assert f"http://localhost:8123/?setup={token}" in capsys.readouterr().err
    assert register(c).status_code == 403
    assert _first(c, token).status_code == 201
    assert make_client(_d(tmp_path, "other")).app.state.setup_token != token  # fresh on every start


def test_explicit_token_is_never_printed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VITRIX_BOOTSTRAP_TOKEN", EXPLICIT)
    make_client(tmp_path)
    captured = capsys.readouterr()
    assert EXPLICIT not in captured.err and EXPLICIT not in captured.out


def test_no_token_configured_keeps_first_account_wins(tmp_path, monkeypatch):
    monkeypatch.delenv("VITRIX_BOOTSTRAP_TOKEN", raising=False)
    c = make_client(tmp_path)
    assert c.get("/api/auth/config").json()["setup_token_required"] is False
    assert register(c).status_code == 201


def test_token_never_appears_in_responses_or_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("VITRIX_BOOTSTRAP_TOKEN", EXPLICIT)
    c = make_client(tmp_path)
    seen = [c.get("/api/auth/config").text, c.get("/api/auth/me").text, _first(c, "guess-xyz").text]
    r = _first(c, EXPLICIT)
    audit = c.get("/api/workspace/audit").text
    seen += [r.text, str(dict(r.headers)), c.get("/api/auth/config").text, c.get("/api/workspace").text, audit, c.get("/api/config").text]
    assert not any(EXPLICIT in s for s in seen)
    assert "guess-xyz" not in audit
    rows = sqlite3.connect(tmp_path / ".vitrix" / "vitrix.db").execute("SELECT actor, action, detail FROM audit").fetchall()
    assert not any(EXPLICIT in " ".join(map(str, row)) or "guess-xyz" in " ".join(map(str, row)) for row in rows)
    assert any(row[1] == "setup.failed" for row in rows)


def test_github_cannot_create_the_first_account_while_a_token_is_required(tmp_path, monkeypatch):
    monkeypatch.setenv("VITRIX_BOOTSTRAP_TOKEN", EXPLICIT)
    c = make_client(tmp_path, monkeypatch=monkeypatch, oauth=GitHubOAuth("cid", "secret"))
    r = c.get("/api/auth/github/start", follow_redirects=False)
    assert r.status_code == 409 and "setup token" in r.json()["detail"]
    r = c.get("/api/auth/github/callback?code=x&state=y", follow_redirects=False)
    assert r.status_code == 302 and "auth_error" in r.headers["location"]
    assert c.get("/api/auth/config").json()["bootstrap"] is True


# --------------------------------------------------------------------------- S4/S6/S8/S9: roles of the new routes

ROLE_MATRIX = [
    ("GET", "/api/drift", "viewer"),
    ("GET", "/api/packs/sources", "viewer"),
    ("GET", "/api/packs/jobs/abc", "viewer"),
    ("POST", "/api/packs/jobs", "editor"),
    ("POST", "/api/ci/drafts", "editor"),
    ("GET", "/api/reviews", "viewer"),
    ("GET", "/api/reviews/counts", "viewer"),
    ("GET", "/api/reviews/reviewers", "viewer"),
    ("GET", "/api/reviews/abc", "viewer"),
    ("POST", "/api/reviews", "editor"),
    ("POST", "/api/reviews/abc/decision", "editor"),
    ("POST", "/api/reviews/abc/rerequest", "editor"),
    ("POST", "/api/reviews/abc/cancel", "editor"),
    ("GET", "/api/comments", "viewer"),
    ("POST", "/api/comments", "viewer"),
    ("PATCH", "/api/comments/abc", "viewer"),
    ("DELETE", "/api/comments/abc", "viewer"),
    ("POST", "/api/comments-evil", "admin"),  # the prefix is "/api/comments/", not "/api/comments"
    ("POST", "/api/packs/other", "admin"),  # unclassified writes stay admin
    ("DELETE", "/api/packs/jobs/abc", "admin"),
    ("PUT", "/api/reviews-x", "admin"),
]


@pytest.mark.parametrize(("method", "path", "role"), ROLE_MATRIX)
def test_required_role_for_new_routes(method, path, role):
    assert auth_api.required_role(method, path) == role


def test_new_routes_are_allowed_and_denied_by_role_at_the_middleware(tmp_path):
    """The guard answers 401 (no session), 403 (role too low) or lets the request through (anything else)."""
    owner = make_client(tmp_path)
    assert register(owner).status_code == 201
    people = {}
    for r in ("viewer", "editor", "admin"):
        person = second_client(tmp_path, owner)
        assert register(person, f"{r}@example.com", r.title(), invite=invite_token(owner, f"{r}@example.com", r)).status_code == 201
        people[r] = person
    people["owner"] = owner
    anonymous = second_client(tmp_path, owner)
    for method, path, need in ROLE_MATRIX:
        body = {} if method != "GET" else None
        assert anonymous.request(method, path, json=body).status_code == 401, (method, path)
        for role, person in people.items():
            resp = person.request(method, path, json=body)
            denied = resp.status_code == 403 and resp.json()["detail"].startswith("This needs the")
            assert denied == (auth.ROLE_LEVEL[role] < auth.ROLE_LEVEL[need]), (method, path, role, resp.status_code)
