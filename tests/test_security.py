"""Testes de segurança da API local (sem autenticação): DNS rebinding, CSRF e cabeçalhos."""

from __future__ import annotations

import json

import pytest
from test_engine import RULE_OK, make_project

from vitrix.api import request_problem
from vitrix.github import GitHubClient, GitHubConfig, GitHubError, _urllib_transport

LOCAL = {"127.0.0.1", "localhost", "[::1]"}


@pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000", "[::1]:8000", "LOCALHOST"])
def test_hosts_locais_passam(host):
    assert request_problem("GET", "/api/rules", {"host": host}, LOCAL, []) is None


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "127.0.0.1.evil.example", "", "192.168.0.10:8000"])
def test_dns_rebinding_e_barrado_ate_em_leitura(host):
    assert request_problem("GET", "/api/config", {"host": host}, LOCAL, []) == (403, "host not allowed")


@pytest.mark.parametrize("ctype", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""])
def test_post_que_nao_e_json_e_barrado(ctype):
    headers = {"host": "127.0.0.1:8000", "content-type": ctype}
    assert request_problem("POST", "/api/regex", headers, LOCAL, [])[0] == 415


def test_post_de_outra_origem_e_barrado_e_cors_configurado_libera():
    headers = {"host": "127.0.0.1:8000", "content-type": "application/json", "origin": "https://evil.example"}
    assert request_problem("POST", "/api/replay", headers, LOCAL, [])[0] == 403
    assert request_problem("POST", "/api/replay", {**headers, "origin": "null"}, LOCAL, [])[0] == 403
    assert request_problem("POST", "/api/replay", {**headers, "origin": "http://localhost:5173"}, LOCAL, ["http://localhost:5173"]) is None
    same = {**headers, "origin": "http://127.0.0.1:8000", "content-type": "application/json; charset=utf-8"}
    assert request_problem("POST", "/api/replay", same, LOCAL, []) is None


@pytest.fixture
def client(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    return TestClient(create_app(make_project(tmp_path)), base_url="http://127.0.0.1:8000")


def test_api_nao_vaza_configuracao_por_rebinding(client):
    assert client.get("/api/config").status_code == 200
    resp = client.get("/api/config", headers={"Host": "evil.example"})
    assert resp.status_code == 403 and "schema_version" not in resp.text
    assert client.get("/api/rules/r.yml", headers={"Host": "evil.example"}).status_code == 403


@pytest.mark.parametrize("path,body", [
    ("/api/regex", {"pattern": "a", "samples": ["a"]}),
    ("/api/replay", {"events": "[]"}),
    ("/api/validate", {"rule": RULE_OK}),
    ("/api/pull-requests", {"path": "x.yml", "rule": RULE_OK}),
    ("/api/config/pull-requests", {"text": "targets: [splunk]"}),
])
def test_csrf_simple_request_nao_executa_nada(client, path, body):
    resp = client.post(path, content=json.dumps(body), headers={"Content-Type": "text/plain", "Origin": "https://evil.example"})
    assert resp.status_code in (403, 415)


def test_cabecalhos_de_seguranca(client):
    headers = client.get("/api/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"


def test_token_so_vai_para_a_api_do_github():
    send = _urllib_transport("segredo")
    for url in ("file:///etc/passwd", "http://api.github.com/repos/x", "https://evil.example/repos/x", "https://api.github.com.evil.example/x"):
        with pytest.raises(GitHubError, match="refused"):
            send("GET", url, None)


def test_repo_e_branch_nao_injetam_caminho():
    from vitrix.github import parse_config

    for bad in ({"repo": "org/x/../../y"}, {"repo": "org/x?a=1"}, {"repo": "org/x", "base": "main/../../x"}):
        with pytest.raises(ValueError):
            parse_config(bad)
    calls = []
    client = GitHubClient(GitHubConfig(repo="org/x", base="feat/a b"), transport=lambda m, u, b: calls.append(u) or (200, {}))
    client._call("GET", "/commits/" + __import__("urllib.parse").parse.quote("feat/a b", safe=""))
    assert calls[0] == "https://api.github.com/repos/org/x/commits/feat%2Fa%20b"


# --------------------------------------------------------------------------- ReDoS through viewer-reachable compute routes

EVIL_RULE = RULE_OK.replace("Image|endswith: '\\\\tool.exe'", "Image|re: '^(a|aa)+$'").replace("    CommandLine|contains: '--bad'\n", "")
EVIL_EVENT = {"Image": "a" * 60 + "b"}
BOUND_SECONDS = 5


def _viewer_client(tmp_path):
    import urllib.parse

    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    owner = TestClient(create_app(make_project(tmp_path, extra_cfg="auth:\n  enabled: true\n")), base_url="http://127.0.0.1:8000")
    pw = "correct horse battery"
    owner.post("/api/auth/register", json={"email": "o@example.com", "name": "O", "password": pw})
    link = owner.post("/api/workspace/invites", json={"email": "v@example.com", "role": "viewer"}).json()["link"]
    token = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)["invite"][0]
    viewer = TestClient(owner.app, base_url="http://127.0.0.1:8000")
    r = viewer.post("/api/auth/register", json={"email": "v@example.com", "name": "V", "password": pw, "invite": token})
    assert r.status_code == 201 and r.json()["user"]["role"] == "viewer"
    return viewer


def _bounded(viewer, path, body):
    import time

    start = time.monotonic()
    resp = viewer.post(path, json=body)
    elapsed = time.monotonic() - start
    assert elapsed < BOUND_SECONDS, f"{path} took {elapsed:.1f}s on a catastrophic regex"
    return resp


def test_viewer_replay_with_catastrophic_regex_is_bounded(tmp_path):
    viewer = _viewer_client(tmp_path)
    resp = _bounded(viewer, "/api/replay", {"events": json.dumps([EVIL_EVENT]), "rule": EVIL_RULE})
    assert resp.status_code == 200
    rule = resp.json()["rules"][0]
    assert rule["matches"] == 0 and "timed out" in rule["error"]


def test_viewer_validate_with_catastrophic_regex_is_bounded(tmp_path):
    viewer = _viewer_client(tmp_path)
    cases = "cases:\n  - {name: evil, expect: match, event: {Image: '" + EVIL_EVENT["Image"] + "'}}\n"
    resp = _bounded(viewer, "/api/validate", {"rule": EVIL_RULE, "cases": cases})
    assert resp.status_code == 200
    assert resp.json()["state"] != "pass" and "timed out" in resp.text  # reported as an error, never a pass


def test_viewer_replay_draft_with_catastrophic_regex_is_bounded(tmp_path):
    viewer = _viewer_client(tmp_path)
    ds = tmp_path / "datasets"
    ds.mkdir(exist_ok=True)
    (ds / "evil.jsonl").write_text(json.dumps(EVIL_EVENT) + "\n", encoding="utf-8")
    resp = _bounded(viewer, "/api/replay/draft", {"rule": EVIL_RULE})
    assert resp.status_code == 200
    body = resp.json()
    assert body["passed"] is False and body["errors"] == 1 and "timed out" in body["datasets"][0]["error_text"]


# --------------------------------------------------------------------------- Sprint 4: roles, private drafts (ADR 0006/0007)

ROLE_TABLE = [  # method, path, minimum role
    ("GET", "/api/sync", "viewer"), ("POST", "/api/sync", "viewer"),  # `force` is checked inside the route
    ("POST", "/api/rules", "editor"), ("PUT", "/api/rules/a/b.yml", "editor"), ("DELETE", "/api/rules/a/b.yml", "editor"),
    ("POST", "/api/ci/local-rules", "editor"),
    ("GET", "/api/rules/a/b.yml/related", "viewer"), ("POST", "/api/related", "viewer"),
    ("POST", "/api/reviews/read-all", "viewer"), ("POST", "/api/reviews/" + "a" * 32 + "/read", "viewer"),
    ("POST", "/api/reviews/" + "a" * 32 + "/unread", "viewer"),
    ("POST", "/api/reviews/" + "a" * 32 + "/decision", "editor"), ("POST", "/api/reviews", "editor"),
    ("POST", "/api/rules/a/b.yml", "admin"),  # no such route: unknown writes stay admin-only
    ("PATCH", "/api/rules/a/b.yml", "admin"),
]


@pytest.mark.parametrize("method,path,need", ROLE_TABLE)
def test_required_role_table_sprint4(method, path, need):
    from vitrix.auth import Identity
    from vitrix.auth_api import required_role

    assert required_role(method, path) == need
    for role in ("viewer", "editor", "admin", "owner"):
        ident = Identity(1, "a@example.com", "A", role, None, None, None, "h")
        assert ident.can(need) == (auth_levels()[role] >= auth_levels()[need])


def auth_levels():
    from vitrix.auth import ROLE_LEVEL

    return ROLE_LEVEL


def test_anonymous_is_401_on_every_sprint4_route(tmp_path):
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    c = TestClient(create_app(make_project(tmp_path, extra_cfg="auth:\n  enabled: true\n")), base_url="http://127.0.0.1:8000")
    for method, path, _ in ROLE_TABLE:
        assert c.request(method, path, json={}).status_code == 401, (method, path)


def test_drafts_are_deleted_on_logout_expiry_and_removal(tmp_path):
    from vitrix.auth import AuthConfig, AuthStore
    from vitrix.drafts import DraftStore

    clock = [1000.0]
    store = AuthStore(":memory:", AuthConfig(enabled=True, session_days=1), clock=lambda: clock[0])
    drafts = DraftStore(tmp_path / "drafts.db")
    store.on_user_done.append(drafts.delete_for_author)
    a = store.create_user("a@example.com", "A", "correct horse battery", "owner")
    b = store.create_user("b@example.com", "B", "correct horse battery", "editor")
    c = store.create_user("c@example.com", "C", "correct horse battery", "editor")

    def save(uid):
        drafts.create(path=None, title="t", rule="r", cases=None, base_hash=None, author={"id": uid, "email": "x", "name": "x"})

    keep = drafts.create(path=None, title="shared", rule="r", cases=None, base_hash=None)  # authorless: never auto-deleted
    for uid in (a, b, c):
        save(uid)
    ta, tb = store.create_session(a), store.create_session(b)
    store.create_session(c)
    # logout wipes the author's drafts (and only theirs)
    store.end_session(ta)
    assert {r["author_id"] for r in drafts.list()} == {None, b, c}
    # expiry: b and c have no session after the clock moves; a new login sweeps them
    clock[0] += 86400 + 1
    assert store.identify(tb) is None
    store.create_session(a)
    assert [r["id"] for r in drafts.list()] == [keep["id"]]
    # removal
    save(b)
    store.remove_member(store.identify(store.create_session(a)), b)
    assert [r["id"] for r in drafts.list()] == [keep["id"]]


def test_purge_except_keeps_active_authors_and_authorless(tmp_path):
    from vitrix.drafts import DraftStore

    drafts = DraftStore(tmp_path / "d.db")
    for uid in (1, 2, None):
        drafts.create(path=None, title="t", rule="r", cases=None, base_hash=None, author={"id": uid, "email": "x", "name": "x"} if uid else None)
    assert drafts.purge_except({1}) == 1
    assert sorted(str(r["author_id"]) for r in drafts.list()) == ["1", "None"]
    assert drafts.purge_except(set()) == 1


def test_logout_over_http_deletes_the_users_drafts(tmp_path):
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    c = TestClient(create_app(make_project(tmp_path, extra_cfg="auth:\n  enabled: true\n")), base_url="http://127.0.0.1:8000")
    pw = "correct horse battery"
    c.post("/api/auth/register", json={"email": "o@example.com", "name": "O", "password": pw})
    assert c.post("/api/drafts", json={"rule": RULE_OK}).status_code == 201
    assert len(c.get("/api/drafts").json()["drafts"]) == 1
    assert c.post("/api/auth/logout", json={}).status_code == 200
    assert c.post("/api/auth/login", json={"email": "o@example.com", "password": pw}).status_code == 200
    assert c.get("/api/drafts").json()["drafts"] == []
