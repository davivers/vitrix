"""Local drafts (ADR 0001): store, HTTP API, roles, limits, staleness and the auth-off loopback rule."""

from __future__ import annotations

import pytest
from test_auth import PW, invite_token, login, register
from test_engine import RULE_OK, make_project

from vitrix import drafts as drafts_mod
from vitrix.config import ConfigError, parse_config_text
from vitrix.drafts import MAX_PER_AUTHOR, DraftError, DraftStore

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from vitrix.api import create_app  # noqa: E402

BASE = "http://127.0.0.1:8000"
LOOPBACK = ("127.0.0.1", 50000)
AUTH_ON = "auth:\n  enabled: true\n"
BODY = {"path": "windows/x.yml", "title": None, "rule": RULE_OK, "cases": "cases: []\n"}


def local_client(tmp_path, monkeypatch, extra: str = "", client=LOOPBACK, hosts: str | None = None) -> TestClient:
    """Accounts off, a localhost-only server (conftest's extra `testserver` host removed)."""
    if hosts is None:
        monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    else:
        monkeypatch.setenv("VITRIX_ALLOWED_HOSTS", hosts)
    return TestClient(create_app(make_project(tmp_path, extra_cfg=extra)), base_url=BASE, client=client)


def team(tmp_path):
    """Accounts on: an owner plus an editor, a second editor and a viewer, each in its own browser."""
    owner = TestClient(create_app(make_project(tmp_path, extra_cfg=AUTH_ON)), base_url=BASE)
    assert register(owner).status_code == 201
    out = {"owner": owner}
    for name, role in (("ed1", "editor"), ("ed2", "editor"), ("view", "viewer")):
        email = f"{name}@example.com"
        token = invite_token(owner, email, role)
        c = TestClient(owner.app, base_url=BASE)
        assert register(c, email=email, name=name.title(), invite=token).status_code == 201
        out[name] = c
    return out


# --------------------------------------------------------------------------- store


def test_store_writes_nothing_until_first_save(tmp_path):
    db = tmp_path / "sub" / "drafts.db"
    s = DraftStore(db)
    assert s.list() == [] and not db.exists() and not db.parent.exists()
    with pytest.raises(DraftError) as e:
        s.get("a" * 32)
    assert e.value.status == 404
    with pytest.raises(DraftError):
        s.delete("a" * 32)
    assert not db.exists()
    s.create(path=None, title="t", rule="x", cases=None, base_hash=None)
    assert db.is_file() and len(s.list()) == 1


def test_store_crud_version_and_order(tmp_path):
    t = iter(range(100, 200))
    s = DraftStore(tmp_path / "d.db", clock=lambda: float(next(t)))
    a = s.create(path=None, title="A", rule="r1", cases=None, base_hash=None)
    b = s.create(path=None, title="B", rule="r2", cases="c", base_hash=None, author={"id": 7, "email": "e@x.io", "name": "E"})
    assert a["version"] == 1 and len(a["id"]) == 32 and b["author_id"] == 7
    assert [d["title"] for d in s.list()] == ["B", "A"]
    upd = s.update(a["id"], path="p.yml", title="A2", rule="r1b", cases=None, base_hash="h", version=1)
    assert upd["version"] == 2 and upd["title"] == "A2" and upd["updated_at"] > a["updated_at"] and upd["created_at"] == a["created_at"]
    assert [d["title"] for d in s.list()] == ["A2", "B"]
    with pytest.raises(DraftError) as e:
        s.update(a["id"], path=None, title="x", rule="r", cases=None, base_hash=None, version=1)
    assert e.value.status == 409
    s.delete(a["id"])
    with pytest.raises(DraftError):
        s.update(a["id"], path=None, title="x", rule="r", cases=None, base_hash=None, version=2)


def test_store_persists_across_instances(tmp_path):
    DraftStore(tmp_path / "d.db").create(path=None, title="keep", rule="r", cases=None, base_hash=None)
    assert [d["title"] for d in DraftStore(tmp_path / "d.db").list()] == ["keep"]


@pytest.mark.parametrize(("title", "rule", "path", "want"), [
    ("  Given  ", "title: Y\n", "p.yml", "Given"),
    (None, "title: From rule\nlevel: low\n", "p.yml", "From rule"),
    ("   ", "title: From rule\n", None, "From rule"),
    (None, "title: [unclosed\n", "dir/p.yml", "dir/p.yml"),  # invalid YAML is fine
    (None, "- a\n- b\n", None, "Untitled draft"),
    (None, "", None, "Untitled draft"),
    ("x" * 300, "", None, "x" * 200),
])
def test_title_resolution(title, rule, path, want):
    assert drafts_mod.resolve_title(title, rule, path) == want


def test_limit_is_per_author(tmp_path):
    s = DraftStore(tmp_path / "d.db")
    me = {"id": 1, "email": "a@x.io", "name": "A"}
    for _ in range(MAX_PER_AUTHOR):
        s.create(path=None, title="t", rule="r", cases=None, base_hash=None, author=me)
    with pytest.raises(DraftError) as e:
        s.create(path=None, title="t", rule="r", cases=None, base_hash=None, author=me)
    assert e.value.status == 409 and "limit" in str(e.value)
    s.create(path=None, title="t", rule="r", cases=None, base_hash=None, author={**me, "id": 2})
    s.create(path=None, title="t", rule="r", cases=None, base_hash=None)  # accounts off: its own bucket


def test_rule_hash_ignores_paths_outside_rules(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yml").write_text("x", encoding="utf-8")
    (tmp_path / "secret.yml").write_text("y", encoding="utf-8")
    assert drafts_mod.rule_hash(rules, "a.yml") and drafts_mod.rule_hash(rules, "nope.yml") is None
    assert drafts_mod.rule_hash(rules, "../secret.yml") is None and drafts_mod.rule_hash(rules, None) is None


# --------------------------------------------------------------------------- config


def test_config_key(tmp_path):
    assert parse_config_text("", tmp_path).drafts_enabled is True
    assert parse_config_text("drafts:\n  enabled: false\n", tmp_path).drafts_enabled is False
    assert parse_config_text("drafts:\n", tmp_path).drafts_enabled is True
    assert parse_config_text("drafts: false\n", tmp_path).drafts_enabled is False
    assert parse_config_text("drafts: {enabled: true}\n", tmp_path).drafts_enabled is True
    for bad in ("drafts: yes please\n", "drafts:\n  enabled: maybe\n"):
        with pytest.raises(ConfigError):
            parse_config_text(bad, tmp_path)


# --------------------------------------------------------------------------- HTTP, accounts off


def test_http_crud_without_accounts(tmp_path, monkeypatch):
    c = local_client(tmp_path, monkeypatch)
    assert c.get("/api/drafts").json() == {"enabled": True, "reason": None, "drafts": []}
    assert not (tmp_path / ".vitrix" / "drafts.db").exists()
    r = c.post("/api/drafts", json=BODY)
    assert r.status_code == 201
    d = r.json()
    assert d["version"] == 1 and d["author"] is None and d["mine"] is True and d["stale"] is False  # rules/windows/x.yml is absent at save and still absent
    assert d["rule"] == RULE_OK and d["cases"] == "cases: []\n" and d["base_hash"] is None
    assert d["title"] and d["created_at"].endswith("Z") and len(d["id"]) == 32
    listing = c.get("/api/drafts").json()["drafts"]
    assert len(listing) == 1 and "rule" not in listing[0] and listing[0]["id"] == d["id"]
    assert c.get(f"/api/drafts/{d['id']}").json() == d
    u = c.put(f"/api/drafts/{d['id']}", json={**BODY, "title": "Renamed", "version": 1})
    assert u.status_code == 200 and u.json()["version"] == 2 and u.json()["title"] == "Renamed"
    assert c.put(f"/api/drafts/{d['id']}", json={**BODY, "version": 1}).status_code == 409
    assert c.delete(f"/api/drafts/{d['id']}").status_code == 204
    assert c.get(f"/api/drafts/{d['id']}").status_code == 404
    assert c.delete(f"/api/drafts/{d['id']}").status_code == 404
    assert c.put(f"/api/drafts/{d['id']}", json={**BODY, "version": 1}).status_code == 404


def test_drafts_never_touch_rules_dir(tmp_path, monkeypatch):
    c = local_client(tmp_path, monkeypatch)
    before = sorted(p.name for p in (tmp_path / "rules").rglob("*"))
    assert c.post("/api/drafts", json=BODY).status_code == 201
    assert sorted(p.name for p in (tmp_path / "rules").rglob("*")) == before
    assert (tmp_path / ".vitrix" / "drafts.db").is_file()


def test_invalid_yaml_and_no_path_can_be_saved(tmp_path, monkeypatch):
    c = local_client(tmp_path, monkeypatch)
    d = c.post("/api/drafts", json={"rule": "title: [broken\n  nope"}).json()
    assert d["path"] is None and d["stale"] is False and d["title"] == "Untitled draft"
    assert c.post("/api/drafts", json={"rule": "x", "path": "  "}).json()["path"] is None


def test_validation_limits_and_bad_paths(tmp_path, monkeypatch):
    c = local_client(tmp_path, monkeypatch)
    big = "x" * 200_001
    assert c.post("/api/drafts", json={"rule": ""}).status_code == 422
    assert c.post("/api/drafts", json={"rule": big}).status_code == 422
    assert c.post("/api/drafts", json={"rule": "x", "cases": big}).status_code == 422
    assert c.post("/api/drafts", json={"rule": "x", "title": "t" * 201}).status_code == 422
    assert c.post("/api/drafts", json={"rule": "x", "path": "a" * 301}).status_code == 422
    for bad in ("../../etc/passwd.yml", "/abs/x.yml", "a/b.txt", "a/../b.yml"):
        assert c.post("/api/drafts", json={"rule": "x", "path": bad}).status_code == 422, bad
    assert c.post("/api/drafts", json={"rule": "x", "path": "win\\x.yml"}).json()["path"] == "win/x.yml"
    d = c.post("/api/drafts", json={"rule": "x"}).json()
    assert c.put(f"/api/drafts/{d['id']}", json={"rule": "x"}).status_code == 422  # version required
    assert c.put(f"/api/drafts/{d['id']}", json={"rule": "x", "version": 0}).status_code == 422
    assert c.get("/api/drafts/not-a-valid-id").status_code == 404
    assert c.get("/api/drafts/" + "A" * 32).status_code == 404  # uppercase is not the id format
    assert c.delete("/api/drafts/" + "g" * 32).status_code == 404


def test_http_limit_409(tmp_path, monkeypatch):
    c = local_client(tmp_path, monkeypatch)
    store = DraftStore(tmp_path / ".vitrix" / "drafts.db")
    for _ in range(MAX_PER_AUTHOR):
        store.create(path=None, title="t", rule="r", cases=None, base_hash=None)
    r = c.post("/api/drafts", json={"rule": "x"})
    assert r.status_code == 409 and r.json()["detail"] == "draft limit reached (100); delete some first"


def test_stale_follows_the_rule_file(tmp_path, monkeypatch):
    c = local_client(tmp_path, monkeypatch)
    d = c.post("/api/drafts", json={**BODY, "path": "r.yml"}).json()  # rules/r.yml exists
    assert d["base_hash"] and d["stale"] is False
    (tmp_path / "rules" / "r.yml").write_text(RULE_OK + "\n# changed\n", encoding="utf-8")
    assert c.get(f"/api/drafts/{d['id']}").json()["stale"] is True
    assert c.get("/api/drafts").json()["drafts"][0]["stale"] is True
    # saving again re-bases the draft on the file as it is now
    u = c.put(f"/api/drafts/{d['id']}", json={**BODY, "path": "r.yml", "version": 1}).json()
    assert u["stale"] is False and u["base_hash"] != d["base_hash"]


# --------------------------------------------------------------------------- the auth-off rule


def test_loopback_rule_requires_a_local_client(tmp_path, monkeypatch):
    c = local_client(tmp_path, monkeypatch, client=("203.0.113.9", 4000))
    r = c.get("/api/drafts")
    assert r.status_code == 200 and r.json()["enabled"] is False and "this machine" in r.json()["reason"] and r.json()["drafts"] == []
    for call in (lambda: c.post("/api/drafts", json=BODY), lambda: c.get("/api/drafts/" + "a" * 32),
                 lambda: c.put("/api/drafts/" + "a" * 32, json={**BODY, "version": 1}), lambda: c.delete("/api/drafts/" + "a" * 32)):
        resp = call()
        assert resp.status_code == 403 and resp.json()["detail"].startswith("Local drafts are off: ")
    assert not (tmp_path / ".vitrix").exists()


def test_ipv6_loopback_is_local(tmp_path, monkeypatch):
    c = local_client(tmp_path, monkeypatch, client=("::1", 4000))
    assert c.post("/api/drafts", json=BODY).status_code == 201


def test_non_local_server_bind_turns_drafts_off_without_accounts(tmp_path, monkeypatch):
    c = local_client(tmp_path, monkeypatch, hosts="testserver")  # e.g. `vitrix serve --host 0.0.0.0` adds hosts
    r = c.get("/api/drafts").json()
    assert r["enabled"] is False and "non-local" in r["reason"]
    assert c.post("/api/drafts", json=BODY).status_code == 403


def test_disabled_in_config(tmp_path, monkeypatch):
    c = local_client(tmp_path, monkeypatch, extra="drafts:\n  enabled: false\n")
    r = c.get("/api/drafts").json()
    assert r["enabled"] is False and "drafts.enabled" in r["reason"]
    assert c.post("/api/drafts", json=BODY).status_code == 403
    assert not (tmp_path / ".vitrix").exists()


def test_disabled_in_config_with_accounts_on(tmp_path):
    owner = TestClient(create_app(make_project(tmp_path, extra_cfg=AUTH_ON + "drafts:\n  enabled: false\n")), base_url=BASE)
    register(owner)
    assert owner.get("/api/drafts").json()["enabled"] is False
    assert owner.post("/api/drafts", json=BODY).status_code == 403


def test_write_guards_still_apply(tmp_path, monkeypatch):
    c = local_client(tmp_path, monkeypatch)
    assert c.post("/api/drafts", content=b"{}", headers={"content-type": "text/plain"}).status_code == 415
    assert c.post("/api/drafts", json=BODY, headers={"origin": "https://evil.example"}).status_code == 403
    assert c.delete("/api/drafts/" + "a" * 32, headers={"origin": "https://evil.example"}).status_code == 403
    assert c.get("/api/drafts", headers={"host": "evil.example"}).status_code == 403


def test_cors_allows_put_and_delete_when_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("VITRIX_CORS_ORIGINS", "http://localhost:5173")
    c = local_client(tmp_path, monkeypatch)
    r = c.options("/api/drafts/" + "a" * 32, headers={"origin": "http://localhost:5173", "access-control-request-method": "DELETE"})
    assert r.status_code == 200 and "DELETE" in r.headers["access-control-allow-methods"] and "PUT" in r.headers["access-control-allow-methods"]


# --------------------------------------------------------------------------- HTTP, accounts on


def test_roles_viewer_reads_editor_writes(tmp_path):
    t = team(tmp_path)
    d = t["ed1"].post("/api/drafts", json=BODY)
    assert d.status_code == 201
    d = d.json()
    assert d["author"]["email"] == "ed1@example.com" and d["mine"] is True
    assert t["view"].post("/api/drafts", json=BODY).status_code == 403
    assert t["view"].put(f"/api/drafts/{d['id']}", json={**BODY, "version": 1}).status_code == 403
    assert t["view"].delete(f"/api/drafts/{d['id']}").status_code == 403
    seen = t["view"].get("/api/drafts").json()
    assert seen["enabled"] is True and seen["drafts"] == []  # drafts are private to their author (ADR 0007)
    assert t["view"].get(f"/api/drafts/{d['id']}").status_code == 404
    assert TestClient(t["owner"].app, base_url=BASE).get("/api/drafts").status_code == 401


def test_drafts_are_private_to_their_author(tmp_path):
    t = team(tmp_path)
    d = t["ed1"].post("/api/drafts", json=BODY).json()
    for who in ("ed2", "owner", "view"):  # other editor, owner and viewer: same 404 as a missing id
        assert t[who].get(f"/api/drafts/{d['id']}").status_code == 404, who
        assert t[who].get("/api/drafts").json()["drafts"] == [], who
        assert t[who].delete(f"/api/drafts/{d['id']}").status_code in (403, 404), who
    assert t["ed2"].put(f"/api/drafts/{d['id']}", json={**BODY, "version": 1}).status_code == 404
    assert t["owner"].put(f"/api/drafts/{d['id']}", json={**BODY, "version": 1}).status_code == 404
    assert t["ed2"].post("/api/ci/drafts", json={"draft_ids": [d["id"]]}).status_code == 404
    assert t["ed1"].get(f"/api/drafts/{d['id']}").json()["version"] == 1
    assert t["ed1"].put(f"/api/drafts/{d['id']}", json={**BODY, "version": 1}).status_code == 200
    assert t["ed1"].put(f"/api/drafts/{d['id']}", json={**BODY, "version": 1}).status_code == 409
    assert t["ed1"].delete(f"/api/drafts/{d['id']}").status_code == 204


def test_authorless_drafts_are_shared_once_accounts_are_on(tmp_path):
    t = team(tmp_path)
    store = DraftStore(tmp_path / ".vitrix" / "drafts.db")
    a = store.create(path=None, title="old", rule="r", cases=None, base_hash=None)
    b = store.create(path=None, title="old2", rule="r", cases=None, base_hash=None)
    assert t["ed2"].get(f"/api/drafts/{a['id']}").json()["mine"] is True
    assert t["view"].get(f"/api/drafts/{a['id']}").status_code == 200  # authorless ones stay shared
    assert t["view"].put(f"/api/drafts/{a['id']}", json={**BODY, "version": 1}).status_code == 403
    assert t["ed2"].put(f"/api/drafts/{a['id']}", json={**BODY, "version": 1}).status_code == 200
    assert t["ed1"].delete(f"/api/drafts/{a['id']}").status_code == 204
    assert t["ed1"].delete(f"/api/drafts/{b['id']}").status_code == 204


def test_limit_counts_per_author_with_accounts(tmp_path):
    t = team(tmp_path)
    store = DraftStore(tmp_path / ".vitrix" / "drafts.db")
    me = t["ed1"].get("/api/auth/me").json()["user"]
    for _ in range(MAX_PER_AUTHOR):
        store.create(path=None, title="t", rule="r", cases=None, base_hash=None, author={"id": me["id"], "email": me["email"], "name": me["name"]})
    assert t["ed1"].post("/api/drafts", json=BODY).status_code == 409
    assert t["ed2"].post("/api/drafts", json=BODY).status_code == 201


def test_accounts_on_allows_drafts_from_any_client_address(tmp_path):
    app = create_app(make_project(tmp_path, extra_cfg=AUTH_ON))
    register(TestClient(app, base_url=BASE, client=LOOPBACK))  # the owner is created from the machine itself
    owner = TestClient(app, base_url=BASE, client=("203.0.113.9", 1))
    login(owner, "owner@example.com", PW)
    assert owner.post("/api/drafts", json=BODY).status_code == 201


# --------------------------------------------------------------------------- source / batch_id (packs import)


def test_create_many_atomic_quota_and_batch_filter(tmp_path):
    s = DraftStore(tmp_path / "d.db")
    ids = s.create_many([{"rule": f"r{i}", "path": f"p{i}.yml", "source": "sigmahq@r1:rules/x", "batch_id": "b1"} for i in range(3)])
    assert len(ids) == 3 and [d["batch_id"] for d in s.list("b1")] == ["b1"] * 3
    assert s.list("nope") == [] and s.get(ids[0])["source"] == "sigmahq@r1:rules/x"
    s.create(path=None, title=None, rule="plain", cases=None, base_hash=None)
    assert s.list()[0]["source"] is None
    over = [{"rule": "r"} for _ in range(MAX_PER_AUTHOR)]
    with pytest.raises(DraftError) as e:
        s.create_many(over)
    assert e.value.status == 409 and len(s.list()) == 4  # nothing stored


def test_old_database_is_migrated(tmp_path):
    import sqlite3

    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.executescript("CREATE TABLE drafts (id TEXT PRIMARY KEY, workspace_id INTEGER NOT NULL DEFAULT 1, path TEXT, title TEXT NOT NULL,"
                      " rule TEXT NOT NULL, cases TEXT, base_hash TEXT, author_id INTEGER, author_email TEXT, author_name TEXT,"
                      " created_at REAL NOT NULL, updated_at REAL NOT NULL, version INTEGER NOT NULL DEFAULT 1);"
                      "INSERT INTO drafts (id,title,rule,created_at,updated_at) VALUES ('" + "a" * 32 + "','t','r',1,1);")
    con.commit()
    con.close()
    s = DraftStore(db)
    assert s.get("a" * 32)["batch_id"] is None
    assert s.create(path=None, title="n", rule="r", cases=None, base_hash=None, batch_id="b")["batch_id"] == "b"


def test_api_exposes_source_and_batch_filter(tmp_path, monkeypatch):
    c = local_client(tmp_path, monkeypatch)
    r = c.post("/api/drafts", json=BODY).json()
    assert r["source"] is None and r["batch_id"] is None
    assert c.get("/api/drafts?batch=zzz").json()["drafts"] == []
    assert len(c.get("/api/drafts").json()["drafts"]) == 1
