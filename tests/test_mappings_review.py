"""Sprint 5 code review fixes (S5-1 .. S5-6) for mappings.yml."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest
from test_engine import CASES_OK, RULE_OK, make_project

from vitrix import mappings, publication
from vitrix.backends import available_targets, convert_text
from vitrix.config import ConfigHolder, KqlConfig, load_config

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from vitrix.api import create_app  # noqa: E402

BASE = "http://127.0.0.1:8000"
LOOPBACK = ("127.0.0.1", 50000)
HAS_GIT = shutil.which("git") is not None


def client(tmp_path, monkeypatch, extra=""):
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    publication.invalidate()
    return TestClient(create_app(make_project(tmp_path, extra_cfg=extra)), base_url=BASE, client=LOOPBACK)


# --------------------------------------------------------------------------- S5-1 inferred tables


def test_inferred_table_is_named_in_the_fix_and_field_mappings_apply():
    target = available_targets()["kql"]
    bad = RULE_OK.replace("CommandLine|contains", "NoSuchField|contains")
    with pytest.raises(Exception) as e:
        convert_text(bad, target, [], KqlConfig())
    assert e.value.details()["fix"] == {"kind": "kql-field", "table": "DeviceProcessEvents", "field": "NoSuchField", "suggestion": None}
    # mapping the field for the INFERRED table makes the rule convert
    out = convert_text(bad, target, [], KqlConfig({}, None, {"DeviceProcessEvents": {"NoSuchField": "CommandLine"}}))
    assert out.startswith("DeviceProcessEvents") and "CommandLine" in out
    # renaming a field that exists also works on an inferred table
    ok = convert_text(RULE_OK, target, [], KqlConfig({}, None, {"DeviceProcessEvents": {"Image": "FileName"}}))
    assert "FileName" in ok.split("\n", 1)[1]


# --------------------------------------------------------------------------- S5-2 holder without vitrix.yml


def test_holder_without_vitrix_yml_picks_up_mappings_yml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    t = [0.0]
    holder = ConfigHolder(None, debounce=0.0, clock=lambda: t[0])
    assert holder.get().kql.tables == {}
    mappings.update(tmp_path, {"kql": {"tables": {"bitbucket/audit": "BitbucketAudit"}}}, None)
    t[0] += 5
    assert holder.get().kql.tables == {"bitbucket/audit": "BitbucketAudit"}
    mappings.update(tmp_path, {"kql": {"tables": {"okta/system": "Okta"}}}, mappings.read(tmp_path)[1])
    holder.refresh()  # explicit refresh works too
    assert set(holder.get().kql.tables) == {"bitbucket/audit", "okta/system"}


# --------------------------------------------------------------------------- S5-3 one guarded reader


def test_reader_refuses_links_big_files_and_does_not_echo_source(tmp_path):
    (tmp_path / "mappings.yml").write_text("kql:\n  tables: {a/b: [unclosed secret-token\n", encoding="utf-8")
    with pytest.raises(mappings.MappingsError) as e:
        mappings.read(tmp_path)
    assert "secret-token" not in str(e.value) and "line" in str(e.value)
    (tmp_path / "mappings.yml").write_text("schema_version: 1\nmysecretkey: 1\n", encoding="utf-8")
    with pytest.raises(mappings.MappingsError) as e:
        mappings.read(tmp_path)
    assert "mysecretkey" not in str(e.value)
    (tmp_path / "mappings.yml").write_text("# " + "x" * (mappings.MAX_BYTES + 10) + "\n", encoding="utf-8")
    with pytest.raises(mappings.MappingsError, match="too large"):
        mappings.read(tmp_path)
    (tmp_path / "mappings.yml").unlink()
    (tmp_path / "real.yml").write_text("schema_version: 1\n", encoding="utf-8")
    try:
        os.symlink(tmp_path / "real.yml", tmp_path / "mappings.yml")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    with pytest.raises(mappings.MappingsError, match="links"):
        mappings.read(tmp_path)
    make_project(tmp_path)
    from vitrix.config import ConfigError

    with pytest.raises(ConfigError, match="links"):  # the config loader uses the same reader
        load_config(str(tmp_path / "vitrix.yml"))


def test_publish_refuses_an_invalid_mappings_file(tmp_path, monkeypatch):
    from test_github import GITHUB_CFG

    c = client(tmp_path, monkeypatch, extra=GITHUB_CFG)
    saved = c.post("/api/rules", json={"path": "n.yml", "rule": RULE_OK.replace("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"), "cases": CASES_OK}).json()
    (tmp_path / "mappings.yml").write_text("kql: {tables: {nope: T}}\n", encoding="utf-8")
    r = c.post("/api/ci/rules", json={"source": "file", "path": "n.yml", "sha": saved["sha"], "cases_sha": saved["cases_sha"]})
    assert r.status_code == 422 and "mappings.yml is invalid" in r.json()["detail"]
    assert c.post("/api/ci/mappings", json={"sha": "0" * 64}).status_code == 422


# --------------------------------------------------------------------------- S5-4 three-way merge


def entry(tables=None, fields=None, default=None, folders=None):
    return {"schema_version": 1, "kql": {"tables": tables or {}, "fields": fields or {}}, "final_language": {"default": default, "folders": folders or {}}}


def test_merge3_keeps_both_sides_and_conflicts_on_the_same_entry():
    base = entry({"a/x": "A"})
    local = entry({"a/x": "A", "b/y": "B"}, default="splunk")  # local added b/y and a default
    theirs = entry({"a/x": "A", "c/z": "C"}, fields={"C": {"f": "g"}})  # origin added c/z and fields
    m = mappings.merge3(base, local, theirs)
    assert m["kql"]["tables"] == {"a/x": "A", "b/y": "B", "c/z": "C"} and m["kql"]["fields"] == {"C": {"f": "g"}} and m["final_language"]["default"] == "splunk"
    # local removal of an entry origin did not touch is applied; origin-only changes survive
    assert mappings.merge3(entry({"a/x": "A", "k/k": "K"}), entry({"a/x": "A"}), entry({"a/x": "A", "k/k": "K", "n/n": "N"}))["kql"]["tables"] == {"a/x": "A", "n/n": "N"}
    with pytest.raises(mappings.MappingsError) as e:
        mappings.merge3(base, entry({"a/x": "LOCAL"}), entry({"a/x": "THEIRS"}))
    assert e.value.status == 409 and "sync first" in str(e.value)
    same = mappings.merge3(base, entry({"a/x": "B2"}), entry({"a/x": "B2"}))  # both made the same change: fine
    assert same["kql"]["tables"] == {"a/x": "B2"}


def _git(root, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "A", "GIT_AUTHOR_EMAIL": "a@x", "GIT_COMMITTER_NAME": "A", "GIT_COMMITTER_EMAIL": "a@x"}
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env, text=True).stdout


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_publish_merges_with_what_others_put_on_origin(tmp_path, monkeypatch):
    from test_github import GITHUB_CFG, FakeGitHub, client_for

    from vitrix import service

    origin, work, other = tmp_path / "origin.git", tmp_path / "work", tmp_path / "other"
    work.mkdir()
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    c = client(work, monkeypatch, extra=GITHUB_CFG)
    cfg = load_config(str(work / "vitrix.yml"))
    sent = []

    class Spy(FakeGitHub):
        def __call__(self, method, url, body):
            if body and "tree" in body:
                sent.append(body["tree"])
            return super().__call__(method, url, body)

    monkeypatch.setattr(service, "GitHubClient", lambda gh: client_for(cfg, Spy()))
    c.put("/api/mappings", json={"sha": None, "kql": {"tables": {"a/x": "A"}}})
    _git(work, "init", "-q", "-b", "main")
    _git(work, "add", ".")
    _git(work, "commit", "-q", "-m", "init")
    _git(work, "remote", "add", "origin", str(origin))
    _git(work, "push", "-q", "origin", "main")
    # a teammate adds c/z on origin
    subprocess.run(["git", "clone", "-q", str(origin), str(other)], check=True)
    mappings.update(other, {"kql": {"tables": {"c/z": "C"}}}, mappings.read(other)[1])
    _git(other, "add", "mappings.yml")
    _git(other, "commit", "-q", "-m", "teammate")
    _git(other, "push", "-q", "origin", "main")
    _git(work, "fetch", "-q", "origin")
    # we add b/y locally, then publish the standalone mappings
    got = c.get("/api/mappings").json()
    put = c.put("/api/mappings", json={"sha": got["sha"], "kql": {"tables": {"b/y": "B"}}}).json()
    publication.invalidate()
    r = c.post("/api/ci/mappings", json={"sha": put["sha"]})
    assert r.status_code == 201, r.text
    body = next(t for tree in sent for t in tree if t["path"] == "mappings.yml")["content"]
    doc = mappings.parse(body)
    assert doc["kql"]["tables"] == {"a/x": "A", "b/y": "B", "c/z": "C"}  # nobody's entries dropped
    # the same entry changed on both sides -> 409
    mappings.update(other, {"kql": {"tables": {"a/x": "THEIRS"}}}, mappings.read(other)[1])
    _git(other, "commit", "-qam", "again")
    _git(other, "push", "-q", "origin", "main")
    _git(work, "fetch", "-q", "origin")
    cur = c.get("/api/mappings").json()
    ours = c.put("/api/mappings", json={"sha": cur["sha"], "kql": {"tables": {"a/x": "OURS"}}}).json()
    publication.invalidate()
    conflict = c.post("/api/ci/mappings", json={"sha": ours["sha"]})
    assert conflict.status_code == 409 and "sync first" in conflict.json()["detail"]


# --------------------------------------------------------------------------- S5-6 stale languages


def test_stale_language_does_not_block_other_edits_and_is_reported(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch, extra="targets: [splunk]\n")
    (tmp_path / "mappings.yml").write_text("schema_version: 1\nfinal_language:\n  default: elastic-eql\n  folders:\n    'win*/*': splunk\n", encoding="utf-8")
    got = c.get("/api/mappings").json()
    assert [w["code"] for w in got["warnings"]] == ["inactive-language"] and got["warnings"][0]["language"] == "elastic-eql"
    # changing ANOTHER entry succeeds although the default is stale
    r = c.put("/api/mappings", json={"sha": got["sha"], "final_language": {"folders": {"lin*/*": "sigma"}}})
    assert r.status_code == 200 and r.json()["final_language"]["default"] == "elastic-eql"
    # setting a new entry to an inactive language is still refused; clearing the stale one works
    sha = r.json()["sha"]
    assert c.put("/api/mappings", json={"sha": sha, "final_language": {"folders": {"x/*": "elastic-eql"}}}).status_code == 422
    fixed = c.put("/api/mappings", json={"sha": sha, "final_language": {"default": None}})
    assert fixed.status_code == 200 and fixed.json()["warnings"] == []
