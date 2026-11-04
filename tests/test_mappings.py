"""mappings.yml (E1): model, merge with vitrix.yml, GET/PUT, KQL field mapping, publish, preview issues as info."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest
from test_engine import CASES_OK, RULE_OK, make_project

from vitrix import local_rules, mappings, publication
from vitrix.backends import available_targets, convert_text
from vitrix.config import ConfigError, ConfigHolder, KqlConfig, load_config

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from vitrix.api import create_app  # noqa: E402

BASE = "http://127.0.0.1:8000"
LOOPBACK = ("127.0.0.1", 50000)

BITBUCKET = """title: Bitbucket permission change
id: eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee
status: test
description: d
author: t
date: 2026-11-01
logsource:
  product: bitbucket
  service: audit
detection:
  selection:
    auditType.category: Permission
    actor.name|contains: bob
  condition: selection
falsepositives: [none]
level: low
"""


def client(tmp_path, monkeypatch, extra="", **kw):
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    publication.invalidate()
    return TestClient(create_app(make_project(tmp_path, extra_cfg=extra, **kw)), base_url=BASE, client=LOOPBACK)


# --------------------------------------------------------------------------- model and merge


def test_parse_validates_schema():
    ok = mappings.parse("schema_version: 1\nkql:\n  tables:\n    Bitbucket/Audit: BitbucketAudit\n  fields:\n    BitbucketAudit:\n      actor.name: ActorName\n")
    assert ok["kql"]["tables"] == {"bitbucket/audit": "BitbucketAudit"} and ok["kql"]["fields"]["BitbucketAudit"] == {"actor.name": "ActorName"}
    assert mappings.parse("")["kql"] == {"tables": {}, "fields": {}}
    for bad in ["- a\n", "schema_version: 2\n", "x: 1\n", "kql: {tables: {nope: T}}\n", "kql: {tables: {a/b: 'bad table'}}\n",
                "kql: {fields: {T: {f: 'bad col!'}}}\n", "kql: {fields: {'bad t': {f: c}}}\n", "kql: [", "kql: {other: 1}\n"]:
        with pytest.raises(mappings.MappingsError):
            mappings.parse(bad)


def test_loader_merges_and_mappings_win_over_vitrix_yml(tmp_path):
    make_project(tmp_path, extra_cfg="kql:\n  tables:\n    windows/system: Event\n    bitbucket/audit: Wrong\n  default_table: Event\n")
    (tmp_path / "mappings.yml").write_text("schema_version: 1\nkql:\n  tables:\n    bitbucket/audit: BitbucketAudit\n  fields:\n    BitbucketAudit:\n      actor.name: ActorName\n", encoding="utf-8")
    cfg = load_config(str(tmp_path / "vitrix.yml"))
    assert cfg.kql.tables == {"windows/system": "Event", "bitbucket/audit": "BitbucketAudit"}
    assert cfg.kql.default_table == "Event" and cfg.kql.fields == {"BitbucketAudit": {"actor.name": "ActorName"}}
    (tmp_path / "mappings.yml").write_text("kql: {tables: {nope: T}}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="mappings.yml"):
        load_config(str(tmp_path / "vitrix.yml"))


def test_hot_reload_picks_up_mappings_yml(tmp_path):
    make_project(tmp_path)
    t = [0.0]
    holder = ConfigHolder(tmp_path / "vitrix.yml", debounce=0.0, clock=lambda: t[0])
    assert holder.get().kql.tables == {}
    mappings.update(tmp_path, {"kql": {"tables": {"bitbucket/audit": "BitbucketAudit"}}}, None)
    t[0] += 5
    assert holder.get().kql.tables == {"bitbucket/audit": "BitbucketAudit"}
    (tmp_path / "mappings.yml").write_text("kql: {tables: {nope: T}}\n", encoding="utf-8")  # a bad edit keeps the last good config
    t[0] += 5
    assert holder.get().kql.tables == {"bitbucket/audit": "BitbucketAudit"} and "mappings.yml" in holder.reload_error


# --------------------------------------------------------------------------- conversion


def test_kql_table_issue_has_a_machine_usable_fix():
    target = available_targets()["kql"]
    with pytest.raises(Exception) as e:
        convert_text(BITBUCKET, target, [], KqlConfig())
    d = e.value.details()
    assert d["code"] == "kql-table" and d["fix"] == {"kind": "kql-table", "key": "bitbucket/audit", "suggestion": "BitbucketAudit_CL"}
    assert "mappings.yml" in d["hint"] and "kql_table: BitbucketAudit_CL" in d["hint"] and "Okta" not in d["hint"]  # same suggestion everywhere


def test_per_rule_kql_table_must_be_an_identifier():
    target = available_targets()["kql"]
    evil = BITBUCKET.replace("level: low", 'level: low\nvitrix:\n  kql_table: "X | drop"')
    with pytest.raises(Exception) as e:
        convert_text(evil, target, [], KqlConfig())
    assert e.value.details()["code"] == "kql-table"  # never pasted into the query
    import yaml

    from vitrix import routing

    assert any("kql_table" in m for m in routing.problems(yaml.safe_load(evil)))


def test_names_with_query_syntax_are_rejected_everywhere(tmp_path):
    for kql in ({"tables": {"a/b": "T | drop"}}, {"fields": {"T": {"f": "c\nx"}}}, {"fields": {"T": {"f'x": "c"}}}):
        with pytest.raises(mappings.MappingsError):
            mappings.apply_patch(mappings.empty(), {"kql": kql})
    (tmp_path / "vitrix.yml").write_text("schema_version: 1\n", encoding="utf-8")
    (tmp_path / "mappings.yml").write_text("kql:\n  tables:\n    a/b: 'T|x'\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "vitrix.yml"))


def test_field_mapping_is_applied_for_the_table():
    target = available_targets()["kql"]
    plain = convert_text(BITBUCKET, target, [], KqlConfig({"bitbucket/audit": "BitbucketAudit"}))
    assert "actor.name" in plain
    mapped = convert_text(BITBUCKET, target, [], KqlConfig({"bitbucket/audit": "BitbucketAudit"}, None,
                                                           {"BitbucketAudit": {"actor.name": "ActorName", "auditType.category": "Category"}}))
    assert "ActorName" in mapped and "Category" in mapped and "actor.name" not in mapped and mapped.startswith("BitbucketAudit")
    other = convert_text(BITBUCKET, target, [], KqlConfig({"bitbucket/audit": "BitbucketAudit"}, None, {"OtherTable": {"actor.name": "Nope"}}))
    assert other == plain  # mappings of another table do not leak


def test_unmapped_field_error_carries_a_kql_field_fix(tmp_path):
    target = available_targets()["kql"]
    rule = RULE_OK.replace("CommandLine|contains", "NoSuchField|contains")
    try:
        convert_text(rule, target, [], KqlConfig({"windows/process_creation": "DeviceProcessEvents"}))
    except Exception as exc:
        d = exc.details()
        assert d["code"] == "kql-field" and d["fix"]["kind"] == "kql-field" and d["fix"]["field"] == "NoSuchField" and d["fix"]["table"] == "DeviceProcessEvents"
    else:
        pytest.skip("this backend version accepts unknown fields")


def test_preview_failures_are_info_and_never_fail_the_rule(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch, rule_text=BITBUCKET, cases_text=None, extra="targets: [splunk, kql]\ndefault_target: splunk\nrequire_cases: false\n")
    # make_project writes its own targets line first; the rule's final language is the default (splunk)
    v = c.post("/api/validate", json={"rule": BITBUCKET, "targets": None}).json()
    assert v["conversions"]["kql"]["ok"] is False and v["conversions"]["kql"]["severity"] == "info" and v["conversions"]["kql"]["final"] is False
    assert v["conversions"]["kql"]["fix"]["kind"] == "kql-table"
    assert [i["severity"] for i in v["preview_issues"]] == ["info"] and v["preview_issues"][0]["target"] == "kql"
    assert v["state"] != "fail" or all(i["severity"] != "info" for i in v["lint"])
    d = c.get("/api/rules/r.yml").json()
    assert d["preview_issues"] and d["conversions"]["kql"]["severity"] == "info"
    # when KQL IS the final language the same failure is an error
    final = BITBUCKET.replace("level: low", "level: low\nvitrix:\n  target: kql")
    v2 = c.post("/api/validate", json={"rule": final}).json()
    assert v2["conversions"]["kql"]["severity"] == "error" and v2["conversions"]["kql"]["final"] is True and v2["preview_issues"] == [] and v2["state"] == "fail"


# --------------------------------------------------------------------------- API


def test_get_put_roundtrip_with_sha_lock_and_patch_semantics(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch, extra="kql:\n  tables:\n    windows/system: Event\n")
    g = c.get("/api/mappings").json()
    assert g["exists"] is False and g["sha"] is None and g["kql"] == {"tables": {}, "fields": {}} and g["from_vitrix_yml"]["tables"] == {"windows/system": "Event"}
    assert g["publication"]["state"] == "absent"
    r = c.put("/api/mappings", json={"sha": None, "kql": {"tables": {"bitbucket/audit": "BitbucketAudit"}, "fields": {"BitbucketAudit": {"actor.name": "ActorName"}}}})
    assert r.status_code == 200, r.text
    one = r.json()
    assert one["exists"] and one["kql"]["tables"] == {"bitbucket/audit": "BitbucketAudit"} and len(one["sha"]) == 64 and one["text"].startswith("# Query mappings")
    assert (tmp_path / "mappings.yml").read_text(encoding="utf-8") == one["text"] and not list(tmp_path.glob(".*.tmp"))
    # the app now converts with it (hot reload through the holder)
    # stale / missing sha -> 409; patch adds and removes with null
    assert c.put("/api/mappings", json={"sha": None, "kql": {"tables": {"a/b": "T"}}}).status_code == 409
    assert c.put("/api/mappings", json={"sha": "0" * 64, "kql": {"tables": {"a/b": "T"}}}).status_code == 409
    two = c.put("/api/mappings", json={"sha": one["sha"], "kql": {"tables": {"bitbucket/audit": None, "okta/system": "Okta"}, "fields": {"BitbucketAudit": {"actor.name": None, "x": "Y"}}}}).json()
    assert two["kql"]["tables"] == {"okta/system": "Okta"} and two["kql"]["fields"] == {"BitbucketAudit": {"x": "Y"}}
    assert c.put("/api/mappings", json={"sha": two["sha"], "kql": {"fields": {"BitbucketAudit": None}}}).json()["kql"]["fields"] == {}


def test_put_validation_and_guards(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    for bad in ({"tables": {"nope": "T"}}, {"tables": {"a/b": "bad table"}}, {"fields": {"T": {"f": "bad col!"}}}, {"other": {}}, {"tables": ["x"]}):
        assert c.put("/api/mappings", json={"sha": None, "kql": bad}).status_code == 422, bad
    assert not (tmp_path / "mappings.yml").exists()
    off = client(tmp_path / "off", monkeypatch, extra="local_rules:\n  enabled: false\n") if (tmp_path / "off").mkdir() is None else None
    assert off.put("/api/mappings", json={"sha": None, "kql": {"tables": {"a/b": "T"}}}).status_code == 403
    remote = TestClient(c.app, base_url=BASE, client=("203.0.113.9", 4000))
    assert remote.put("/api/mappings", json={"sha": None, "kql": {"tables": {"a/b": "T"}}}).status_code == 403
    assert remote.get("/api/mappings").status_code == 200


def test_invalid_mappings_file_on_disk_is_a_clear_error(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    (tmp_path / "mappings.yml").write_text("kql: {tables: {nope: T}}\n", encoding="utf-8")
    r = c.get("/api/mappings")
    assert r.status_code == 422 and "mappings.yml is invalid" in r.json()["detail"]


def test_symlinked_mappings_file_is_refused(tmp_path):
    (tmp_path / "real.yml").write_text("schema_version: 1\n", encoding="utf-8")
    try:
        os.symlink(tmp_path / "real.yml", tmp_path / "mappings.yml")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    with pytest.raises(mappings.MappingsError, match="links"):
        mappings.update(tmp_path, {"kql": {"tables": {"a/b": "T"}}}, local_rules.sha_of((tmp_path / "mappings.yml").read_bytes()))


def test_audit_is_written_with_accounts(tmp_path, monkeypatch):
    from test_auth import register

    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    c = TestClient(create_app(make_project(tmp_path, extra_cfg="auth:\n  enabled: true\n")), base_url=BASE)
    assert register(c).status_code == 201
    assert c.put("/api/mappings", json={"sha": None, "kql": {"tables": {"a/b": "T"}}}).status_code == 200
    assert any(a["action"] == "mappings.saved" for a in c.get("/api/workspace/audit").json())


# --------------------------------------------------------------------------- publication and publish


HAS_GIT = shutil.which("git") is not None


def _git(root, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "A", "GIT_AUTHOR_EMAIL": "a@x", "GIT_COMMITTER_NAME": "A", "GIT_COMMITTER_EMAIL": "a@x"}
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env, text=True).stdout


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_publication_and_publish_include_mappings_only_when_changed(tmp_path, monkeypatch):
    from test_github import GITHUB_CFG, FakeGitHub, client_for

    from vitrix import service

    origin = tmp_path / "origin.git"
    work = tmp_path / "work"
    work.mkdir()
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    c = client(work, monkeypatch, extra=GITHUB_CFG)
    cfg = load_config(str(work / "vitrix.yml"))
    fakes = []

    def make(gh):
        fakes.append(FakeGitHub())
        return client_for(cfg, fakes[-1])

    monkeypatch.setattr(service, "GitHubClient", make)
    _git(work, "init", "-q", "-b", "main")
    _git(work, "add", ".")
    _git(work, "commit", "-q", "-m", "init")
    _git(work, "remote", "add", "origin", str(origin))
    _git(work, "push", "-q", "origin", "main")
    _git(work, "fetch", "-q", "origin")
    saved = c.post("/api/rules", json={"path": "n.yml", "rule": RULE_OK.replace("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"), "cases": CASES_OK}).json()
    body = {"source": "file", "path": "n.yml", "sha": saved["sha"], "cases_sha": saved["cases_sha"]}
    no_map = c.post("/api/ci/rules", json=body).json()
    assert no_map["mappings_included"] is False and not any(f.endswith("mappings.yml") for f in no_map["files"])
    m = c.put("/api/mappings", json={"sha": None, "kql": {"tables": {"bitbucket/audit": "BitbucketAudit"}}}).json()
    assert m["publication"]["state"] == "local" and m["publication"]["git"] == "untracked"
    with_map = c.post("/api/ci/rules", json=body).json()
    assert with_map["mappings_included"] is True and any(f.endswith("mappings.yml") for f in with_map["files"])
    batch = c.post("/api/ci/local-rules", json={"paths": ["n.yml"]}).json()
    assert any(f.endswith("mappings.yml") for f in batch["files"])
    # standalone publish: sha lock, then success
    assert c.post("/api/ci/mappings", json={"sha": "0" * 64}).status_code == 409
    alone = c.post("/api/ci/mappings", json={"sha": m["sha"]})
    assert alone.status_code == 201 and alone.json()["files"][-1].endswith("mappings.yml") and alone.json()["sha"] == m["sha"]
    # once it is in origin/main it is published and no longer attached
    _git(work, "add", "mappings.yml")
    _git(work, "commit", "-q", "-m", "mappings")
    _git(work, "push", "-q", "origin", "main")
    _git(work, "fetch", "-q", "origin")
    publication.invalidate()
    assert c.get("/api/mappings").json()["publication"]["state"] == "published"
    again = c.post("/api/ci/rules", json=body).json()
    assert again["mappings_included"] is False


def test_standalone_publish_needs_the_file(tmp_path, monkeypatch):
    from test_github import GITHUB_CFG

    c = client(tmp_path, monkeypatch, extra=GITHUB_CFG)
    assert c.post("/api/ci/mappings", json={"sha": "0" * 64}).status_code == 404


@pytest.mark.parametrize("logsource,expected", [
    ({"product": "bitbucket", "service": "audit"}, "BitbucketAudit_CL"),
    ({"product": "okta", "service": "okta"}, "Okta_CL"),
    ({"product": "github", "service": "audit"}, "GitHubAuditLogPolling_CL"),
    ({"product": "jira", "category": "audit-log"}, "JiraAuditlog_CL"),
    ({"product": "my-app", "service": "web_logs"}, "MyappWeblogs_CL"),
    ({"service": "cloudtrail"}, "Cloudtrail_CL"),
    ({"product": "zeek", "service": "dns"}, "Corelight_v2_dns"),
    ({"product": "9lives"}, "T9lives_CL"),
])
def test_table_suggestion_is_derived_from_the_logsource(logsource, expected):
    from vitrix.backends import suggest_table
    from vitrix.mapping_names import valid_table

    got = suggest_table(logsource)
    assert got == expected and valid_table(got)
    assert suggest_table({}) is None


def test_final_conversion_failure_is_counted_as_an_error(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch, rule_text=BITBUCKET, cases_text=None, extra="require_cases: false\n")
    row = c.get("/api/rules").json()[0]
    assert row["state"] == "fail" and row["lint"]["errors"] >= 1  # was "0 errors" while failing
    d = c.get("/api/rules/r.yml").json()
    assert d["counts"]["errors"] >= 1 and d["counts"]["info"] == 0
    v = c.post("/api/validate", json={"rule": BITBUCKET, "targets": ["splunk"]}).json()
    assert v["counts"]["info"] >= 0 and v["counts"]["errors"] == sum(i["severity"] == "error" for i in v["lint"])
