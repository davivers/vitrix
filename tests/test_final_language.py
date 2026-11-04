"""Final language chosen in the app: the `sigma` pseudo-target and mappings.yml `final_language` (Sprint 5 addendum)."""

from __future__ import annotations

import json

import pytest
from test_engine import RULE_OK, make_project, run

from vitrix import mappings, routing
from vitrix.config import load_config

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from vitrix.api import create_app  # noqa: E402

BASE = "http://127.0.0.1:8000"
LOOPBACK = ("127.0.0.1", 50000)


def client(tmp_path, monkeypatch, extra=""):
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    return TestClient(create_app(make_project(tmp_path, extra_cfg=extra)), base_url=BASE, client=LOOPBACK)


def with_target(target: str) -> str:
    return RULE_OK.replace("level: medium", f"level: medium\nvitrix:\n  target: {target}")


def write_final(tmp_path, body: str):
    (tmp_path / "mappings.yml").write_text("schema_version: 1\n" + body, encoding="utf-8")


# --------------------------------------------------------------------------- resolution order


def test_resolution_order_and_sources(tmp_path):
    make_project(tmp_path, extra_cfg="default_target: splunk\nroutes:\n  - match: 'win*/*'\n    target: kql\n")
    path = str(tmp_path / "vitrix.yml")
    plain = load_config(path)
    assert routing.resolve(plain, "windows/a.yml", {}).source == "legacy-config" and routing.resolve(plain, "linux/a.yml", {}).targets == ["splunk"]
    write_final(tmp_path, "final_language:\n  default: elastic-eql\n  folders:\n    'windows/*': sigma\n    'windows/proc/*': splunk\n")
    cfg = load_config(path)
    assert routing.resolve(cfg, "windows/a.yml", {}).targets == ["sigma"] and routing.resolve(cfg, "windows/a.yml", {}).source == "folder"
    deep = routing.resolve(cfg, "windows/proc/a.yml", {})  # the most specific folder wins
    assert deep.targets == ["splunk"] and deep.folder == "windows/proc/*"
    ws = routing.resolve(cfg, "linux/a.yml", {})
    assert ws.targets == ["elastic-eql"] and ws.source == "workspace"  # beats legacy default_target
    assert routing.resolve(cfg, None, {}).source == "workspace"  # unsaved rule: no folder
    rule = {"vitrix": {"target": "kql"}}
    assert routing.resolve(cfg, "windows/a.yml", rule).source == "rule" and routing.resolve(cfg, "windows/a.yml", rule).targets == ["kql"]
    assert routing.resolve(cfg, "x.yml", {}, override=["splunk"]).source == "override"
    nothing = load_config(path)
    assert nothing.final_default == "elastic-eql"


def test_all_active_when_nothing_is_configured(tmp_path):
    make_project(tmp_path)
    assert routing.resolve(load_config(str(tmp_path / "vitrix.yml")), "a.yml", {}).source == "all"


# --------------------------------------------------------------------------- sigma


def test_sigma_target_listed_first_and_never_fails(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    t = c.get("/api/targets").json()
    assert t[0]["name"] == "sigma" and t[0]["status"] == "ok" and t[0]["backend"] is None and t[0]["plugin"] is None and t[0]["label"].startswith("Keep as Sigma")
    v = c.post("/api/validate", json={"rule": with_target("sigma")}).json()
    assert v["targets"] == ["sigma"] and v["final_language"] == {"targets": ["sigma"], "source": "rule", "folder": None}
    assert v["conversions"]["sigma"]["ok"] and v["conversions"]["sigma"]["final"] is True
    conv = next(x for x in v["quality"]["checks"] if x["id"] == "conversion")
    assert conv["passed"] is None and "not applicable" in conv["detail"]
    # other languages are previews: info at most, never errors
    assert all(i["severity"] == "info" for i in v["preview_issues"]) and v["counts"]["errors"] == 0


def test_sigma_even_when_a_preview_language_cannot_convert(tmp_path, monkeypatch):
    bitbucket = with_target("sigma").replace("product: windows", "product: bitbucket").replace("category: process_creation", "service: audit")
    c = client(tmp_path, monkeypatch)
    v = c.post("/api/validate", json={"rule": bitbucket}).json()
    assert v["conversions"]["kql"]["ok"] is False and v["conversions"]["kql"]["severity"] == "info"
    assert v["state"] != "fail" and v["counts"]["errors"] == 0 and v["preview_issues"][0]["fix"]["kind"] == "kql-table"


def test_cli_copies_sigma_to_dist(tmp_path, capsys):
    cfg = make_project(tmp_path, rule_text=with_target("sigma"))
    assert run(cfg, "check", "--strict", "--gate") == 0
    out = tmp_path / "dist" / "sigma" / "r.yml"
    assert out.is_file() and "title: Test rule" in out.read_text(encoding="utf-8")
    manifest = json.loads((tmp_path / "dist" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["rules"][0]["targets"] == ["sigma"] and manifest["rules"][0]["target_source"] == "rule"
    assert not (tmp_path / "dist" / "splunk").exists()
    assert run(cfg, "convert") == 0  # the CI workflow's commands keep working


def test_cli_workspace_default_sigma_from_mappings(tmp_path):
    cfg = make_project(tmp_path)
    write_final(tmp_path, "final_language:\n  default: sigma\n")
    assert run(cfg, "check", "--strict", "--gate") == 0
    assert (tmp_path / "dist" / "sigma" / "r.yml").is_file()


# --------------------------------------------------------------------------- API


def test_put_final_language_and_rule_endpoints_show_the_source(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch)
    g = c.get("/api/mappings").json()
    assert g["final_language"] == {"default": None, "folders": {}}
    r = c.put("/api/mappings", json={"sha": None, "final_language": {"default": "sigma", "folders": {"win*/*": "splunk"}}})
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["final_language"] == {"default": "sigma", "folders": {"win*/*": "splunk"}} and "final_language:" in got["text"]
    rule = next(x for x in c.get("/api/rules").json() if x["id"] == "r.yml")
    assert rule["target_source"] == "workspace" and rule["final_language"] == {"targets": ["sigma"], "source": "workspace", "folder": None}
    detail = c.get("/api/rules/r.yml").json()
    assert detail["final_language"]["source"] == "workspace"
    v = c.post("/api/validate", json={"rule": RULE_OK, "path": "windows/new.yml"}).json()  # saved-path validation applies folders
    assert v["final_language"] == {"targets": ["splunk"], "source": "folder", "folder": "win*/*"}
    v = c.post("/api/validate", json={"rule": with_target("kql"), "path": "windows/new.yml"}).json()
    assert v["final_language"]["source"] == "rule"
    # null clears; unknown / inactive / malformed ids are refused
    cleared = c.put("/api/mappings", json={"sha": got["sha"], "final_language": {"default": None, "folders": {"win*/*": None}}}).json()
    assert cleared["final_language"] == {"default": None, "folders": {}} and "final_language" not in cleared["text"]
    for bad in ({"default": "oracle"}, {"default": "Bad Id"}, {"folders": {"/abs/*": "splunk"}}, {"folders": {"../x": "splunk"}}, {"folders": {"a/*": "nope"}}, {"x": 1}):
        assert c.put("/api/mappings", json={"sha": cleared["sha"], "final_language": bad}).status_code == 422, bad
    assert c.put("/api/mappings", json={"sha": cleared["sha"]}).status_code == 422  # nothing to change


def test_kql_edit_is_not_blocked_by_an_inactive_final_language(tmp_path, monkeypatch):
    c = client(tmp_path, monkeypatch, extra="targets: [splunk]\n")
    write_final(tmp_path, "final_language:\n  default: elastic-eql\n")  # pulled from Git; vitrix.yml has since dropped it
    sha = c.get("/api/mappings").json()["sha"]
    assert c.put("/api/mappings", json={"sha": sha, "kql": {"tables": {"a/b": "T"}}}).status_code == 200


def test_mappings_model_rejects_bad_final_language():
    for bad in ("final_language: [a]\n", "final_language: {default: 'x y'}\n", "final_language: {folders: {'a b': splunk}}\n", "final_language: {other: 1}\n"):
        with pytest.raises(mappings.MappingsError):
            mappings.parse(bad)
