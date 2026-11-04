"""B4: the running app picks up edits of vitrix.yml (and says which file/when), keeps the last good config on a bad edit."""

from __future__ import annotations

import os

import pytest
from test_engine import make_project

from vitrix.config import ConfigHolder

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from vitrix.api import create_app  # noqa: E402

BASE = "http://127.0.0.1:8000"


def edit(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))  # distinct mtime even on coarse clocks


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("VITRIX_AUTH", "off")
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    path = make_project(tmp_path)
    monkeypatch.setenv("VITRIX_CONFIG_RELOAD_SECONDS", "0")
    return TestClient(create_app(path), base_url=BASE, client=("127.0.0.1", 50000)), path


def test_edit_is_seen_by_the_next_request(app):
    client, path = app
    first = client.get("/api/config").json()
    assert first["targets"] == ["splunk", "kql", "elastic-eql"] and first["file"].endswith("vitrix.yml") and first["reload_error"] is None
    edit(path, "schema_version: 1\ntargets: [splunk]\nquality_gate:\n  min_positive: 3\n")
    again = client.get("/api/config").json()
    assert again["targets"] == ["splunk"] and again["quality_gate"]["min_positive"] == 3 and again["reload_error"] is None
    assert "targets: [splunk]" in again["text"]
    assert [t["name"] for t in client.get("/api/targets").json() if t["active"]] == ["splunk"]


def test_invalid_edit_keeps_the_last_good_config(app):
    client, path = app
    edit(path, "schema_version: 1\ntargets: [splunk]\n")
    assert client.get("/api/config").json()["targets"] == ["splunk"]
    edit(path, "targets: [unclosed\n  - : :\n")
    bad = client.get("/api/config").json()
    assert bad["targets"] == ["splunk"] and bad["reload_error"] and "vitrix.yml" in bad["reload_error"]
    edit(path, "schema_version: 1\ntargets: [kql]\n")
    ok = client.get("/api/config").json()
    assert ok["targets"] == ["kql"] and ok["reload_error"] is None


def test_startup_only_settings_are_not_hot_swapped(app):
    client, path = app
    edit(path, "schema_version: 1\ntargets: [splunk]\nauth:\n  enabled: true\ndrafts:\n  enabled: false\nreviews: false\n")
    out = client.get("/api/config").json()
    assert sorted(out["restart_required"]) == ["drafts.enabled", "reviews.enabled"]
    assert out["targets"] == ["splunk"]  # the rest of the file did apply
    assert client.get("/api/drafts").json()["enabled"] is True


def test_holder_debounces_and_without_a_file_is_static(tmp_path, monkeypatch):
    t = [0.0]
    h = ConfigHolder(make_project(tmp_path), debounce=1.0, clock=lambda: t[0])
    path = str(h.path)
    edit(path, "schema_version: 1\ntargets: [splunk]\n")
    assert h.get().targets == ["splunk", "kql", "elastic-eql"]  # inside the debounce window: not even a stat
    t[0] = 2.0
    assert h.get().targets == ["splunk"]


def test_auth_change_needs_a_restart(tmp_path, monkeypatch):
    monkeypatch.delenv("VITRIX_AUTH", raising=False)
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("VITRIX_CONFIG_RELOAD_SECONDS", "0")
    path = make_project(tmp_path, extra_cfg="auth:\n  enabled: false\n")
    client = TestClient(create_app(path), base_url=BASE)
    assert client.get("/api/auth/config").json()["enabled"] is False
    edit(path, "schema_version: 1\ntargets: [splunk]\nauth:\n  enabled: true\n")
    out = client.get("/api/config").json()
    assert out["restart_required"] == ["auth"] and out["targets"] == ["splunk"]
    assert client.get("/api/auth/config").json()["enabled"] is False


@pytest.mark.parametrize("bad", ["data_dir: 5", "datasets_dir: [1]", "rules_dir: ''", "output_dir: {a: 1}"])
def test_wrongly_typed_paths_keep_the_old_config_with_a_clear_error(app, bad):
    client, path = app
    edit(path, "schema_version: 1\ntargets: [splunk]\n" + bad + "\n")
    out = client.get("/api/config").json()
    assert out["targets"] == ["splunk", "kql", "elastic-eql"] and out["reload_error"] and bad.split(":")[0] in out["reload_error"]


def test_any_unexpected_error_on_reload_is_contained(app, monkeypatch):
    client, path = app
    import vitrix.config as cfgmod

    def boom(_path=None):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cfgmod, "load_config", boom)
    edit(path, "schema_version: 1\ntargets: [splunk]\n")
    out = client.get("/api/config")
    assert out.status_code == 200 and out.json()["reload_error"] == "kaboom" and out.json()["targets"] == ["splunk", "kql", "elastic-eql"]


def test_path_keys_and_github_need_a_restart(app):
    client, path = app
    edit(path, "schema_version: 1\ntargets: [splunk]\nrules_dir: other\ncases_dir: c2\ndatasets_dir: d2\noutput_dir: o2\ngithub:\n  repo: org/x\n")
    out = client.get("/api/config").json()
    assert sorted(out["restart_required"]) == ["cases_dir", "datasets_dir", "github", "output_dir", "rules_dir"]
    assert out["rules_dir"] == "rules" and out["github"] is None and out["targets"] == ["splunk"]


def test_a_request_sees_one_config_version(tmp_path):
    h = ConfigHolder(make_project(tmp_path), debounce=0.0)
    live = h.live
    with h.snapshot():
        before = live.targets
        edit(str(h.path), "schema_version: 1\ntargets: [splunk]\nquality_gate:\n  min_positive: 4\n")
        assert h.get().targets == ["splunk"]  # the file did change underneath...
        assert live.targets == before and live.gate.min_positive == 1  # ...but this request keeps its snapshot
    assert live.targets == ["splunk"] and live.gate.min_positive == 4
