"""Related rules, targets view and draft summary (Sprint 4 designer asks)."""

from __future__ import annotations

import pytest
from test_engine import CASES_OK, RULE_OK, make_project

from vitrix import service
from vitrix.config import load_config
from vitrix.related import related_rules

RULE_2 = RULE_OK.replace("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").replace("title: ", "title: Other ", 1)
RULE_UNRELATED = RULE_OK.replace("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "cccccccc-cccc-4ccc-8ccc-cccccccccccc").replace(
    "[attack.execution, attack.t1059.001]", "[attack.persistence]").replace("product: windows", "product: linux").replace("category: process_creation", "category: auditd")


def test_related_rules_say_why(tmp_path):
    cfg = load_config(make_project(tmp_path))
    (tmp_path / "rules" / "o.yml").write_text(RULE_2, encoding="utf-8")
    (tmp_path / "rules" / "u.yml").write_text(RULE_UNRELATED, encoding="utf-8")
    out = related_rules(cfg, rid="r.yml")
    assert [r["id"] for r in out][0] == "o.yml"
    first = out[0]
    assert first["same_logsource"] and first["shared_fields"] and "same log source" in first["why"] and first["shared_techniques"]
    assert "r.yml" not in [r["id"] for r in out]
    # unsaved rule text works the same, unparsable text gives an empty list
    assert related_rules(cfg, text=RULE_OK)[0]["id"] in {"r.yml", "o.yml"}
    assert related_rules(cfg, text="a: [") == [] and related_rules(cfg, rid="missing.yml") == []


def test_targets_view_has_backend_plugin_status_and_usage(tmp_path):
    cfg = load_config(make_project(tmp_path))
    view = {t["name"]: t for t in service.targets_view(cfg)}
    assert {"splunk", "kql", "elastic-eql", "elastic-lucene"} <= set(view)
    sp = view["splunk"]
    assert sp["backend"] == "splunk" and sp["plugin"] == "pysigma-backend-splunk" and sp["status"] in ("ok", "missing_plugin", "error")
    assert isinstance(sp["used_by"], int) and sum(t["used_by"] for t in view.values()) >= 1
    assert view["elastic-lucene"]["backend"] == "elasticsearch (lucene)"


def test_missing_plugin_is_reported_not_raised():
    from vitrix.backends import Target, target_info

    def boom(_):
        raise ImportError("No module named 'sigma.backends.splunk'")

    info = target_info(Target("splunk", "Splunk", "spl", boom))
    assert info["status"] == "missing_plugin" and "pip install pysigma-backend-splunk" in info["message"]
    assert target_info(Target("x", "X", "x", lambda _: 1 / 0))["status"] == "error"


def test_api_related_and_draft_summary(tmp_path):
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    (tmp_path / "x").mkdir()
    cfg_path = make_project(tmp_path)
    (tmp_path / "rules" / "o.yml").write_text(RULE_2, encoding="utf-8")
    c = TestClient(create_app(cfg_path), base_url="http://127.0.0.1:8000")
    assert c.get("/api/rules/r.yml/related").json()[0]["id"] == "o.yml"
    assert c.get("/api/rules/nope.yml/related").status_code == 404
    assert c.post("/api/related", json={"rule": RULE_OK}).status_code == 200
    assert c.get("/api/targets").json()[0].keys() >= {"name", "backend", "plugin", "status", "used_by"}
    c.post("/api/drafts", json={"path": "windows/d.yml", "rule": RULE_OK, "cases": CASES_OK})
    drafts = c.get("/api/drafts").json()
    if drafts["enabled"]:
        d = drafts["drafts"][0]
        assert d["level"] == "medium" and d["target"] and set(d["quality"]) == {"ready", "blockers", "score"}
