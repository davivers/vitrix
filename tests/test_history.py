"""Git history, impact analysis, ATT&CK Navigator export and health score."""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest
from test_engine import CASES_OK, RULE_OK, make_project

from vitrix import flow, history
from vitrix.config import load_config

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

RULE_2 = RULE_OK.replace("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").replace(
    "[attack.execution, attack.t1059.001]", "[attack.persistence, attack.t1053.005]").replace("--bad", "--evil")


def git(root, *args, date="2026-10-01T10:00:00", author="Ana"):
    env = {**os.environ, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date, "GIT_AUTHOR_NAME": author,
           "GIT_AUTHOR_EMAIL": "a@example.com", "GIT_COMMITTER_NAME": author, "GIT_COMMITTER_EMAIL": "a@example.com"}
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)


@pytest.fixture
def repo(tmp_path):
    cfg_path = make_project(tmp_path)
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-q", "-m", "feat: first rule", date="2026-10-01T10:00:00")
    (tmp_path / "rules" / "r2.yml").write_text(RULE_2, encoding="utf-8")
    (tmp_path / "cases" / "r2.yml").write_text(CASES_OK.replace("--bad", "--evil"), encoding="utf-8")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-q", "-m", "feat: persistence rule", date="2026-10-05T10:00:00", author="Bruno")
    (tmp_path / "rules" / "r.yml").write_text(RULE_OK.replace("level: medium", "level: low"), encoding="utf-8")
    git(tmp_path, "commit", "-q", "-am", "tune: lower level", date="2026-10-09T10:00:00")
    history._cache.clear()
    return tmp_path, load_config(cfg_path)


def test_coverage_over_time_and_activity(repo):
    _, cfg = repo
    h = history.history(cfg)
    assert h["available"] is True and h["commits"] == 3
    assert [(p["date"], p["rules"], p["tactics"], p["techniques"]) for p in h["timeline"]] == [
        ("2026-10-01", 1, 1, 1), ("2026-10-05", 2, 2, 2), ("2026-10-09", 2, 2, 2)]
    assert h["activity"][0]["subject"] == "tune: lower level"
    authors = {a["name"]: a for a in h["authors"]}
    assert authors["Ana"]["commits"] == 2 and authors["Bruno"]["rules_created"] == 1


def test_audit_trail_per_rule(repo):
    _, cfg = repo
    r = history.rule_history(cfg, "r.yml")
    assert r["tracked"] is True and r["commits"] == 2
    assert r["created_by"] == "Ana" and [e["change"] for e in r["log"]] == ["modified", "created"]
    assert history.rule_history(cfg, "missing.yml")["tracked"] is False


def test_deleted_rule_leaves_the_timeline(repo):
    root, cfg = repo
    git(root, "rm", "-q", "rules/r2.yml", "cases/r2.yml")
    git(root, "commit", "-q", "-m", "chore: retire rule", date="2026-10-12T10:00:00")
    history._cache.clear()
    h = history.history(cfg)
    assert h["timeline"][-1]["rules"] == 1 and h["rules"]["r2.yml"]["deleted"] is True


def test_no_git_repository_means_no_history(tmp_path):
    cfg = load_config(make_project(tmp_path))
    out = history.history(cfg)
    assert out["available"] is False and out["reason"]


def test_review_check_uses_git_age(repo):
    root, _ = repo
    with open(root / "vitrix.yml", "a", encoding="utf-8") as fh:
        fh.write("quality_gate:\n  review_days: 1\n")
    history._cache.clear()
    rule = flow.quality_report(load_config(str(root / "vitrix.yml")), only="r2.yml")["rules"][0]
    review = next(c for c in rule["checks"] if c["id"] == "review")
    assert review["passed"] is False and review["blocking"] is False  # recommendation only
    assert rule["ready"] is True and rule["stages"]["gate"] == "warn"


# --------------------------------------------------------------------------- impact, Navigator, health


EVIL = {"Image": "C:\\\\x\\\\tool.exe", "CommandLine": "tool.exe --bad"}
OTHER = {"Image": "C:\\\\x\\\\tool.exe", "CommandLine": "tool.exe --other"}


def test_impact_analysis_shows_added_and_removed_events(tmp_path):
    cfg = load_config(make_project(tmp_path))
    (tmp_path / "datasets").mkdir()
    (tmp_path / "datasets" / "sim.jsonl").write_text("\n".join(json.dumps(e) for e in [EVIL, OTHER]), encoding="utf-8")
    (tmp_path / "datasets" / "sim.expect.yml").write_text("expect:\n  r.yml: 1\n", encoding="utf-8")
    edited = RULE_OK.replace("CommandLine|contains: '--bad'", "CommandLine|contains: '--other'")
    out = flow.impact_analysis(cfg, "r.yml", edited)
    d = out["datasets"][0]
    assert out["saved"] is True and out["changed"] is True
    assert (d["before"], d["after"], d["added"], d["removed"]) == (1, 1, [2], [1])
    assert d["meets_expectation"] is True
    new = flow.impact_analysis(cfg, None, RULE_OK)
    assert new["saved"] is False and new["datasets"][0]["before"] is None and new["datasets"][0]["after"] == 1


def test_navigator_layer_format(tmp_path):
    cfg = load_config(make_project(tmp_path))
    layer = flow.navigator_layer(cfg)
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    assert layer["techniques"] == [{"techniqueID": "T1059.001", "score": 1, "comment": "Test rule", "enabled": True,
                                    "metadata": [{"name": "rule", "value": "r.yml"}], "showSubtechniques": True}]


def test_health_score_never_hides_a_blocker(tmp_path):
    # A blocker (here the opt-in false-positive case for high rules) caps the score below approval.
    cfg = load_config(make_project(tmp_path, rule_text=RULE_OK.replace("level: medium", "level: high"),
                                   extra_cfg="quality_gate:\n  false_positive_levels: [high]\n"))
    rule = flow.quality_report(cfg)["rules"][0]
    assert rule["ready"] is False and rule["score"] <= 69


def test_logsource_coverage(tmp_path):
    cfg = load_config(make_project(tmp_path))
    assert flow.logsource_coverage(cfg) == [{"logsource": "windows / process_creation", "product": "windows", "rules": 1,
                                             "techniques": ["T1059.001"], "tactics": ["execution"]}]


def test_api_history_impact_and_navigator(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    client = TestClient(create_app(make_project(tmp_path)), base_url="http://127.0.0.1:8000")
    assert client.get("/api/history").json()["available"] is False
    assert client.post("/api/impact", json={"rule": RULE_OK, "path": "r.yml"}).json()["saved"] is True
    assert client.post("/api/impact", json={"rule": RULE_OK, "path": "../x.yml"}).status_code == 422
    nav = client.get("/api/coverage/navigator")
    assert nav.json()["domain"] == "enterprise-attack" and "attachment" in nav.headers["content-disposition"]
    v = client.post("/api/validate", json={"rule": RULE_OK, "cases": CASES_OK, "path": "r.yml"}).json()
    assert v["quality"]["ready"] is True and "score" in v["quality"]


def test_empty_repo_and_non_repo_are_structured_states_not_git_errors(tmp_path):
    cfg = load_config(make_project(tmp_path))
    nr = history.history(cfg)
    assert nr["available"] is False and nr["state"] == "not_a_repo" and "fatal" not in nr["message"]
    git(tmp_path, "init", "-q", "-b", "main")
    history._cache.clear()
    empty = history.history(cfg)
    assert empty["state"] == "no_commits" and "no commits yet" in empty["message"] and "ambiguous" not in json.dumps(empty)
    rh = history.rule_history(cfg, "r.yml")
    assert rh["available"] is False and rh["state"] == "no_commits"
    from vitrix import drift

    with pytest.raises(drift.DriftError) as exc:
        drift.drift(cfg)
    assert "no commits yet" in str(exc.value) and "ambiguous" not in str(exc.value)
