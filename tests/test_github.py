"""GitHub integration: configuration, CI-gated pull requests and the read-only connector.

Every test uses a fake GitHub transport: no network calls.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from test_engine import CASES_OK, RULE_OK, make_project

from vitrix import service
from vitrix.config import ConfigError, load_config
from vitrix.github import GitHubClient, GitHubConfig, GitHubError, branch_slug

REPO = "org/detections"
GITHUB_CFG = f"github:\n  repo: {REPO}\n  base: main\n"
SHA = "c" * 40
BASE_SHA = "b" * 40
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)


def _run(branch, status, conclusion, created, updated, number=1, sha="abcdef123", name="vitrix", workflow_id=1):
    return {"id": number, "run_number": number, "name": name, "display_title": "t", "head_branch": branch, "head_sha": sha,
            "status": status, "conclusion": conclusion, "created_at": created, "run_started_at": created, "workflow_id": workflow_id,
            "path": f".github/workflows/{name}.yml", "updated_at": updated, "html_url": f"https://github.com/{REPO}/actions/runs/{number}"}


# Read responses of the connector, in GitHub API format.
READS = {
    "": {"html_url": f"https://github.com/{REPO}", "default_branch": "main", "private": True},
    "/commits/main": {"sha": "9e3f1c2aaaa", "html_url": f"https://github.com/{REPO}/commit/9e3f1c2",
                      "author": {"login": "ana"}, "commit": {"message": "feat: new rule\n\nbody", "author": {"date": "2026-11-02T10:00:00Z"}}},
    "/pulls?state=open&base=main&per_page=50": [
        {"number": 9, "title": "feat: new rule X", "user": {"login": "ana"}, "html_url": f"https://github.com/{REPO}/pull/9",
         "head": {"ref": "vitrix/x-abc123"}, "draft": False, "created_at": "2026-11-01T12:00:00Z"},
        {"number": 8, "title": "tune: Y", "user": {"login": "bruno"}, "html_url": f"https://github.com/{REPO}/pull/8",
         "head": {"ref": "tune-y"}, "draft": True, "created_at": "2026-10-31T12:00:00Z"},
    ],
    "/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=50": [
        {"number": 7, "created_at": "2026-10-30T00:00:00Z", "merged_at": "2026-10-30T02:00:00Z"},
        {"number": 6, "created_at": "2026-10-28T00:00:00Z", "merged_at": "2026-10-28T10:00:00Z"},
        {"number": 5, "created_at": "2026-10-27T00:00:00Z", "merged_at": None},  # closed without merge: ignored
        {"number": 4, "created_at": "2026-10-26T00:00:00Z", "merged_at": "2026-10-26T04:00:00Z"},
    ],
    "/actions/runs?branch=main&per_page=20": {"workflow_runs": [
        _run("main", "in_progress", None, "2026-11-02T10:01:00Z", "2026-11-02T10:02:00Z", 43),
        _run("main", "completed", "success", "2026-11-01T10:00:00Z", "2026-11-01T10:03:00Z", 42),
        _run("main", "completed", "failure", "2026-10-31T10:00:00Z", "2026-10-31T10:01:00Z", 41),
        _run("main", "completed", "success", "2026-10-30T10:00:00Z", "2026-10-30T10:02:00Z", 40),
    ]},
    "/actions/runs?event=pull_request&per_page=50": {"workflow_runs": [
        _run("vitrix/x-abc123", "completed", "failure", "2026-11-01T12:05:00Z", "2026-11-01T12:07:00Z", 39),
        _run("vitrix/x-abc123", "completed", "success", "2026-11-01T12:01:00Z", "2026-11-01T12:03:00Z", 38),
    ]},
}


class FakeGitHub:
    """Answers like the GitHub API and records the calls. `ci` sets the runs for commit SHA."""

    def __init__(self, fail: dict[str, int] | None = None, ci: list[dict] | None = None, branch_sha: str = SHA):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.fail = fail or {}
        self.ci = ci if ci is not None else [_run("vitrix/x", "completed", "success", "2026-11-02T10:00:00Z", "2026-11-02T10:02:00Z", 50, SHA)]
        self.branch_sha = branch_sha

    def __call__(self, method: str, url: str, body: dict | None):
        self.calls.append((method, url, body))
        path = url.split(f"/repos/{REPO}", 1)[1]
        for prefix, status in self.fail.items():
            if path.startswith(prefix):
                return status, {"message": "failed"}
        if method == "GET" and path in READS:
            return 200, READS[path]
        if method == "GET" and path == "/git/ref/heads/main":
            return 200, {"object": {"sha": BASE_SHA}}
        if method == "GET" and path.startswith("/git/ref/heads/vitrix/"):
            return 200, {"object": {"sha": self.branch_sha}}
        if method == "GET" and path == f"/git/commits/{BASE_SHA}":
            return 200, {"tree": {"sha": "tree000"}}
        if method == "GET" and path == f"/git/commits/{SHA}":
            return 200, {"message": "feat: new rule Test rule\n\nNew rule submitted from the Vitrix UI."}
        if method == "GET" and path.startswith("/actions/runs?head_sha="):
            return 200, {"workflow_runs": self.ci}
        if path == "/git/trees":
            return 201, {"sha": "tree222"}
        if path == "/git/commits":
            return 201, {"sha": SHA}
        if path == "/git/refs":
            return 201, {"ref": body["ref"]}
        if path == "/pulls":
            return 201, {"html_url": f"https://github.com/{REPO}/pull/7", "number": 7}
        return 404, {"message": "Not Found"}

    def body_of(self, path: str) -> dict:
        return next(b for m, u, b in self.calls if u.endswith(path) and m == "POST")

    def posted(self, path: str) -> bool:
        return any(m == "POST" and u.endswith(path) for m, u, _ in self.calls)


def project_cfg(tmp_path, extra: str = GITHUB_CFG, **kw):
    return load_config(make_project(tmp_path, extra_cfg=extra, **kw))


def client_for(cfg, fake):
    return GitHubClient(cfg.github, transport=fake)


# --------------------------------------------------------------------------- configuration


def test_github_section_is_optional_and_validated(tmp_path):
    assert project_cfg(tmp_path, extra="").github is None
    cfg = project_cfg(tmp_path, extra=f"github:\n  repo: {REPO}\n  path: sec/vitrix/\n  workflow: vitrix\n")
    assert cfg.github == GitHubConfig(repo=REPO, base="main", path="sec/vitrix", workflow="vitrix")
    assert cfg.github.repo_path("rules/a.yml") == "sec/vitrix/rules/a.yml"


@pytest.mark.parametrize("bad", [
    "github: org/detections\n",
    "github:\n  repo: no-slash\n",
    "github:\n  repo: org/x\n  base: '../main'\n",
    "github:\n  repo: org/x\n  path: ../outside\n",
    "github:\n  repo: org/x\n  workflow: ''\n",
])
def test_invalid_github_section_is_an_error(tmp_path, bad):
    with pytest.raises(ConfigError):
        project_cfg(tmp_path, extra=bad)


def test_client_without_token_explains_what_to_do(monkeypatch):
    for env in ("VITRIX_GITHUB_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(env, raising=False)
    with pytest.raises(GitHubError, match="VITRIX_GITHUB_TOKEN") as exc:
        GitHubClient(GitHubConfig(repo="org/x"))
    assert exc.value.status == 503


def test_branch_name_is_safe():
    assert branch_slug("windows/PowerShell Enc.yml") == "windows-powershell-enc"
    assert branch_slug("...yml") == "rule"


# --------------------------------------------------------------------------- step 1: push for CI


@pytest.mark.parametrize("path", ["../vitrix.yml", "/etc/x.yml", "a/../b.yml", "rule.txt", "a b.yml", ""])
def test_invalid_rule_path_is_refused(path):
    with pytest.raises(service.ChangeError):
        service.normalize_rule_path(path)


def test_submit_pushes_rule_and_cases_in_one_commit_without_a_pr(tmp_path):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub()
    out = service.submit_rule(cfg, "windows/new.yml", RULE_OK, CASES_OK, client=client_for(cfg, fake))

    assert out["commit"] == SHA and out["branch"].startswith("vitrix/windows-new-")
    assert out["is_new"] is True
    assert out["files"] == ["cases/windows/new.yml", "rules/windows/new.yml"]
    tree = fake.body_of("/git/trees")
    assert tree["base_tree"] == "tree000"
    assert {e["path"]: e["content"] for e in tree["tree"]} == {"rules/windows/new.yml": RULE_OK, "cases/windows/new.yml": CASES_OK}
    commit = fake.body_of("/git/commits")
    assert commit["parents"] == [BASE_SHA]
    assert commit["message"].startswith("feat: new rule Test rule\n\n")
    assert "Local quality gate: ready" in commit["message"].replace("**", "")
    assert not fake.posted("/pulls")  # step 1 never opens a pull request
    assert not (tmp_path / "rules" / "windows").exists()  # nothing written to the local disk


def test_submit_existing_rule_is_a_tune(tmp_path):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub()
    out = service.submit_rule(cfg, "r.yml", RULE_OK, CASES_OK, client=client_for(cfg, fake))
    assert out["is_new"] is False and out["title"].startswith("tune: ")


def test_submit_respects_the_project_folder(tmp_path):
    cfg = project_cfg(tmp_path, extra=GITHUB_CFG + "  path: sec\n")
    out = service.submit_rule(cfg, "r.yml", RULE_OK, CASES_OK, client=client_for(cfg, FakeGitHub()))
    assert out["files"] == ["sec/cases/r.yml", "sec/rules/r.yml"]


def test_rule_blocked_by_the_local_gate_is_never_sent(tmp_path):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub()
    with pytest.raises(service.ChangeError, match="local quality gate"):
        service.submit_rule(cfg, "r.yml", RULE_OK, CASES_OK.replace("--ok", "--bad"), client=client_for(cfg, fake))
    with pytest.raises(service.ChangeError, match="local quality gate"):
        service.submit_rule(cfg, "r.yml", RULE_OK, None, client=client_for(cfg, fake))  # no cases
    assert fake.calls == []


def test_without_github_section_nothing_is_sent(tmp_path):
    cfg = project_cfg(tmp_path, extra="")
    with pytest.raises(GitHubError, match="github") as exc:
        service.submit_rule(cfg, "r.yml", RULE_OK, CASES_OK)
    assert exc.value.status == 503


def test_github_error_becomes_a_clear_message(tmp_path):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub(fail={"/git/trees": 403})
    with pytest.raises(GitHubError, match="lacks permission"):
        service.submit_rule(cfg, "r.yml", RULE_OK, CASES_OK, client=client_for(cfg, fake))


# --------------------------------------------------------------------------- CI status and step 2


@pytest.mark.parametrize("runs,state", [
    ([], "none"),
    ([_run("b", "in_progress", None, "2026-11-02T10:00:00Z", "2026-11-02T10:01:00Z", 1, SHA)], "pending"),
    ([_run("b", "completed", "failure", "2026-11-02T10:00:00Z", "2026-11-02T10:01:00Z", 1, SHA)], "failure"),
    ([_run("b", "completed", "success", "2026-11-02T10:00:00Z", "2026-11-02T10:01:00Z", 1, SHA),
      _run("b", "completed", "failure", "2026-11-02T10:00:00Z", "2026-11-02T10:01:00Z", 2, SHA, "other", 2)], "failure"),
    ([_run("b", "completed", "success", "2026-11-02T10:00:00Z", "2026-11-02T10:01:00Z", 1, SHA)], "success"),
])
def test_ci_state_for_one_exact_commit(tmp_path, runs, state):
    cfg = project_cfg(tmp_path)
    assert service.ci_status(cfg, SHA, client=client_for(cfg, FakeGitHub(ci=runs)))["state"] == state


def test_ci_ignores_runs_of_other_commits_and_other_workflows(tmp_path):
    cfg = project_cfg(tmp_path, extra=GITHUB_CFG + "  workflow: vitrix\n")
    runs = [_run("b", "completed", "success", "2026-11-02T10:00:00Z", "2026-11-02T10:01:00Z", 1, "d" * 40),
            _run("b", "completed", "success", "2026-11-02T10:00:00Z", "2026-11-02T10:01:00Z", 2, SHA, "lint-only", 9)]
    assert service.ci_status(cfg, SHA, client=client_for(cfg, FakeGitHub(ci=runs)))["state"] == "none"


def test_rerun_counts_the_newest_attempt(tmp_path):
    cfg = project_cfg(tmp_path)
    old = _run("b", "completed", "failure", "2026-11-02T10:00:00Z", "2026-11-02T10:01:00Z", 1, SHA)
    new = {**_run("b", "completed", "success", "2026-11-02T10:05:00Z", "2026-11-02T10:06:00Z", 1, SHA), "run_attempt": 2}
    assert service.ci_status(cfg, SHA, client=client_for(cfg, FakeGitHub(ci=[old, new])))["state"] == "success"


def test_invalid_commit_id_is_refused(tmp_path):
    cfg = project_cfg(tmp_path)
    with pytest.raises(GitHubError, match="invalid commit"):
        service.ci_status(cfg, "../../x", client=client_for(cfg, FakeGitHub()))


def test_pull_request_opens_only_after_ci_passed(tmp_path):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub()
    pr = service.open_pull_request(cfg, "vitrix/new-abc123", SHA, client=client_for(cfg, fake))
    assert pr["number"] == 7 and pr["ci"]["state"] == "success"
    body = fake.body_of("/pulls")
    assert body["head"] == "vitrix/new-abc123" and body["base"] == "main"
    assert body["title"] == "feat: new rule Test rule"  # first line of the validated commit
    assert "Validated by CI before opening" in body["body"]


@pytest.mark.parametrize("runs,reason", [
    ([], "has not run"),
    ([_run("b", "in_progress", None, "2026-11-02T10:00:00Z", "2026-11-02T10:01:00Z", 1, SHA)], "still running"),
    ([_run("b", "completed", "failure", "2026-11-02T10:00:00Z", "2026-11-02T10:01:00Z", 1, SHA)], "CI failed"),
])
def test_pull_request_is_blocked_without_green_ci(tmp_path, runs, reason):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub(ci=runs)
    with pytest.raises(GitHubError, match=reason) as exc:
        service.open_pull_request(cfg, "vitrix/new-abc123", SHA, client=client_for(cfg, fake))
    assert exc.value.status == 409
    assert not fake.posted("/pulls")


def test_pull_request_is_blocked_if_the_branch_moved_after_ci(tmp_path):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub(branch_sha="e" * 40)
    with pytest.raises(GitHubError, match="changed after CI"):
        service.open_pull_request(cfg, "vitrix/new-abc123", SHA, client=client_for(cfg, fake))
    assert not fake.posted("/pulls")


@pytest.mark.parametrize("branch", ["main", "feature/x", "vitrix/../main"])
def test_only_vitrix_branches_can_be_proposed(tmp_path, branch):
    cfg = project_cfg(tmp_path)
    with pytest.raises(GitHubError, match="only vitrix/"):
        service.open_pull_request(cfg, branch, SHA, client=client_for(cfg, FakeGitHub()))


# --------------------------------------------------------------------------- read-only connector


def test_activity_summarises_prs_merge_time_and_ci():
    a = GitHubClient(GitHubConfig(repo=REPO), transport=FakeGitHub()).activity(now=NOW)
    assert a["head"]["sha"] == "9e3f1c2aaaa" and a["head"]["message"] == "feat: new rule"
    assert a["pulls"]["open"] == 2 and a["pulls"]["from_vitrix"] == 1
    # the newest run on the PR branch failed: the PR counts as failing
    assert [p["ci"] for p in a["pulls"]["items"]] == ["failure", None]
    assert a["pulls"]["failing"] == 1
    assert a["pulls"]["items"][0]["age_hours"] == 24.0
    assert a["merge"] == {"sample": 3, "median_hours": 4.0, "p90_hours": 10.0}
    assert a["ci"]["success_rate"] == 67 and a["ci"]["sample"] == 3  # in-progress runs are not counted
    assert a["ci"]["last"]["state"] == "pending" and a["ci"]["last"]["number"] == 43
    assert a["ci"]["runs"][1]["duration_s"] == 180


def test_activity_without_data_never_invents_numbers():
    empty = {"": {}, "/commits/main": {}, "/pulls?state=open&base=main&per_page=50": [],
             "/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=50": [],
             "/actions/runs?branch=main&per_page=20": {"workflow_runs": []},
             "/actions/runs?event=pull_request&per_page=50": {"workflow_runs": []}}
    a = GitHubClient(GitHubConfig(repo=REPO), transport=lambda m, u, b: (200, empty[u.split(f"/repos/{REPO}", 1)[1]])).activity(now=NOW)
    assert a["merge"]["median_hours"] is None and a["ci"]["success_rate"] is None and a["ci"]["last"] is None


def test_activity_service_never_raises_and_caches(tmp_path, monkeypatch):
    assert service.github_activity(project_cfg(tmp_path, extra=""))["reason"] == "not_configured"
    cfg = project_cfg(tmp_path)
    service._activity_cache.clear()
    for env in ("VITRIX_GITHUB_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(env, raising=False)
    assert service.github_activity(cfg)["reason"] == "no_token"

    fake = FakeGitHub()
    assert service.github_activity(cfg, client=client_for(cfg, fake))["pulls"]["open"] == 2
    calls = len(fake.calls)
    service.github_activity(cfg, client=client_for(cfg, fake))
    assert len(fake.calls) == calls  # served from the cache
    service.github_activity(cfg, client=client_for(cfg, fake), refresh=True)
    assert len(fake.calls) > calls

    service._activity_cache.clear()
    broken = service.github_activity(cfg, client=client_for(cfg, FakeGitHub(fail={"/commits": 404})))
    assert broken["available"] is False and broken["reason"] == "error"
    service._activity_cache.clear()


# --------------------------------------------------------------------------- vitrix.yml from the UI


def test_config_view_has_the_text_and_effective_config(tmp_path):
    view = service.config_view(project_cfg(tmp_path))
    assert view["path"] == "vitrix.yml" and view["text"].startswith("schema_version: 1")
    assert view["github"] == {"repo": REPO, "base": "main", "path": "", "workflow": None}
    assert view["output_dir"] == "dist" and view["quality_gate"]["min_positive"] == 1


def test_validate_edited_config(tmp_path):
    cfg = project_cfg(tmp_path)
    ok = service.validate_config_text(cfg, "schema_version: 1\ntargets: [splunk]\n" + GITHUB_CFG)
    assert ok["ok"] is True and ok["config"]["targets"] == ["splunk"]
    bad = service.validate_config_text(cfg, "targets: [splunk, missing-siem]")
    assert bad["ok"] is False and "missing-siem" in bad["errors"][0]
    assert any("github" in w for w in bad["warnings"])
    assert service.validate_config_text(cfg, "targets: [")["ok"] is False
    assert service.validate_config_text(cfg, "schema_version: 9")["ok"] is False
    assert "not found" in service.validate_config_text(cfg, "extra_pipelines: [no/such.yml]")["errors"][0]


def test_submit_config_pushes_only_valid_configs(tmp_path):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub()
    out = service.submit_config(cfg, "schema_version: 1\ntargets: [kql]\n" + GITHUB_CFG, client=client_for(cfg, fake))
    assert out["files"] == ["vitrix.yml"] and out["title"] == "chore: update vitrix.yml"
    assert {e["path"] for e in fake.body_of("/git/trees")["tree"]} == {"vitrix.yml"}
    assert not fake.posted("/pulls")
    with pytest.raises(service.ChangeError):
        service.submit_config(cfg, "targets: [xyz]", client=client_for(cfg, fake))


def test_rule_list_explains_what_is_pending(tmp_path):
    cfg = load_config(make_project(tmp_path, cases_text=CASES_OK.replace("--ok", "--bad")))
    rule = service.list_rules(cfg)[0]
    assert rule["state"] == "fail" and rule["issues"][0]["severity"] == "error" and "neg" in rule["issues"][0]["message"]


# --------------------------------------------------------------------------- API


@pytest.fixture
def api(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    fake = FakeGitHub()
    monkeypatch.setattr(service, "GitHubClient", lambda gh: GitHubClient(gh, transport=fake))
    monkeypatch.setenv("VITRIX_GITHUB_TOKEN", "test-secret")
    return TestClient(create_app(make_project(tmp_path, extra_cfg=GITHUB_CFG)), base_url="http://127.0.0.1:8000"), fake


def test_api_github_status_never_exposes_the_token(api):
    client, _ = api
    resp = client.get("/api/github")
    assert resp.json() == {"configured": True, "source": "vitrix.yml", "repo": REPO, "base": "main", "workflow": None,
                           "token": True, "token_source": "VITRIX_GITHUB_TOKEN"}
    assert "test-secret" not in resp.text


def test_api_full_flow_ci_then_pull_request(api):
    client, fake = api
    sub = client.post("/api/ci/rules", json={"path": "windows/new.yml", "rule": RULE_OK, "cases": CASES_OK})
    assert sub.status_code == 201 and sub.json()["commit"] == SHA
    assert not fake.posted("/pulls")
    assert client.get(f"/api/ci/status?commit={SHA}").json()["state"] == "success"
    pr = client.post("/api/pull-requests", json={"branch": sub.json()["branch"], "commit": SHA})
    assert pr.status_code == 201 and pr.json()["number"] == 7


def test_api_pull_request_without_green_ci_is_409(api):
    client, fake = api
    fake.ci = []
    resp = client.post("/api/pull-requests", json={"branch": "vitrix/x-1", "commit": SHA})
    assert resp.status_code == 409 and "has not run" in resp.json()["detail"]
    assert not fake.posted("/pulls")


def test_api_refuses_other_sites_and_hosts(api):
    client, fake = api
    body = {"path": "windows/new.yml", "rule": RULE_OK, "cases": CASES_OK}
    assert client.post("/api/ci/rules", json=body, headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/ci/rules", json=body, headers={"Host": "evil.example"}).status_code == 403
    assert fake.calls == []


def test_api_bad_path_and_bad_rule_are_422(api):
    client, _ = api
    assert client.post("/api/ci/rules", json={"path": "../x.yml", "rule": RULE_OK, "cases": CASES_OK}).status_code == 422
    bad = RULE_OK.replace("id: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n", "")
    assert client.post("/api/ci/rules", json={"path": "x.yml", "rule": bad, "cases": CASES_OK}).status_code == 422


def test_api_config_validate_and_submit(api):
    client, fake = api
    assert client.post("/api/config/validate", json={"text": "targets: [xyz]"}).json()["ok"] is False
    text = "schema_version: 1\ntargets: [splunk]\n" + GITHUB_CFG
    assert client.post("/api/ci/config", json={"text": text}).status_code == 201
    assert client.post("/api/ci/config", json={"text": "targets: [xyz]"}).status_code == 422
    assert not fake.posted("/pulls")
