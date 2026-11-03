"""Pull requests pela interface: configuração, cliente do GitHub (transporte falso) e rota da API."""

from __future__ import annotations

import pytest
from test_engine import CASES_OK, RULE_OK, make_project

from vitrix import service
from vitrix.config import ConfigError, load_config
from vitrix.github import (
    GitHubClient,
    GitHubConfig,
    GitHubError,
    branch_slug,
)

GITHUB_CFG = "github:\n  repo: org/deteccoes\n  base: main\n"


def _run(branch, status, conclusion, created, updated, number=1):
    return {"id": number, "run_number": number, "name": "vitrix", "display_title": "t", "head_branch": branch, "head_sha": "abcdef123",
            "status": status, "conclusion": conclusion, "created_at": created, "run_started_at": created,
            "updated_at": updated, "html_url": f"https://github.com/org/deteccoes/actions/runs/{number}"}


# Respostas de leitura do conector, no formato da API do GitHub.
READS = {
    "": {"html_url": "https://github.com/org/deteccoes", "default_branch": "main", "private": True},
    "/commits/main": {"sha": "9e3f1c2aaaa", "html_url": "https://github.com/org/deteccoes/commit/9e3f1c2",
                      "author": {"login": "ana"}, "commit": {"message": "feat: nova regra\n\ncorpo", "author": {"date": "2026-11-02T10:00:00Z"}}},
    "/pulls?state=open&base=main&per_page=50": [
        {"number": 9, "title": "feat: nova regra X", "user": {"login": "ana"}, "html_url": "https://github.com/org/deteccoes/pull/9",
         "head": {"ref": "vitrix/x-abc123"}, "draft": False, "created_at": "2026-11-01T12:00:00Z"},
        {"number": 8, "title": "tune: Y", "user": {"login": "bruno"}, "html_url": "https://github.com/org/deteccoes/pull/8",
         "head": {"ref": "tune-y"}, "draft": True, "created_at": "2026-10-31T12:00:00Z"},
    ],
    "/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=50": [
        {"number": 7, "created_at": "2026-10-30T00:00:00Z", "merged_at": "2026-10-30T02:00:00Z"},
        {"number": 6, "created_at": "2026-10-28T00:00:00Z", "merged_at": "2026-10-28T10:00:00Z"},
        {"number": 5, "created_at": "2026-10-27T00:00:00Z", "merged_at": None},  # fechado sem merge: fora da conta
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
    """Responde como a API do GitHub e guarda as chamadas feitas."""

    def __init__(self, fail: dict[str, int] | None = None):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.fail = fail or {}

    def __call__(self, method: str, url: str, body: dict | None):
        self.calls.append((method, url, body))
        path = url.split("/repos/org/deteccoes", 1)[1]
        for prefix, status in self.fail.items():
            if path.startswith(prefix):
                return status, {"message": "falhou"}
        if method == "GET" and path in READS:
            return 200, READS[path]
        if method == "GET" and path.startswith("/git/ref/heads/"):
            return 200, {"object": {"sha": "base111"}}
        if method == "GET" and path.startswith("/git/commits/"):
            return 200, {"tree": {"sha": "tree000"}}
        if path == "/git/trees":
            return 201, {"sha": "tree222"}
        if path == "/git/commits":
            return 201, {"sha": "commit333"}
        if path == "/git/refs":
            return 201, {"ref": body["ref"]}
        if path == "/pulls":
            return 201, {"html_url": "https://github.com/org/deteccoes/pull/7", "number": 7}
        return 404, {"message": "Not Found"}

    def body_of(self, path: str) -> dict:
        return next(b for m, u, b in self.calls if u.endswith(path) and m == "POST")


def project_cfg(tmp_path, extra: str = GITHUB_CFG, **kw):
    return load_config(make_project(tmp_path, extra_cfg=extra, **kw))


# --------------------------------------------------------------------------- configuração


def test_config_github_opcional_e_validada(tmp_path):
    assert project_cfg(tmp_path, extra="").github is None
    cfg = project_cfg(tmp_path, extra="github:\n  repo: org/deteccoes\n  path: sec/vitrix/\n")
    assert cfg.github == GitHubConfig(repo="org/deteccoes", base="main", path="sec/vitrix")
    assert cfg.github.repo_path("rules/a.yml") == "sec/vitrix/rules/a.yml"


@pytest.mark.parametrize("bad", [
    "github: org/deteccoes\n",
    "github:\n  repo: sem-barra\n",
    "github:\n  repo: org/x\n  base: '../main'\n",
    "github:\n  repo: org/x\n  path: ../fora\n",
])
def test_config_github_invalida_da_erro(tmp_path, bad):
    with pytest.raises(ConfigError):
        project_cfg(tmp_path, extra=bad)


def test_cliente_sem_token_explica_o_que_fazer(monkeypatch):
    for env in ("VITRIX_GITHUB_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(env, raising=False)
    with pytest.raises(GitHubError, match="VITRIX_GITHUB_TOKEN") as exc:
        GitHubClient(GitHubConfig(repo="org/x"))
    assert exc.value.status == 503


def test_nome_do_branch_e_seguro():
    assert branch_slug("windows/PowerShell Enc.yml") == "windows-powershell-enc"
    assert branch_slug("...yml") == "regra"


# --------------------------------------------------------------------------- serviço


@pytest.mark.parametrize("path", ["../vitrix.yml", "/etc/x.yml", "a/../b.yml", "regra.txt", "a b.yml", ""])
def test_caminho_da_regra_invalido_e_recusado(path):
    with pytest.raises(service.ChangeError):
        service.normalize_rule_path(path)


def test_pr_com_regra_e_casos_em_um_commit(tmp_path):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub()
    out = service.propose_change(cfg, "windows/nova.yml", RULE_OK, CASES_OK, client=GitHubClient(cfg.github, transport=fake))

    assert out["url"] == "https://github.com/org/deteccoes/pull/7"
    assert out["is_new"] is True
    assert out["files"] == ["cases/windows/nova.yml", "rules/windows/nova.yml"]
    assert out["branch"].startswith("vitrix/windows-nova-")
    tree = fake.body_of("/git/trees")
    assert tree["base_tree"] == "tree000"
    assert {e["path"]: e["content"] for e in tree["tree"]} == {"rules/windows/nova.yml": RULE_OK, "cases/windows/nova.yml": CASES_OK}
    assert fake.body_of("/git/commits")["parents"] == ["base111"]
    pr = fake.body_of("/pulls")
    assert pr["base"] == "main" and pr["head"] == out["branch"]
    assert pr["title"] == "feat: nova regra Regra de teste"
    assert "Testes locais:** 2/2" in pr["body"]
    assert not (tmp_path / "rules" / "windows").exists()  # nada gravado no disco local


def test_pr_de_regra_existente_e_tune(tmp_path):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub()
    out = service.propose_change(cfg, "r.yml", RULE_OK, None, client=GitHubClient(cfg.github, transport=fake))
    assert out["is_new"] is False
    assert out["files"] == ["rules/r.yml"]
    assert fake.body_of("/pulls")["title"].startswith("tune: ")


def test_pr_respeita_a_pasta_do_projeto_no_repositorio(tmp_path):
    cfg = project_cfg(tmp_path, extra=GITHUB_CFG + "  path: sec\n")
    fake = FakeGitHub()
    out = service.propose_change(cfg, "r.yml", RULE_OK, CASES_OK, client=GitHubClient(cfg.github, transport=fake))
    assert out["files"] == ["sec/cases/r.yml", "sec/rules/r.yml"]


def test_regra_reprovada_nao_vira_pr(tmp_path):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub()
    wrong = CASES_OK.replace("--ok", "--bad")
    with pytest.raises(service.ChangeError, match="reprovada"):
        service.propose_change(cfg, "r.yml", RULE_OK, wrong, client=GitHubClient(cfg.github, transport=fake))
    assert fake.calls == []


def test_sem_secao_github_nao_abre_pr(tmp_path):
    cfg = project_cfg(tmp_path, extra="")
    with pytest.raises(GitHubError, match="github") as exc:
        service.propose_change(cfg, "r.yml", RULE_OK, None)
    assert exc.value.status == 503


def test_erro_do_github_vira_mensagem_clara(tmp_path):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub(fail={"/git/trees": 403})
    with pytest.raises(GitHubError, match="permissão de escrita"):
        service.propose_change(cfg, "r.yml", RULE_OK, None, client=GitHubClient(cfg.github, transport=fake))
    assert not any(u.endswith("/pulls") for _, u, _ in fake.calls)


# --------------------------------------------------------------------------- API

PR_BODY = {"path": "windows/nova.yml", "rule": RULE_OK, "cases": CASES_OK}


@pytest.fixture
def api(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    fake = FakeGitHub()
    monkeypatch.setattr(service, "GitHubClient", lambda gh: GitHubClient(gh, transport=fake))
    monkeypatch.setenv("VITRIX_GITHUB_TOKEN", "segredo-de-teste")
    app = create_app(make_project(tmp_path, extra_cfg=GITHUB_CFG))
    return TestClient(app, base_url="http://127.0.0.1:8000"), fake


def test_api_status_do_github_nao_expoe_o_token(api):
    client, _ = api
    resp = client.get("/api/github")
    assert resp.json() == {"configured": True, "repo": "org/deteccoes", "base": "main", "token": True}
    assert "segredo" not in resp.text


def test_api_abre_pull_request(api):
    client, fake = api
    resp = client.post("/api/pull-requests", json=PR_BODY)
    assert resp.status_code == 201
    assert resp.json()["number"] == 7
    assert any(u.endswith("/pulls") for _, u, _ in fake.calls)


def test_api_recusa_outros_sites_e_hosts(api):
    client, fake = api
    assert client.post("/api/pull-requests", json=PR_BODY, headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/pull-requests", json=PR_BODY, headers={"Host": "evil.example"}).status_code == 403
    assert client.post("/api/pull-requests", json=PR_BODY, headers={"Origin": "http://127.0.0.1:8000"}).status_code == 201
    calls_before = len(fake.calls)
    import json

    resp = client.post("/api/pull-requests", content=json.dumps(PR_BODY), headers={"Content-Type": "text/plain"})
    assert resp.status_code in (415, 422)
    assert len(fake.calls) == calls_before


def test_api_erros_de_caminho_e_de_regra_sao_422(api):
    client, _ = api
    assert client.post("/api/pull-requests", json={**PR_BODY, "path": "../x.yml"}).status_code == 422
    bad = RULE_OK.replace("id: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n", "")
    assert client.post("/api/pull-requests", json={**PR_BODY, "rule": bad}).status_code == 422


# --------------------------------------------------------------------------- conector (leitura)

NOW = __import__("datetime").datetime(2026, 11, 2, 12, 0, tzinfo=__import__("datetime").timezone.utc)


def test_atividade_resume_prs_merge_e_ci():
    a = GitHubClient(GitHubConfig(repo="org/deteccoes"), transport=FakeGitHub()).activity(now=NOW)
    assert a["head"]["sha"] == "9e3f1c2aaaa"
    assert a["head"]["message"] == "feat: nova regra"
    assert a["pulls"]["open"] == 2
    assert a["pulls"]["from_vitrix"] == 1
    # o run mais novo do branch do PR reprovou: o PR conta como reprovado
    assert [p["ci"] for p in a["pulls"]["items"]] == ["failure", None]
    assert a["pulls"]["failing"] == 1
    assert a["pulls"]["items"][0]["age_hours"] == 24.0
    assert a["merge"] == {"sample": 3, "median_hours": 4.0, "p90_hours": 10.0}
    # em andamento não entra na taxa: 2 de 3 concluídos
    assert a["ci"]["success_rate"] == 67
    assert a["ci"]["sample"] == 3
    assert a["ci"]["last"]["state"] == "pending" and a["ci"]["last"]["number"] == 43
    assert a["ci"]["runs"][1]["duration_s"] == 180


def test_atividade_sem_dados_nao_inventa_numeros():
    empty = {"": {}, "/commits/main": {}, "/pulls?state=open&base=main&per_page=50": [],
             "/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=50": [],
             "/actions/runs?branch=main&per_page=20": {"workflow_runs": []},
             "/actions/runs?event=pull_request&per_page=50": {"workflow_runs": []}}

    def transport(method, url, body):
        return 200, empty[url.split("/repos/org/deteccoes", 1)[1]]

    a = GitHubClient(GitHubConfig(repo="org/deteccoes"), transport=transport).activity(now=NOW)
    assert a["merge"]["median_hours"] is None
    assert a["ci"]["success_rate"] is None
    assert a["ci"]["last"] is None


def test_servico_de_atividade_nunca_quebra_e_usa_cache(tmp_path, monkeypatch):
    assert service.github_activity(project_cfg(tmp_path, extra=""))["reason"] == "not_configured"

    cfg = project_cfg(tmp_path)
    service._activity_cache.clear()
    for env in ("VITRIX_GITHUB_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(env, raising=False)
    assert service.github_activity(cfg)["reason"] == "no_token"

    fake = FakeGitHub()
    ok = service.github_activity(cfg, client=GitHubClient(cfg.github, transport=fake))
    assert ok["available"] is True and ok["pulls"]["open"] == 2
    calls = len(fake.calls)
    service.github_activity(cfg, client=GitHubClient(cfg.github, transport=fake))
    assert len(fake.calls) == calls  # veio do cache
    service.github_activity(cfg, client=GitHubClient(cfg.github, transport=fake), refresh=True)
    assert len(fake.calls) > calls

    service._activity_cache.clear()
    broken = service.github_activity(cfg, client=GitHubClient(cfg.github, transport=FakeGitHub(fail={"/commits": 404})))
    assert broken["available"] is False and broken["reason"] == "error"
    service._activity_cache.clear()


# --------------------------------------------------------------------------- vitrix.yml pela interface


def test_config_view_traz_o_texto_e_a_configuracao_efetiva(tmp_path):
    cfg = project_cfg(tmp_path)
    view = service.config_view(cfg)
    assert view["path"] == "vitrix.yml"
    assert view["text"].startswith("schema_version: 1")
    assert view["github"] == {"repo": "org/deteccoes", "base": "main", "path": ""}
    assert view["output_dir"] == "dist"


def test_validar_config_editada(tmp_path):
    cfg = project_cfg(tmp_path)
    ok = service.validate_config_text(cfg, "schema_version: 1" + chr(10) + "targets: [splunk]" + chr(10) + GITHUB_CFG)
    assert ok["ok"] is True and ok["config"]["targets"] == ["splunk"]

    bad = service.validate_config_text(cfg, "targets: [splunk, siem-inexistente]")
    assert bad["ok"] is False and "siem-inexistente" in bad["errors"][0]
    assert any("github" in w for w in bad["warnings"])

    assert service.validate_config_text(cfg, "targets: [")["ok"] is False
    assert service.validate_config_text(cfg, "schema_version: 9")["ok"] is False
    missing = service.validate_config_text(cfg, "extra_pipelines: [nao/existe.yml]")
    assert "não encontrado" in missing["errors"][0]


def test_pr_da_config(tmp_path):
    cfg = project_cfg(tmp_path)
    fake = FakeGitHub()
    text = "schema_version: 1" + chr(10) + "targets: [kql]" + chr(10) + GITHUB_CFG
    out = service.propose_config_change(cfg, text, client=GitHubClient(cfg.github, transport=fake))
    assert out["files"] == ["vitrix.yml"]
    assert fake.body_of("/pulls")["title"] == "chore: atualiza vitrix.yml"
    assert {e["path"] for e in fake.body_of("/git/trees")["tree"]} == {"vitrix.yml"}
    with pytest.raises(service.ChangeError):
        service.propose_config_change(cfg, "targets: [xyz]", client=GitHubClient(cfg.github, transport=fake))


def test_api_config_validate_e_pr(api):
    client, _ = api
    assert client.post("/api/config/validate", json={"text": "targets: [xyz]"}).json()["ok"] is False
    text = "schema_version: 1" + chr(10) + "targets: [splunk]" + chr(10) + GITHUB_CFG
    assert client.post("/api/config/pull-requests", json={"text": text}).status_code == 201
    assert client.post("/api/config/pull-requests", json={"text": text}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/config/pull-requests", json={"text": "targets: [xyz]"}).status_code == 422


def test_lista_de_regras_explica_as_pendencias(tmp_path):
    wrong = CASES_OK.replace("--ok", "--bad")
    cfg = load_config(make_project(tmp_path, cases_text=wrong))
    rule = service.list_rules(cfg)[0]
    assert rule["state"] == "fail"
    assert rule["issues"][0]["severity"] == "error"
    assert "neg" in rule["issues"][0]["message"]
