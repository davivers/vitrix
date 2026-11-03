"""Testes da API HTTP."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from test_engine import CASES_OK, RULE_OK, make_project  # noqa: E402

from vitrix import service  # noqa: E402
from vitrix.api import MAX_TEXT, create_app  # noqa: E402
from vitrix.config import load_config  # noqa: E402


@pytest.fixture
def project(tmp_path):
    return make_project(tmp_path)


@pytest.fixture
def client(project):
    return TestClient(create_app(project))


def test_health_e_config(client):
    assert client.get("/api/health").json()["ok"] is True
    cfg = client.get("/api/config").json()
    assert cfg["targets"] == ["splunk", "kql", "elastic-eql"]
    assert cfg["rules_dir"] == "rules"


def test_targets_marca_os_ativos(client):
    targets = {t["name"]: t for t in client.get("/api/targets").json()}
    assert targets["splunk"]["active"] is True
    assert targets["elastic-lucene"]["active"] is False


def test_lista_de_regras(client):
    rules = client.get("/api/rules").json()
    assert len(rules) == 1
    r = rules[0]
    assert r["id"] == "r.yml"
    assert r["state"] == "ok"
    assert r["tactics"] == ["execution"]
    assert r["techniques"] == ["T1059.001"]
    assert r["tests"] == {"total": 2, "passed": 2}


def test_detalhe_traz_queries_por_siem_e_testes(client):
    d = client.get("/api/rules/r.yml").json()
    assert d["state"] == "ok"
    assert set(d["conversions"]) == {"splunk", "kql", "elastic-eql"}
    assert all(c["ok"] for c in d["conversions"].values())
    assert "FolderPath" in d["conversions"]["kql"]["query"]
    assert "Image" in d["conversions"]["splunk"]["query"]
    assert [r["passed"] for r in d["tests"]["results"]] == [True, True]
    assert d["tests"]["cases_text"].startswith("cases:")


def test_regra_inexistente_e_caminhos_fora_da_pasta_dao_404(client, project):
    assert client.get("/api/rules/nao-existe.yml").status_code == 404
    for evil in ("..%2Fvitrix.yml", "%2E%2E/vitrix.yml", "..%2F..%2Fetc%2Fpasswd"):
        resp = client.get(f"/api/rules/{evil}")
        assert resp.status_code == 404
        assert "schema_version" not in resp.text
    assert service.resolve_rule(load_config(project), "../vitrix.yml") is None


def test_validate_regra_boa_com_casos(client):
    body = client.post("/api/validate", json={"rule": RULE_OK, "cases": CASES_OK}).json()
    assert body["state"] == "ok"
    assert all(c["ok"] for c in body["conversions"].values())
    assert [r["passed"] for r in body["tests"]["results"]] == [True, True]


def test_validate_sem_casos_nao_roda_testes(client):
    body = client.post("/api/validate", json={"rule": RULE_OK}).json()
    assert body["tests"] is None
    assert body["state"] == "ok"


def test_validate_aponta_erro_de_lint(client):
    bad = RULE_OK.replace("id: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n", "")
    body = client.post("/api/validate", json={"rule": bad}).json()
    assert body["state"] == "fail"
    assert any("id" in i["message"] for i in body["lint"] if i["severity"] == "error")


def test_validate_yaml_invalido(client):
    body = client.post("/api/validate", json={"rule": "title: [sem fechar"}).json()
    assert body["state"] == "fail"
    assert "invalid YAML" in body["lint"][0]["message"]
    assert body["conversions"] == {}


def test_validate_caso_que_falha_marca_fail(client):
    wrong = CASES_OK.replace("--ok", "--bad")
    body = client.post("/api/validate", json={"rule": RULE_OK, "cases": wrong}).json()
    assert body["state"] == "fail"
    failed = [r for r in body["tests"]["results"] if not r["passed"]]
    assert failed and failed[0]["expect"] == "no_match" and failed[0]["got"] == "match"


def test_validate_alvo_desconhecido_e_limite_de_tamanho(client):
    assert client.post("/api/validate", json={"rule": RULE_OK, "targets": ["xyz"]}).status_code == 422
    assert client.post("/api/validate", json={"rule": "x" * (MAX_TEXT + 1)}).status_code == 422


def test_stats_derivadas_do_repositorio(client):
    s = client.get("/api/stats").json()
    assert s["rules"]["total"] == 1
    assert s["rules"]["by_status"] == {"test": 1}
    assert s["mitre"]["covered"] == 1
    assert s["mitre"]["total"] == 14
    assert s["mitre"]["coverage_pct"] == 7
    assert len(s["mitre"]["uncovered"]) == 13
    assert s["tests"] == {"total": 2, "passed": 2, "rules_without_cases": 0, "rules_all_passing": 1}
    assert s["pipeline"] == {"parse": {"ok": 1, "failed": 0}, "validation": {"ok": 1, "warn": 0, "fail": 0}, "conversion": {"ok": 1, "failed": 0}}
    assert s["mitre"]["tactics"][0] == {"slug": "execution", "id": "TA0002", "name": "Execution", "count": 1}
    assert s["lint"] == {"errors": 0, "warnings": 0}


def test_repositorio_de_exemplo_pela_api(user_repo):
    app = create_app(str(user_repo))
    c = TestClient(app)
    rules = c.get("/api/rules").json()
    assert {r["id"] for r in rules} == {"windows/powershell_encoded.yml", "windows/schtasks_system.yml"}
    assert all(r["state"] == "ok" for r in rules)
    stats = c.get("/api/stats").json()
    assert stats["mitre"]["covered"] == 2  # execution (PowerShell) e persistence (schtasks)
    assert stats["tests"] == {"total": 11, "passed": 11, "rules_without_cases": 0, "rules_all_passing": 2}


def test_interface_servida_na_raiz_com_fallback_e_sem_vazar_arquivos(client):
    from vitrix.api import UI_DIR

    if not (UI_DIR / "index.html").is_file():
        pytest.skip("interface não compilada (cd web && npm run build)")
    assert "<div id=\"root\">" in client.get("/").text
    assert "<div id=\"root\">" in client.get("/editor/windows/x.yml").text  # rota do React
    assert client.get("/api/nao-existe").status_code == 404
    assert client.get("/api/nao-existe").headers["content-type"].startswith("application/json")
    for evil in ("..%2Fapi.py", "%2E%2E/api.py", "..%2F..%2Fpyproject.toml"):
        assert "FastAPI" not in client.get(f"/{evil}").text
