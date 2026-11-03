"""Testes de segurança da API local (sem autenticação): DNS rebinding, CSRF e cabeçalhos."""

from __future__ import annotations

import json

import pytest
from test_engine import RULE_OK, make_project

from vitrix.api import request_problem
from vitrix.github import GitHubClient, GitHubConfig, GitHubError, _urllib_transport

LOCAL = {"127.0.0.1", "localhost", "[::1]"}


@pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000", "[::1]:8000", "LOCALHOST"])
def test_hosts_locais_passam(host):
    assert request_problem("GET", "/api/rules", {"host": host}, LOCAL, []) is None


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "127.0.0.1.evil.example", "", "192.168.0.10:8000"])
def test_dns_rebinding_e_barrado_ate_em_leitura(host):
    assert request_problem("GET", "/api/config", {"host": host}, LOCAL, []) == (403, "host não permitido")


@pytest.mark.parametrize("ctype", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""])
def test_post_que_nao_e_json_e_barrado(ctype):
    headers = {"host": "127.0.0.1:8000", "content-type": ctype}
    assert request_problem("POST", "/api/regex", headers, LOCAL, [])[0] == 415


def test_post_de_outra_origem_e_barrado_e_cors_configurado_libera():
    headers = {"host": "127.0.0.1:8000", "content-type": "application/json", "origin": "https://evil.example"}
    assert request_problem("POST", "/api/replay", headers, LOCAL, [])[0] == 403
    assert request_problem("POST", "/api/replay", {**headers, "origin": "null"}, LOCAL, [])[0] == 403
    assert request_problem("POST", "/api/replay", {**headers, "origin": "http://localhost:5173"}, LOCAL, ["http://localhost:5173"]) is None
    same = {**headers, "origin": "http://127.0.0.1:8000", "content-type": "application/json; charset=utf-8"}
    assert request_problem("POST", "/api/replay", same, LOCAL, []) is None


@pytest.fixture
def client(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    return TestClient(create_app(make_project(tmp_path)), base_url="http://127.0.0.1:8000")


def test_api_nao_vaza_configuracao_por_rebinding(client):
    assert client.get("/api/config").status_code == 200
    resp = client.get("/api/config", headers={"Host": "evil.example"})
    assert resp.status_code == 403 and "schema_version" not in resp.text
    assert client.get("/api/rules/r.yml", headers={"Host": "evil.example"}).status_code == 403


@pytest.mark.parametrize("path,body", [
    ("/api/regex", {"pattern": "a", "samples": ["a"]}),
    ("/api/replay", {"events": "[]"}),
    ("/api/validate", {"rule": RULE_OK}),
    ("/api/pull-requests", {"path": "x.yml", "rule": RULE_OK}),
    ("/api/config/pull-requests", {"text": "targets: [splunk]"}),
])
def test_csrf_simple_request_nao_executa_nada(client, path, body):
    resp = client.post(path, content=json.dumps(body), headers={"Content-Type": "text/plain", "Origin": "https://evil.example"})
    assert resp.status_code in (403, 415)


def test_cabecalhos_de_seguranca(client):
    headers = client.get("/api/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"


def test_token_so_vai_para_a_api_do_github():
    send = _urllib_transport("segredo")
    for url in ("file:///etc/passwd", "http://api.github.com/repos/x", "https://evil.example/repos/x", "https://api.github.com.evil.example/x"):
        with pytest.raises(GitHubError, match="recusada"):
            send("GET", url, None)


def test_repo_e_branch_nao_injetam_caminho():
    from vitrix.github import parse_config

    for bad in ({"repo": "org/x/../../y"}, {"repo": "org/x?a=1"}, {"repo": "org/x", "base": "main/../../x"}):
        with pytest.raises(ValueError):
            parse_config(bad)
    calls = []
    client = GitHubClient(GitHubConfig(repo="org/x", base="feat/a b"), transport=lambda m, u, b: calls.append(u) or (200, {}))
    client._call("GET", "/commits/" + __import__("urllib.parse").parse.quote("feat/a b", safe=""))
    assert calls[0] == "https://api.github.com/repos/org/x/commits/feat%2Fa%20b"
