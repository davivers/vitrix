"""Linguagem final por regra: `vitrix.target`, `routes`, `default_target` e a CLI/API em cima disso."""

from __future__ import annotations

import json

import pytest
from test_engine import CASES_OK, RULE_OK, make_project, run

from vitrix.config import ConfigError, load_config
from vitrix.routing import resolve

OTHER_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def with_target(text: str, target: str = "kql") -> str:
    return text + f"vitrix:\n  target: {target}\n"


def manifest(tmp_path) -> dict:
    return json.loads((tmp_path / "dist" / "manifest.json").read_text())


# --------------------------------------------------------------------------- resolução


def test_ordem_de_decisao_regra_rota_padrao_todos(tmp_path):
    cfg = load_config(make_project(tmp_path, extra_cfg="default_target: splunk\nroutes:\n  - {match: 'windows/*', target: kql}\n"))
    doc = {"vitrix": {"target": "elastic-eql"}}

    assert resolve(cfg, "windows/a.yml", doc).targets == ["elastic-eql"]
    assert resolve(cfg, "windows/a.yml", doc).source == "rule"
    assert resolve(cfg, "windows/a.yml", {}).targets == ["kql"]
    assert resolve(cfg, "windows/a.yml", {}).source == "route"
    assert resolve(cfg, "linux/b.yml", {}).targets == ["splunk"]
    assert resolve(cfg, "linux/b.yml", {}).source == "default"
    assert resolve(cfg, None, {}).source == "default"  # regra ainda não salva: sem rota

    (tmp_path / "p").mkdir()
    plain = load_config(make_project(tmp_path / "p"))
    assert resolve(plain, "x.yml", {}).targets == ["splunk", "kql", "elastic-eql"]
    assert resolve(plain, "x.yml", {}).source == "all"


def test_regra_aceita_lista_de_alvos_e_o_override_da_cli_vence_tudo(tmp_path):
    cfg = load_config(make_project(tmp_path))
    assert resolve(cfg, "r.yml", {"vitrix": {"target": ["splunk", "kql"]}}).targets == ["splunk", "kql"]
    forced = resolve(cfg, "r.yml", {"vitrix": {"target": "kql"}}, override=["splunk"])
    assert (forced.targets, forced.source) == (["splunk"], "override")


@pytest.mark.parametrize("doc", [{"vitrix": "sim"}, {"vitrix": {"target": []}}, {"vitrix": {"target": 3}}, {"vitrix": {"target": [1]}}])
def test_campo_invalido_na_regra_e_ignorado_na_resolucao(tmp_path, doc):
    cfg = load_config(make_project(tmp_path))
    assert resolve(cfg, "r.yml", doc).source == "all"  # o lint acusa o erro; a resolução cai no padrão


# --------------------------------------------------------------------------- CLI


def test_convert_gera_so_a_linguagem_escolhida(tmp_path):
    cfg = make_project(tmp_path, with_target(RULE_OK, "kql"))
    assert run(cfg, "convert") == 0
    assert (tmp_path / "dist" / "kql" / "r.kql").is_file()
    assert not (tmp_path / "dist" / "splunk").exists()
    assert not (tmp_path / "dist" / "elastic-eql").exists()
    rule = manifest(tmp_path)["rules"][0]
    assert rule["targets"] == ["kql"] and rule["target_source"] == "rule"
    assert list(rule["outputs"]) == ["kql"]
    assert manifest(tmp_path)["targets"] == ["kql"]


def test_rotas_e_padrao_do_vitrix_yml(tmp_path):
    cfg = make_project(tmp_path, extra_cfg="default_target: splunk\nroutes:\n  - {match: 'windows/*', target: kql}\n")
    (tmp_path / "rules" / "windows").mkdir()
    (tmp_path / "rules" / "windows" / "a.yml").write_text(RULE_OK.replace("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", OTHER_ID))
    assert run(cfg, "convert") == 0
    assert (tmp_path / "dist" / "kql" / "windows" / "a.kql").is_file()  # rota
    assert (tmp_path / "dist" / "splunk" / "r.spl").is_file()  # padrão
    assert not (tmp_path / "dist" / "kql" / "r.kql").exists()


def test_trocar_a_linguagem_remove_a_saida_antiga(tmp_path):
    cfg = make_project(tmp_path, with_target(RULE_OK, "splunk"))
    assert run(cfg, "convert") == 0
    assert (tmp_path / "dist" / "splunk" / "r.spl").is_file()
    (tmp_path / "rules" / "r.yml").write_text(with_target(RULE_OK, "kql"))
    assert run(cfg, "convert") == 0
    assert not (tmp_path / "dist" / "splunk" / "r.spl").exists()
    assert (tmp_path / "dist" / "kql" / "r.kql").is_file()


def test_opcao_target_da_cli_forca_o_alvo_para_todas_as_regras(tmp_path):
    cfg = make_project(tmp_path, with_target(RULE_OK, "kql"))
    assert run(cfg, "convert", "-t", "splunk") == 0
    assert (tmp_path / "dist" / "splunk" / "r.spl").is_file()
    assert not (tmp_path / "dist" / "kql").exists()


def test_alvo_desconhecido_na_regra_reprova_o_lint_e_a_conversao(tmp_path, capsys):
    cfg = make_project(tmp_path, with_target(RULE_OK, "qradar"))
    assert run(cfg, "check") == 1
    out = capsys.readouterr().out
    assert "alvo desconhecido 'qradar'" in out
    assert not (tmp_path / "dist" / "qradar").exists()


def test_bloco_vitrix_mal_formado_e_erro_de_lint(tmp_path, capsys):
    cfg = make_project(tmp_path, RULE_OK + "vitrix: sim\n")
    assert run(cfg, "lint") == 1
    assert "deve ser um mapa" in capsys.readouterr().out
    cfg = make_project(tmp_path, RULE_OK + "vitrix:\n  alvo: kql\n")
    run(cfg, "lint")
    assert "chave desconhecida em 'vitrix': alvo" in capsys.readouterr().out


def test_alvo_desconhecido_no_vitrix_yml_e_erro_de_uso(tmp_path, capsys):
    cfg = make_project(tmp_path, extra_cfg="default_target: nao-existe\n")
    assert run(cfg, "convert") == 2
    assert "nao-existe" in capsys.readouterr().err


@pytest.mark.parametrize(
    "extra",
    ["routes: nada\n", "routes:\n  - {target: kql}\n", "routes:\n  - {match: 'a/*'}\n", "default_target: 3\n"],
)
def test_configuracao_de_rotas_invalida(tmp_path, extra):
    with pytest.raises(ConfigError):
        load_config(make_project(tmp_path, extra_cfg=extra))


# --------------------------------------------------------------------------- API


pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from vitrix.api import create_app  # noqa: E402


def test_api_expoe_linguagem_final_origem_e_conversao(tmp_path):
    client = TestClient(create_app(make_project(tmp_path, with_target(RULE_OK, "kql"))))
    rule = client.get("/api/rules").json()[0]
    assert rule["targets"] == ["kql"] and rule["target_source"] == "rule"
    assert rule["conversion"] == {"kql": True}
    assert rule["state"] == "ok"

    detail = client.get("/api/rules/r.yml").json()
    assert detail["targets"] == ["kql"]
    assert list(detail["conversions"])[0] == "kql"  # a escolhida vem primeiro
    assert set(detail["conversions"]) == {"kql", "splunk", "elastic-eql"}  # os demais ficam de pré-visualização

    stats = client.get("/api/stats").json()
    assert stats["by_target"] == {"kql": 1} and stats["conversion_failures"] == 0
    assert client.get("/api/config").json()["routes"] == []


def test_api_regra_com_alvo_desconhecido_fica_reprovada(tmp_path):
    client = TestClient(create_app(make_project(tmp_path, with_target(RULE_OK, "qradar"))))
    rule = client.get("/api/rules").json()[0]
    assert rule["state"] == "fail" and rule["conversion"] == {"qradar": False}
    assert client.get("/api/stats").json()["conversion_failures"] == 1


def test_validate_devolve_a_escolha_e_so_ela_reprova(tmp_path):
    client = TestClient(create_app(make_project(tmp_path, extra_cfg="default_target: splunk\n")))
    body = client.post("/api/validate", json={"rule": with_target(RULE_OK, "elastic-eql"), "cases": CASES_OK}).json()
    assert body["targets"] == ["elastic-eql"] and body["target_source"] == "rule"
    assert list(body["conversions"])[0] == "elastic-eql"
    assert body["state"] == "ok"

    body = client.post("/api/validate", json={"rule": RULE_OK}).json()
    assert body["targets"] == ["splunk"] and body["target_source"] == "default"
