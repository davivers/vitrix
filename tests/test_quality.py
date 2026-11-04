"""Testes de validação ampliados, replay de logs e quality gate (o fluxo Escrever → … → Deploy)."""

from __future__ import annotations

import json

import pytest
import yaml
from test_engine import CASES_OK, RULE_OK, make_project, run

from vitrix import flow
from vitrix.cases import parse_cases, run_cases
from vitrix.config import ConfigError, load_config
from vitrix.evaluator import evaluate, exclusion_selections
from vitrix.lint import lint_doc
from vitrix.replay import ReplayError, check_expectations, load_events

BS = chr(92) * 2  # o fixture RULE_OK usa barra invertida dupla nos caminhos


def doc_of(text: str) -> dict:
    return yaml.safe_load(text)


def messages(doc: dict) -> list[str]:
    return [i.message for i in lint_doc(doc, "r.yml")]


# --------------------------------------------------------------------------- 01 · sintaxe e schema


def test_regex_invalida_e_erro_e_regex_cara_e_aviso():
    doc = doc_of(RULE_OK)
    doc["detection"]["selection"]["CommandLine|re"] = "(abc"
    assert any("invalid regex" in m for m in messages(doc))
    doc["detection"]["selection"]["CommandLine|re"] = "(a+)+$"
    assert any("backtracking" in m for m in messages(doc))


def test_modificador_desconhecido_sugere_o_certo():
    doc = doc_of(RULE_OK)
    doc["detection"]["selection"]["CommandLine|contians"] = "x"
    msgs = messages(doc)
    assert any("unknown modifier 'contians'" in m and "contains" in m for m in msgs)


def test_campo_com_erro_de_digitacao_e_tipos():
    doc = doc_of(RULE_OK)
    doc["falsepositive"] = ["x"]
    doc["references"] = "http://x"
    doc["date"] = "01/11/2026"
    msgs = messages(doc)
    assert any("did you mean 'falsepositives'" in m for m in msgs)
    assert any("'references' must be a list" in m for m in msgs)
    assert any("YYYY-MM-DD" in m for m in msgs)


def test_campo_customizado_nao_gera_ruido():
    doc = doc_of(RULE_OK)
    doc["custom_owner"] = "time-x"
    assert not any("custom_owner" in m for m in messages(doc))


def test_regra_muito_complexa_gera_aviso():
    doc = doc_of(RULE_OK)
    doc["detection"]["selection"]["CommandLine|contains"] = [f"v{i}" for i in range(60)]
    assert any("complex rule" in m for m in messages(doc))


# --------------------------------------------------------------------------- 04 · MITRE


def test_mitre_tatica_desconhecida_e_tecnica_sem_tatica():
    doc = doc_of(RULE_OK)
    doc["tags"] = ["attack.t1059.001", "attack.executoin"]
    msgs = messages(doc)
    assert any("unknown ATT&CK tactic" in m and "attack.execution" in m for m in msgs)
    assert any("without its tactic" in m for m in msgs)
    doc["tags"] = ["attack.execution", "attack.t1059.001", "attack.g0016", "attack.s0002"]
    assert not any("MITRE" in m or "ATT&CK" in m for m in messages(doc))


def test_logica_identica_em_duas_regras_e_apontada(tmp_path):
    cfg = make_project(tmp_path)
    other = RULE_OK.replace("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    (tmp_path / "rules" / "copia.yml").write_text(other, encoding="utf-8")
    (tmp_path / "cases" / "copia.yml").write_text(CASES_OK, encoding="utf-8")
    assert run(cfg, "lint") == 0  # aviso, não erro
    assert run(cfg, "lint", "--strict") == 1


# --------------------------------------------------------------------------- 02/03 · casos, falsos positivos e exclusões

RULE_FILTER = RULE_OK.replace(
    "  condition: selection",
    "  filter_admin:\n    User: 'svc_admin'\n  condition: selection and not filter_admin",
)


def test_selecoes_de_exclusao():
    doc = doc_of(RULE_FILTER)
    assert exclusion_selections(doc) == {"filter_admin"}
    doc["detection"]["condition"] = "selection and not 1 of skip*"
    doc["detection"]["skip_a"] = {"User": "x"}
    assert exclusion_selections(doc) == {"filter_admin", "skip_a"}


def test_caso_de_falso_positivo_prova_a_exclusao(tmp_path):
    cfg = load_config(make_project(tmp_path))
    tool = f"C:{BS}x{BS}tool.exe"
    text = json.dumps({"cases": [
        {"name": "pos", "expect": "match", "event": {"Image": tool, "CommandLine": "tool.exe --bad", "User": "ana"}},
        {"name": "fp", "kind": "false_positive", "expect": "no_match", "event": {"Image": tool, "CommandLine": "tool.exe --bad", "User": "svc_admin"}},
        {"name": "neg", "expect": "no_match", "event": {"Image": tool, "CommandLine": "tool.exe --ok", "User": "ana"}},
    ]})
    cases, problems = parse_cases(text, "c.yml", "r.yml")
    results, problems = run_cases(cfg, "r.yml", [doc_of(RULE_FILTER)], cases, problems)
    by_name = {r.name: r for r in results}
    assert all(r.passed for r in results)
    assert by_name["fp"].kind == "false_positive" and by_name["fp"].exercises_filter is True
    assert by_name["neg"].kind == "negative" and by_name["neg"].exercises_filter is False


def test_kind_incoerente_com_expect_e_erro():
    text = "cases:\n  - {name: x, kind: false_positive, expect: match, event: {A: 1}}\n  - {name: y, kind: zzz, expect: match, event: {A: 1}}\n"
    cases, problems = parse_cases(text, "c.yml", "r.yml")
    assert cases == []
    assert any("requires expect: no_match" in p.message for p in problems)
    assert any("'kind' must be one of" in p.message for p in problems)


def test_qualidade_dos_dados_de_teste(tmp_path):
    cfg = load_config(make_project(tmp_path))
    text = "cases:\n  - {name: a, expect: no_match, event: {Outro: 1}}\n  - {name: b, expect: no_match, event: {Outro: 1}}\n"
    cases, problems = parse_cases(text, "c.yml", "r.yml")
    assert any("same event as case 1" in p.message for p in problems)
    _, problems = run_cases(cfg, "r.yml", [doc_of(RULE_OK)], cases, problems)
    assert any("has none of the fields the rule uses" in p.message for p in problems)


def test_caso_de_borda_campo_nulo_e_maiusculas():
    doc = doc_of(RULE_OK)
    assert evaluate(doc, {"Image": None, "CommandLine": "--bad"}) is False
    assert evaluate(doc, {"image": f"C:{BS}X{BS}TOOL.EXE", "commandline": "TOOL.EXE --BAD"}) is True


# --------------------------------------------------------------------------- 05/06/07 · replay, desempenho e regressão


def test_carrega_eventos_em_varios_formatos():
    assert load_events('[{"a": 1}, {"a": 2}]') == [{"a": 1}, {"a": 2}]
    assert load_events('{"a": 1}\n{"a": 2}\n') == [{"a": 1}, {"a": 2}]
    assert load_events("events:\n  - {a: 1}\n") == [{"a": 1}]
    with pytest.raises(ReplayError):
        load_events("[1, 2]")


def write_dataset(tmp_path, events, expect: str | None = None):
    (tmp_path / "datasets").mkdir(exist_ok=True)
    (tmp_path / "datasets" / "sim.jsonl").write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    if expect is not None:
        (tmp_path / "datasets" / "sim.expect.yml").write_text(expect, encoding="utf-8")


EVIL = {"Image": f"C:{BS}x{BS}tool.exe", "CommandLine": "tool.exe --bad"}
GOOD = {"Image": f"C:{BS}x{BS}tool.exe", "CommandLine": "tool.exe --ok"}


def test_replay_conta_matches_mede_tempo_e_confere_expectativas(tmp_path):
    cfg = load_config(make_project(tmp_path))
    write_dataset(tmp_path, [EVIL, GOOD, EVIL], "expect:\n  r.yml: 2\nothers: 0\n")
    res = flow.run_dataset(cfg, "sim.jsonl")
    assert res["events"] == 3
    rule = res["rules"][0]
    assert rule["matches"] == 2 and rule["sample"] == [1, 3]
    assert rule["duration_ms"] >= 0
    assert res["passed"] is True


def test_regressao_quando_a_contagem_muda(tmp_path):
    cfg = load_config(make_project(tmp_path))
    write_dataset(tmp_path, [EVIL, GOOD], "expect:\n  r.yml: 2\n")
    res = flow.run_dataset(cfg, "sim.jsonl")
    assert res["passed"] is False
    assert "exactly 2" in res["checks"][0]["message"]
    assert run(make_project(tmp_path), "replay") == 1


def test_expectativas_min_max_e_others():
    result = {"rules": [{"rule": "a.yml", "matches": 3}, {"rule": "b.yml", "matches": 1}]}
    checks = check_expectations(result, {"a.yml": {"min": 1, "max": None}}, 0)
    assert [c["passed"] for c in checks] == [True, False]  # b.yml disparou sem estar previsto


def test_dataset_fora_da_pasta_nao_e_lido(tmp_path):
    cfg = load_config(make_project(tmp_path))
    write_dataset(tmp_path, [EVIL])
    with pytest.raises(KeyError):
        flow.run_dataset(cfg, "../vitrix.yml")


# --------------------------------------------------------------------------- quality gate


def test_high_rule_needs_no_false_positive_case_by_default(tmp_path):
    cfg = load_config(make_project(tmp_path, rule_text=RULE_OK.replace("level: medium", "level: high")))
    rule = flow.quality_report(cfg)["rules"][0]
    assert rule["ready"] is True, rule["blockers"]
    assert not any(c["id"] == "false_positive_cases" for c in rule["checks"])  # not shown, no score cost


def test_gate_bloqueia_regra_high_sem_caso_de_falso_positivo(tmp_path):
    cfg = load_config(make_project(tmp_path, rule_text=RULE_OK.replace("level: medium", "level: high"),
                                   extra_cfg="quality_gate:\n  false_positive_levels: [high]\n"))
    rule = flow.quality_report(cfg)["rules"][0]
    assert rule["ready"] is False
    assert any("False-positive" in b for b in rule["blockers"])
    assert rule["stages"]["analyze"] == "fail" and rule["stages"]["deploy"] == "skip"
    assert rule["answers"][3] == "fail" and rule["answers"][5] == "fail"


def test_gate_aprova_regra_medium_com_casos(tmp_path):
    cfg = load_config(make_project(tmp_path))
    q = flow.quality_report(cfg)
    rule = q["rules"][0]
    assert rule["ready"] is True, rule["blockers"]
    assert rule["stages"]["gate"] == "ok" and rule["stages"]["deploy"] == "pending"
    assert rule["stages"]["replay"] == "skip"  # sem dataset: não se aplica
    assert {k: q["summary"][k] for k in ("total", "ready", "blocked", "stale")} == {"total": 1, "ready": 1, "blocked": 0, "stale": 0}
    assert 70 <= q["summary"]["health"] <= 100 and rule["score"] == q["summary"]["health"]


def test_gate_exige_teste_da_exclusao(tmp_path):
    cfg = load_config(make_project(tmp_path, rule_text=RULE_FILTER))
    rule = flow.quality_report(cfg)["rules"][0]
    assert "Exclusion (filter) proven by a test case" in rule["blockers"]


def test_gate_configuravel(tmp_path):
    extra = "quality_gate:\n  allow_warnings: false\n  require_replay: true\n  min_positive: 2\n"
    cfg = load_config(make_project(tmp_path, rule_text=RULE_OK.replace("falsepositives: [none]\n", ""), extra_cfg=extra))
    blockers = flow.quality_report(cfg)["rules"][0]["blockers"]
    assert "No lint warnings" in blockers
    assert "Expectation in a replay dataset" in blockers
    assert "At least 2 positive case(s)" in blockers


@pytest.mark.parametrize("bad", ["quality_gate: 1\n", "quality_gate:\n  nao_existe: 1\n", "quality_gate:\n  min_positive: -1\n",
                                 "quality_gate:\n  false_positive_levels: [altissimo]\n", "quality_gate:\n  allow_warnings: talvez\n"])
def test_gate_invalido_no_vitrix_yml(tmp_path, bad):
    with pytest.raises(ConfigError):
        load_config(make_project(tmp_path, extra_cfg=bad))


def test_gate_regressao_de_replay_bloqueia(tmp_path):
    cfg_path = make_project(tmp_path)
    write_dataset(tmp_path, [EVIL], "expect:\n  r.yml: 2\n")
    rule = flow.quality_report(load_config(cfg_path))["rules"][0]
    assert rule["stages"]["replay"] == "fail"
    assert run(cfg_path, "gate") == 1
    assert run(cfg_path, "check", "--gate") == 1
    assert run(cfg_path, "check") == 0  # sem --gate, o check continua como antes


def test_relatorio_markdown_e_json(tmp_path, capsys):
    cfg_path = make_project(tmp_path)
    assert run(cfg_path, "report") == 0
    out = capsys.readouterr().out
    assert "## Quality gate" in out and "| `r.yml` |" in out
    assert run(cfg_path, "report", "--format", "json", "-o", str(tmp_path / "r.json")) == 0
    data = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert data["quality"]["summary"]["ready"] == 1
    assert data["tests"]["by_kind"]["positive"] == {"total": 1, "passed": 1}


def test_repositorio_de_exemplo_passa_no_gate_e_no_replay(user_repo):
    cfg = str(user_repo)
    assert run(cfg, "gate") == 0
    assert run(cfg, "replay") == 0
    assert run(cfg, "check", "--strict", "--gate") == 0

# --------------------------------------------------------------------------- API


@pytest.fixture
def client(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    write_dataset(tmp_path, [EVIL, GOOD], "expect:\n  r.yml: 1\n")
    return TestClient(create_app(make_project(tmp_path)))


def test_api_do_fluxo(client):
    q = client.get("/api/quality").json()
    assert q["summary"]["ready"] == 1
    assert [s["id"] for s in q["stages"]] == ["write", "validate", "test", "replay", "analyze", "gate", "deploy"]
    assert client.get("/api/quality/r.yml").json()["ready"] is True
    assert client.get("/api/quality/nao.yml").status_code == 404
    assert client.get("/api/tests").json()["by_kind"]["negative"]["total"] == 1
    cov = client.get("/api/coverage").json()
    assert cov["tactics"][0]["slug"] == "reconnaissance"
    assert any(t["slug"] == "execution" and t["techniques"][0]["id"] == "T1059.001" for t in cov["tactics"])
    assert client.get("/api/datasets").json()[0]["name"] == "sim.jsonl"
    assert client.get("/api/datasets/sim.jsonl/replay").json()["passed"] is True
    assert client.get("/api/datasets/..%2Fvitrix.yml/replay").status_code == 404
    assert "# Vitrix report" in client.get("/api/report?format=md").text


def test_api_replay_colado_e_validate_com_gate(client):
    events = json.dumps([EVIL, GOOD])
    assert client.post("/api/replay", json={"events": events}).json()["rules"][0]["matches"] == 1
    draft = client.post("/api/replay", json={"events": events, "rule": RULE_OK.replace("--bad", "--ok")}).json()
    assert draft["rules"][0]["matches"] == 1 and draft["rules"][0]["rule"] == "<editor>"
    assert client.post("/api/replay", json={"events": "[1]"}).status_code == 422
    v = client.post("/api/validate", json={"rule": RULE_OK, "cases": CASES_OK}).json()
    assert v["quality"]["ready"] is True
    assert v["quality"]["datasets"][0]["matches"] == 1
    assert v["tests"]["results"][0]["kind"] == "positive"


# --------------------------------------------------------------------------- approval by minimum score


def test_rule_without_blockers_but_below_min_score_is_not_approved(tmp_path):
    # Warnings and missing edge/false-positive cases are only recommendations: no blocker, but a lower score.
    weak = RULE_OK.replace("falsepositives: [none]\n", "").replace("description: d\n", "")
    cfg = load_config(make_project(tmp_path, rule_text=weak, extra_cfg="quality_gate:\n  min_score: 95\n"))
    rule = flow.quality_report(cfg)["rules"][0]
    assert rule["score"] < 95 and rule["min_score"] == 95
    check = next(c for c in rule["checks"] if c["id"] == "min_score")
    assert check["passed"] is False and check["blocking"] is True
    assert rule["ready"] is False and "Health score at least 95" in rule["blockers"]
    assert rule["score"] == flow.quality_report(load_config(make_project(tmp_path, rule_text=weak, extra_cfg="quality_gate:\n  min_score: 0\n")))["rules"][0]["score"]


def test_rule_reaching_the_min_score_is_approved(tmp_path):
    cfg = load_config(make_project(tmp_path, extra_cfg="quality_gate:\n  min_score: 80\n"))
    rule = flow.quality_report(cfg)["rules"][0]
    assert rule["score"] >= 80 and rule["ready"] is True
    assert next(c for c in rule["checks"] if c["id"] == "min_score")["passed"] is True


def test_min_score_zero_turns_the_threshold_off(tmp_path):
    cfg = load_config(make_project(tmp_path, extra_cfg="quality_gate:\n  min_score: 0\n"))
    assert not any(c["id"] == "min_score" for c in flow.quality_report(cfg)["rules"][0]["checks"])


@pytest.mark.parametrize("bad", ["min_score: 101", "min_score: -1", "min_score: high"])
def test_invalid_min_score_is_a_config_error(tmp_path, bad):
    with pytest.raises(ConfigError):
        load_config(make_project(tmp_path, extra_cfg=f"quality_gate:\n  {bad}\n"))


def test_editor_validation_reports_approval(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    client = TestClient(create_app(make_project(tmp_path, extra_cfg="quality_gate:\n  min_score: 99\n")), base_url="http://127.0.0.1:8000")
    q = client.post("/api/validate", json={"rule": RULE_OK, "cases": CASES_OK}).json()["quality"]
    assert q["min_score"] == 99 and q["score"] < 99 and q["ready"] is False
