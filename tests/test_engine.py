"""Testes do próprio motor (não confundir com os casos de teste das regras em cases/)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from vitrix.cli import main
from vitrix.evaluator import UnsupportedError, evaluate

REPO = Path(__file__).resolve().parents[1]


def rule(detection: str, extra: str = "") -> dict:
    """Monta um documento Sigma mínimo para testar o avaliador."""
    import yaml

    text = (
        "title: t\nid: 11111111-1111-4111-8111-111111111111\nstatus: test\nlevel: low\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        f"{extra}detection:\n{textwrap.indent(textwrap.dedent(detection), '  ')}"
    )
    return yaml.safe_load(text)


# --------------------------------------------------------------------------- avaliador


def test_modificadores_basicos_ignoram_maiusculas():
    doc = rule(
        """
        selection:
          Image|endswith: '\\cmd.exe'
          CommandLine|contains: whoami
        condition: selection
        """
    )
    assert evaluate(doc, {"Image": "C:\\Windows\\System32\\CMD.EXE", "CommandLine": "cmd /c WhoAmI"})
    assert not evaluate(doc, {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c dir"})


def test_contains_all_exige_todos_os_valores():
    doc = rule(
        """
        selection:
          CommandLine|contains|all: ['/create', '/ru']
        condition: selection
        """
    )
    assert evaluate(doc, {"CommandLine": "schtasks /create /ru SYSTEM"})
    assert not evaluate(doc, {"CommandLine": "schtasks /create"})


def test_curinga_e_igualdade_exata():
    doc = rule(
        """
        selection:
          User: 'adm*'
        condition: selection
        """
    )
    assert evaluate(doc, {"User": "admin01"})
    assert not evaluate(doc, {"User": "xadmin"})


def test_regex_e_cased():
    doc = rule(
        """
        selection:
          CommandLine|re: '-e[nc]+ '
        condition: selection
        """
    )
    assert evaluate(doc, {"CommandLine": "x -enc y"})
    cased = rule(
        """
        selection:
          CommandLine|contains|cased: PowerShell
        condition: selection
        """
    )
    assert evaluate(cased, {"CommandLine": "PowerShell -x"})
    assert not evaluate(cased, {"CommandLine": "powershell -x"})


def test_condicoes_com_not_or_parenteses_e_quantificadores():
    doc = rule(
        """
        sel_a:
          A: '1'
        sel_b:
          B: '2'
        filter_c:
          C: '3'
        condition: (sel_a or sel_b) and not filter_c
        """
    )
    assert evaluate(doc, {"A": "1"})
    assert evaluate(doc, {"B": "2"})
    assert not evaluate(doc, {"A": "1", "C": "3"})
    assert not evaluate(doc, {"Z": "9"})

    quant = rule(
        """
        sel_a:
          A: '1'
        sel_b:
          B: '2'
        condition: all of sel_*
        """
    )
    assert evaluate(quant, {"A": "1", "B": "2"})
    assert not evaluate(quant, {"A": "1"})

    anyof = rule(
        """
        sel_a:
          A: '1'
        sel_b:
          B: '2'
        condition: 1 of them
        """
    )
    assert evaluate(anyof, {"B": "2"})


def test_lista_de_mapas_e_palavras_chave():
    doc = rule(
        """
        selection:
          - A: '1'
          - B: '2'
        condition: selection
        """
    )
    assert evaluate(doc, {"B": "2"})
    kw = rule(
        """
        keywords:
          - mimikatz
        condition: keywords
        """
    )
    assert evaluate(kw, {"msg": "execução de MIMIKATZ detectada"})


def test_exists_e_nulo():
    doc = rule(
        """
        selection:
          Parent|exists: false
        condition: selection
        """
    )
    assert evaluate(doc, {"Image": "x"})
    assert not evaluate(doc, {"Parent": "y"})


def test_nao_suportado_levanta_erro_em_vez_de_passar_em_silencio():
    windash = rule(
        """
        selection:
          CommandLine|windash|contains: '-enc'
        condition: selection
        """
    )
    with pytest.raises(UnsupportedError):
        evaluate(windash, {"CommandLine": "-enc"})

    agg = rule(
        """
        selection:
          A: '1'
        condition: selection | count() > 3
        """
    )
    with pytest.raises(UnsupportedError):
        evaluate(agg, {"A": "1"})


# --------------------------------------------------------------------------- projeto temporário


RULE_OK = """\
title: Test rule
id: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
status: test
description: d
author: a
date: 2026-11-01
tags: [attack.execution, attack.t1059.001]
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\\\\tool.exe'
    CommandLine|contains: '--bad'
  condition: selection
falsepositives: [none]
level: medium
"""

CASES_OK = """\
cases:
  - {name: pos, expect: match, event: {Image: 'C:\\\\x\\\\tool.exe', CommandLine: 'tool.exe --bad'}}
  - {name: neg, expect: no_match, event: {Image: 'C:\\\\x\\\\tool.exe', CommandLine: 'tool.exe --ok'}}
"""


def make_project(tmp_path: Path, rule_text: str | None = RULE_OK, cases_text: str | None = CASES_OK, extra_cfg: str = "") -> str:
    if "auth:" not in extra_cfg:  # accounts are ON by default; most tests drive the API as one local user
        extra_cfg += ("" if not extra_cfg or extra_cfg.endswith("\n") else "\n") + "auth:\n  enabled: false\n"
    (tmp_path / "vitrix.yml").write_text(
        "schema_version: 1\ntargets: [splunk, kql, elastic-eql]\n" + extra_cfg, encoding="utf-8"
    )
    if rule_text is not None:
        (tmp_path / "rules").mkdir(exist_ok=True)
        (tmp_path / "rules" / "r.yml").write_text(rule_text, encoding="utf-8")
    if cases_text is not None:
        (tmp_path / "cases").mkdir(exist_ok=True)
        (tmp_path / "cases" / "r.yml").write_text(cases_text, encoding="utf-8")
    return str(tmp_path / "vitrix.yml")


def run(cfg: str, *args: str) -> int:
    return main(["-c", cfg, *args])


def test_projeto_valido_passa_em_tudo(tmp_path, capsys):
    cfg = make_project(tmp_path)
    assert run(cfg, "check", "--strict") == 0
    assert (tmp_path / "dist" / "splunk" / "r.spl").is_file()
    assert (tmp_path / "dist" / "manifest.json").is_file()


def test_lint_pega_erros_de_schema_e_de_condicao(tmp_path, capsys):
    bad = RULE_OK.replace("id: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "id: nao-e-uuid").replace(
        "condition: selection", "condition: selecao_que_nao_existe"
    )
    cfg = make_project(tmp_path, rule_text=bad)
    assert run(cfg, "lint") == 1
    out = capsys.readouterr().out
    assert "UUID" in out
    assert "selecao_que_nao_existe" in out


def test_lint_avisos_so_falham_com_strict(tmp_path):
    sem_fp = RULE_OK.replace("falsepositives: [none]\n", "")
    cfg = make_project(tmp_path, rule_text=sem_fp)
    assert run(cfg, "lint") == 0
    assert run(cfg, "lint", "--strict") == 1


def test_id_duplicado_entre_arquivos(tmp_path):
    cfg = make_project(tmp_path)
    (tmp_path / "rules" / "copia.yml").write_text(RULE_OK, encoding="utf-8")
    assert run(cfg, "lint") == 1


def test_caso_que_falha_derruba_o_comando(tmp_path, capsys):
    wrong = CASES_OK.replace("--ok", "--bad")  # o "negativo" agora dispara a regra
    cfg = make_project(tmp_path, cases_text=wrong)
    assert run(cfg, "test") == 1
    out = capsys.readouterr().out
    assert "✗ neg" in out and "expected: no_match · got: match" in out


def test_regra_sem_casos_falha_quando_exigido(tmp_path, capsys):
    cfg = make_project(tmp_path, cases_text=None)
    assert run(cfg, "test") == 1
    assert "no test cases" in capsys.readouterr().out


def test_exige_positivo_e_negativo(tmp_path, capsys):
    so_positivo = "cases:\n  - {name: pos, expect: match, event: {Image: 'a\\\\tool.exe', CommandLine: '--bad'}}\n"
    cfg = make_project(tmp_path, cases_text=so_positivo)
    assert run(cfg, "test") == 1
    assert "no_match" in capsys.readouterr().out


def test_alvo_desconhecido_retorna_2(tmp_path, capsys):
    cfg = make_project(tmp_path)
    assert run(cfg, "convert", "-t", "inexistente") == 2


def test_cada_alvo_usa_seu_proprio_mapeamento_de_campos(tmp_path, capsys):
    """Guarda contra o pySigma contaminar a regra entre um alvo e o seguinte."""
    cfg = make_project(tmp_path)
    assert run(cfg, "convert", "--stdout") == 0
    out = capsys.readouterr().out
    splunk = out.split("→ splunk")[1].split("# ")[0]
    kql = out.split("→ kql")[1].split("# ")[0]
    eql = out.split("→ elastic-eql")[1].split("# ")[0]
    assert "Image=" in splunk
    assert "FolderPath" in kql and "Image" not in kql
    assert "process.executable" in eql and "FolderPath" not in eql


def test_pipeline_extra_renomeia_campos(tmp_path, capsys):
    (tmp_path / "pipelines").mkdir()
    (tmp_path / "pipelines" / "meu.yml").write_text(
        "name: meu\npriority: 10\ntransformations:\n  - id: renomear\n    type: field_name_mapping\n"
        "    mapping:\n      CommandLine: linha_de_comando\n",
        encoding="utf-8",
    )
    cfg = make_project(tmp_path, extra_cfg="extra_pipelines: [pipelines/meu.yml]\n")
    assert run(cfg, "convert", "--stdout", "-t", "splunk") == 0
    out = capsys.readouterr().out
    assert "linha_de_comando" in out and "CommandLine" not in out


# --------------------------------------------------------------------------- the repository `vitrix init` creates


def test_exemplos_do_repositorio_passam(user_repo):
    cfg = str(user_repo)
    assert run(cfg, "lint", "--strict") == 0
    assert run(cfg, "test") == 0
    assert run(cfg, "convert", "--stdout") == 0


def test_wildcard_matcher_is_linear_and_keeps_sigma_semantics():
    import time

    from vitrix.evaluator import evaluate

    def hit(value, text, mod="", **kw):
        rule = {"detection": {"s": {f"F{mod}": value}, "condition": "s"}}
        return evaluate(rule, {"F": text})

    t0 = time.perf_counter()
    assert hit("*a*a*a*a*ab", "a" * 200, "|contains") is False
    assert time.perf_counter() - t0 < 1
    assert hit("ab", "xxABxx", "|contains") and not hit("ab", "xxABxx", "|contains|cased")
    assert hit(r"C:\Win*\cmd.exe", r"c:\windows\system32\cmd.exe")
    assert hit(r"a\*b", "a*b") and not hit(r"a\*b", "axb")
    assert hit(r"a\?b", "a?b") and not hit(r"a\?b", "axb")
    assert hit("a?c", "abc") and not hit("a?c", "ac")
    assert hit("a*c", "a"+chr(10)+"b"+chr(10)+"c") and hit("*", "") and not hit("a", "")
    assert hit("exe", "cmd.exe", "|endswith") and hit("cmd", "cmd.exe", "|startswith")
    assert hit(r"a\b", r"a\b")  # lone backslash stays literal
