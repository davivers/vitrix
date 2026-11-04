"""Regex Workbench: mesma engine do avaliador, tempo limite e dicas de otimização."""

from __future__ import annotations

import pytest

from vitrix.regex_lab import RegexLabError, analyze, lint_pattern

BS = chr(92)


def test_casa_e_devolve_grupos_e_trecho():
    out = analyze(r"-(enc|EncodedCommand)\s+(?P<payload>\S+)", "i", ["powershell -ENC SQBFAFgA", "powershell -File a.ps1"])
    assert out["ok"] is True and out["timeout"] is False
    first, second = out["results"]
    assert first["matched"] is True and second["matched"] is False
    m = first["matches"][0]
    assert m["groups"][0] == "ENC" and m["named"] == {"payload": "SQBFAFgA"}
    assert out["names"] == ["payload"]
    assert out["sigma"] == r"Field|re|i: '-(enc|EncodedCommand)\s+(?P<payload>\S+)'"


def test_regex_invalida_aponta_posicao():
    out = analyze("abc(", "", ["x"])
    assert out["ok"] is False and out["position"] in (3, 4)  # `regex` reports the end of the pattern


def test_backtracking_catastrofico_estoura_o_tempo_sem_travar():
    out = analyze("(a|aa)+$", "", ["a" * 60 + "!"], timeout=1.0)
    assert out["timeout"] is True and out["ok"] is False
    assert out["engine"]["name"].startswith("Python regex")
    assert any("nested" in t["message"] for t in lint_pattern("(a+)+$"))


def test_dicas_de_otimizacao():
    msgs = [t["message"] for t in lint_pattern(".*mimikatz.*")]
    assert any("unnecessary" in m for m in msgs)
    assert any("contains" in m for m in msgs)
    msgs = [t["message"] for t in lint_pattern(f"C:{BS}Windows{BS}System32{BS}cmd{BS}.exe")]
    assert any("Windows path" in m for m in msgs)
    assert lint_pattern(r"^(?:cmd|powershell)\.exe$") == []


@pytest.mark.parametrize("args", [("a", "x", []), ("a" * 3000, "", []), ("a", "", ["x"] * 51), ("a", "", ["x" * 30000])])
def test_limites(args):
    with pytest.raises(RegexLabError):
        analyze(*args)


def test_api_regex(monkeypatch):
    monkeypatch.setenv("VITRIX_AUTH", "off")
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    client = TestClient(create_app())
    body = client.post("/api/regex", json={"pattern": "cmd", "flags": "i", "samples": ["CMD.EXE"]}).json()
    assert body["results"][0]["matched"] is True
    assert client.post("/api/regex", json={"pattern": "a", "flags": "q"}).status_code == 422


# ---- U6: same engine as the evaluator + target flavor warnings -----------------------------


def test_engine_is_the_evaluators_regex_package():
    import regex

    out = analyze("abc", "", ["abc"])
    assert out["engine"] == {"name": "Python regex (Vitrix evaluator)", "version": regex.__version__, "timeout_ms": 2000}
    # regex-only syntax (possessive quantifier / atomic group) compiles here exactly as in the evaluator
    assert analyze("a++b", "", ["aaab"])["results"][0]["matched"] is True
    assert analyze(r"\p{Lu}+", "", ["ABc"])["results"][0]["matches"][0]["text"] == "AB"


def _warn(pattern, targets, flags=""):
    return analyze(pattern, flags, ["x"], targets=targets)["flavor_warnings"]


def test_flavor_warnings_per_target():
    w = _warn(r"(?<=a)b(?!c)(\w)\1", ["splunk", "kql", "elastic-eql"])
    assert not [x for x in w if x["target"] == "splunk"]
    kql = [x for x in w if x["target"] == "kql"]
    assert {x["flavor"] for x in kql} == {"RE2 (Kusto)"}
    assert any("lookahead" in x["message"] for x in kql) and any("backreferences" in x["message"] for x in kql)
    assert any(x["target"] == "elastic-eql" and "lookahead" in x["message"] for x in w)
    assert any("atomic" in x["message"] for x in _warn("(?>a+)b", ["kql"]))
    assert any("possessive" in x["message"] for x in _warn("a++b", ["kql"]))
    assert any(r"\Z" in x["message"] for x in _warn(r"abc\Z", ["kql"]))
    assert any("fixed length" in x["message"] for x in _warn(r"(?<=a+)b", ["splunk"]))


def test_flavor_warnings_clean_and_lucene_semantics():
    assert _warn(r"^(?:cmd|powershell)\.exe$", ["splunk", "kql"]) == []
    assert _warn("abc", []) == []
    lucene = _warn(r"^cmd\d+$", ["elastic-lucene"])
    assert any("anchors" in x["message"] for x in lucene) and any("shorthand" in x["message"] for x in lucene)
    assert any("implicitly anchored" in x["message"] for x in _warn("cmd", ["elastic-eql"]))
    assert not any("implicitly" in x["message"] for x in _warn(".*cmd.*", ["elastic-eql"]))
    assert _warn("a", ["nosuchtarget"]) == []
    assert _warn(r"C:\\1", ["kql"]) == []  # an escaped backslash followed by 1 is not a backreference
    assert any("backreferences" in x["message"] for x in _warn(r"(a)\1", ["kql"]))


def test_regex_endpoint_defaults_to_configured_targets(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from test_engine import make_project

    from vitrix.api import create_app

    cfg_path = make_project(tmp_path)
    monkeypatch.setenv("VITRIX_AUTH", "off")
    client = TestClient(create_app(cfg_path))
    body = client.post("/api/regex", json={"pattern": "(?=a)a", "samples": ["a"]}).json()
    assert body["engine"]["name"].startswith("Python regex")
    assert {x["target"] for x in body["flavor_warnings"]} >= {"kql"}
    only = client.post("/api/regex", json={"pattern": "(?=a)a", "targets": ["splunk"]}).json()
    assert only["flavor_warnings"] == []
