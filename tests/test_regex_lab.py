"""Regex Workbench: mesma engine do avaliador, tempo limite e dicas de otimização."""

from __future__ import annotations

import pytest

from vitrix.regex_lab import RegexLabError, analyze, lint_pattern, list_engines

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



# ---- U6: choose the regex engine -------------------------------------------------------------

ENGINE_IDS = ["python-regex", "python-re", "re2", "pcre2"]


def test_engine_list_has_versions_and_notes():
    import regex

    engines = {e["id"]: e for e in list_engines()}
    assert list(engines) == ENGINE_IDS
    assert engines["python-regex"]["version"] == regex.__version__ and engines["python-regex"]["name"] == "Python regex (Vitrix evaluator)"
    for e in engines.values():
        assert set(e) == {"id", "name", "version", "available", "notes", "flags_supported"}
        assert e["available"] is True and e["version"] and e["notes"] and e["flags_supported"] == ["i", "m", "s"]


def test_default_engine_is_the_evaluators():
    out = analyze("abc", "", ["abc"])
    assert out["engine"]["id"] == "python-regex" and out["engine"]["name"] == "Python regex (Vitrix evaluator)"
    assert out["engine"]["timeout_ms"] == 2000 and out["engine"]["version"]
    assert "flavor_warnings" not in out
    assert analyze("a++b", "", ["aaab"])["results"][0]["matched"] is True  # regex-only syntax, as in the evaluator


@pytest.mark.parametrize("engine", ENGINE_IDS)
def test_every_engine_matches_groups_and_flags(engine):
    out = analyze(r"-(enc|x)\s+(?P<payload>\S+)", "i", ["powershell -ENC SQBF", "powershell -File"], engine=engine)
    assert out["ok"] is True and out["engine"]["id"] == engine
    first, second = out["results"]
    assert first["matched"] is True and second["matched"] is False
    m = first["matches"][0]
    assert (m["start"], m["end"], m["text"]) == (11, 20, "-ENC SQBF")
    assert m["groups"] == ["ENC", "SQBF"] and m["named"] == {"payload": "SQBF"}
    assert out["names"] == ["payload"] and out["groups"] == 2
    ml = analyze("^b$", "m", ["a\nb\nc"], engine=engine)
    assert ml["results"][0]["matched"] is True
    dot = analyze("a.b", "s", ["a\nb"], engine=engine)
    assert dot["results"][0]["matched"] is True
    assert analyze("a.b", "", ["a\nb"], engine=engine)["results"][0]["matched"] is False


@pytest.mark.parametrize("engine", ENGINE_IDS)
def test_invalid_regex_is_the_engines_own_error(engine):
    out = analyze("abc(", "", ["x"], engine=engine)
    assert out["ok"] is False and out["error"] and out["engine"]["id"] == engine
    if engine != "re2":  # RE2 reports no position
        assert isinstance(out["position"], int)


def test_re2_rejects_lookaround_and_backreferences_with_its_own_message():
    look = analyze("(?<=a)b", "", ["ab"], engine="re2")
    assert look["ok"] is False and "invalid perl operator" in look["error"]
    back = analyze(r"(a)\1", "", ["aa"], engine="re2")
    assert back["ok"] is False and "invalid escape sequence" in back["error"]
    # the backtracking engines accept both
    for engine in ("python-regex", "python-re", "pcre2"):
        assert analyze("(?<=a)b", "", ["ab"], engine=engine)["results"][0]["matched"] is True
        assert analyze(r"(a)\1", "", ["aa"], engine=engine)["results"][0]["matched"] is True


@pytest.mark.parametrize("engine", ["python-regex", "python-re", "pcre2"])
def test_catastrophic_backtracking_times_out_per_engine(engine):
    out = analyze("(a|aa)+$", "", ["a" * 60 + "!"], timeout=1.0, engine=engine)
    assert out["timeout"] is True and out["ok"] is False and out["engine"]["id"] == engine


def test_re2_is_linear_on_the_same_pattern():
    out = analyze("(a|aa)+$", "", ["a" * 5000 + "!"], timeout=5.0, engine="re2")
    assert out["ok"] is True and out["timeout"] is False and out["results"][0]["matched"] is False


def test_unknown_engine_and_unknown_flag_are_rejected():
    with pytest.raises(RegexLabError):
        analyze("a", "", [], engine="perl5")
    with pytest.raises(RegexLabError):
        analyze("a", "x", [], engine="re2")


def test_engines_endpoint_and_engine_parameter(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from test_engine import make_project

    from vitrix.api import create_app

    monkeypatch.setenv("VITRIX_AUTH", "off")
    client = TestClient(create_app(make_project(tmp_path)))
    engines = client.get("/api/regex/engines").json()
    assert [e["id"] for e in engines] == ENGINE_IDS and all(e["available"] for e in engines)
    body = client.post("/api/regex", json={"pattern": "(?=a)a", "samples": ["a"], "engine": "re2"}).json()
    assert body["ok"] is False and body["engine"]["id"] == "re2"
    assert client.post("/api/regex", json={"pattern": "a", "engine": "nope"}).status_code == 422
    assert client.post("/api/regex", json={"pattern": "a", "samples": ["a"]}).json()["engine"]["id"] == "python-regex"
