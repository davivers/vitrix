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
    assert out["ok"] is False and out["position"] == 3


def test_backtracking_catastrofico_estoura_o_tempo_sem_travar():
    out = analyze("(a+)+$", "", ["a" * 40 + "!"], timeout=1.0)
    assert out["timeout"] is True and out["ok"] is False
    assert any("nested" in t["message"] for t in out["tips"])


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


def test_api_regex():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from vitrix.api import create_app

    client = TestClient(create_app())
    body = client.post("/api/regex", json={"pattern": "cmd", "flags": "i", "samples": ["CMD.EXE"]}).json()
    assert body["results"][0]["matched"] is True
    assert client.post("/api/regex", json={"pattern": "a", "flags": "q"}).status_code == 422
