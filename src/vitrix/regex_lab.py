"""Regex Workbench: desenvolver, testar e otimizar expressões regulares de regras Sigma.

Usa o mesmo motor do avaliador local (`re` do Python), então o que passa aqui passa nos
casos de teste. Cada análise roda num processo separado com tempo limite: uma regex com
backtracking catastrófico estoura o tempo em vez de travar o servidor.

    python -m vitrix.regex_lab   (lê JSON da entrada padrão; uso interno)
"""

from __future__ import annotations

import json
import re
import subprocess  # nosec B404
import sys
import threading
import time

from .lint import NESTED_QUANTIFIER

TIMEOUT_S = 2.0
_SLOTS = threading.BoundedSemaphore(2)  # no máximo 2 processos de regex ao mesmo tempo
MAX_SAMPLES = 50
MAX_SAMPLE_LEN = 20_000
MAX_PATTERN_LEN = 2_000
FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
# \W, \S, \D, \B... logo depois de algo que parece caminho do Windows: provavelmente a barra
# era literal (C:\Windows vira C: + "não-palavra" + indows).
WINDOWS_PATH_ESCAPE = re.compile(r"[A-Za-z]:\\(?=[A-Za-z])|\\(?:Windows|System32|Users|Program|AppData|Temp)\b", re.IGNORECASE)


class RegexLabError(Exception):
    pass


def lint_pattern(pattern: str) -> list[dict]:
    """Avisos de desempenho e de armadilhas comuns. Não executa a regex."""
    tips: list[dict] = []

    def tip(severity: str, message: str) -> None:
        tips.append({"severity": severity, "message": message})

    if NESTED_QUANTIFIER.search(pattern):
        tip("error", "quantificador aninhado como (a+)+: backtracking catastrófico; reescreva sem repetir o grupo")
    if re.search(r"(\.\*){2,}|\.\*\.\*", pattern):
        tip("warning", ".* repetido: cada um multiplica o backtracking; um só basta")
    if pattern.startswith(".*") or pattern.endswith(".*"):
        tip("info", "o modificador |re do Sigma já procura em qualquer posição: .* no início ou no fim é desnecessário")
    if re.search(r"\((?!\?)[^()]*\|[^()]*\)", pattern) and not re.search(r"\(\?:", pattern):
        tip("info", "grupo com captura: se não precisa do valor, use (?:...) que é mais leve")
    if WINDOWS_PATH_ESCAPE.search(pattern):
        tip("warning", "barra invertida de caminho do Windows sem escape: em regex, \\W, \\S, \\U... são classes; escreva \\\\ para a barra")
    literal = re.fullmatch(r"(\.\*)?((?:[^\\.*+?()\[\]{}|^$]|\\[\\.])+)(\.\*)?", pattern)
    if literal:
        tip("info", "regex sem metacaracteres: Field|contains (ou startswith/endswith) é mais rápido e portável entre SIEMs")
    if len(pattern) > 300:
        tip("warning", f"regex longa ({len(pattern)} caracteres): difícil de revisar e cara no SIEM")
    return tips


def _run(pattern: str, flags: str, samples: list[str]) -> dict:
    """Executa no processo atual. Chamado pelo subprocesso."""
    value = 0
    for f in flags:
        value |= FLAGS[f]
    try:
        rx = re.compile(pattern, value)
    except re.error as exc:
        return {"ok": False, "error": str(exc), "position": exc.pos}
    results = []
    for s in samples:
        t0 = time.perf_counter()
        matches = []
        for m in rx.finditer(s):
            matches.append({"start": m.start(), "end": m.end(), "text": m.group(0)[:500],
                            "groups": [g if g is None else g[:200] for g in m.groups()],
                            "named": {k: (v if v is None else v[:200]) for k, v in m.groupdict().items()}})
            if len(matches) >= 100:
                break
        results.append({"matched": bool(matches), "matches": matches, "duration_ms": round((time.perf_counter() - t0) * 1000, 3)})
    return {"ok": True, "groups": rx.groups, "names": list(rx.groupindex), "results": results}


def analyze(pattern: str, flags: str = "", samples: list[str] | None = None, timeout: float = TIMEOUT_S) -> dict:
    """Compila, roda nas amostras (em subprocesso, com tempo limite) e dá dicas de otimização."""
    samples = list(samples or [])
    if len(pattern) > MAX_PATTERN_LEN:
        raise RegexLabError(f"regex com mais de {MAX_PATTERN_LEN} caracteres")
    if len(samples) > MAX_SAMPLES:
        raise RegexLabError(f"no máximo {MAX_SAMPLES} amostras")
    if any(len(s) > MAX_SAMPLE_LEN for s in samples):
        raise RegexLabError(f"amostra com mais de {MAX_SAMPLE_LEN} caracteres")
    bad = set(flags) - set(FLAGS)
    if bad:
        raise RegexLabError(f"flag desconhecida: {''.join(sorted(bad))} (use i, m, s)")

    tips = lint_pattern(pattern)
    started = time.perf_counter()
    if not _SLOTS.acquire(timeout=timeout):
        raise RegexLabError("muitas execuções ao mesmo tempo; tente de novo")
    try:
        # Argumentos fixos (o próprio Python, modo isolado -I); a regex e as amostras vão pela
        # entrada padrão como JSON, nunca pela linha de comando nem por shell.
        proc = subprocess.run(  # nosec B603
            [sys.executable, "-I", "-m", "vitrix.regex_lab"],
            input=json.dumps({"pattern": pattern, "flags": flags, "samples": samples}),
            capture_output=True, text=True, encoding="utf-8", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "timeout": True, "error": f"a execução passou de {timeout:g} s: backtracking catastrófico provável",
                "tips": tips, "sigma": None}
    finally:
        _SLOTS.release()
    if proc.returncode != 0:
        raise RegexLabError(f"falha ao executar a regex: {proc.stderr.strip()[-300:]}")
    out = json.loads(proc.stdout)
    out["tips"] = tips
    out["timeout"] = False
    out["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
    mods = "".join(f"|{f}" for f in sorted(flags))
    out["sigma"] = f"Field|re{mods}: '{pattern.replace(chr(39), chr(39) * 2)}'" if out.get("ok") else None
    return out


if __name__ == "__main__":
    req = json.loads(sys.stdin.read())
    sys.stdout.write(json.dumps(_run(req["pattern"], req["flags"], req["samples"])))
