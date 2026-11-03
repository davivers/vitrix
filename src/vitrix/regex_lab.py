"""Regex Workbench: develop, test and optimise the regular expressions of Sigma rules.

Uses the same engine as the local evaluator (Python's `re`), so what passes here passes in
the test cases. Each analysis runs in a separate process with a timeout: a regex with
catastrophic backtracking hits the timeout instead of freezing the server.

    python -m vitrix.regex_lab   (reads JSON from stdin; internal use)
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
_SLOTS = threading.BoundedSemaphore(2)  # at most 2 regex processes at the same time
MAX_SAMPLES = 50
MAX_SAMPLE_LEN = 20_000
MAX_PATTERN_LEN = 2_000
FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
# \W, \S, \D, \B... right after something that looks like a Windows path: the backslash was
# probably meant literally (C:\Windows becomes C: + "non-word" + indows).
WINDOWS_PATH_ESCAPE = re.compile(r"[A-Za-z]:\\(?=[A-Za-z])|\\(?:Windows|System32|Users|Program|AppData|Temp)\b", re.IGNORECASE)


class RegexLabError(Exception):
    pass


def lint_pattern(pattern: str) -> list[dict]:
    """Performance warnings and common pitfalls. Does not run the regex."""
    tips: list[dict] = []

    def tip(severity: str, message: str) -> None:
        tips.append({"severity": severity, "message": message})

    if NESTED_QUANTIFIER.search(pattern):
        tip("error", "nested quantifier such as (a+)+: catastrophic backtracking; rewrite it without repeating the group")
    if re.search(r"(\.\*){2,}|\.\*\.\*", pattern):
        tip("warning", "repeated .*: each one multiplies backtracking; one is enough")
    if pattern.startswith(".*") or pattern.endswith(".*"):
        tip("info", "Sigma's |re modifier already searches anywhere: a leading or trailing .* is unnecessary")
    if re.search(r"\((?!\?)[^()]*\|[^()]*\)", pattern) and not re.search(r"\(\?:", pattern):
        tip("info", "capturing group: if you do not need the value, use (?:...) which is lighter")
    if WINDOWS_PATH_ESCAPE.search(pattern):
        tip("warning", "unescaped Windows path backslash: in regex \\W, \\S, \\U... are classes; write \\\\ for the backslash")
    literal = re.fullmatch(r"(\.\*)?((?:[^\\.*+?()\[\]{}|^$]|\\[\\.])+)(\.\*)?", pattern)
    if literal:
        tip("info", "regex without metacharacters: Field|contains (or startswith/endswith) is faster and portable across SIEMs")
    if len(pattern) > 300:
        tip("warning", f"long regex ({len(pattern)} characters): hard to review and expensive in the SIEM")
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
    """Compile, run on the samples (in a subprocess, with a timeout) and give optimisation tips."""
    samples = list(samples or [])
    if len(pattern) > MAX_PATTERN_LEN:
        raise RegexLabError(f"regex longer than {MAX_PATTERN_LEN} characters")
    if len(samples) > MAX_SAMPLES:
        raise RegexLabError(f"at most {MAX_SAMPLES} samples")
    if any(len(s) > MAX_SAMPLE_LEN for s in samples):
        raise RegexLabError(f"sample longer than {MAX_SAMPLE_LEN} characters")
    bad = set(flags) - set(FLAGS)
    if bad:
        raise RegexLabError(f"unknown flag: {''.join(sorted(bad))} (use i, m, s)")

    tips = lint_pattern(pattern)
    started = time.perf_counter()
    if not _SLOTS.acquire(timeout=timeout):
        raise RegexLabError("too many runs at the same time; try again")
    try:
        # Fixed arguments (Python itself, isolated mode -I); the regex and samples go through
        # stdin as JSON, never through the command line or a shell.
        proc = subprocess.run(  # nosec B603
            [sys.executable, "-I", "-m", "vitrix.regex_lab"],
            input=json.dumps({"pattern": pattern, "flags": flags, "samples": samples}),
            capture_output=True, text=True, encoding="utf-8", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "timeout": True, "error": f"the run took more than {timeout:g} s: catastrophic backtracking is likely",
                "tips": tips, "sigma": None}
    finally:
        _SLOTS.release()
    if proc.returncode != 0:
        raise RegexLabError(f"failed to run the regex: {proc.stderr.strip()[-300:]}")
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
