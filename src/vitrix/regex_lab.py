"""Regex Workbench: develop, test and optimise the regular expressions of Sigma rules.

The engine is chosen per request: `python-regex` (default, the evaluator's own engine, so what passes
here passes in test cases and replay), `python-re`, `re2` (Google RE2) or `pcre2`. Each analysis runs in
a separate process with a timeout: a regex with catastrophic backtracking hits the timeout instead of
freezing the server.

    python -m vitrix.regex_lab   (reads JSON from stdin; internal use)
"""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import platform
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

# --------------------------------------------------------------------------- engines
# id -> (display name, importable module, PyPI distribution for the version, notes)
ENGINES: dict[str, dict] = {
    "python-regex": {"name": "Python regex (Vitrix evaluator)", "module": "regex", "dist": "regex",
                     "notes": "The engine the Vitrix evaluator runs |re with: what passes here passes in test cases and replay. "
                              "Backtracking, lookaround, backreferences, atomic groups, possessive quantifiers."},
    "python-re": {"name": "Python re (standard library)", "module": "re", "dist": None,
                  "notes": "Python's built-in re module. Backtracking; no possessive quantifiers or atomic groups before Python 3.11."},
    "re2": {"name": "RE2 (Google)", "module": "re2", "dist": "google-re2",
            "notes": "Linear-time engine used by KQL-class systems. No lookaround, no backreferences, no atomic groups; "
                     "an unsupported construct is reported by RE2 itself as a compile error."},
    "pcre2": {"name": "PCRE2", "module": "pcre2", "dist": "pcre2",
              "notes": "Perl-compatible regular expressions (the flavor Splunk and many tools use). Backtracking with a match limit."},
}
DEFAULT_ENGINE = "python-regex"
FLAG_NAMES = ("i", "m", "s")


def _import(engine: str):  # noqa: ANN202
    import importlib

    return importlib.import_module(ENGINES[engine]["module"])


def _version(engine: str) -> str:
    dist = ENGINES[engine]["dist"]
    if dist is None:
        return platform.python_version()
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def list_engines() -> list[dict]:
    """`GET /api/regex/engines`: every engine with its version and whether it can run here."""
    out = []
    for eid, spec in ENGINES.items():
        try:
            _import(eid)
            available, notes = True, spec["notes"]
        except ImportError:
            available, notes = False, f"{spec['notes']} Not installed: pip install {spec['dist']}"
        out.append({"id": eid, "name": spec["name"], "version": _version(eid) if available else None,
                    "available": available, "notes": notes, "flags_supported": list(FLAG_NAMES)})
    return out


def engine_info(engine: str = DEFAULT_ENGINE, timeout: float = TIMEOUT_S) -> dict:
    return {"id": engine, "name": ENGINES[engine]["name"], "version": _version(engine), "timeout_ms": int(timeout * 1000)}


class _Compiled:
    """Uniform view over the four engines: finditer(text) -> match objects with start/end/group/groups/groupdict."""

    def __init__(self, engine: str, pattern: str, flags: str):
        self.engine = engine
        mod = _import(engine)
        if engine in ("python-regex", "python-re") or engine == "pcre2":
            value = 0
            for f in flags:
                value |= {"i": mod.IGNORECASE, "m": mod.MULTILINE, "s": mod.DOTALL}[f]
            self.rx = mod.compile(pattern, value)
        else:  # re2: i and s are options; multi-line has none, so it goes in as an inline flag
            opts = mod.Options()
            opts.log_errors = False
            opts.case_sensitive = "i" not in flags
            opts.dot_nl = "s" in flags
            self.rx = mod.compile(("(?m)" if "m" in flags else "") + pattern, opts)

    @property
    def groups(self) -> int:
        return self.rx.groups

    @property
    def names(self) -> list[str]:
        return list(self.rx.groupindex)

    def finditer(self, text: str):  # noqa: ANN201
        if self.engine == "python-regex":
            return self.rx.finditer(text, timeout=TIMEOUT_S / 2)
        return self.rx.finditer(text)


def _error(engine: str, exc: Exception) -> dict:
    """Compile error as the engine itself words it, with the position when the engine gives one."""
    msg = exc.args[0] if exc.args else str(exc)
    if isinstance(msg, bytes):
        msg = msg.decode("utf-8", "replace")
    msg = str(msg)
    pos = getattr(exc, "pos", None)
    if pos is None:
        found = re.search(r"position (\d+)", msg)
        pos = int(found.group(1)) if found else None
    return {"ok": False, "error": msg, "position": pos}


def _run(pattern: str, flags: str, samples: list[str], engine: str = DEFAULT_ENGINE) -> dict:
    """Run in the current process (called by the subprocess)."""
    try:
        compiled = _Compiled(engine, pattern, flags)
    except ImportError:
        return {"ok": False, "error": f"{ENGINES[engine]['name']} is not installed: pip install {ENGINES[engine]['dist']}"}
    except Exception as exc:  # each engine has its own error class  # noqa: BLE001
        return _error(engine, exc)
    results = []
    for s in samples:
        t0 = time.perf_counter()
        matches = []
        try:
            for m in compiled.finditer(s):
                matches.append({"start": m.start(), "end": m.end(), "text": m.group(0)[:500],
                                "groups": [g if g is None else g[:200] for g in m.groups()],
                                "named": {k: (v if v is None else v[:200]) for k, v in m.groupdict().items()}})
                if len(matches) >= 100:
                    break
        except TimeoutError:
            return {"ok": False, "timeout": True, "error": "the run timed out: catastrophic backtracking is likely"}
        except Exception as exc:  # PCRE2 match limit / engine failures at match time  # noqa: BLE001
            text = str(exc)
            if "limit" in text:
                return {"ok": False, "timeout": True, "error": f"the engine gave up ({text}): catastrophic backtracking is likely"}
            return {"ok": False, "error": text}
        results.append({"matched": bool(matches), "matches": matches, "duration_ms": round((time.perf_counter() - t0) * 1000, 3)})
    return {"ok": True, "groups": compiled.groups, "names": compiled.names, "results": results}


def analyze(pattern: str, flags: str = "", samples: list[str] | None = None, timeout: float = TIMEOUT_S,
            engine: str = DEFAULT_ENGINE) -> dict:
    """Compile and run on the samples with the chosen engine (in a subprocess, with a timeout); add optimisation tips.

    The response carries `engine`: {id, name, version, timeout_ms}."""
    samples = list(samples or [])
    if engine not in ENGINES:
        raise RegexLabError(f"unknown engine {engine!r} (use one of: {', '.join(ENGINES)})")
    if len(pattern) > MAX_PATTERN_LEN:
        raise RegexLabError(f"regex longer than {MAX_PATTERN_LEN} characters")
    if len(samples) > MAX_SAMPLES:
        raise RegexLabError(f"at most {MAX_SAMPLES} samples")
    if any(len(s) > MAX_SAMPLE_LEN for s in samples):
        raise RegexLabError(f"sample longer than {MAX_SAMPLE_LEN} characters")
    bad = set(flags) - set(FLAG_NAMES)
    if bad:
        raise RegexLabError(f"unknown flag: {''.join(sorted(bad))} (use i, m, s)")
    try:
        _import(engine)
    except ImportError:
        raise RegexLabError(f"{ENGINES[engine]['name']} is not installed here: pip install {ENGINES[engine]['dist']}") from None

    tips = lint_pattern(pattern)
    extra = {"engine": engine_info(engine, timeout)}
    started = time.perf_counter()
    if not _SLOTS.acquire(timeout=timeout):
        raise RegexLabError("too many runs at the same time; try again")
    try:
        # Fixed arguments (Python itself, isolated mode -I); the regex and samples go through
        # stdin as JSON, never through the command line or a shell.
        proc = subprocess.run(  # nosec B603
            [sys.executable, "-I", "-m", "vitrix.regex_lab"],
            input=json.dumps({"pattern": pattern, "flags": flags, "samples": samples, "engine": engine}),
            capture_output=True, text=True, encoding="utf-8", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "timeout": True, "error": f"the run took more than {timeout:g} s: catastrophic backtracking is likely",
                "tips": tips, "sigma": None, **extra}
    finally:
        _SLOTS.release()
    if proc.returncode != 0:
        raise RegexLabError(f"failed to run the regex: {proc.stderr.strip()[-300:]}")
    out = json.loads(proc.stdout)
    out["tips"] = tips
    out.update(extra)
    out.setdefault("timeout", False)
    out["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
    mods = "".join(f"|{f}" for f in sorted(flags))
    out["sigma"] = f"Field|re{mods}: '{pattern.replace(chr(39), chr(39) * 2)}'" if out.get("ok") else None
    return out


if __name__ == "__main__":
    req = json.loads(sys.stdin.read())
    sys.stdout.write(json.dumps(_run(req["pattern"], req["flags"], req["samples"], req.get("engine", DEFAULT_ENGINE))))
