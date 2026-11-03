"""Local evaluator for Sigma rules (a subset).

Runs a rule's detection logic against an event (a dict) without a SIEM. Events use the
field names of the Sigma rule itself (Image, CommandLine, ...), before any per-SIEM field
mapping.

Supported
- map selections, lists of maps (OR) and keyword lists
- modificadores: contains, startswith, endswith, all, re (+ i, m, s), cased, exists
- wildcards * and ? in values (escape with \\* and \\?)
- conditions with and / or / not, parentheses, "1 of x*", "all of x*", "1 of them", "all of them"

Not supported (raises UnsupportedError, never passes silently)
- modifiers such as windash, base64, cidr, lt/gt, fieldref
- aggregation conditions (count, near) and correlation rules
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any


class UnsupportedError(Exception):
    """The rule uses something the local evaluator cannot run yet."""


SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cased", "exists"}
_KEYWORDS = {"and", "or", "not", "of", "them", "1", "all"}


# --------------------------------------------------------------------------- campos


def _get(event: dict, field: str) -> tuple[bool, Any]:
    if field in event:
        return True, event[field]
    low = field.lower()
    for key, value in event.items():
        if str(key).lower() == low:
            return True, value
    return False, None


def _to_regex(value: str) -> str:
    """Turn a Sigma value (with wildcards) into a regex. Only \\* and \\? are escapes."""
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def _match_value(actual: Any, expected: Any, mods: set[str]) -> bool:
    if actual is None or expected is None:
        return actual is None and expected is None

    if "re" in mods:
        flags = 0
        if "i" in mods:
            flags |= re.IGNORECASE
        if "m" in mods:
            flags |= re.MULTILINE
        if "s" in mods:
            flags |= re.DOTALL
        return re.search(str(expected), str(actual), flags) is not None

    pattern = _to_regex(str(expected))
    if "contains" in mods:
        pattern = f".*{pattern}.*"
    elif "startswith" in mods:
        pattern = f"{pattern}.*"
    elif "endswith" in mods:
        pattern = f".*{pattern}"
    flags = re.DOTALL | (0 if "cased" in mods else re.IGNORECASE)
    return re.fullmatch(pattern, str(actual), flags) is not None


def _match_field(event: dict, spec: str, expected: Any) -> bool:
    field, *mods_list = spec.split("|")
    mods = set(mods_list)
    unknown = mods - SUPPORTED_MODIFIERS
    if unknown:
        raise UnsupportedError(f"unsupported modifier: {', '.join(sorted(unknown))} (field {field})")

    present, actual = _get(event, field)
    if "exists" in mods:
        return present == bool(expected)

    values = expected if isinstance(expected, list) else [expected]
    actuals = actual if isinstance(actual, list) else [actual]

    def one(value: Any) -> bool:
        return any(_match_value(a, value, mods) for a in actuals)

    results = [one(v) for v in values]
    return all(results) if "all" in mods else any(results)


def _keyword(event: dict, keyword: str) -> bool:
    return any(_match_value(str(v), keyword, {"contains"}) for v in event.values() if v is not None)


def _eval_selection(selection: Any, event: dict) -> bool:
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        if selection and all(isinstance(x, dict) for x in selection):
            return any(_eval_selection(x, event) for x in selection)
        return any(_keyword(event, str(x)) for x in selection)
    raise UnsupportedError(f"unsupported selection format: {type(selection).__name__}")


# --------------------------------------------------------------------------- condition


def tokenize(condition: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", condition)


def condition_refs(condition: str) -> tuple[set[str], set[str]]:
    """Selection names and patterns ('x*', 'them') referenced by a condition."""
    tokens = tokenize(condition)
    names: set[str] = set()
    patterns: set[str] = set()
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        low = tok.lower()
        if low in ("1", "all") and i + 2 < len(tokens) + 0 and tokens[i + 1].lower() == "of":
            patterns.add(tokens[i + 2])
            i += 3
            continue
        if low not in _KEYWORDS and tok not in "()":
            names.add(tok)
        i += 1
    return names, patterns


class _Parser:
    def __init__(self, condition: str, results: dict[str, bool]):
        if "|" in condition:
            raise UnsupportedError("aggregation conditions (count, near) are not supported")
        self.tokens = tokenize(condition)
        self.results = results
        self.pos = 0

    def parse(self) -> bool:
        value = self._or()
        if self.pos != len(self.tokens):
            raise UnsupportedError(f"invalid condition near {self.tokens[self.pos]!r}")
        return value

    def _peek(self) -> str | None:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        if self.pos >= len(self.tokens):
            raise UnsupportedError("condition ended unexpectedly")
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _or(self) -> bool:
        value = self._and()
        while self._peek() == "or":
            self._next()
            rhs = self._and()
            value = value or rhs
        return value

    def _and(self) -> bool:
        value = self._not()
        while self._peek() == "and":
            self._next()
            rhs = self._not()
            value = value and rhs
        return value

    def _not(self) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        tok = self._next()
        if tok == "(":
            value = self._or()
            if self._next() != ")":
                raise UnsupportedError("unclosed parenthesis in the condition")
            return value
        low = tok.lower()
        if low in ("1", "all") and self._peek() == "of":
            self._next()
            target = self._next()
            names = (
                list(self.results)
                if target.lower() == "them"
                else [n for n in self.results if fnmatch.fnmatchcase(n, target)]
            )
            if not names:
                return False
            vals = [self.results[n] for n in names]
            return all(vals) if low == "all" else any(vals)
        if tok not in self.results:
            raise UnsupportedError(f"the condition references '{tok}', which does not exist in detection")
        return self.results[tok]


# --------------------------------------------------------------------------- API


def _selections(doc: dict) -> dict[str, Any]:
    detection = doc.get("detection") or {}
    return {k: v for k, v in detection.items() if k not in ("condition", "timeframe")}


def check_supported(doc: dict) -> None:
    """Raise UnsupportedError if the rule uses anything outside the supported subset."""
    if "correlation" in doc:
        raise UnsupportedError("correlation rules are not supported")

    def walk(sel: Any) -> None:
        if isinstance(sel, dict):
            for spec in sel:
                mods = set(str(spec).split("|")[1:])
                unknown = mods - SUPPORTED_MODIFIERS
                if unknown:
                    raise UnsupportedError(f"unsupported modifier: {', '.join(sorted(unknown))}")
        elif isinstance(sel, list):
            for item in sel:
                walk(item)

    for sel in _selections(doc).values():
        walk(sel)
    cond = (doc.get("detection") or {}).get("condition")
    for c in cond if isinstance(cond, list) else [cond]:
        if isinstance(c, str) and "|" in c:
            raise UnsupportedError("aggregation conditions (count, near) are not supported")


def exclusion_selections(doc: dict) -> set[str]:
    """Exclusion selections: those negated in the condition (`not filter`, `not 1 of filter*`)
    and, by Sigma convention, those whose name starts with `filter`."""
    names = set(_selections(doc))
    found = {n for n in names if n.lower().startswith("filter")}
    cond = (doc.get("detection") or {}).get("condition")
    for c in cond if isinstance(cond, list) else [cond]:
        tokens = tokenize(str(c)) if c is not None else []
        for i, tok in enumerate(tokens[:-1]):
            if tok.lower() != "not":
                continue
            nxt = tokens[i + 1]
            if nxt.lower() in ("1", "all") and i + 3 < len(tokens) and tokens[i + 2].lower() == "of":
                pattern = tokens[i + 3]
                found |= names if pattern.lower() == "them" else {n for n in names if fnmatch.fnmatchcase(n, pattern)}
            elif nxt in names:
                found.add(nxt)
    return found


def evaluate(doc: dict, event: dict, force_false: set[str] | None = None) -> bool:
    """True if the event fires the rule. `force_false` turns selections off (used to prove exclusions)."""
    check_supported(doc)
    detection = doc.get("detection") or {}
    condition = detection.get("condition")
    if condition is None:
        raise UnsupportedError("the rule has no condition")
    results = {name: (False if force_false and name in force_false else _eval_selection(sel, event)) for name, sel in _selections(doc).items()}
    conditions = condition if isinstance(condition, list) else [condition]
    return any(_Parser(str(c), results).parse() for c in conditions)
