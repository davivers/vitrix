r"""Regex flavors of the SIEM targets: which constructs the evaluator's engine accepts but a target does not.

Sources: Microsoft Learn "Regex syntax - Kusto" (KQL is RE2-class: no lookaround / backreferences, `\A` and
`\z` but no `\Z`); Splunk uses PCRE (almost everything works); Elastic EQL `regex()` / `regex~()` and Lucene
`regexp` use Lucene's own engine ("does not support anchor operators ^ and $; the regex must match the entire
string", elastic.co regexp-syntax docs).
"""

from __future__ import annotations

import re

_ESC = r"(?<!\\)(?:\\\\)*"  # an even number of backslashes before: the next char is not escaped
LOOKAROUND = re.compile(_ESC + r"\(\?<?[=!]")
BACKREF = re.compile(_ESC + r"(?:\\[1-9]|\\k<|\(\?P=)")
ATOMIC = re.compile(_ESC + r"\(\?>")
POSSESSIVE = re.compile(_ESC + r"(?:[*+?]|\{\d+(?:,\d*)?\})\+")
CONDITIONAL = re.compile(_ESC + r"\(\?\(")
LAZY = re.compile(_ESC + r"(?:[*+?]|\{\d+(?:,\d*)?\})\?")
UPPER_Z = re.compile(_ESC + r"\\Z")
ANCHOR = re.compile(_ESC + r"(?:[\^$]|\\[AzZ])")
SHORTHAND = re.compile(_ESC + r"\\[dDwWsS]")
VAR_LOOKBEHIND = re.compile(r"\(\?<[=!][^)]*(?:[*+]|\{\d*,\d*\}|\|)")

TARGET_FLAVORS = {
    "splunk": "PCRE",
    "kql": "RE2 (Kusto)",
    "elastic-eql": "Lucene regexp",
    "elastic-lucene": "Lucene regexp",
}


def flavor_warnings(pattern: str, flags: str, targets: list[str]) -> list[dict]:
    """For each active target, the constructs of `pattern` its regex flavor does not support."""
    out: list[dict] = []
    for target in dict.fromkeys(targets):
        flavor = TARGET_FLAVORS.get(target)
        if flavor is None:
            continue

        def warn(message: str, target: str = target, flavor: str = flavor) -> None:
            out.append({"target": target, "flavor": flavor, "message": message})

        if target == "splunk":
            if VAR_LOOKBEHIND.search(pattern):
                warn("PCRE lookbehind must have a fixed length: quantifiers or alternatives of different lengths inside (?<=...) / (?<!...) fail")
        elif target == "kql":
            if LOOKAROUND.search(pattern):
                warn("RE2 has no lookahead/lookbehind ((?=, (?!, (?<=, (?<!); rewrite without them")
            if BACKREF.search(pattern):
                warn("RE2 has no backreferences (\\1, \\k<name>, (?P=name))")
            if ATOMIC.search(pattern) or POSSESSIVE.search(pattern):
                warn("RE2 has no atomic groups ((?>...)) or possessive quantifiers (a++, a*+)")
            if CONDITIONAL.search(pattern):
                warn("RE2 has no conditional groups ((?(1)...))")
            if UPPER_Z.search(pattern):
                warn("RE2 has no \\Z; use \\z for the end of the text")
            if flags:
                warn("KQL gets the i/m/s flags as inline flags ((?i), (?m), (?s)) in the pattern; check the generated query")
        else:  # Lucene regexp: Elastic EQL regex()/regex~() and Lucene queries
            if LOOKAROUND.search(pattern):
                warn("Lucene regexp has no lookahead/lookbehind")
            if BACKREF.search(pattern):
                warn("Lucene regexp has no backreferences")
            if ATOMIC.search(pattern) or POSSESSIVE.search(pattern) or CONDITIONAL.search(pattern):
                warn("Lucene regexp has no atomic groups, possessive quantifiers or conditionals")
            if LAZY.search(pattern):
                warn("Lucene regexp has no lazy quantifiers (a*?, a+?)")
            if ANCHOR.search(pattern):
                warn("Lucene regexp has no ^, $, \\A or \\z anchors: it always matches the WHOLE value, unlike Sigma's search-anywhere |re")
            elif not (pattern.startswith(".*") and pattern.endswith(".*")):
                warn("Lucene regexp matches the whole value (implicitly anchored): wrap the pattern in .* ... .* to search anywhere as Sigma does")
            if SHORTHAND.search(pattern):
                warn("Lucene regexp does not document \\d, \\w or \\s shorthand classes; use [0-9], [A-Za-z0-9_] or [ \\t\\r\\n]")
            if "i" in flags:
                warn("Lucene regexp is case-sensitive: EQL needs regex~(), Lucene queries need case_insensitive: true")
    return out
