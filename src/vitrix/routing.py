"""Final query language of each rule: which target(s) it is converted to.

Decision order, from the most specific to the most general:

1. `vitrix.target` inside the rule itself (string or list)                      source `rule`
2. mappings.yml `final_language.folders` (most specific matching pattern wins)   source `folder`
3. mappings.yml `final_language.default`                                         source `workspace`
4. legacy vitrix.yml: the first `routes` match, then `default_target`           source `legacy-config`
5. every active `targets` entry in vitrix.yml                                    source `all`

`sigma` is a pseudo-target: "keep the rule as Sigma, no conversion". Choosing it is the same as choosing a language.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from .config import Config
from .loader import RuleFile
from .mapping_names import valid_table

KEY = "vitrix"
RULE_KEYS = {"target", "owner", "review_by", "suppressions", "kql_table"}  # governance keys: see governance.py


@dataclass(frozen=True)
class Resolved:
    targets: list[str]
    source: str  # "rule" | "folder" | "workspace" | "legacy-config" | "all" | "override"
    folder: str | None = None  # the matching pattern when source == "folder"


def first_detection(docs: list) -> object:
    return next((d for d in docs if isinstance(d, dict) and "detection" in d), docs[0] if docs else None)


def declared(doc: object) -> list[str] | None:
    """Targets chosen in the rule, or None if it chose none (or the field is invalid)."""
    if not isinstance(doc, dict):
        return None
    block = doc.get(KEY)
    if not isinstance(block, dict):
        return None
    value = block.get("target")
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, list) and value and all(isinstance(v, str) and v.strip() for v in value):
        return [v.strip() for v in value]
    return None


def problems(doc: object) -> list[str]:
    """Format errors of the rule's `vitrix` block (used by the lint)."""
    if not isinstance(doc, dict) or KEY not in doc:
        return []
    block = doc[KEY]
    if not isinstance(block, dict):
        return [f"'{KEY}' must be a mapping (e.g. {KEY}: {{target: splunk}})"]
    out = [f"unknown key in '{KEY}': {k}" for k in block if k not in RULE_KEYS]
    if "target" in block and declared(doc) is None:
        out.append(f"'{KEY}.target' must be a target name or a non-empty list of names")
    table = block.get("kql_table")
    if "kql_table" in block and not valid_table(table):
        out.append(f"'{KEY}.kql_table' must be a table name such as Event or SecurityEvent")
    return out


def resolve(cfg: Config, rule_rel: str | None, doc: object, override: list[str] | None = None) -> Resolved:
    """Decide the targets of a rule. `rule_rel` is the path inside rules/ (None: unsaved rule)."""
    if override:
        return Resolved(list(override), "override")
    chosen = declared(doc)
    if chosen:
        return Resolved(chosen, "rule")
    if rule_rel is not None:
        hits = [p for p in cfg.final_folders if fnmatchcase(rule_rel, p)]
        if hits:
            best = max(hits, key=lambda p: (len(p.replace("*", "").replace("?", "")), len(p)))  # most specific pattern
            return Resolved([cfg.final_folders[best]], "folder", best)
    if cfg.final_default:
        return Resolved([cfg.final_default], "workspace")
    if rule_rel is not None:
        for pattern, targets in cfg.routes:
            if fnmatchcase(rule_rel, pattern):
                return Resolved(list(targets), "legacy-config")
    if cfg.default_target:
        return Resolved([cfg.default_target], "legacy-config")
    return Resolved(list(cfg.targets), "all")


def config_target_names(cfg: Config) -> set[str]:
    """Every target name used in vitrix.yml (to validate against the available ones)."""
    names = set(cfg.targets)
    names.update(cfg.final_folders.values())
    if cfg.final_default:
        names.add(cfg.final_default)
    if cfg.default_target:
        names.add(cfg.default_target)
    for _, targets in cfg.routes:
        names.update(targets)
    return names


def rules_rel(cfg: Config, path: Path) -> str:
    """File path inside rules/ (used by routes and URLs)."""
    try:
        return path.resolve().relative_to(cfg.rules_dir.resolve()).as_posix()
    except ValueError:
        return path.name


def plan(cfg: Config, files: list[RuleFile], override: list[str] | None = None) -> dict[str, Resolved]:
    """Targets of each rule file, keyed by `RuleFile.rel`."""
    return {rf.rel: resolve(cfg, rules_rel(cfg, rf.path), first_detection(rf.docs), override) for rf in files}
