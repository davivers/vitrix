"""Discovery and loading of rule files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .config import Config

RULE_SUFFIXES = {".yml", ".yaml"}


class RuleLoadError(Exception):
    """The file could not be read as YAML."""


@dataclass
class RuleFile:
    path: Path
    rel: str
    text: str
    docs: list  # YAML documents (a Sigma file may hold several, separated by ---)


def find_rule_files(paths: list[str], cfg: Config) -> list[Path]:
    """Resolve the requested paths (files or folders) into a sorted list of files."""
    roots = [Path(p) for p in paths] if paths else [cfg.rules_dir]
    found: list[Path] = []
    for root in roots:
        if root.is_dir():
            found.extend(p for p in root.rglob("*") if p.suffix in RULE_SUFFIXES and p.is_file())
        elif root.is_file():
            found.append(root)
        else:
            raise FileNotFoundError(f"path not found: {root}")
    return sorted({p.resolve() for p in found})


def load_rule(path: Path, cfg: Config) -> RuleFile:
    text = path.read_text(encoding="utf-8")
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"invalid YAML: {exc}") from exc
    return RuleFile(path=path, rel=cfg.rel(path), text=text, docs=docs)
