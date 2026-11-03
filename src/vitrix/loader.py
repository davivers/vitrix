"""Descoberta e leitura de arquivos de regra."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .config import Config

RULE_SUFFIXES = {".yml", ".yaml"}


class RuleLoadError(Exception):
    """O arquivo não pôde ser lido como YAML."""


@dataclass
class RuleFile:
    path: Path
    rel: str
    text: str
    docs: list  # documentos YAML (um arquivo Sigma pode ter vários, separados por ---)


def find_rule_files(paths: list[str], cfg: Config) -> list[Path]:
    """Resolve os caminhos pedidos (arquivos ou pastas) em uma lista ordenada de arquivos."""
    roots = [Path(p) for p in paths] if paths else [cfg.rules_dir]
    found: list[Path] = []
    for root in roots:
        if root.is_dir():
            found.extend(p for p in root.rglob("*") if p.suffix in RULE_SUFFIXES and p.is_file())
        elif root.is_file():
            found.append(root)
        else:
            raise FileNotFoundError(f"caminho não encontrado: {root}")
    return sorted({p.resolve() for p in found})


def load_rule(path: Path, cfg: Config) -> RuleFile:
    text = path.read_text(encoding="utf-8")
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"YAML inválido: {exc}") from exc
    return RuleFile(path=path, rel=cfg.rel(path), text=text, docs=docs)
