"""Leitura do vitrix.yml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .github import GitHubConfig
from .github import parse_config as parse_github

SCHEMA_VERSION = 1


class ConfigError(Exception):
    """Erro de configuração (vitrix.yml inválido)."""


LEVELS = ("informational", "low", "medium", "high", "critical")


@dataclass
class GateConfig:
    """Critérios do quality gate: o que uma regra precisa para estar pronta para publicação."""

    min_positive: int = 1  # casos que devem disparar
    min_negative: int = 1  # casos que não devem disparar
    false_positive_levels: list[str] = field(default_factory=lambda: ["high", "critical"])  # exigem caso false_positive
    require_filter_test: bool = True  # regra com exclusão (filter*) precisa de um caso que a exercite
    require_mitre: bool = True  # técnica ATT&CK obrigatória
    allow_warnings: bool = True  # False: qualquer aviso de lint bloqueia
    blocked_status: list[str] = field(default_factory=lambda: ["deprecated", "unsupported"])
    require_replay: bool = False  # True: a regra precisa de expectativa em algum dataset de replay


def _parse_gate(data: object) -> GateConfig:
    if data is None:
        return GateConfig()
    if not isinstance(data, dict):
        raise ConfigError("'quality_gate' deve ser um mapa")
    gate = GateConfig()
    for key, value in data.items():
        if not hasattr(gate, key):
            raise ConfigError(f"quality_gate.{key}: opção desconhecida (use {', '.join(GateConfig.__dataclass_fields__)})")
        default = getattr(gate, key)
        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise ConfigError(f"quality_gate.{key} deve ser true ou false")
        elif isinstance(default, int):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ConfigError(f"quality_gate.{key} deve ser um inteiro >= 0")
        elif not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"quality_gate.{key} deve ser uma lista")
        if key == "false_positive_levels" and (bad := [v for v in value if v not in LEVELS]):
            raise ConfigError(f"quality_gate.false_positive_levels: level inválido {', '.join(bad)}")
        setattr(gate, key, value)
    return gate


@dataclass
class Config:
    root: Path
    rules_dir: Path
    cases_dir: Path
    output_dir: Path
    targets: list[str] = field(default_factory=lambda: ["splunk", "kql", "elastic-eql"])
    default_target: str | None = None
    routes: list[tuple[str, list[str]]] = field(default_factory=list)
    extra_pipelines: list[Path] = field(default_factory=list)
    require_cases: bool = True
    github: GitHubConfig | None = None  # repositório para abrir PRs pela interface
    path: Path | None = None  # o vitrix.yml lido (None = padrões, sem arquivo)
    datasets_dir: Path | None = None  # logs para replay (padrão: <raiz>/datasets)
    gate: GateConfig = field(default_factory=GateConfig)

    def rel(self, path: Path) -> str:
        """Caminho relativo à raiz do projeto, para mensagens."""
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return str(path)


def load_config(path: str | Path | None = None) -> Config:
    """Carrega o vitrix.yml. Sem arquivo, usa os padrões a partir do diretório atual."""
    cfg_path = Path(path) if path else Path.cwd() / "vitrix.yml"
    if path and not cfg_path.is_file():
        raise ConfigError(f"arquivo de configuração não encontrado: {cfg_path}")

    text = cfg_path.read_text(encoding="utf-8") if cfg_path.is_file() else ""
    cfg = parse_config_text(text, cfg_path.parent.resolve(), cfg_path.name)
    cfg.path = cfg_path.resolve() if cfg_path.is_file() else None
    return cfg


def parse_config_text(text: str, root: Path, name: str = "vitrix.yml") -> Config:
    """Interpreta o texto de um vitrix.yml como se estivesse em `root`. Não lê nem grava arquivos."""
    data: dict = {}
    if text.strip():
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{name} não é um YAML válido: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"{name} deve ser um mapa YAML")

    version = data.get("schema_version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise ConfigError(
            f"schema_version {version!r} não suportado por esta versão (esperado {SCHEMA_VERSION})"
        )

    targets = data.get("targets", ["splunk", "kql", "elastic-eql"])
    if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets) or not targets:
        raise ConfigError("'targets' deve ser uma lista não vazia de nomes de alvo")

    default_target = data.get("default_target")
    if default_target is not None and (not isinstance(default_target, str) or not default_target.strip()):
        raise ConfigError("'default_target' deve ser o nome de um alvo")

    routes: list[tuple[str, list[str]]] = []
    raw_routes = data.get("routes", [])
    if not isinstance(raw_routes, list):
        raise ConfigError("'routes' deve ser uma lista de {match, target}")
    for i, item in enumerate(raw_routes, 1):
        if not isinstance(item, dict) or not isinstance(item.get("match"), str) or not item["match"].strip():
            raise ConfigError(f"routes[{i}]: informe 'match' (padrão de caminho dentro de rules/)")
        tgt = item.get("target")
        if isinstance(tgt, str) and tgt.strip():
            names = [tgt.strip()]
        elif isinstance(tgt, list) and tgt and all(isinstance(t, str) and t.strip() for t in tgt):
            names = [t.strip() for t in tgt]
        else:
            raise ConfigError(f"routes[{i}]: 'target' deve ser um nome de alvo ou uma lista de nomes")
        routes.append((item["match"].strip(), names))

    extra = data.get("extra_pipelines", [])
    if not isinstance(extra, list):
        raise ConfigError("'extra_pipelines' deve ser uma lista de caminhos")

    try:
        github = parse_github(data.get("github"))
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    return Config(
        root=root,
        rules_dir=root / data.get("rules_dir", "rules"),
        cases_dir=root / data.get("cases_dir", "cases"),
        output_dir=root / data.get("output_dir", "dist"),
        targets=targets,
        default_target=default_target.strip() if default_target else None,
        routes=routes,
        extra_pipelines=[root / p for p in extra],
        require_cases=bool(data.get("require_cases", True)),
        github=github,
        datasets_dir=root / data.get("datasets_dir", "datasets"),
        gate=_parse_gate(data.get("quality_gate")),
    )
