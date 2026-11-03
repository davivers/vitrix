"""Loading of vitrix.yml."""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .github import GitHubConfig
from .github import parse_config as parse_github

SCHEMA_VERSION = 1


class ConfigError(Exception):
    """Configuration error (invalid vitrix.yml)."""


LEVELS = ("informational", "low", "medium", "high", "critical")


@dataclass
class GateConfig:
    """Quality gate criteria: what a rule needs to be ready to publish."""

    min_positive: int = 1  # cases that must fire
    min_negative: int = 1  # cases that must not fire
    false_positive_levels: list[str] = field(default_factory=lambda: ["high", "critical"])  # require a false_positive case
    require_filter_test: bool = True  # a rule with an exclusion (filter*) needs a case that exercises it
    require_mitre: bool = True  # an ATT&CK technique is required
    allow_warnings: bool = True  # False: any lint warning blocks
    blocked_status: list[str] = field(default_factory=lambda: ["deprecated", "unsupported"])
    require_replay: bool = False  # True: the rule needs an expectation in some replay dataset
    review_days: int = 180  # recommend reviewing rules unchanged in Git for more than N days (0 = off)
    min_score: int = 80  # health score (0-100) a rule needs to be approved (0 = no threshold)
    require_owner: bool = False  # True: a rule without vitrix.owner is blocked
    require_suppression_reason: bool = False  # True: every exclusion needs vitrix.suppressions.<name>.reason
    block_expired_suppressions: bool = True  # an exclusion past its vitrix.suppressions.<name>.expires blocks


def _parse_gate(data: object) -> GateConfig:
    if data is None:
        return GateConfig()
    if not isinstance(data, dict):
        raise ConfigError("'quality_gate' must be a mapping")
    gate = GateConfig()
    for key, value in data.items():
        if not hasattr(gate, key):
            raise ConfigError(f"quality_gate.{key}: unknown option (use {', '.join(GateConfig.__dataclass_fields__)})")
        default = getattr(gate, key)
        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise ConfigError(f"quality_gate.{key} must be true or false")
        elif isinstance(default, int):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ConfigError(f"quality_gate.{key} must be an integer >= 0")
        elif not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"quality_gate.{key} must be a list")
        if key == "min_score" and not 0 <= value <= 100:
            raise ConfigError("quality_gate.min_score must be between 0 and 100")
        if key == "false_positive_levels" and (bad := [v for v in value if v not in LEVELS]):
            raise ConfigError(f"quality_gate.false_positive_levels: invalid level {', '.join(bad)}")
        setattr(gate, key, value)
    return gate


@dataclass
class AuthConfig:
    """Accounts and workspace membership. Off by default: the local single-user mode is unchanged."""

    enabled: bool = False
    session_days: int = 14
    github_login: bool = True  # offer "Continue with GitHub" when VITRIX_GITHUB_CLIENT_ID/SECRET are set
    workspace_name: str = "Detection workspace"


_RETIRED_AUTH_KEYS = ("allow_signup", "signup_role")


def _parse_auth(data: object) -> AuthConfig:
    if data is None:
        return AuthConfig()
    if not isinstance(data, dict):
        raise ConfigError("'auth' must be a mapping")
    auth = AuthConfig()
    for key, value in data.items():
        if key in _RETIRED_AUTH_KEYS:  # registration is invite-only after the owner: old keys are ignored
            warnings.warn(f"auth.{key} is no longer supported and is ignored (after the first account, people join by invitation only)", stacklevel=2)
            continue
        if not hasattr(auth, key):
            raise ConfigError(f"auth.{key}: unknown option (use {', '.join(AuthConfig.__dataclass_fields__)})")
        default = getattr(auth, key)
        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise ConfigError(f"auth.{key} must be true or false")
        elif isinstance(default, int):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 365:
                raise ConfigError(f"auth.{key} must be an integer between 1 and 365")
        elif not isinstance(value, str) or not value.strip():
            raise ConfigError(f"auth.{key} must be a non-empty string")
        setattr(auth, key, value.strip() if isinstance(value, str) else value)
    return auth


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
    github: GitHubConfig | None = None  # repository for CI validation and pull requests
    github_source: str | None = None  # "vitrix.yml", "git remote" (auto-detected) or None
    path: Path | None = None  # the vitrix.yml read (None = defaults, no file)
    datasets_dir: Path | None = None  # logs for replay (default: <root>/datasets)
    gate: GateConfig = field(default_factory=GateConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    data_dir: Path | None = None  # accounts database etc. (default: <root>/.vitrix)
    drafts_enabled: bool = True  # local drafts in <data_dir>/drafts.db (drafts.enabled)

    def rel(self, path: Path) -> str:
        """Path relative to the project root, for messages."""
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return str(path)


def load_config(path: str | Path | None = None) -> Config:
    """Load vitrix.yml. Without a file, use the defaults from the current directory."""
    cfg_path = Path(path) if path else Path.cwd() / "vitrix.yml"
    if path and not cfg_path.is_file():
        raise ConfigError(f"configuration file not found: {cfg_path}")

    text = cfg_path.read_text(encoding="utf-8") if cfg_path.is_file() else ""
    cfg = parse_config_text(text, cfg_path.parent.resolve(), cfg_path.name)
    cfg.path = cfg_path.resolve() if cfg_path.is_file() else None
    return cfg


def parse_config_text(text: str, root: Path, name: str = "vitrix.yml") -> Config:
    """Parse the text of a vitrix.yml as if it were in `root`. Reads and writes no files."""
    data: dict = {}
    if text.strip():
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{name} is not valid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"{name} must be a YAML mapping")

    version = data.get("schema_version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise ConfigError(
            f"schema_version {version!r} is not supported by this version (expected {SCHEMA_VERSION})"
        )

    targets = data.get("targets", ["splunk", "kql", "elastic-eql"])
    if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets) or not targets:
        raise ConfigError("'targets' must be a non-empty list of target names")

    default_target = data.get("default_target")
    if default_target is not None and (not isinstance(default_target, str) or not default_target.strip()):
        raise ConfigError("'default_target' must be a target name")

    routes: list[tuple[str, list[str]]] = []
    raw_routes = data.get("routes", [])
    if not isinstance(raw_routes, list):
        raise ConfigError("'routes' must be a list of {match, target}")
    for i, item in enumerate(raw_routes, 1):
        if not isinstance(item, dict) or not isinstance(item.get("match"), str) or not item["match"].strip():
            raise ConfigError(f"routes[{i}]: set 'match' (a path pattern inside rules/)")
        tgt = item.get("target")
        if isinstance(tgt, str) and tgt.strip():
            names = [tgt.strip()]
        elif isinstance(tgt, list) and tgt and all(isinstance(t, str) and t.strip() for t in tgt):
            names = [t.strip() for t in tgt]
        else:
            raise ConfigError(f"routes[{i}]: 'target' must be a target name or a list of names")
        routes.append((item["match"].strip(), names))

    extra = data.get("extra_pipelines", [])
    if not isinstance(extra, list):
        raise ConfigError("'extra_pipelines' must be a list of paths")

    raw_github = data.get("github")
    github_source = "vitrix.yml"
    if raw_github is False:  # `github: false` turns GitHub (and auto-detection) off
        github, github_source = None, None
    elif raw_github is None:  # not configured: use the git remote of this folder, if it is on GitHub
        from .gitremote import detect

        github = detect(root)
        github_source = "git remote" if github else None
    else:
        try:
            github = parse_github(raw_github)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc

    raw_drafts = data.get("drafts")
    if raw_drafts is None:
        raw_drafts = {}
    elif raw_drafts is False:  # `drafts: false` is shorthand for `drafts: {enabled: false}`
        raw_drafts = {"enabled": False}
    if not isinstance(raw_drafts, dict) or not isinstance(raw_drafts.get("enabled", True), bool):
        raise ConfigError("'drafts' must be a mapping (or false) and drafts.enabled must be true or false")

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
        github_source=github_source,
        datasets_dir=root / data.get("datasets_dir", "datasets"),
        gate=_parse_gate(data.get("quality_gate")),
        auth=_parse_auth(data.get("auth")),
        data_dir=root / data.get("data_dir", ".vitrix"),
        drafts_enabled=raw_drafts.get("enabled", True),
    )
