"""Loading of vitrix.yml."""

from __future__ import annotations

import contextlib
import contextvars
import dataclasses
import os
import re
import sys
import threading
import time
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    false_positive_levels: list[str] = field(default_factory=list)  # opt-in: levels that require a false_positive case
    require_filter_test: bool = True  # a rule with an exclusion (filter*) needs a case that exercises it
    require_mitre: bool = True  # an ATT&CK technique is required
    allow_warnings: bool = True  # False: any lint warning blocks
    blocked_status: list[str] = field(default_factory=lambda: ["deprecated", "unsupported"])
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
        if key == "require_replay":  # still in the vitrix.yml of existing repositories
            warnings.warn("quality_gate.require_replay is no longer supported and is ignored (replay never affects approval)", stacklevel=2)
            continue
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
    """Accounts and workspace membership. ON by default; opt out with `auth.enabled: false` or VITRIX_AUTH=off."""

    enabled: bool = True
    session_days: int = 14
    github_login: bool = True  # offer "Continue with GitHub" when VITRIX_GITHUB_CLIENT_ID/SECRET are set
    workspace_name: str = "Detection workspace"
    enabled_source: str = "default"  # where `enabled` came from: "env" (VITRIX_AUTH) | "config" (vitrix.yml) | "default"
    bootstrap_token: str | None = None  # VITRIX_BOOTSTRAP_TOKEN: None, "auto" or an explicit value (never serialised)


_TRUE, _FALSE = ("on", "1", "true", "yes"), ("off", "0", "false", "no")
MIN_BOOTSTRAP_TOKEN = 16


def _apply_auth_env(auth: AuthConfig, present: dict) -> None:
    """Environment overrides (ADR 0002): VITRIX_AUTH beats vitrix.yml beats the default; bad values are config errors."""
    auth.enabled_source = "config" if present and "enabled" in present else "default"
    raw = os.environ.get("VITRIX_AUTH", "").strip().lower()
    if raw:
        if raw not in _TRUE + _FALSE:
            raise ConfigError("VITRIX_AUTH must be on or off (also 1/0, true/false, yes/no)")
        value = raw in _TRUE
        if auth.enabled and not value:
            print("warning: VITRIX_AUTH=off overrides auth.enabled: true in vitrix.yml; the API has no accounts.", file=sys.stderr)
        auth.enabled, auth.enabled_source = value, "env"
    token = os.environ.get("VITRIX_BOOTSTRAP_TOKEN", "").strip()
    if token:
        if token != "auto" and len(token) < MIN_BOOTSTRAP_TOKEN:  # nosec B105
            raise ConfigError(f"VITRIX_BOOTSTRAP_TOKEN must be 'auto' or at least {MIN_BOOTSTRAP_TOKEN} characters")
        auth.bootstrap_token = token


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


def _auth_with_env(data: object) -> AuthConfig:
    auth = _parse_auth(data)
    _apply_auth_env(auth, data if isinstance(data, dict) else {})
    return auth


_TABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_LOGSOURCE_KEY = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.*-]+$")


@dataclass(frozen=True)
class KqlConfig:
    """Table for KQL queries when the backend cannot infer one from the rule (see backends.kql_table)."""

    tables: dict[str, str] = field(default_factory=dict)  # "product/service" or "product/category" -> table
    default_table: str | None = None
    fields: dict[str, dict[str, str]] = field(default_factory=dict)  # Table -> {SigmaField: Column} (mappings.yml only)


def _parse_kql(raw: object) -> KqlConfig:
    if raw is None:
        return KqlConfig()
    if not isinstance(raw, dict) or set(raw) - {"tables", "default_table"}:
        raise ConfigError("'kql' must be a mapping with 'tables' and/or 'default_table'")
    tables = raw.get("tables") or {}
    if not isinstance(tables, dict):
        raise ConfigError("kql.tables must map 'product/service' (or 'product/category') to a table name, e.g. windows/system: Event")
    out: dict[str, str] = {}
    for key, table in tables.items():
        if not isinstance(key, str) or not _LOGSOURCE_KEY.match(key.strip().lower()):
            raise ConfigError(f"kql.tables key {key!r} must look like 'product/service' or 'product/category' (e.g. windows/system)")
        if not isinstance(table, str) or not _TABLE.match(table.strip()):
            raise ConfigError(f"kql.tables.{key}: {table!r} is not a valid table name (letters, digits and _ only)")
        out[key.strip().lower()] = table.strip()
    default = raw.get("default_table")
    if default is not None and (not isinstance(default, str) or not _TABLE.match(default.strip())):
        raise ConfigError(f"kql.default_table: {default!r} is not a valid table name (letters, digits and _ only)")
    return KqlConfig(out, default.strip() if default else None)


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
    kql: KqlConfig = field(default_factory=KqlConfig)  # fallback tables for KQL
    reviews_enabled: bool = True  # comments and review requests in <data_dir>/reviews.db (reviews.enabled; needs accounts)
    local_rules_enabled: bool = True  # Save writes rule files into rules/ and cases/ (local_rules.enabled; ADR 0007)
    final_default: str | None = None  # mappings.yml final_language.default (workspace-wide final language)
    final_folders: dict[str, str] = field(default_factory=dict)  # mappings.yml final_language.folders: glob under rules/ -> language id
    sync_enabled: bool = True  # GitHub sync: throttled fetch + safe fast-forward (ADR 0006); `sync: false` or VITRIX_SYNC=off
    sync_interval: int = 30  # seconds between fetches, clamped 10..3600
    sync_fast_forward: bool = True

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
    _merge_mappings(cfg)
    return cfg


def _merge_mappings(cfg: Config) -> None:
    """mappings.yml (next to vitrix.yml) wins over vitrix.yml `kql.tables`; its `kql.fields` are new."""
    from . import mappings

    try:
        doc, sha, _ = mappings.read(cfg.root)  # the one guarded reader
    except mappings.MappingsError as exc:
        raise ConfigError(f"mappings.yml: {exc}") from None
    if sha is None:
        return
    kql = doc["kql"]
    cfg.kql = KqlConfig({**cfg.kql.tables, **kql["tables"]}, cfg.kql.default_table, kql["fields"])
    cfg.final_default = doc["final_language"]["default"]
    cfg.final_folders = dict(doc["final_language"]["folders"])


def _dir(data: dict, key: str, default: str) -> str:
    value = data.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"'{key}' must be a folder name (a non-empty string), not {value!r}")
    return value


def _inside(root: Path, key: str, value: str) -> str:
    """A configured folder must stay inside the project root: sync can pull a vitrix.yml change from
    GitHub, and rules/cases/datasets/output folders are written to by the app."""
    try:
        (root / value).resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        raise ConfigError(f"'{key}' must be a folder inside the project, not {value!r}") from None
    # Checked the same way on every OS: vitrix.yml is shared between Windows and Linux machines/CI, and on
    # Linux "C:/x" or "\\\\server\\share" would otherwise pass as ordinary relative folder names.
    windows_absolute = re.match(r"^[A-Za-z]:", value) or value.startswith(("\\", "/"))
    if Path(value).is_absolute() or Path(value).drive or windows_absolute:
        raise ConfigError(f"'{key}' must be a relative folder inside the project, not {value!r}")
    return value


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

    raw_reviews = data.get("reviews")
    if raw_reviews is None:
        raw_reviews = {}
    elif raw_reviews is False:
        raw_reviews = {"enabled": False}
    if not isinstance(raw_reviews, dict) or not isinstance(raw_reviews.get("enabled", True), bool):
        raise ConfigError("'reviews' must be a mapping (or false) and reviews.enabled must be true or false")

    raw_local = data.get("local_rules")
    if raw_local is None:
        raw_local = {}
    elif raw_local is False:
        raw_local = {"enabled": False}
    if not isinstance(raw_local, dict) or not isinstance(raw_local.get("enabled", True), bool):
        raise ConfigError("'local_rules' must be a mapping (or false) and local_rules.enabled must be true or false")

    raw_sync = data.get("sync")
    if raw_sync is None:
        raw_sync = {}
    elif raw_sync is False:
        raw_sync = {"enabled": False}
    if not isinstance(raw_sync, dict) or not isinstance(raw_sync.get("enabled", True), bool) or not isinstance(raw_sync.get("fast_forward", True), bool):
        raise ConfigError("'sync' must be a mapping (or false); sync.enabled and sync.fast_forward must be true or false")
    interval = raw_sync.get("interval_seconds", 30)
    if isinstance(interval, bool) or not isinstance(interval, int):
        raise ConfigError("sync.interval_seconds must be a whole number of seconds")
    sync_enabled = raw_sync.get("enabled", True)
    env_sync = os.environ.get("VITRIX_SYNC", "").strip().lower()
    if env_sync in ("off", "0", "false"):
        sync_enabled = False
    elif env_sync in ("on", "1", "true"):
        sync_enabled = True

    return Config(
        root=root,
        rules_dir=root / _inside(root, "rules_dir", _dir(data, "rules_dir", "rules")),
        cases_dir=root / _inside(root, "cases_dir", _dir(data, "cases_dir", "cases")),
        output_dir=root / _inside(root, "output_dir", _dir(data, "output_dir", "dist")),
        targets=targets,
        default_target=default_target.strip() if default_target else None,
        routes=routes,
        extra_pipelines=[root / p for p in extra],
        require_cases=bool(data.get("require_cases", True)),
        github=github,
        github_source=github_source,
        datasets_dir=root / _inside(root, "datasets_dir", _dir(data, "datasets_dir", "datasets")),
        gate=_parse_gate(data.get("quality_gate")),
        auth=_auth_with_env(data.get("auth")),
        data_dir=root / _dir(data, "data_dir", ".vitrix"),
        drafts_enabled=raw_drafts.get("enabled", True),
        reviews_enabled=raw_reviews.get("enabled", True),
        kql=_parse_kql(data.get("kql")),
        local_rules_enabled=raw_local.get("enabled", True),
        sync_enabled=sync_enabled,
        sync_interval=max(10, min(3600, interval)),
        sync_fast_forward=raw_sync.get("fast_forward", True),
    )


# Settings that were used to build long-lived objects at startup (stores, routes): a reload keeps the
# startup value and reports the key in `restart_required` instead of half-applying it.
_STARTUP_ONLY = {"auth": "auth", "data_dir": "data_dir", "drafts.enabled": "drafts_enabled", "reviews.enabled": "reviews_enabled",
                 "rules_dir": "rules_dir", "cases_dir": "cases_dir", "datasets_dir": "datasets_dir", "output_dir": "output_dir",
                 "github": "github"}


class ConfigHolder:
    """The running server's configuration, reloaded when vitrix.yml changes on disk.

    `get()` stats the file (at most once per `debounce` seconds) and re-parses it when its mtime/size
    changed. An invalid edit keeps the last good configuration and sets `reload_error`.
    """

    def __init__(self, path: str | Path | None = None, debounce: float = 1.0, clock=time.monotonic):  # noqa: ANN001
        self._lock = threading.RLock()
        self._clock, self._debounce = clock, debounce
        self._cfg = load_config(path)
        self._startup = self._cfg
        self.path = self._cfg.path
        self._root = self._cfg.root
        self.loaded_at = time.time()
        self.reload_error: str | None = None
        self.restart_required: list[str] = []
        self._stamp = self._stat()
        self._checked = clock()

    def _stat(self) -> tuple | None:
        """Stamp of vitrix.yml AND mappings.yml (a project without vitrix.yml still watches mappings.yml)."""
        st = None
        if self.path:
            try:
                st = self.path.stat()
            except OSError:
                return None
        try:
            ms = self._root.joinpath("mappings.yml").stat()
        except OSError:
            ms = None  # an absent mappings.yml is part of the stamp
        return (st.st_mtime_ns if st else None, st.st_size if st else None, ms.st_mtime_ns if ms else None, ms.st_size if ms else None)

    def get(self) -> Config:
        with self._lock:
            now = self._clock()
            if now - self._checked >= self._debounce:
                self._checked = now
                stamp = self._stat()
                if stamp != self._stamp:
                    self._stamp = stamp
                    self._reload()
            return self._cfg

    def refresh(self) -> None:
        """Re-read vitrix.yml now (after a sync changed the working tree), ignoring the debounce."""
        with self._lock:
            self._checked = self._clock()
            self._stamp = self._stat()
            self._reload()

    def _load_pathless(self) -> Config:
        cfg = parse_config_text("", self._root)
        _merge_mappings(cfg)
        return cfg

    def _reload(self) -> None:
        try:
            new = load_config(self.path) if self.path else self._load_pathless()
        except Exception as exc:  # a bad edit must never break the running server: keep the last good config
            self.reload_error = str(exc) or type(exc).__name__
            return
        changed = [key for key, attr in _STARTUP_ONLY.items() if getattr(new, attr) != getattr(self._startup, attr)]
        keep = {attr: getattr(self._startup, attr) for attr in (*_STARTUP_ONLY.values(), "github_source")}
        self._cfg = dataclasses.replace(new, **keep)
        self.restart_required = changed
        self.reload_error = None
        self.loaded_at = time.time()

    @contextlib.contextmanager
    def snapshot(self):  # noqa: ANN201
        """Pin one Config for the code running inside (a request), so it never mixes two versions of the file."""
        token = _SNAPSHOT.set(self.get())
        try:
            yield
        finally:
            _SNAPSHOT.reset(token)

    @property
    def live(self) -> Config:
        """A stand-in for `Config` that always reads the current configuration (for code that captured `cfg`)."""
        return _Live(self)  # type: ignore[return-value]

    def status(self) -> dict:
        self.get()
        return {"file": str(self.path) if self.path else None, "loaded_at": datetime.fromtimestamp(self.loaded_at, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "reload_error": self.reload_error, "restart_required": list(self.restart_required)}


_SNAPSHOT: contextvars.ContextVar[Config | None] = contextvars.ContextVar("vitrix_config_snapshot", default=None)


class _Live:
    __slots__ = ("_holder",)

    def __init__(self, holder: ConfigHolder):
        object.__setattr__(self, "_holder", holder)

    def __getattr__(self, name: str):  # noqa: ANN204
        return getattr(_SNAPSHOT.get() or self._holder.get(), name)
