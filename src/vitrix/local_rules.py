"""Local rules are real rule files (ADR 0007): Save writes `<rules_dir>/<id>` and `<cases_dir>/<id>`.

The app never runs `git add`/`commit`: the working tree is the user's. Every path goes through
`resolve_target` (one place for the confinement rules); writes are atomic and serialised with the
git sync through `sync.REPO_LOCK`; updates and deletes use an optimistic `sha` (sha256 of the file
bytes) so two editors cannot silently overwrite each other.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from pathlib import Path

import yaml

from . import publication
from .config import Config
from .service import ChangeError, normalize_rule_path
from .sync import REPO_LOCK

MAX_ID_CHARS = 300
MAX_SEGMENTS = 8
MAX_CHARS = 200_000
MAX_BYTES = 256 * 1024
MAX_FILES = 5000
_DEVICE = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])$", re.IGNORECASE)
_SUFFIXES = {".yml", ".yaml"}


class LocalRuleError(Exception):
    """A refused operation; `status` is the HTTP status, `issues` the located YAML problems (422)."""

    def __init__(self, message: str, status: int = 422, issues: list[dict] | None = None):
        super().__init__(message)
        self.status = status
        self.issues = issues


def sha_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_link(path: Path) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def normalize_id(rid: str) -> str:
    """Safe relative id (`windows/x.yml`) or LocalRuleError 422."""
    if not isinstance(rid, str) or len(rid) > MAX_ID_CHARS:
        raise LocalRuleError("invalid path: too long")
    try:
        rel = normalize_rule_path(rid)
    except ChangeError as exc:
        raise LocalRuleError(str(exc)) from None
    parts = rel.split("/")
    if len(parts) > MAX_SEGMENTS:
        raise LocalRuleError(f"invalid path: more than {MAX_SEGMENTS} folders deep")
    for seg in parts:
        if seg.endswith(".") or seg.endswith(" "):
            raise LocalRuleError("invalid path: names cannot end with '.' or a space")
        if _DEVICE.match(seg.split(".")[0]):
            raise LocalRuleError("invalid path: reserved name")
    if Path(rel).suffix.lower() not in _SUFFIXES:
        raise LocalRuleError("invalid path: use .yml or .yaml")
    return rel


def resolve_target(cfg: Config, rid: str, kind: str = "rules") -> Path:
    """Absolute path of `rid` below the rules (or cases) folder, confined: no link or junction on any
    existing component and the real path stays inside the folder. The file need not exist."""
    rel = normalize_id(rid)
    root = cfg.rules_dir if kind == "rules" else cfg.cases_dir
    if _is_link(root):
        raise LocalRuleError("invalid path: links are not allowed inside rules/")
    real_root = root.resolve()
    cur = root
    for seg in rel.split("/"):
        cur = cur / seg
        if _is_link(cur):
            raise LocalRuleError("invalid path: links are not allowed inside rules/")
    target = cur.resolve()
    if not target.is_relative_to(real_root):
        raise LocalRuleError("invalid path: links are not allowed inside rules/")
    return cur


def _collision(root: Path, rel: str) -> str | None:
    """Real relative path of an existing folder/file that matches `rel` case-insensitively but not exactly
    (any segment: a folder `windows/` blocks `Windows/x.yml`). None when there is no such clash."""
    cur = root
    real: list[str] = []
    parts = rel.split("/")
    for n, seg in enumerate(parts):
        names = [e.name for e in cur.iterdir()] if cur.is_dir() else []
        if seg in names:
            real.append(seg)
        else:
            other = next((x for x in names if x.lower() == seg.lower()), None)
            if other is None:
                return None
            return "/".join([*real, other, *parts[n + 1:]])
        cur = cur / seg
    return None


def _check_text(text: object, what: str, required: bool) -> str:
    if not isinstance(text, str):
        raise LocalRuleError(f"{what} must be text")
    if required and not text.strip():
        raise LocalRuleError(f"{what} is empty")
    if len(text) > MAX_CHARS or len(text.encode("utf-8")) > MAX_BYTES:
        raise LocalRuleError(f"{what} is too large (max 256 KiB)")
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        from .service import yaml_error_issue

        issue = yaml_error_issue(exc)
        raise LocalRuleError(f"the {what} is not valid YAML", 422,
                             [{"severity": issue.severity, "message": issue.message, "code": issue.code, "line": issue.line}]) from None
    if what == "rule" and (not docs or not isinstance(docs[0], dict)):
        raise LocalRuleError("the rule is not valid YAML: the first document must be a mapping", 422,
                             [{"severity": "error", "message": "the first YAML document must be a mapping", "code": "invalid-yaml", "line": 1}])
    return text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.vitrix-{secrets.token_hex(4)}.tmp"
    try:
        with open(tmp, "x", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise LocalRuleError("the rules folder is not writable", 503) from exc


def _count_rules(cfg: Config) -> int:
    return sum(1 for p in cfg.rules_dir.rglob("*") if p.suffix.lower() in _SUFFIXES) if cfg.rules_dir.is_dir() else 0


def read(cfg: Config, rid: str, strict: bool = False) -> dict:
    """{id, rule, cases, sha, cases_sha} of the files on disk; 404 when the rule file is absent.
    `strict` (before publishing): the rule and any cases file must be valid YAML, else 422."""
    rule_path = resolve_target(cfg, rid)
    if not rule_path.is_file():
        raise LocalRuleError("rule not found", 404)
    cases_path = resolve_target(cfg, rid, "cases")
    rule_b = rule_path.read_bytes()
    cases_b = cases_path.read_bytes() if cases_path.is_file() else None
    if strict:
        _check_text(rule_b.decode("utf-8", "replace"), "rule", True)
        if cases_b is not None:
            _check_text(cases_b.decode("utf-8", "replace"), "cases", False)
    return {"id": normalize_id(rid), "rule": rule_b.decode("utf-8", "replace"), "cases": cases_b.decode("utf-8", "replace") if cases_b is not None else None,
            "sha": sha_of(rule_b), "cases_sha": sha_of(cases_b) if cases_b is not None else None}


def create(cfg: Config, rid: str, rule: str, cases: str | None) -> dict:
    rel = normalize_id(rid)
    rule_t = _check_text(rule, "rule", True)
    cases_t = _check_text(cases, "cases", False) if cases and cases.strip() else None
    with REPO_LOCK:
        rule_path = resolve_target(cfg, rel)
        cases_path = resolve_target(cfg, rel, "cases")
        if rule_path.exists():
            raise LocalRuleError(f"a rule already exists at {cfg.rel(rule_path)}", 409)
        clash = _collision(cfg.rules_dir, rel)
        if clash:
            raise LocalRuleError(f"a rule path already exists with different letter case: {cfg.rel(cfg.rules_dir)}/{clash}", 409)
        # a leftover cases file is never silently attached (it was not checked and would be published)
        if cases_path.exists() or _collision(cfg.cases_dir, rel):
            raise LocalRuleError(f"{cfg.rel(cases_path)} already exists", 409)
        if _count_rules(cfg) >= MAX_FILES:
            raise LocalRuleError(f"too many rule files ({MAX_FILES})", 409)
        _atomic_write(rule_path, rule_t)
        if cases_t is not None:
            _atomic_write(cases_path, cases_t)
    publication.invalidate()
    return read(cfg, rel)


def update(cfg: Config, rid: str, rule: str, cases: str | None, remove_cases: bool, sha: str, cases_sha: str | None) -> dict:
    rel = normalize_id(rid)
    rule_t = _check_text(rule, "rule", True)
    cases_t = _check_text(cases, "cases", False) if cases is not None and cases.strip() else None
    with REPO_LOCK:
        rule_path = resolve_target(cfg, rel)
        if not rule_path.is_file():
            raise LocalRuleError("rule not found", 404)
        if sha_of(rule_path.read_bytes()) != sha:
            raise LocalRuleError("the rule changed on disk since you loaded it", 409)
        cases_path = resolve_target(cfg, rel, "cases")
        if cases_t is not None or remove_cases:
            current = sha_of(cases_path.read_bytes()) if cases_path.is_file() else None
            if current != cases_sha:
                raise LocalRuleError("the test cases changed on disk since you loaded them", 409)
        _atomic_write(rule_path, rule_t)
        if remove_cases:
            try:
                cases_path.unlink(missing_ok=True)
            except OSError as exc:
                raise LocalRuleError("the rules folder is not writable", 503) from exc
        elif cases_t is not None:
            _atomic_write(cases_path, cases_t)
    publication.invalidate()
    return read(cfg, rel)


def delete(cfg: Config, rid: str, sha: str) -> None:
    """Remove rule + cases files of a rule that is not in the published base."""
    rel = normalize_id(rid)
    with REPO_LOCK:
        rule_path = resolve_target(cfg, rel)
        if not rule_path.is_file():
            raise LocalRuleError("rule not found", 404)
        if sha_of(rule_path.read_bytes()) != sha:
            raise LocalRuleError("the rule changed on disk since you loaded it", 409)
        if publication.in_base(cfg, rel):
            raise LocalRuleError("Published rules are removed through a pull request.", 409)
        cases_path = resolve_target(cfg, rel, "cases")
        try:
            rule_path.unlink()
            cases_path.unlink(missing_ok=True)
        except OSError as exc:
            raise LocalRuleError("the rules folder is not writable", 503) from exc
    publication.invalidate()
