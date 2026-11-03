"""Local drafts: unfinished rules saved in `<data_dir>/drafts.db` instead of opening a pull request.

Stdlib only (SQLite), same pattern as `auth.AuthStore`. A draft lives ONLY in this database: nothing
is ever written to `rules/` or the working tree, and `path` is metadata (never opened for writing).
A draft reaches the repository only through the normal flow: load it in the Editor, then Publish.
The file is created on the first write; a server that never saves a draft writes nothing.
See `.claude/adr/0001-local-drafts.md`.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import yaml

MAX_PER_AUTHOR = 100
MAX_TITLE = 200
DEFAULT_TITLE = "Untitled draft"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS drafts (
  id TEXT PRIMARY KEY,
  workspace_id INTEGER NOT NULL DEFAULT 1,
  path TEXT,
  title TEXT NOT NULL,
  rule TEXT NOT NULL,
  cases TEXT,
  base_hash TEXT,
  author_id INTEGER,
  author_email TEXT,
  author_name TEXT,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS drafts_by_updated ON drafts (workspace_id, updated_at DESC);
"""

_LIST = (
    "SELECT id, path, title, rule, cases, base_hash, author_id, author_email, author_name, created_at, updated_at, version"
    " FROM drafts WHERE workspace_id=? ORDER BY updated_at DESC, created_at DESC"
)
_GET = (
    "SELECT id, path, title, rule, cases, base_hash, author_id, author_email, author_name, created_at, updated_at, version"
    " FROM drafts WHERE id=? AND workspace_id=?"
)


class DraftError(Exception):
    """A refused draft operation. `status` is the HTTP status the API should answer with."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def resolve_title(title: str | None, rule: str, path: str | None) -> str:
    """The given title, else the rule's `title:`, else its path, else a placeholder. Never raises:
    a draft may hold invalid YAML."""
    if title and title.strip():
        return title.strip()[:MAX_TITLE]
    try:
        doc = next(iter(yaml.safe_load_all(rule)), None)
    except yaml.YAMLError:
        doc = None
    found = doc.get("title") if isinstance(doc, dict) else None
    if isinstance(found, str) and found.strip():
        return found.strip()[:MAX_TITLE]
    return (path or DEFAULT_TITLE)[:MAX_TITLE]


def rule_hash(rules_dir: Path, path: str | None) -> str | None:
    """SHA-256 of `rules/<path>` (a path already normalised by `service.normalize_rule_path`), or None."""
    if not path:
        return None
    root = rules_dir.resolve()
    target = (root / path).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return None
    return hashlib.sha256(target.read_bytes()).hexdigest()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DraftStore:
    """SQLite store of drafts for one workspace. Thread-safe (one lock)."""

    workspace_id = 1  # one tenant per server for now; the schema already carries the id

    def __init__(self, path: Path | str, clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self._now = clock
        self._lock = threading.RLock()
        self._db: sqlite3.Connection | None = None

    def _conn(self, create: bool) -> sqlite3.Connection | None:
        """The connection; None when there is no file yet and we are only reading."""
        if self._db is None:
            if not create and not self.path.is_file():
                return None
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
            self._db.row_factory = sqlite3.Row
            self._db.executescript(_SCHEMA)
        return self._db

    def _q(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._lock:
            db = self._conn(create=False)
            return [dict(r) for r in db.execute(sql, args).fetchall()] if db else []

    def list(self) -> list[dict]:
        return self._q(_LIST, (self.workspace_id,))

    def get(self, draft_id: str) -> dict:
        rows = self._q(_GET, (draft_id, self.workspace_id))
        if not rows:
            raise DraftError("draft not found", 404)
        return rows[0]

    def create(self, *, path: str | None, title: str | None, rule: str, cases: str | None, base_hash: str | None,
               author: dict | None = None) -> dict:
        """`author` is {"id","email","name"} or None (accounts off). Max 100 drafts per author."""
        author_id = author["id"] if author else None
        now = self._now()
        draft_id = uuid.uuid4().hex
        with self._lock:
            db = self._conn(create=True)
            used = db.execute("SELECT COUNT(*) FROM drafts WHERE workspace_id=? AND author_id IS ?", (self.workspace_id, author_id)).fetchone()[0]
            if used >= MAX_PER_AUTHOR:
                raise DraftError(f"draft limit reached ({MAX_PER_AUTHOR}); delete some first", 409)
            db.execute(
                "INSERT INTO drafts (id, workspace_id, path, title, rule, cases, base_hash, author_id, author_email, author_name, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (draft_id, self.workspace_id, path, resolve_title(title, rule, path), rule, cases, base_hash, author_id,
                 author["email"] if author else None, author["name"] if author else None, now, now),
            )
        return self.get(draft_id)

    def update(self, draft_id: str, *, path: str | None, title: str | None, rule: str, cases: str | None,
               base_hash: str | None, version: int) -> dict:
        """Replace the content if `version` is still current (else 409); bumps the version."""
        with self._lock:
            db = self._conn(create=False)
            cur = db.execute(
                "UPDATE drafts SET path=?, title=?, rule=?, cases=?, base_hash=?, updated_at=?, version=version+1"
                " WHERE id=? AND workspace_id=? AND version=?",
                (path, resolve_title(title, rule, path), rule, cases, base_hash, self._now(), draft_id, self.workspace_id, version),
            ) if db else None
            if cur is None or cur.rowcount == 0:
                self.get(draft_id)  # 404 if it vanished
                raise DraftError("draft changed since you loaded it", 409)
        return self.get(draft_id)

    def delete(self, draft_id: str) -> None:
        with self._lock:
            db = self._conn(create=False)
            if db is None or db.execute("DELETE FROM drafts WHERE id=? AND workspace_id=?", (draft_id, self.workspace_id)).rowcount == 0:
                raise DraftError("draft not found", 404)


def public(row: dict, *, current_hash: str | None, me_id: int | None, auth_on: bool, full: bool = False) -> dict:
    """The JSON shape of the API (Summary; with `full`, the Draft with rule, cases and base_hash)."""
    out = {
        "id": row["id"],
        "path": row["path"],
        "title": row["title"],
        "author": {"id": row["author_id"], "email": row["author_email"], "name": row["author_name"]} if row["author_id"] is not None else None,
        "created_at": iso(row["created_at"]),
        "updated_at": iso(row["updated_at"]),
        "version": row["version"],
        "stale": bool(row["path"]) and current_hash != row["base_hash"],
        "mine": row["author_id"] in (None, me_id) if auth_on else True,  # authorless drafts are shared
    }
    if full:
        out.update(rule=row["rule"], cases=row["cases"], base_hash=row["base_hash"])
    return out
