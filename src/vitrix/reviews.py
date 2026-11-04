"""Workspace reviews and comments: `<data_dir>/reviews.db` (SQLite, stdlib only).

Same pattern as `drafts.DraftStore`: the file is created on the first write. People are stored by
id plus an email/name snapshot; membership and roles are checked by the API layer against
`auth.AuthStore`. Reviews are advisory (never a quality-gate check). See `.claude/adr/0005-workspace-reviews.md`.
"""

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from .drafts import content_hash

MAX_OPEN_PER_REQUESTER = 200
MAX_COMMENTS_PER_TARGET = 500
MAX_LIST = 200
OPEN_STATES = ("pending", "changes_requested")
STATES = ("pending", "approved", "changes_requested", "cancelled")
KINDS = ("rule", "draft")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
  id TEXT PRIMARY KEY,
  workspace_id INTEGER NOT NULL DEFAULT 1,
  target_kind TEXT NOT NULL CHECK(target_kind IN ('rule','draft')),
  target_ref TEXT NOT NULL,
  target_title TEXT NOT NULL,
  target_hash TEXT NOT NULL,
  target_version INTEGER,
  requester_id INTEGER NOT NULL,
  requester_email TEXT NOT NULL,
  requester_name TEXT NOT NULL,
  reviewer_id INTEGER NOT NULL,
  reviewer_email TEXT NOT NULL,
  reviewer_name TEXT NOT NULL,
  note TEXT,
  state TEXT NOT NULL CHECK(state IN ('pending','approved','changes_requested','cancelled')),
  decision_note TEXT,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  decided_at REAL,
  version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS reviews_by_reviewer ON reviews (workspace_id, reviewer_id, state);
CREATE INDEX IF NOT EXISTS reviews_by_requester ON reviews (workspace_id, requester_id, state);
CREATE INDEX IF NOT EXISTS reviews_by_target ON reviews (workspace_id, target_kind, target_ref);
CREATE TABLE IF NOT EXISTS review_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  review_id TEXT NOT NULL REFERENCES reviews(id),
  type TEXT NOT NULL,
  actor_id INTEGER NOT NULL,
  actor_name TEXT NOT NULL,
  text TEXT NOT NULL,
  at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS review_events_by_review ON review_events (review_id, id);
CREATE TABLE IF NOT EXISTS review_unread (
  review_id TEXT NOT NULL REFERENCES reviews(id),
  user_id INTEGER NOT NULL,
  kind TEXT NOT NULL,
  actor_name TEXT NOT NULL DEFAULT '',
  at REAL NOT NULL,
  PRIMARY KEY (review_id, user_id)
);
CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  workspace_id INTEGER NOT NULL DEFAULT 1,
  target_kind TEXT NOT NULL CHECK(target_kind IN ('rule','draft')),
  target_ref TEXT NOT NULL,
  review_id TEXT REFERENCES reviews(id),
  target_hash TEXT,
  author_id INTEGER NOT NULL,
  author_email TEXT NOT NULL,
  author_name TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at REAL NOT NULL,
  edited_at REAL,
  deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS comments_by_target ON comments (workspace_id, target_kind, target_ref, created_at);
"""


class ReviewError(Exception):
    """A refused review operation. `status` is the HTTP status the API should answer with."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


text_hash = content_hash


class ReviewStore:
    """SQLite store of reviews and comments for one workspace. Thread-safe (one lock)."""

    workspace_id = 1

    def __init__(self, path: Path | str, clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self._now = clock
        self._lock = threading.RLock()
        self._db: sqlite3.Connection | None = None

    def _conn(self, create: bool) -> sqlite3.Connection | None:
        if self._db is None:
            if not create and not self.path.is_file():
                return None
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
            self._db.row_factory = sqlite3.Row
            self._db.executescript(_SCHEMA)
            for column in ("snapshot_text", "base_text"):  # added after the first release: migrate older files
                try:
                    self._db.execute(f"ALTER TABLE reviews ADD COLUMN {column} TEXT")  # nosec B608 - literal names
                except sqlite3.OperationalError:
                    pass  # already there
        return self._db

    def _q(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._lock:
            db = self._conn(create=False)
            return [dict(r) for r in db.execute(sql, args).fetchall()] if db else []

    # ------------------------------------------------------------------ reviews

    def get(self, review_id: str) -> dict:
        rows = self._q("SELECT * FROM reviews WHERE id=? AND workspace_id=?", (review_id, self.workspace_id))
        if not rows:
            raise ReviewError("review not found", 404)
        return rows[0]

    def list(self, *, reviewer_id: int | None = None, requester_id: int | None = None, states: tuple[str, ...] | None = None,
             kind: str | None = None, ref: str | None = None) -> list[dict]:
        where, args = ["workspace_id=?"], [self.workspace_id]
        for column, value in (("reviewer_id", reviewer_id), ("requester_id", requester_id), ("target_kind", kind), ("target_ref", ref)):
            if value is not None:
                where.append(f"{column}=?")
                args.append(value)
        if states:
            where.append(f"state IN ({','.join('?' * len(states))})")
            args += list(states)
        # Justification for the nosec below: only literal column names are interpolated; every value is a bound parameter
        return self._q(f"SELECT * FROM reviews WHERE {' AND '.join(where)} ORDER BY updated_at DESC, created_at DESC LIMIT {MAX_LIST}", tuple(args))  # nosec B608

    def counts(self, user_id: int) -> dict:
        rows = self._q(
            "SELECT SUM(reviewer_id=? AND state='pending') AS to_review, SUM(requester_id=? AND state IN ('pending','changes_requested')) AS requested"
            " FROM reviews WHERE workspace_id=? AND target_kind != 'draft'", (user_id, user_id, self.workspace_id))
        row = rows[0] if rows else {}
        return {"to_review": int(row.get("to_review") or 0), "requested": int(row.get("requested") or 0)}

    # ------------------------------------------------------------------ events and unread state

    def _event(self, db: sqlite3.Connection, review_id: str, type_: str, actor: dict, text: str) -> None:
        db.execute("INSERT INTO review_events (review_id, type, actor_id, actor_name, text, at) VALUES (?,?,?,?,?,?)",
                   (review_id, type_, actor["id"], actor["name"] or actor.get("email", ""), text, self._now()))

    def _mark_unread(self, db: sqlite3.Connection, review_id: str, user_id: int, kind: str, actor_name: str) -> None:
        db.execute("INSERT OR REPLACE INTO review_unread (review_id, user_id, kind, actor_name, at) VALUES (?,?,?,?,?)",
                   (review_id, user_id, kind, actor_name, self._now()))

    def events(self, review_id: str) -> list[dict]:
        return self._q("SELECT id, type, actor_id, actor_name, text, at FROM review_events WHERE review_id=? ORDER BY id", (review_id,))

    def unread_ids(self, user_id: int) -> set[str]:
        return {r["review_id"] for r in self._q("SELECT review_id FROM review_unread WHERE user_id=?", (user_id,))}

    def mark_read(self, review_id: str, user_id: int) -> None:
        with self._lock:
            db = self._conn(create=False)
            if db:
                db.execute("DELETE FROM review_unread WHERE review_id=? AND user_id=?", (review_id, user_id))

    def mark_unread(self, review_id: str, user_id: int) -> None:
        with self._lock:
            row = self.get(review_id)
            if user_id not in (row["reviewer_id"], row["requester_id"]):
                raise ReviewError("This review is not yours.", 403)
            assigned = user_id == row["reviewer_id"]
            db = self._conn(create=True)
            if db is None:
                raise ReviewError("review store unavailable", 503)
            self._mark_unread(db, review_id, user_id, "assigned" if assigned else "decided", row["requester_name"] if assigned else row["reviewer_name"])

    def read_all(self, user_id: int) -> int:
        with self._lock:
            db = self._conn(create=False)
            return db.execute("DELETE FROM review_unread WHERE user_id=?", (user_id,)).rowcount if db else 0

    def unread_summary(self, user_id: int, limit: int = 3) -> dict:
        """Number of unread reviews and the newest `limit` of them (for the notification toast)."""
        rows = self._q(
            "SELECT u.review_id AS id, u.kind, u.actor_name, u.at, r.target_title AS title, r.requester_name, r.state FROM review_unread u"
            " JOIN reviews r ON r.id=u.review_id WHERE u.user_id=? AND r.workspace_id=? AND r.target_kind != 'draft' ORDER BY u.at DESC", (user_id, self.workspace_id))
        return {"unread": len(rows), "latest": rows[:limit]}

    def request(self, *, kind: str, ref: str, title: str, target_hash: str, target_version: int | None,
                requester: dict, reviewer: dict, note: str | None, snapshot_text: str | None = None) -> dict:
        """`requester` / `reviewer`: {"id","email","name"}. 409 on a duplicate open request or over the limit."""
        review_id = uuid.uuid4().hex
        now = self._now()
        with self._lock:
            db = self._conn(create=True)
            dup = db.execute(
                "SELECT 1 FROM reviews WHERE workspace_id=? AND target_kind=? AND target_ref=? AND reviewer_id=? AND state IN ('pending','changes_requested')",
                (self.workspace_id, kind, ref, reviewer["id"])).fetchone()
            if dup:
                raise ReviewError("This reviewer already has an open review for this target.", 409)
            open_n = db.execute("SELECT COUNT(*) FROM reviews WHERE workspace_id=? AND requester_id=? AND state IN ('pending','changes_requested')",
                                (self.workspace_id, requester["id"])).fetchone()[0]
            if open_n >= MAX_OPEN_PER_REQUESTER:
                raise ReviewError(f"You have {MAX_OPEN_PER_REQUESTER} open review requests; cancel some first.", 409)
            db.execute(
                "INSERT INTO reviews (id, workspace_id, target_kind, target_ref, target_title, target_hash, target_version, requester_id, requester_email,"
                " requester_name, reviewer_id, reviewer_email, reviewer_name, note, state, created_at, updated_at, snapshot_text, base_text)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?,?,?)",
                (review_id, self.workspace_id, kind, ref, title, target_hash, target_version, requester["id"], requester["email"], requester["name"],
                 reviewer["id"], reviewer["email"], reviewer["name"], note, now, now, snapshot_text, snapshot_text))
            self._event(db, review_id, "requested", requester, f"{requester['name']} requested review from {reviewer['name']}" + (f': "{note}"' if note else ""))
            self._mark_unread(db, review_id, reviewer["id"], "assigned", requester["name"])
        return self.get(review_id)

    def _transition(self, review_id: str, version: int, sets: str, args: tuple, allowed: tuple[str, ...], why: str) -> dict:
        """Compare-and-set on `version` and `state`; the 409 text says which one failed."""
        with self._lock:
            row = self.get(review_id)
            if row["version"] != version:
                raise ReviewError("The review changed since you loaded it; reload and try again.", 409)
            if row["state"] not in allowed:
                raise ReviewError(why, 409)
            db = self._conn(create=True)
            # Justification for the nosec below: `sets` is a literal from this module; every value is a bound parameter
            db.execute(f"UPDATE reviews SET {sets}, updated_at=?, version=version+1 WHERE id=? AND version=?", (*args, self._now(), review_id, version))  # nosec B608
        return self.get(review_id)

    def decide(self, review_id: str, *, decision: str, note: str | None, version: int, current_hash: str | None) -> dict:
        """Approve / request changes. 409 if not pending, version moved, or the target changed since the request."""
        row = self.get(review_id)
        if row["state"] == "pending" and current_hash != row["target_hash"]:
            raise ReviewError("The rule changed since the review was requested; ask for a new review.", 409)
        now = self._now()
        out = self._transition(review_id, version, "state=?, decision_note=?, decided_at=?", (decision, note, now), ("pending",),
                               "This review is no longer pending.")
        with self._lock:
            db = self._conn(create=True)
            if db is None:
                raise ReviewError("review store unavailable", 503)
            who = {"id": row["reviewer_id"], "name": row["reviewer_name"], "email": row["reviewer_email"]}
            verb = "approved" if decision == "approved" else "requested changes"
            self._event(db, review_id, decision, who, f"{who['name']} {verb}" + (f': "{note}"' if note else ""))
            self._mark_unread(db, review_id, row["requester_id"], "decided", who["name"])
            db.execute("DELETE FROM review_unread WHERE review_id=? AND user_id=?", (review_id, row["reviewer_id"]))
        return out

    def rerequest(self, review_id: str, *, version: int, title: str, target_hash: str, target_version: int | None,
                  snapshot_text: str | None = None, note: str | None = None) -> dict:
        """New round on the same review: the previous round's snapshot becomes the diff baseline."""
        out = self._transition(
            review_id, version,
            "state='pending', decision_note=NULL, decided_at=NULL, target_title=?, target_hash=?, target_version=?,"
            " base_text=snapshot_text, snapshot_text=?, note=COALESCE(?, note)",
            (title, target_hash, target_version, snapshot_text, note), OPEN_STATES, "Only a pending or changes-requested review can be re-requested.")
        with self._lock:
            db = self._conn(create=True)
            if db is None:
                raise ReviewError("review store unavailable", 503)
            who = {"id": out["requester_id"], "name": out["requester_name"], "email": out["requester_email"]}
            self._event(db, review_id, "rerequested", who, f"{who['name']} requested again" + (f': "{note}"' if note else ""))
            self._mark_unread(db, review_id, out["reviewer_id"], "assigned", who["name"])
        return out

    def cancel(self, review_id: str, *, version: int, actor: dict | None = None) -> dict:
        out = self._transition(review_id, version, "state='cancelled'", (), OPEN_STATES, "Only an open review can be cancelled.")
        with self._lock:
            db = self._conn(create=True)
            if db is None:
                raise ReviewError("review store unavailable", 503)
            who = actor or {"id": out["requester_id"], "name": out["requester_name"]}
            self._event(db, review_id, "cancelled", who, f"{who['name']} cancelled the request")
            db.execute("DELETE FROM review_unread WHERE review_id=?", (review_id,))
        return out

    def approved(self, kind: str, ref: str, target_hash: str) -> list[dict]:
        """Approved reviews of this target whose reviewed content is exactly `target_hash` (for `Reviewed-by`)."""
        return self._q("SELECT reviewer_email, reviewer_name FROM reviews WHERE workspace_id=? AND target_kind=? AND target_ref=?"
                       " AND state='approved' AND target_hash=? ORDER BY decided_at", (self.workspace_id, kind, ref, target_hash))

    # ------------------------------------------------------------------ comments

    def get_comment(self, comment_id: str) -> dict:
        rows = self._q("SELECT * FROM comments WHERE id=? AND workspace_id=?", (comment_id, self.workspace_id))
        if not rows:
            raise ReviewError("comment not found", 404)
        return rows[0]

    def comments(self, kind: str, ref: str, review_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM comments WHERE workspace_id=? AND target_kind=? AND target_ref=?"
        args: tuple = (self.workspace_id, kind, ref)
        if review_id:
            sql += " AND review_id=?"
            args += (review_id,)
        return self._q(f"{sql} ORDER BY created_at, rowid LIMIT {MAX_COMMENTS_PER_TARGET}", args)

    def add_comment(self, *, kind: str, ref: str, body: str, author: dict, target_hash: str | None, review_id: str | None = None) -> dict:
        comment_id = uuid.uuid4().hex
        with self._lock:
            db = self._conn(create=True)
            n = db.execute("SELECT COUNT(*) FROM comments WHERE workspace_id=? AND target_kind=? AND target_ref=?", (self.workspace_id, kind, ref)).fetchone()[0]
            if n >= MAX_COMMENTS_PER_TARGET:
                raise ReviewError(f"This target already has {MAX_COMMENTS_PER_TARGET} comments.", 409)
            db.execute(
                "INSERT INTO comments (id, workspace_id, target_kind, target_ref, review_id, target_hash, author_id, author_email, author_name, body, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (comment_id, self.workspace_id, kind, ref, review_id, target_hash, author["id"], author["email"], author["name"], body, self._now()))
        return self.get_comment(comment_id)

    def edit_comment(self, comment_id: str, body: str) -> dict:
        with self._lock:
            if self.get_comment(comment_id)["deleted"]:
                raise ReviewError("comment not found", 404)
            self._conn(create=True).execute("UPDATE comments SET body=?, edited_at=? WHERE id=?", (body, self._now(), comment_id))
        return self.get_comment(comment_id)

    def delete_comment(self, comment_id: str) -> None:
        """Soft delete: the row stays (threads keep their shape) but the text is wiped."""
        with self._lock:
            self.get_comment(comment_id)
            self._conn(create=True).execute("UPDATE comments SET deleted=1, body='' WHERE id=?", (comment_id,))
