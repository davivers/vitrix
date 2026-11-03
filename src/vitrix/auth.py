"""Accounts, sessions and workspace membership.

One Vitrix server serves one **workspace** (one tenant = one detection repository) and many
people. Everything is stdlib: SQLite for storage, scrypt for passwords, random opaque session
tokens in an HttpOnly cookie. Off unless `auth.enabled: true` in vitrix.yml.

Security decisions (see tests/test_auth.py):

- passwords: scrypt with a per-user salt, constant-time comparison, minimum length 10; a login for
  an unknown email still burns one scrypt so timing does not reveal which emails exist;
- sessions: 256-bit random token; only its SHA-256 is stored, so a leaked database cannot be
  replayed; a new token on every login (no fixation); logout and password change revoke;
- brute force: 5 failed logins per (email, IP) lock that pair for 5 minutes;
- registration: the first account becomes the owner; afterwards ONLY invited people (no open
  sign-up); invites are single use, expire in 7 days and are shown once (only their hash is stored);
- GitHub login: OAuth web flow with a `state` bound to a cookie; an existing account is linked
  only through a **verified** GitHub email; the GitHub access token is discarded, never stored;
- roles: viewer < editor < admin < owner; the last owner can never be removed or demoted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64decode, b64encode
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .config import AuthConfig

ROLES = ("viewer", "editor", "admin", "owner")
ROLE_LEVEL = {r: i for i, r in enumerate(ROLES, 1)}
SESSION_COOKIE = "vitrix_session"
OAUTH_COOKIE = "vitrix_oauth"
MIN_PASSWORD = 10
INVITE_DAYS = 7
MAX_FAILURES = 5
LOCKOUT_S = 300
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
_SCRYPT = (2**14, 8, 1)  # n, r, p


class AuthError(Exception):
    """A refused auth operation. `status` is the HTTP status the API should answer with."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Identity:
    user_id: int
    email: str
    name: str
    role: str
    github_login: str | None
    avatar_url: str | None
    github_id: int | None = None
    session_hash: str = ""

    @property
    def label(self) -> str:
        return self.name or self.email

    def can(self, role: str) -> bool:
        return ROLE_LEVEL[self.role] >= ROLE_LEVEL[role]

    def public(self) -> dict:
        return {"id": self.user_id, "email": self.email, "name": self.name, "role": self.role,
                "github_login": self.github_login, "avatar_url": self.avatar_url}


# --------------------------------------------------------------------------- passwords


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = _SCRYPT
    digest = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${b64encode(salt).decode()}${b64encode(digest).decode()}"


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time check. With no stored hash (unknown user, GitHub-only account) it still burns
    one scrypt and returns False, so response time does not reveal the account state."""
    if not stored:
        hash_password(password)
        return False
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc, b64decode(digest))
    except (ValueError, TypeError):
        return False


def check_password_policy(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise AuthError(f"The password must have at least {MIN_PASSWORD} characters.", 422)
    if len(password) > 256:
        raise AuthError("The password is too long.", 422)
    if len(set(password)) < 4:
        raise AuthError("The password is too repetitive.", 422)


def normalize_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not _EMAIL.match(email):
        raise AuthError("Enter a valid email address.", 422)
    return email


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --------------------------------------------------------------------------- store

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL DEFAULT '', password_hash TEXT,
  github_id INTEGER UNIQUE, github_login TEXT, avatar_url TEXT, created_at INTEGER NOT NULL, last_login INTEGER);
CREATE TABLE IF NOT EXISTS workspaces (id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS members (
  workspace_id INTEGER NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL, joined_at INTEGER NOT NULL, PRIMARY KEY (workspace_id, user_id));
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS invites (
  id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, workspace_id INTEGER NOT NULL, email TEXT NOT NULL,
  role TEXT NOT NULL, created_by INTEGER, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, user_id INTEGER, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
"""


_USER_BY = {
    "id": "SELECT * FROM users WHERE id = ?",
    "email": "SELECT * FROM users WHERE email = ?",
    "github_id": "SELECT * FROM users WHERE github_id = ?",
}


class AuthStore:
    """SQLite store for one workspace. Thread-safe (one lock; fine for a team-sized server)."""

    def __init__(self, path: Path | str, cfg: AuthConfig | None = None, clock: Callable[[], float] = time.time):
        self.cfg = cfg or AuthConfig(enabled=True)
        self._now = clock
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._failures: dict[tuple[str, str], tuple[int, float]] = {}
        with self._lock:
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.executescript(_SCHEMA)
            if not self._db.execute("SELECT 1 FROM workspaces").fetchone():
                self._db.execute("INSERT INTO workspaces (id, name, created_at) VALUES (1, ?, ?)", (self.cfg.workspace_name, int(self._now())))

    workspace_id = 1  # one tenant per server for now; the schema already carries the id

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def _x(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            return self._db.execute(sql, args).lastrowid or 0

    # ------------------------------------------------------------------- users

    def user_count(self) -> int:
        return self._q("SELECT COUNT(*) AS n FROM users")[0]["n"]

    def _user(self, column: str, arg: object) -> sqlite3.Row | None:
        rows = self._q(_USER_BY[column], (arg,))  # fixed statements only: no SQL is ever built from input
        return rows[0] if rows else None

    def user_by_email(self, email: str) -> sqlite3.Row | None:
        return self._user("email", email.strip().lower())

    def user_by_github(self, github_id: int) -> sqlite3.Row | None:
        return self._user("github_id", github_id)

    def create_user(self, email: str, name: str, password: str | None, role: str, github: dict | None = None) -> int:
        email = normalize_email(email)
        if self.user_by_email(email):
            raise AuthError("This email is already registered.", 409)
        uid = self._x(
            "INSERT INTO users (email, name, password_hash, github_id, github_login, avatar_url, created_at) VALUES (?,?,?,?,?,?,?)",
            (email, (name or "").strip()[:100], hash_password(password) if password else None, (github or {}).get("id"),
             (github or {}).get("login"), (github or {}).get("avatar_url"), int(self._now())),
        )
        self._x("INSERT INTO members (workspace_id, user_id, role, joined_at) VALUES (?,?,?,?)", (self.workspace_id, uid, role, int(self._now())))
        return uid

    def link_github(self, user_id: int, profile: dict) -> None:
        self._x("UPDATE users SET github_id=?, github_login=?, avatar_url=COALESCE(avatar_url, ?) WHERE id=?",
                (profile["id"], profile["login"], profile.get("avatar_url"), user_id))

    # ------------------------------------------------------------------- login throttle

    def _locked(self, key: tuple[str, str]) -> float:
        count, since = self._failures.get(key, (0, 0.0))
        if count >= MAX_FAILURES and self._now() - since < LOCKOUT_S:
            return LOCKOUT_S - (self._now() - since)
        if count >= MAX_FAILURES:
            self._failures.pop(key, None)
        return 0.0

    def verify_login(self, email: str, password: str, ip: str = "") -> int:
        """User id if the credentials are right. One generic error for every failure."""
        key = ((email or "").strip().lower(), ip)
        wait = self._locked(key)
        if wait:
            raise AuthError(f"Too many failed attempts. Try again in {int(wait // 60) + 1} minute(s).", 429)
        row = self.user_by_email(key[0]) if key[0] else None
        if row is not None and row["password_hash"] and verify_password(password or "", row["password_hash"]):
            self._failures.pop(key, None)
            return row["id"]
        if row is None or not row["password_hash"]:
            verify_password(password or "", None)  # equalise timing
        count, since = self._failures.get(key, (0, self._now()))
        self._failures[key] = (count + 1, since if count else self._now())
        raise AuthError("Wrong email or password.", 401)

    # ------------------------------------------------------------------- sessions

    def create_session(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        now = int(self._now())
        self._x("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                (_sha(token), user_id, now, now + self.cfg.session_days * 86400))
        self._x("UPDATE users SET last_login=? WHERE id=?", (now, user_id))
        self._x("DELETE FROM sessions WHERE expires_at < ?", (now,))
        return token

    def identify(self, token: str | None) -> Identity | None:
        if not token:
            return None
        h = _sha(token)
        rows = self._q(
            "SELECT u.*, m.role AS role, s.expires_at AS exp FROM sessions s JOIN users u ON u.id = s.user_id "
            "JOIN members m ON m.user_id = u.id AND m.workspace_id = ? WHERE s.token_hash = ?", (self.workspace_id, h))
        if not rows or rows[0]["exp"] < self._now():
            return None
        r = rows[0]
        return Identity(r["id"], r["email"], r["name"], r["role"], r["github_login"], r["avatar_url"], r["github_id"], h)

    def end_session(self, token: str | None) -> None:
        if token:
            self._x("DELETE FROM sessions WHERE token_hash=?", (_sha(token),))

    def revoke_sessions(self, user_id: int, keep_hash: str = "") -> None:
        self._x("DELETE FROM sessions WHERE user_id=? AND token_hash != ?", (user_id, keep_hash))

    def change_password(self, user_id: int, current: str, new: str, keep_hash: str = "") -> None:
        row = self._user("id", user_id)
        if row is None or not verify_password(current, row["password_hash"]):
            raise AuthError("The current password is wrong.", 403)
        check_password_policy(new)
        self._x("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new), user_id))
        self.revoke_sessions(user_id, keep_hash)

    # ------------------------------------------------------------------- members

    def members(self) -> list[dict]:
        rows = self._q(
            "SELECT u.id, u.email, u.name, u.github_login, u.avatar_url, u.last_login, m.role, m.joined_at, "
            "(u.password_hash IS NOT NULL) AS has_password FROM members m JOIN users u ON u.id = m.user_id "
            "WHERE m.workspace_id = ? ORDER BY m.joined_at", (self.workspace_id,))
        return [dict(r) for r in rows]

    def _owners(self) -> int:
        return self._q("SELECT COUNT(*) AS n FROM members WHERE workspace_id=? AND role='owner'", (self.workspace_id,))[0]["n"]

    def _role(self, user_id: int) -> str | None:
        rows = self._q("SELECT role FROM members WHERE workspace_id=? AND user_id=?", (self.workspace_id, user_id))
        return rows[0]["role"] if rows else None

    def set_role(self, actor: Identity, user_id: int, role: str) -> None:
        if role not in ROLES:
            raise AuthError("Unknown role.", 422)
        current = self._role(user_id)
        if current is None:
            raise AuthError("Member not found.", 404)
        if (role == "owner" or current == "owner") and not actor.can("owner"):
            raise AuthError("Only an owner can grant or change the owner role.", 403)
        if current == "owner" and role != "owner" and self._owners() <= 1:
            raise AuthError("The workspace needs at least one owner.", 409)
        self._x("UPDATE members SET role=? WHERE workspace_id=? AND user_id=?", (role, self.workspace_id, user_id))
        # sessions are NOT revoked: identify() re-reads the role on every request, so the new role applies at once

    def remove_member(self, actor: Identity, user_id: int) -> None:
        current = self._role(user_id)
        if current is None:
            raise AuthError("Member not found.", 404)
        if current == "owner" and (not actor.can("owner") or self._owners() <= 1):
            raise AuthError("Only an owner can remove an owner, and the last owner cannot be removed.", 409)
        self._x("DELETE FROM users WHERE id=?", (user_id,))  # cascades to membership and sessions

    def rename_workspace(self, name: str) -> None:
        name = (name or "").strip()
        if not 1 <= len(name) <= 80:
            raise AuthError("The workspace name must have 1 to 80 characters.", 422)
        self._x("UPDATE workspaces SET name=? WHERE id=?", (name, self.workspace_id))

    @property
    def workspace_name(self) -> str:
        return self._q("SELECT name FROM workspaces WHERE id=?", (self.workspace_id,))[0]["name"]

    # ------------------------------------------------------------------- invites

    def create_invite(self, actor: Identity, email: str, role: str) -> str:
        email = normalize_email(email)
        if role not in ROLES or (role == "owner" and not actor.can("owner")):
            raise AuthError("You cannot invite with that role.", 403)
        if self.user_by_email(email):
            raise AuthError("That person already has an account. Change their role instead.", 409)
        token = secrets.token_urlsafe(24)
        now = int(self._now())
        self._x("DELETE FROM invites WHERE workspace_id=? AND email=? AND used_at IS NULL", (self.workspace_id, email))
        self._x("INSERT INTO invites (token_hash, workspace_id, email, role, created_by, created_at, expires_at) VALUES (?,?,?,?,?,?,?)",
                (_sha(token), self.workspace_id, email, role, actor.user_id, now, now + INVITE_DAYS * 86400))
        return token

    def find_invite(self, token: str | None) -> sqlite3.Row | None:
        if not token:
            return None
        rows = self._q("SELECT * FROM invites WHERE token_hash=? AND used_at IS NULL AND expires_at > ?", (_sha(token), int(self._now())))
        return rows[0] if rows else None

    def invite_for_email(self, email: str) -> sqlite3.Row | None:
        rows = self._q("SELECT * FROM invites WHERE email=? AND used_at IS NULL AND expires_at > ?", (email, int(self._now())))
        return rows[0] if rows else None

    def consume_invite(self, invite_id: int) -> None:
        self._x("UPDATE invites SET used_at=? WHERE id=?", (int(self._now()), invite_id))

    def invites(self) -> list[dict]:
        rows = self._q("SELECT id, email, role, created_at, expires_at FROM invites WHERE workspace_id=? AND used_at IS NULL AND expires_at > ? ORDER BY created_at DESC",
                       (self.workspace_id, int(self._now())))
        return [dict(r) for r in rows]

    def revoke_invite(self, invite_id: int) -> None:
        self._x("DELETE FROM invites WHERE id=? AND workspace_id=? AND used_at IS NULL", (invite_id, self.workspace_id))

    # ------------------------------------------------------------------- audit

    def log(self, who: Identity | str | None, action: str, detail: str = "") -> None:
        actor = who.label if isinstance(who, Identity) else (who or "system")
        uid = who.user_id if isinstance(who, Identity) else None
        self._x("INSERT INTO audit (ts, user_id, actor, action, detail) VALUES (?,?,?,?,?)", (int(self._now()), uid, actor[:120], action, detail[:500]))

    def audit(self, limit: int = 100) -> list[dict]:
        return [dict(r) for r in self._q("SELECT ts, actor, action, detail FROM audit ORDER BY id DESC LIMIT ?", (min(max(limit, 1), 500),))]


# --------------------------------------------------------------------------- registration policy


def _role_for_new_account(store: AuthStore, email: str, invite_token: str | None, verified_email: bool = False) -> tuple[str, int | None]:
    """The role a new account gets, and the invite it consumes. Raises when registration is closed."""
    if store.user_count() == 0:
        return "owner", None  # bootstrap: the first account owns the workspace
    invite = store.find_invite(invite_token) if invite_token else None
    if invite is not None:
        if invite["email"] != email:
            raise AuthError("This invitation was issued for a different email address.", 403)
        return invite["role"], invite["id"]
    if invite_token:
        raise AuthError("This invitation is invalid or has expired.", 403)
    pending = store.invite_for_email(email) if verified_email else None  # only a GitHub-VERIFIED email may skip the token
    if pending is not None:
        return pending["role"], pending["id"]
    raise AuthError("Registration is by invitation only. Ask a workspace admin for an invite.", 403)


def register_local(store: AuthStore, email: str, name: str, password: str, invite_token: str | None = None) -> Identity:
    email = normalize_email(email)
    check_password_policy(password)
    if not (name or "").strip():
        raise AuthError("Enter your name.", 422)
    role, invite_id = _role_for_new_account(store, email, invite_token)
    uid = store.create_user(email, name, password, role)
    if invite_id:
        store.consume_invite(invite_id)
    ident = Identity(uid, email, name.strip(), role, None, None)
    store.log(ident, "account.register", f"role {role}" + (" (first account, workspace owner)" if role == "owner" and store.user_count() == 1 else ""))
    return ident


def login_github(store: AuthStore, profile: dict, invite_token: str | None = None) -> int:
    """User id for a GitHub profile: existing link, link through a VERIFIED email, or a new account."""
    row = store.user_by_github(profile["id"])
    if row is not None:
        return row["id"]
    email = profile.get("email")  # only ever a verified, primary email (see GitHubOAuth.profile)
    if not email:
        raise AuthError("Your GitHub account has no verified primary email. Verify one on GitHub and try again.", 400)
    existing = store.user_by_email(email)
    if existing is not None:
        store.link_github(existing["id"], profile)
        store.log(str(existing["email"]), "account.github_linked", f"@{profile['login']}")
        return existing["id"]
    role, invite_id = _role_for_new_account(store, email, invite_token, verified_email=True)
    uid = store.create_user(email, profile.get("name") or profile["login"], None, role, github=profile)
    if invite_id:
        store.consume_invite(invite_id)
    store.log(email, "account.register", f"GitHub @{profile['login']}, role {role}")
    return uid


# --------------------------------------------------------------------------- GitHub OAuth

Http = Callable[[str, str, dict, bytes | None], tuple[int, object]]
_OAUTH_HOSTS = ("https://github.com/", "https://api.github.com/")


def _http(method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, object]:
    if not url.startswith(_OAUTH_HOSTS):  # secrets only go to GitHub over HTTPS
        raise AuthError("Refused a request outside GitHub.", 502)
    req = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": "vitrix", **headers})
    try:
        # URL checked above: only https://github.com/ or https://api.github.com/
        with urllib.request.urlopen(req, timeout=15) as res:  # nosec B310
            return res.status, json.loads(res.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise AuthError(f"Could not reach GitHub: {exc}", 502) from exc


class GitHubOAuth:
    """The authorization-code flow. The access token lives only for the length of one request."""

    def __init__(self, client_id: str, client_secret: str, http: Http = _http):
        self.client_id, self._secret, self._http = client_id, client_secret, http

    def authorize_url(self, state: str, redirect_uri: str) -> str:
        q = urllib.parse.urlencode({"client_id": self.client_id, "redirect_uri": redirect_uri, "scope": "read:user user:email",
                                    "state": state, "allow_signup": "false"})
        return f"https://github.com/login/oauth/authorize?{q}"

    def profile(self, code: str, redirect_uri: str) -> dict:
        body = json.dumps({"client_id": self.client_id, "client_secret": self._secret, "code": code, "redirect_uri": redirect_uri}).encode()
        status, data = self._http("POST", "https://github.com/login/oauth/access_token", {"Accept": "application/json", "Content-Type": "application/json"}, body)
        token = data.get("access_token") if isinstance(data, dict) else None
        if status != 200 or not token:
            raise AuthError("GitHub did not accept the sign-in. Start again.", 400)
        auth = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28"}
        status, user = self._http("GET", "https://api.github.com/user", auth, None)
        if status != 200 or not isinstance(user, dict) or not isinstance(user.get("id"), int) or not user.get("login"):
            raise AuthError("Could not read your GitHub profile.", 502)
        status, emails = self._http("GET", "https://api.github.com/user/emails", auth, None)
        verified = None
        if status == 200 and isinstance(emails, list):
            primary = [e for e in emails if isinstance(e, dict) and e.get("primary") and e.get("verified") and e.get("email")]
            verified = (primary or [e for e in emails if isinstance(e, dict) and e.get("verified") and e.get("email")] or [None])[0]
        return {"id": user["id"], "login": user["login"], "name": user.get("name") or user["login"], "avatar_url": user.get("avatar_url"),
                "email": verified["email"].strip().lower() if verified else None}


def attribution(ident: Identity) -> str:
    """Commit-message trailers that credit the person who used the UI (the push itself uses the server token).

    Only a GitHub-linked account gets a `Co-authored-by` (GitHub resolves its noreply address); a local
    account's email is not verified, so it is recorded as text and never used as a commit identity.
    """
    clean = re.sub(r"[\r\n<>]", " ", ident.name or ident.email).strip()[:100]
    lines = [f"Submitted-by: {clean} ({ident.email}) via Vitrix"]
    if ident.github_id and ident.github_login:
        lines.append(f"Co-authored-by: {clean} <{ident.github_id}+{ident.github_login}@users.noreply.github.com>")
    return "\n".join(lines)
