"""HTTP side of accounts and workspaces: login, register, GitHub OAuth, members, invites, audit.

`authorize()` is the gatekeeper used by the API middleware: with `auth.enabled` every /api route
except the public ones needs a valid session, and each route needs a minimum role.
"""

from __future__ import annotations

import hmac
import os
import secrets
import urllib.parse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from . import auth
from .auth import AuthError, AuthStore, GitHubOAuth, Identity
from .config import Config

PUBLIC = {
    "/api/health",
    "/api/auth/config",
    "/api/auth/me",
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/github/start",
    "/api/auth/github/callback",
}
# POSTs that only COMPUTE and write nothing (disk, GitHub): any signed-in viewer may use them.
VIEWER_POSTS = {"/api/regex", "/api/validate", "/api/impact", "/api/replay", "/api/replay/draft", "/api/config/validate"}
# POSTs that write or publish (CI, pull requests, local drafts): editor and above.
EDITOR_POSTS = {"/api/ci/rules", "/api/pull-requests", "/api/drafts"}


def required_role(method: str, path: str) -> str:
    """The minimum role for a request. Writes default to admin: new routes are safe until classified."""
    if path.startswith("/api/workspace"):
        return "viewer" if (method == "GET" and path == "/api/workspace") else "admin"
    if path.startswith("/api/auth/"):
        return "viewer"  # logout, password: any signed-in person
    if method in ("GET", "HEAD"):
        return "viewer"
    if path.startswith("/api/drafts/"):  # PUT/DELETE a draft; author-or-admin is checked in the route
        return "editor"
    if path in VIEWER_POSTS:
        return "viewer"
    return "editor" if path in EDITOR_POSTS else "admin"


def authorize(store: AuthStore, request: Request) -> JSONResponse | None:
    """None when allowed (and `request.state.identity` is set); otherwise the 401/403 response."""
    path = request.url.path
    if not path.startswith("/api/") or path in PUBLIC:
        return None
    ident = store.identify(request.cookies.get(auth.SESSION_COOKIE))
    if ident is None:
        return JSONResponse(status_code=401, content={"detail": "Sign in to continue."})
    need = required_role(request.method, path)
    if not ident.can(need):
        return JSONResponse(status_code=403, content={"detail": f"This needs the {need} role; you are {ident.role}."})
    request.state.identity = ident
    return None


def who(request: Request) -> Identity | None:
    return getattr(request.state, "identity", None)


# --------------------------------------------------------------------------- request models


class RegisterRequest(BaseModel):
    email: str = Field(max_length=254)
    name: str = Field(max_length=100)
    password: str = Field(max_length=256)
    invite: str | None = Field(default=None, max_length=100)


class LoginRequest(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(max_length=256)


class PasswordRequest(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(max_length=256)


class RoleRequest(BaseModel):
    role: str = Field(max_length=20)


class InviteRequest(BaseModel):
    email: str = Field(max_length=254)
    role: str = Field(default="editor", max_length=20)


class WorkspaceRequest(BaseModel):
    name: str = Field(max_length=200)


# --------------------------------------------------------------------------- helpers


def github_oauth_from_env() -> GitHubOAuth | None:
    cid, secret = os.environ.get("VITRIX_GITHUB_CLIENT_ID", "").strip(), os.environ.get("VITRIX_GITHUB_CLIENT_SECRET", "").strip()
    return GitHubOAuth(cid, secret) if cid and secret else None


def _secure(request: Request) -> bool:
    return request.url.scheme == "https" or os.environ.get("VITRIX_COOKIE_SECURE") == "1"


def _client_ip(request: Request) -> str:
    if os.environ.get("VITRIX_TRUST_PROXY") == "1":  # only behind a proxy you control
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.client.host if request.client else ""


def _public_url(request: Request) -> str:
    base = os.environ.get("VITRIX_PUBLIC_URL", "").rstrip("/")
    return base or f"{request.url.scheme}://{request.headers.get('host', 'localhost')}"


def _start_session(store: AuthStore, request: Request, response: Response, user_id: int) -> None:
    token = store.create_session(user_id)  # a fresh token on every login: no session fixation
    response.set_cookie(auth.SESSION_COOKIE, token, max_age=store.cfg.session_days * 86400, httponly=True, samesite="lax", secure=_secure(request), path="/")


def _me(store: AuthStore, ident: Identity | None) -> dict:
    return {"enabled": True, "authenticated": ident is not None, "user": ident.public() if ident else None,
            "workspace": store.workspace_name, "can": {r: ident.can(r) for r in auth.ROLES} if ident else {}}


def _fail(exc: AuthError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=str(exc))


# --------------------------------------------------------------------------- routes


def install(app: FastAPI, cfg: Config, store: AuthStore | None, oauth: GitHubOAuth | None) -> None:
    """Always serves /api/auth/config and /api/auth/me (the UI asks them first); the rest only when enabled."""

    @app.get("/api/auth/config")
    def auth_config() -> dict:
        if store is None:
            return {"enabled": False}
        return {"enabled": True, "workspace": store.workspace_name, "bootstrap": store.user_count() == 0,
                "registration": "owner-bootstrap" if store.user_count() == 0 else "invite-only", "github": oauth is not None and cfg.auth.github_login}

    @app.get("/api/auth/me")
    def me(request: Request) -> dict:
        if store is None:
            return {"enabled": False, "authenticated": True, "user": None, "workspace": None, "can": {r: True for r in auth.ROLES}}
        return _me(store, store.identify(request.cookies.get(auth.SESSION_COOKIE)))

    if store is None:
        return

    @app.post("/api/auth/register", status_code=201)
    def register(req: RegisterRequest, request: Request) -> JSONResponse:
        try:
            ident = auth.register_local(store, req.email, req.name, req.password, req.invite)
        except AuthError as exc:
            raise _fail(exc) from None
        response = JSONResponse(status_code=201, content=_me(store, ident))
        _start_session(store, request, response, ident.user_id)
        return response

    @app.post("/api/auth/login")
    def login(req: LoginRequest, request: Request) -> JSONResponse:
        try:
            uid = store.verify_login(req.email, req.password, _client_ip(request))
        except AuthError as exc:
            store.log(req.email.strip().lower()[:120], "login.failed", f"ip {_client_ip(request)}")
            raise _fail(exc) from None
        token = store.create_session(uid)
        ident = store.identify(token)
        store.log(ident, "login", "password")
        response = JSONResponse(content=_me(store, ident))
        response.set_cookie(auth.SESSION_COOKIE, token, max_age=cfg.auth.session_days * 86400, httponly=True, samesite="lax", secure=_secure(request), path="/")
        return response

    @app.post("/api/auth/logout")
    def logout(request: Request) -> JSONResponse:
        store.end_session(request.cookies.get(auth.SESSION_COOKIE))
        response = JSONResponse(content={"ok": True})
        response.delete_cookie(auth.SESSION_COOKIE, path="/")
        return response

    @app.post("/api/auth/password")
    def change_password(req: PasswordRequest, request: Request) -> dict:
        ident = who(request)
        assert_ident(ident)
        try:
            store.change_password(ident.user_id, req.current, req.new, ident.session_hash)  # type: ignore[union-attr]
        except AuthError as exc:
            raise _fail(exc) from None
        store.log(ident, "password.changed", "other sessions revoked")
        return {"ok": True}

    # ------------------------------------------------------------------- GitHub OAuth

    @app.get("/api/auth/github/start")
    def github_start(request: Request, invite: str | None = None) -> Response:
        if oauth is None or not cfg.auth.github_login:
            raise HTTPException(status_code=404, detail="GitHub sign-in is not configured.")
        state = secrets.token_urlsafe(24)
        response = RedirectResponse(oauth.authorize_url(state, _public_url(request) + "/api/auth/github/callback"), status_code=302)
        # state (+ optional invite token) in an HttpOnly cookie: the callback must present the same state
        value = f"{state}.{(invite or '')[:100]}"
        response.set_cookie(auth.OAUTH_COOKIE, value, max_age=600, httponly=True, samesite="lax", secure=_secure(request), path="/api/auth/github")
        return response

    @app.get("/api/auth/github/callback")
    def github_callback(request: Request, code: str = "", state: str = "", error: str = "") -> Response:
        def back(message: str | None = None) -> Response:
            target = "/" if message is None else "/?" + urllib.parse.urlencode({"auth_error": message})
            resp = RedirectResponse(target, status_code=302)
            resp.delete_cookie(auth.OAUTH_COOKIE, path="/api/auth/github")
            return resp

        if oauth is None or not cfg.auth.github_login:
            return back("GitHub sign-in is not configured.")
        cookie = request.cookies.get(auth.OAUTH_COOKIE, "")
        expected, _, invite = cookie.partition(".")
        if error or not code or not expected or not hmac.compare_digest(expected, state):
            return back("The GitHub sign-in could not be verified. Start again.")  # state mismatch = possible CSRF
        try:
            profile = oauth.profile(code, _public_url(request) + "/api/auth/github/callback")
            uid = auth.login_github(store, profile, invite or None)
        except AuthError as exc:
            return back(str(exc))
        token = store.create_session(uid)
        store.log(store.identify(token), "login", f"GitHub @{profile['login']}")
        response = back()
        response.set_cookie(auth.SESSION_COOKIE, token, max_age=cfg.auth.session_days * 86400, httponly=True, samesite="lax", secure=_secure(request), path="/")
        return response

    # ------------------------------------------------------------------- workspace

    @app.get("/api/workspace")
    def workspace(request: Request) -> dict:
        ident = who(request)
        assert_ident(ident)
        out: dict = {"name": store.workspace_name, "role": ident.role, "member_count": len(store.members())}  # type: ignore[union-attr]
        if ident.can("admin"):  # type: ignore[union-attr]
            out["members"] = store.members()
            out["invites"] = store.invites()
        return out

    @app.patch("/api/workspace")
    def rename(req: WorkspaceRequest, request: Request) -> dict:
        try:
            store.rename_workspace(req.name)
        except AuthError as exc:
            raise _fail(exc) from None
        store.log(who(request), "workspace.renamed", req.name[:80])
        return {"name": store.workspace_name}

    @app.patch("/api/workspace/members/{user_id}")
    def set_role(user_id: int, req: RoleRequest, request: Request) -> dict:
        ident = who(request)
        assert_ident(ident)
        try:
            store.set_role(ident, user_id, req.role)  # type: ignore[arg-type]
        except AuthError as exc:
            raise _fail(exc) from None
        store.log(ident, "member.role", f"user {user_id} → {req.role}")
        return {"ok": True}

    @app.delete("/api/workspace/members/{user_id}")
    def remove(user_id: int, request: Request) -> dict:
        ident = who(request)
        assert_ident(ident)
        try:
            store.remove_member(ident, user_id)  # type: ignore[arg-type]
        except AuthError as exc:
            raise _fail(exc) from None
        store.log(ident, "member.removed", f"user {user_id}")
        return {"ok": True}

    @app.post("/api/workspace/invites", status_code=201)
    def invite(req: InviteRequest, request: Request) -> dict:
        ident = who(request)
        assert_ident(ident)
        try:
            token = store.create_invite(ident, req.email, req.role)  # type: ignore[arg-type]
        except AuthError as exc:
            raise _fail(exc) from None
        store.log(ident, "invite.created", f"{req.email.strip().lower()} as {req.role}")
        # shown once: only the hash is stored. No email is sent; the admin shares the link.
        return {"link": f"{_public_url(request)}/?invite={urllib.parse.quote(token)}", "email": req.email.strip().lower(), "role": req.role,
                "expires_in_days": auth.INVITE_DAYS}

    @app.delete("/api/workspace/invites/{invite_id}")
    def revoke(invite_id: int, request: Request) -> dict:
        store.revoke_invite(invite_id)
        store.log(who(request), "invite.revoked", f"invite {invite_id}")
        return {"ok": True}

    @app.get("/api/workspace/audit")
    def audit(limit: int = 100) -> list[dict]:
        return store.audit(limit)


def assert_ident(ident: Identity | None) -> None:
    if ident is None:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
