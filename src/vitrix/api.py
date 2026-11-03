"""Vitrix HTTP API (FastAPI) and web UI server.

Nothing here writes to the local disk. The only writes go to GitHub with the token from the
environment (see github.py), and always in two steps: push a branch so the real CI validates
it, then open the pull request only if that CI passed. The API has no authentication, so
`vitrix serve` listens on localhost by default and every request goes through
`request_problem` (Host, Origin, JSON-only POST: against DNS rebinding and CSRF).

    GET  /api/health
    GET  /api/config                   effective configuration and vitrix.yml text
    POST /api/config/validate          validate an edited vitrix.yml
    GET  /api/targets
    GET  /api/stats                    dashboard numbers
    GET  /api/rules                    every rule with its state
    GET  /api/rules/{id}               rule, lint, queries per SIEM and tests
    POST /api/validate                 validate an unsaved rule (with its quality gate)
    POST /api/impact                   impact analysis: saved rule vs. edited version on the datasets
    GET  /api/quality[/{id}]           lifecycle and quality gate, rule by rule
    GET  /api/tests                    test suites: every case, by kind
    GET  /api/coverage                 ATT&CK matrix and data sources
    GET  /api/coverage/navigator       ATT&CK Navigator layer (JSON)
    GET  /api/history[/{id}]           Git history: coverage over time, activity, audit trail
    GET  /api/datasets                 replay datasets in datasets/
    GET  /api/datasets/{name}/replay   replay one dataset with its expectations
    POST /api/replay                   replay pasted events (all rules or the edited one)
    POST /api/regex                    Regex Workbench (subprocess with a timeout)
    GET  /api/report?format=md|json    consolidated report
    GET  /api/github                   configured repository and whether a token exists (never the token)
    GET  /api/github/activity          open PRs, CI runs and time to merge (60 s cache)
    POST /api/ci/rules                 step 1: push a rule to a branch so the real CI validates it
    POST /api/ci/config                step 1 for vitrix.yml
    GET  /api/ci/status?commit=SHA     state of the real CI for that commit
    POST /api/pull-requests            step 2: open the PR, only if CI passed for that commit
    /api/auth/*  /api/workspace/*      accounts, GitHub sign-in, members, invites, audit (when auth.enabled)
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, auth, auth_api, flow, history, regex_lab, service
from .backends import available_targets
from .config import load_config
from .github import GitHubError
from .replay import ReplayError

MAX_TEXT = 200_000  # characters per text field
UI_DIR = Path(__file__).parent / "ui"  # UI build (web/ -> npm run build)


class ValidateRequest(BaseModel):
    rule: str = Field(max_length=MAX_TEXT, description="Sigma rule YAML")
    cases: str | None = Field(default=None, max_length=MAX_TEXT, description="test cases YAML (optional)")
    targets: list[str] | None = Field(default=None, max_length=10, description="targets; default: those in vitrix.yml")
    path: str | None = Field(default=None, max_length=300, description="rule path inside rules/ when editing an existing rule")


class ImpactRequest(BaseModel):
    rule: str = Field(max_length=MAX_TEXT)
    path: str | None = Field(default=None, max_length=300)


class SubmitRuleRequest(BaseModel):
    path: str = Field(min_length=1, max_length=300, description="rule path inside rules/, e.g. windows/x.yml")
    rule: str = Field(min_length=1, max_length=MAX_TEXT, description="Sigma rule YAML")
    cases: str | None = Field(default=None, max_length=MAX_TEXT, description="test cases YAML (optional)")
    title: str | None = Field(default=None, max_length=200, description="pull request title (optional)")


class SubmitConfigRequest(BaseModel):
    text: str = Field(max_length=MAX_TEXT, description="vitrix.yml content")
    title: str | None = Field(default=None, max_length=200)


class PullRequestRequest(BaseModel):
    branch: str = Field(min_length=1, max_length=200, description="branch created by step 1")
    commit: str = Field(min_length=40, max_length=40, description="commit validated by CI")
    title: str | None = Field(default=None, max_length=200)


class ReplayRequest(BaseModel):
    events: str = Field(max_length=5_000_000, description="events as JSON, JSON Lines or YAML")
    rule: str | None = Field(default=None, max_length=MAX_TEXT, description="only this rule (Editor); default: all")


class RegexRequest(BaseModel):
    pattern: str = Field(max_length=2_000)
    flags: str = Field(default="", max_length=3, description="i, m and/or s (Sigma's |re|i|m|s)")
    samples: list[str] = Field(default_factory=list, max_length=50)


class ConfigTextRequest(BaseModel):
    text: str = Field(max_length=MAX_TEXT, description="vitrix.yml content")


LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


def _host_only(value: str) -> str:
    value = value.strip().lower()
    if value.startswith("["):
        return value.split("]")[0] + "]"
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def allowed_hosts() -> set[str]:
    """localhost plus VITRIX_ALLOWED_HOSTS (`vitrix serve --host X` adds X)."""
    extra = {_host_only(h) for h in os.environ.get("VITRIX_ALLOWED_HOSTS", "").split(",") if h.strip()}
    return LOCAL_HOSTS | extra


def request_problem(method: str, path: str, headers: dict[str, str], hosts: set[str], allowed_origins: list[str]) -> tuple[int, str] | None:
    """Defence applied to every request (the API has no authentication):

    - Host not in the list → 403. Stops DNS rebinding: a site that points its own domain at
      127.0.0.1 cannot read rules or configuration through the victim's browser.
    - POST/PUT/PATCH/DELETE from another origin → 403, and a non-JSON body → 415. Stops CSRF,
      including the text/plain "simple request" that skips the CORS preflight.
    """
    host = _host_only(headers.get("host", ""))
    if host not in hosts:
        return 403, "host not allowed"
    if method in ("POST", "PUT", "PATCH", "DELETE") and path.startswith("/api/"):
        origin = headers.get("origin")
        if origin and origin not in allowed_origins and _host_only(origin.split("://", 1)[-1]) != host:
            return 403, "origin not allowed"
        # DELETE has no body; a cross-site DELETE needs a CORS preflight we never allow, and Origin is checked above
        if method != "DELETE" and headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            return 415, "send the body as application/json"
    return None


def _github_errors(fn):  # noqa: ANN001, ANN202
    """Map change and GitHub errors to HTTP errors."""
    try:
        return fn()
    except service.ChangeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except GitHubError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from None


def create_app(config_path: str | None = None) -> FastAPI:
    cfg = load_config(config_path or os.environ.get("VITRIX_CONFIG"))
    app = FastAPI(title="Vitrix API", version=__version__)

    origins = [o.strip() for o in os.environ.get("VITRIX_CORS_ORIGINS", "").split(",") if o.strip()]
    if origins:
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
    hosts = allowed_hosts()
    store = auth.AuthStore(cfg.data_dir / "vitrix.db", cfg.auth) if cfg.auth.enabled and cfg.data_dir else None
    oauth = auth_api.github_oauth_from_env() if store is not None and cfg.auth.github_login else None

    @app.middleware("http")
    async def _guard(request: Request, call_next):  # noqa: ANN001, ANN202
        problem = request_problem(request.method, request.url.path, {k.lower(): v for k, v in request.headers.items()}, hosts, origins)
        if problem:
            return JSONResponse(status_code=problem[0], content={"detail": problem[1]})
        if store is not None:
            denied = auth_api.authorize(store, request)  # sessions and roles; sets request.state.identity
            if denied is not None:
                return denied
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")  # account and workspace data must not be cached
        return response

    auth_api.install(app, cfg, store, oauth)

    @app.exception_handler(service.ServiceError)
    def _service_error(_, exc: service.ServiceError):  # noqa: ANN001
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "version": __version__}

    @app.get("/api/config")
    def config() -> dict:
        return service.config_view(cfg)

    @app.post("/api/config/validate")
    def config_validate(req: ConfigTextRequest) -> dict:
        return service.validate_config_text(cfg, req.text)

    @app.get("/api/targets")
    def targets() -> list[dict]:
        return [
            {"name": name, "label": t.label, "extension": t.extension, "active": name in cfg.targets}
            for name, t in sorted(available_targets().items())
        ]

    @app.get("/api/stats")
    def stats() -> dict:
        return service.repo_stats(cfg)

    @app.get("/api/rules")
    def rules() -> list[dict]:
        return service.list_rules(cfg)

    @app.get("/api/rules/{rid:path}")
    def rule(rid: str) -> dict:
        try:
            return service.rule_detail(cfg, rid)
        except KeyError:
            raise HTTPException(status_code=404, detail="rule not found") from None

    @app.post("/api/validate")
    def validate(req: ValidateRequest) -> dict:
        registry = available_targets()
        unknown = [t for t in (req.targets or []) if t not in registry]
        if unknown:
            raise HTTPException(status_code=422, detail=f"unknown target: {', '.join(unknown)}")
        path = None
        if req.path:
            try:
                path = service.normalize_rule_path(req.path)
            except service.ChangeError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from None
        result = service.validate_text(cfg, req.rule, req.cases, req.targets)
        result["quality"] = flow.draft_quality(cfg, result, req.rule, bool(req.cases and req.cases.strip()), path)
        return result

    @app.post("/api/impact")
    def impact(req: ImpactRequest) -> dict:
        try:
            path = service.normalize_rule_path(req.path) if req.path else None
            return flow.impact_analysis(cfg, path, req.rule)
        except (service.ChangeError, ReplayError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.get("/api/quality")
    def quality() -> dict:
        return flow.quality_report(cfg)

    @app.get("/api/quality/{rid:path}")
    def quality_rule(rid: str) -> dict:
        found = flow.quality_report(cfg, only=rid)["rules"]
        if not found:
            raise HTTPException(status_code=404, detail="rule not found")
        return found[0]

    @app.get("/api/tests")
    def tests() -> dict:
        return flow.test_suites(cfg)

    @app.get("/api/coverage")
    def coverage() -> dict:
        return flow.coverage(cfg)

    @app.get("/api/coverage/navigator")
    def navigator() -> JSONResponse:
        return JSONResponse(flow.navigator_layer(cfg), headers={"Content-Disposition": 'attachment; filename="vitrix-attack-layer.json"'})

    @app.get("/api/history")
    def repo_history() -> dict:
        return history.history(cfg)

    @app.get("/api/history/{rid:path}")
    def rule_history(rid: str) -> dict:
        return history.rule_history(cfg, rid)

    @app.get("/api/datasets")
    def datasets() -> list[dict]:
        return flow.list_datasets(cfg)

    @app.get("/api/datasets/{name:path}/replay")
    def dataset_replay(name: str) -> dict:
        try:
            return flow.run_dataset(cfg, name)
        except KeyError:
            raise HTTPException(status_code=404, detail="dataset not found") from None
        except ReplayError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.post("/api/replay")
    def replay_events(req: ReplayRequest) -> dict:
        try:
            return flow.replay_text(cfg, req.events, req.rule)
        except ReplayError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.post("/api/regex")
    def regex(req: RegexRequest) -> dict:
        try:
            return regex_lab.analyze(req.pattern, req.flags, req.samples)
        except regex_lab.RegexLabError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.get("/api/report", response_model=None)
    def report_(format: str = "json"):
        data = flow.report(cfg)
        if format == "md":
            return PlainTextResponse(flow.report_markdown(data), media_type="text/markdown; charset=utf-8")
        return data

    @app.get("/api/github")
    def github() -> dict:
        return service.github_status(cfg)

    @app.get("/api/github/activity")
    def github_activity(refresh: bool = False) -> dict:
        return service.github_activity(cfg, refresh=refresh)

    @app.post("/api/ci/rules", status_code=201)
    def ci_submit_rule(req: SubmitRuleRequest, request: Request) -> dict:
        who = auth_api.who(request)
        out = _github_errors(lambda: service.submit_rule(cfg, req.path, req.rule, req.cases, req.title, submitted_by=auth.attribution(who) if who else ""))
        if store is not None:
            store.log(who, "rule.ci_submitted", f"{req.path} → {out['branch']} @ {out['commit'][:7]}")
        return out

    @app.post("/api/ci/config", status_code=201)
    def ci_submit_config(req: SubmitConfigRequest, request: Request) -> dict:
        who = auth_api.who(request)
        out = _github_errors(lambda: service.submit_config(cfg, req.text, req.title, submitted_by=auth.attribution(who) if who else ""))
        if store is not None:
            store.log(who, "config.ci_submitted", f"{out['branch']} @ {out['commit'][:7]}")
        return out

    @app.get("/api/ci/status")
    def ci_status(commit: str) -> dict:
        return _github_errors(lambda: service.ci_status(cfg, commit))

    @app.post("/api/pull-requests", status_code=201)
    def pull_request(req: PullRequestRequest, request: Request) -> dict:
        out = _github_errors(lambda: service.open_pull_request(cfg, req.branch, req.commit, req.title))
        if store is not None:
            store.log(auth_api.who(request), "pull_request.opened", f"#{out['number']} from {req.branch}")
        return out

    _mount_ui(app)
    return app


def _mount_ui(app: FastAPI) -> None:
    """Serve the web UI at "/", falling back to index.html (React routes)."""
    index = UI_DIR / "index.html"
    if not index.is_file():
        return  # package without the UI build: API only
    ui_root = UI_DIR.resolve()
    app.mount("/assets", StaticFiles(directory=UI_DIR / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def ui(path: str) -> FileResponse:
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status_code=404, detail="route not found")
        candidate = (UI_DIR / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(ui_root):
            return FileResponse(candidate)
        return FileResponse(index)
