"""Vitrix HTTP API (FastAPI) and web UI server.

Nothing here writes to the local disk except local drafts (rows in `<data_dir>/drafts.db`, see
drafts.py; with accounts off only for a loopback client on a localhost-only server). The only
writes to the repository go to GitHub with the token from the environment (see github.py), and
always in two steps: push a branch so the real CI validates it, then open the pull request only
if that CI passed. The API has no authentication, so
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
    GET  /api/drift?ref=               rule matches now vs at a Git ref (default: base branch)
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
    GET|POST /api/drafts               local drafts: list / save (no PR)
    GET|PUT|DELETE /api/drafts/{id}    load / update (optimistic `version`, 409) / delete a draft
    /api/auth/*  /api/workspace/*      accounts, GitHub sign-in, members, invites, audit (when auth.enabled)
"""

from __future__ import annotations

import ipaddress
import os
import re
import time
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, auth, auth_api, flow, history, local_rules, packs_api, publication, regex_lab, reviews_api, service, sync_api
from . import drafts as drafts_mod
from . import drift as drift_mod
from . import replay as replay_mod
from .backends import available_targets
from .config import ConfigHolder
from .evaluator import regex_budget
from .github import GitHubError
from .related import related_rules
from .replay import ReplayError

MAX_TEXT = 200_000  # characters per text field
UI_DIR = Path(__file__).parent / "ui"  # UI build (web/ -> npm run build)


class ValidateRequest(BaseModel):
    rule: str = Field(max_length=MAX_TEXT, description="Sigma rule YAML")
    cases: str | None = Field(default=None, max_length=MAX_TEXT, description="test cases YAML (optional)")
    targets: list[str] | None = Field(default=None, max_length=10, description="targets; default: those in vitrix.yml")
    path: str | None = Field(default=None, max_length=300, description="rule path inside rules/ when editing an existing rule")


class RelatedRequest(BaseModel):
    rule: str = Field(max_length=MAX_TEXT)
    limit: int = Field(default=8, ge=1, le=50)


class ImpactRequest(BaseModel):
    rule: str = Field(max_length=MAX_TEXT)
    path: str | None = Field(default=None, max_length=300)


class SubmitRuleRequest(BaseModel):
    path: str = Field(min_length=1, max_length=300, description="rule path inside rules/, e.g. windows/x.yml")
    source: Literal["text", "file"] = Field(default="text", description="'file': publish the saved rule file (rule/cases must be absent)")
    sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$", description="source=file: sha of the rule file you saw")
    cases_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$", description="source=file: sha of the cases file you saw")
    rule: str | None = Field(default=None, min_length=1, max_length=MAX_TEXT, description="Sigma rule YAML (source=text)")
    cases: str | None = Field(default=None, max_length=MAX_TEXT, description="test cases YAML (optional)")
    title: str | None = Field(default=None, max_length=200, description="pull request title (optional)")
    draft_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$", description="the draft this rule was loaded from (for Reviewed-by)")


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


class ReplayDraftRequest(BaseModel):
    rule: str = Field(max_length=MAX_TEXT, description="the unsaved rule YAML from the Editor")
    datasets: list[str] | None = Field(default=None, max_length=50, description="dataset names; default: all")
    path: str | None = Field(default=None, max_length=500, description="rule id if editing an existing rule (expectation lookup)")
    cases: str | None = Field(default=None, max_length=MAX_TEXT, description="cases YAML of the draft; default: the saved cases of `path`")
    compare: bool = Field(default=False, description="add before/added/removed per dataset against the saved version of `path`")


class RegexRequest(BaseModel):
    pattern: str = Field(max_length=2_000)
    flags: str = Field(default="", max_length=3, description="i, m and/or s (Sigma's |re|i|m|s)")
    samples: list[str] = Field(default_factory=list, max_length=50)
    targets: list[str] | None = Field(default=None, max_length=10, description="targets to check flavors for; default: the configured ones")


class ConfigTextRequest(BaseModel):
    text: str = Field(max_length=MAX_TEXT, description="vitrix.yml content")


class DraftRequest(BaseModel):
    path: str | None = Field(default=None, max_length=300, description="rule path inside rules/ (metadata only)")
    title: str | None = Field(default=None, max_length=drafts_mod.MAX_TITLE)
    rule: str = Field(min_length=1, max_length=MAX_TEXT, description="Sigma rule YAML (may be invalid)")
    cases: str | None = Field(default=None, max_length=MAX_TEXT)


class LocalRuleCreate(BaseModel):
    path: str = Field(min_length=1, max_length=300)
    rule: str = Field(min_length=1, max_length=MAX_TEXT)
    cases: str | None = Field(default=None, max_length=MAX_TEXT)


class LocalRuleUpdate(BaseModel):
    rule: str = Field(min_length=1, max_length=MAX_TEXT)
    cases: str | None = Field(default=None, max_length=MAX_TEXT, description="null = leave the cases file unchanged")
    remove_cases: bool = False
    sha: str = Field(pattern=r"^[0-9a-f]{64}$")
    cases_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class SubmitLocalRulesRequest(BaseModel):
    paths: list[str] = Field(min_length=1, max_length=50, description="local rule ids to publish as one branch")
    title: str | None = Field(default=None, max_length=200)


class SubmitDraftsRequest(BaseModel):
    draft_ids: list[str] = Field(min_length=1, max_length=50, description="drafts to publish as one branch")
    title: str | None = Field(default=None, max_length=200)


class DraftUpdateRequest(DraftRequest):
    version: int = Field(ge=1, description="the version you loaded; 409 if the draft changed since")


_DRAFT_ID = re.compile(r"^[0-9a-f]{32}$")
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
        err = HTTPException(status_code=422, detail=str(exc))
        err.blocked = getattr(exc, "blocked", None)  # type: ignore[attr-defined]  # DraftsBlocked carries the per-draft reasons
        raise err from None
    except GitHubError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from None


def create_app(config_path: str | None = None) -> FastAPI:
    holder = ConfigHolder(config_path or os.environ.get("VITRIX_CONFIG"), debounce=float(os.environ.get("VITRIX_CONFIG_RELOAD_SECONDS", "1")))  # re-reads vitrix.yml when it changes
    cfg = holder.live
    app = FastAPI(title="Vitrix API", version=__version__)

    origins = [o.strip() for o in os.environ.get("VITRIX_CORS_ORIGINS", "").split(",") if o.strip()]
    if origins:
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["Content-Type"])
    hosts = allowed_hosts()
    store = auth.AuthStore(cfg.data_dir / "vitrix.db", cfg.auth) if cfg.auth.enabled and cfg.data_dir else None
    oauth = auth_api.github_oauth_from_env() if store is not None and cfg.auth.github_login else None
    setup_token = auth_api.setup_token_for(cfg) if store is not None else None
    auto_generated = bool(setup_token) and (cfg.auth.bootstrap_token or "auto") == "auto"
    if setup_token and auto_generated and store is not None and store.user_count() == 0:  # nosec B105
        auth_api.announce_setup_token(setup_token, os.environ.get("VITRIX_PUBLIC_URL") or os.environ.get("VITRIX_SERVE_URL") or "http://localhost:8000")

    @app.middleware("http")
    async def _guard(request: Request, call_next):  # noqa: ANN001, ANN202
        problem = request_problem(request.method, request.url.path, {k.lower(): v for k, v in request.headers.items()}, hosts, origins)
        if problem:
            return JSONResponse(status_code=problem[0], content={"detail": problem[1]})
        if store is not None:
            denied = auth_api.authorize(store, request)  # sessions and roles; sets request.state.identity
            if denied is not None:
                return denied
        with holder.snapshot():  # one config version for the whole request
            response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")  # account and workspace data must not be cached
        return response

    app.state.setup_token = setup_token  # tests and embedders; never returned by any route
    auth_api.install(app, cfg, store, oauth, setup_token)

    @app.exception_handler(service.ServiceError)
    def _service_error(_, exc: service.ServiceError):  # noqa: ANN001
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "version": __version__}

    @app.get("/api/config")
    def config() -> dict:
        return {**service.config_view(cfg), **holder.status()}

    @app.post("/api/config/validate")
    def config_validate(req: ConfigTextRequest) -> dict:
        return service.validate_config_text(cfg, req.text)

    @app.get("/api/targets")
    def targets() -> list[dict]:
        return service.targets_view(cfg)

    @app.get("/api/stats")
    def stats() -> dict:
        return service.repo_stats(cfg)

    @app.get("/api/rules")
    def rules(publication_state: str | None = Query(default=None, alias="publication", max_length=20)) -> list[dict]:
        items = service.list_rules(cfg)
        pm = publication.publication_map(cfg)
        unknown = publication._info("unknown", reason="no file")  # noqa: SLF001
        for item in items:
            item["publication"] = pm.get(item["id"], unknown)
        if publication_state:
            wanted = {"unmerged": {"local", "pushed", "in_pr"}}.get(publication_state, {publication_state})
            items = [i for i in items if i["publication"]["state"] in wanted]
        return items

    @app.get("/api/rules/{rid:path}/related")
    def rule_related(rid: str, limit: int = Query(default=8, ge=1, le=50)) -> list[dict]:
        if service.resolve_rule(cfg, rid) is None:
            raise HTTPException(status_code=404, detail="rule not found")
        return related_rules(cfg, rid=rid, limit=limit)

    @app.post("/api/related")
    def related_unsaved(req: RelatedRequest) -> list[dict]:
        return related_rules(cfg, text=req.rule, limit=req.limit)

    def rule_view(rid: str) -> dict:
        try:
            detail = service.rule_detail(cfg, rid)
        except KeyError:
            raise HTTPException(status_code=404, detail="rule not found") from None
        try:
            disk = local_rules.read(cfg, detail["id"])
            sha, cases_sha = disk["sha"], disk["cases_sha"]
        except local_rules.LocalRuleError:
            sha = cases_sha = None
        pub = publication.publication_map(cfg, only=detail["id"]).get(detail["id"]) or publication._info("unknown", reason="no file")  # noqa: SLF001
        return {**detail, "sha": sha, "cases_sha": cases_sha, "publication": pub}

    @app.get("/api/rules/{rid:path}")
    def rule(rid: str) -> dict:
        return rule_view(rid)

    def local_errors(fn):  # noqa: ANN001, ANN202
        try:
            return fn()
        except local_rules.LocalRuleError as exc:
            if exc.issues:
                raise HTTPException(status_code=exc.status, detail={"message": str(exc), "issues": exc.issues}) from None
            raise HTTPException(status_code=exc.status, detail=str(exc)) from None

    def local_ready(request: Request) -> None:
        reason = local_writes_off(request)
        if reason:
            raise HTTPException(status_code=403, detail=f"Local rules are off: {reason}")

    @app.post("/api/rules", status_code=201)
    def rules_create(req: LocalRuleCreate, request: Request) -> dict:
        local_ready(request)
        made = local_errors(lambda: local_rules.create(cfg, req.path, req.rule, req.cases))
        if store is not None:
            store.log(auth_api.who(request), "rule.saved_local", f"{made['id']} created sha {made['sha'][:7]}")
        return rule_view(made["id"])

    @app.put("/api/rules/{rid:path}")
    def rules_update(rid: str, req: LocalRuleUpdate, request: Request) -> dict:
        local_ready(request)
        made = local_errors(lambda: local_rules.update(cfg, rid, req.rule, req.cases, req.remove_cases, req.sha, req.cases_sha))
        if store is not None:
            store.log(auth_api.who(request), "rule.saved_local", f"{made['id']} updated sha {made['sha'][:7]}")
        return rule_view(made["id"])

    @app.delete("/api/rules/{rid:path}", status_code=204)
    def rules_delete(rid: str, request: Request, sha: str = Query(pattern=r"^[0-9a-f]{64}$")) -> Response:
        local_ready(request)
        local_errors(lambda: local_rules.delete(cfg, rid, sha))
        if store is not None:
            store.log(auth_api.who(request), "rule.deleted_local", rid)
        return Response(status_code=204)

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
        with regex_budget():
            result = service.validate_text(cfg, req.rule, req.cases, req.targets)
            result["quality"] = flow.draft_quality(cfg, result, req.rule, bool(req.cases and req.cases.strip()), path)
        return result

    @app.post("/api/impact")
    def impact(req: ImpactRequest) -> dict:
        try:
            path = service.normalize_rule_path(req.path) if req.path else None
            with regex_budget():
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

    @app.get("/api/drift")
    def rule_drift(ref: str | None = None, rule: str | None = Query(default=None, max_length=300)) -> dict:
        """Matches per rule now vs at a Git ref (default: base branch). Read-only."""
        try:
            with regex_budget(30):
                return drift_mod.drift(cfg, ref.strip() if ref and ref.strip() else None, rule.strip() if rule and rule.strip() else None)
        except drift_mod.DriftError as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from None
        except ReplayError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

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
            with regex_budget():
                return flow.replay_text(cfg, req.events, req.rule)
        except ReplayError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.get("/api/replay/datasets")
    def replay_datasets() -> list[dict]:
        return replay_mod.list_dataset_info(cfg)

    @app.post("/api/replay/draft")
    def replay_draft(req: ReplayDraftRequest) -> dict:
        try:
            with regex_budget():
                return replay_mod.replay_draft(cfg, req.rule, req.datasets, req.path, req.cases, req.compare)
        except ReplayError as exc:  # structured: {code, message, hint}
            raise HTTPException(status_code=422, detail=exc.payload()) from None

    @app.post("/api/regex")
    def regex(req: RegexRequest) -> dict:
        try:
            return regex_lab.analyze(req.pattern, req.flags, req.samples, targets=req.targets if req.targets is not None else list(cfg.targets))
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
        rule_text, cases_text, sha = req.rule, req.cases, None
        if req.source == "file":
            if req.rule is not None or req.cases is not None:
                raise HTTPException(status_code=422, detail="source=file reads the saved files: do not send rule or cases")
            if not req.sha:
                raise HTTPException(status_code=422, detail="source=file needs the sha of the saved rule")
            disk = local_errors(lambda: local_rules.read(cfg, req.path, strict=True))
            if disk["sha"] != req.sha or disk["cases_sha"] != req.cases_sha:
                raise HTTPException(status_code=409, detail="the rule changed on disk since you loaded it")
            rule_text, cases_text, sha = disk["rule"], disk["cases"], disk["sha"]
        elif rule_text is None:
            raise HTTPException(status_code=422, detail="rule is required")
        content = {("rule", req.path.strip().replace("\\", "/").strip("/")): rule_text}  # a bad path fails below
        if req.draft_id:
            content[("draft", req.draft_id)] = rule_text
        trailers = reviews.trailers(content)
        try:
            published = publication.in_base(cfg, local_rules.normalize_id(req.path))
        except local_rules.LocalRuleError:
            published = None
        is_new = (True if req.source == "file" else None) if published is None else not published
        out = _github_errors(lambda: service.submit_rule(cfg, req.path, rule_text, cases_text, req.title, submitted_by=auth.attribution(who) if who else "",
                                                         trailers=trailers, is_new=is_new))
        publication.invalidate()
        if sha:
            out["sha"] = sha
        if store is not None:
            store.log(who, "rule.ci_submitted", f"{req.path} → {out['branch']} @ {out['commit'][:7]}" + (f" sha {sha[:7]}" if sha else ""))
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

    # ------------------------------------------------------------------ local drafts (ADR 0001)
    drafts = drafts_mod.DraftStore(cfg.data_dir / "drafts.db") if cfg.drafts_enabled and cfg.data_dir else None

    def local_writes_off(request: Request) -> str | None:
        """Why writing local rule files is unavailable for this request, or None (ADR 0007)."""
        if not cfg.local_rules_enabled:
            return "local rules are off (local_rules.enabled: false)"
        return writes_off(request, "local rules")

    def drafts_off(request: Request) -> str | None:
        """Why drafts are unavailable for this request, or None. Without accounts only a loopback
        client of a localhost-only server may write (Host alone can be forged by non-browser clients)."""
        if drafts is None:
            return "disabled in vitrix.yml (drafts.enabled: false)"
        return writes_off(request, "drafts")

    def writes_off(request: Request, what: str) -> str | None:
        if store is not None:
            return None
        host = request.client.host if request.client else ""
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            return f"accounts are off, so {what} only work from this machine (in Docker, turn on accounts: auth.enabled: true)"
        if not hosts <= LOCAL_HOSTS:
            return "accounts are off and this server accepts non-local hosts"
        return None

    def drafts_ready(request: Request, draft_id: str | None = None) -> drafts_mod.DraftStore:
        reason = drafts_off(request)
        if reason or drafts is None:
            raise HTTPException(status_code=403, detail=f"Local drafts are off: {reason}")
        if draft_id is not None and not _DRAFT_ID.match(draft_id):
            raise HTTPException(status_code=404, detail="draft not found")
        return drafts

    draft_meta: dict[tuple[str, int], dict] = {}

    def draft_extras(row: dict) -> dict:
        """level, final language and quality gate summary of a draft (cached per draft version)."""
        key = (row["id"], row["version"])
        if key not in draft_meta:
            if len(draft_meta) > 500:
                draft_meta.clear()
            try:
                val = service.validate_text(cfg, row["rule"], row["cases"])
                q = flow.draft_quality(cfg, val, row["rule"], row["cases"] is not None, row["path"])
                quality = {"ready": bool(q["ready"]), "blockers": len(q["blockers"]), "score": q["score"]}
            except Exception:  # noqa: BLE001 - a broken draft must still be listed
                val, quality = {}, None
            try:
                import yaml as _yaml
                doc = next((d for d in _yaml.safe_load_all(row["rule"]) if isinstance(d, dict)), {})
                level = doc.get("level") if isinstance(doc.get("level"), str) else None
            except Exception:  # noqa: BLE001
                level = None
            targets = val.get("targets") or []
            draft_meta[key] = {"quality": quality, "level": level, "target": targets[0] if targets else None}
        return draft_meta[key]

    def draft_json(request: Request, row: dict, full: bool = True) -> dict:
        who = auth_api.who(request)
        out = drafts_mod.public(row, current_hash=drafts_mod.rule_hash(cfg.rules_dir, row["path"]),
                                me_id=who.user_id if who else None, auth_on=store is not None, full=full)
        return {**out, **draft_extras(row)}

    def draft_fields(req: DraftRequest) -> dict:
        try:
            path = service.normalize_rule_path(req.path) if req.path and req.path.strip() else None
        except service.ChangeError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"path": path, "title": req.title, "rule": req.rule, "cases": req.cases,
                "base_hash": drafts_mod.rule_hash(cfg.rules_dir, path)}

    def visible(request: Request, row: dict) -> bool:
        """Drafts are private scratch (ADR 0007): only their author sees them. Authorless ones (saved with
        accounts off) stay shared. Anyone else gets the same 404 as for a missing id, admins included."""
        who = auth_api.who(request)
        return store is None or row["author_id"] is None or (who is not None and row["author_id"] == who.user_id)

    def own_draft(request: Request, db: drafts_mod.DraftStore, draft_id: str) -> dict:
        row = db.get(draft_id)
        if not visible(request, row):
            raise HTTPException(status_code=404, detail="draft not found")
        return row

    sweep = {"at": 0.0}

    def sweep_drafts(force: bool = False) -> None:
        """Drop drafts of users with no live session (expiry), at most every 10 minutes."""
        if store is None or drafts is None or (not force and time.monotonic() - sweep["at"] < 600):
            return
        sweep["at"] = time.monotonic()
        store.sweep_expired()
        drafts.purge_except(store.active_user_ids())

    if store is not None and drafts is not None:
        store.on_user_done.append(drafts.delete_for_author)  # logout, last session expired, account removal
        sweep_drafts(force=True)

    @app.exception_handler(drafts_mod.DraftError)
    def _draft_error(_, exc: drafts_mod.DraftError):  # noqa: ANN001
        return JSONResponse(status_code=exc.status, content={"detail": str(exc)})

    @app.get("/api/drafts")
    def drafts_list(request: Request, batch: str | None = None) -> dict:
        reason = drafts_off(request)
        if reason or drafts is None:
            return {"enabled": False, "reason": reason, "drafts": []}
        sweep_drafts()
        return {"enabled": True, "reason": None, "drafts": [draft_json(request, r, full=False) for r in drafts.list(batch) if visible(request, r)]}

    @app.post("/api/drafts", status_code=201)
    def drafts_create(req: DraftRequest, request: Request) -> dict:
        db = drafts_ready(request)
        who = auth_api.who(request)
        author = {"id": who.user_id, "email": who.email, "name": who.name} if who else None
        return draft_json(request, db.create(author=author, **draft_fields(req)))

    @app.get("/api/drafts/{draft_id}")
    def drafts_get(draft_id: str, request: Request) -> dict:
        return draft_json(request, own_draft(request, drafts_ready(request, draft_id), draft_id))

    @app.put("/api/drafts/{draft_id}")
    def drafts_update(draft_id: str, req: DraftUpdateRequest, request: Request) -> dict:
        db = drafts_ready(request, draft_id)
        own_draft(request, db, draft_id)  # 404 unless yours (or an authorless shared draft)
        return draft_json(request, db.update(draft_id, version=req.version, **draft_fields(req)))

    @app.delete("/api/drafts/{draft_id}", status_code=204)
    def drafts_delete(draft_id: str, request: Request) -> Response:
        db = drafts_ready(request, draft_id)
        own_draft(request, db, draft_id)
        db.delete(draft_id)
        return Response(status_code=204)

    app.include_router(packs_api.build_router(cfg, off=local_writes_off, auth_on=store is not None, audit=store.log if store is not None else None))  # S6, ADR 0004
    def draft_authors(rows: list[dict], publisher) -> list[str]:  # noqa: ANN001
        """`Co-authored-by` for each other draft author with a GitHub-linked account (same rule as `auth.attribution`)."""
        out: dict[int, str] = {}
        for uid in {r["author_id"] for r in rows if r["author_id"] not in (None, publisher.user_id if publisher else None)}:
            u = store._user("id", uid) if store is not None else None
            if u is not None and u["github_id"] and u["github_login"]:
                ident = auth.Identity(u["id"], u["email"], u["name"], "viewer", u["github_login"], None, u["github_id"])
                out[uid] = next(line for line in auth.attribution(ident).splitlines() if line.startswith("Co-authored-by"))
        return [out[k] for k in sorted(out)]

    @app.post("/api/ci/drafts", status_code=201, response_model=None)
    def ci_submit_drafts(req: SubmitDraftsRequest, request: Request):  # noqa: ANN202
        """Publish several drafts as one `vitrix/pack-...` branch (all pass the gate, or 422 and nothing is pushed)."""
        db = drafts_ready(request)
        ids = list(dict.fromkeys(req.draft_ids))
        if not all(_DRAFT_ID.match(i) for i in ids):
            raise HTTPException(status_code=422, detail="draft_ids must be 32-character draft ids")
        rows = [own_draft(request, db, i) for i in ids]  # 404 if one is missing or not yours
        who = auth_api.who(request)
        trailers = draft_authors(rows, who) + reviews.trailers({k: row["rule"] for row in rows for k in (("draft", row["id"]), ("rule", row["path"])) if k[1]})
        try:
            out = _github_errors(lambda: service.submit_drafts(cfg, rows, req.title, submitted_by=auth.attribution(who) if who else "", trailers=trailers))
        except HTTPException as exc:
            blocked = getattr(exc, "blocked", None)
            if blocked is None:
                raise
            return JSONResponse(status_code=422, content={"detail": exc.detail, "blocked": blocked})
        if store is not None:
            store.log(who, "drafts.ci_submitted", f"{len(ids)} drafts → {out['branch']} @ {out['commit'][:7]}")
        return out

    @app.post("/api/ci/local-rules", status_code=201, response_model=None)
    def ci_submit_local_rules(req: SubmitLocalRulesRequest, request: Request):  # noqa: ANN202
        """Publish several saved local rules as one `vitrix/pack-...` branch (all pass the gate, or 422 and nothing is pushed)."""
        who = auth_api.who(request)
        ids = list(dict.fromkeys(req.paths))
        rows = []
        for rid in ids:
            disk = local_errors(lambda rid=rid: local_rules.read(cfg, rid, strict=True))
            rows.append({"id": disk["id"], "path": disk["id"], "title": None, "rule": disk["rule"], "cases": disk["cases"]})
        trailers = reviews.trailers({("rule", r["path"]): r["rule"] for r in rows})
        try:
            out = _github_errors(lambda: service.submit_drafts(cfg, rows, req.title, submitted_by=auth.attribution(who) if who else "", trailers=trailers))
        except HTTPException as exc:
            blocked = getattr(exc, "blocked", None)
            if blocked is None:
                raise
            return JSONResponse(status_code=422, content={"detail": exc.detail, "blocked": blocked})
        publication.invalidate()
        if store is not None:
            store.log(who, "rule.ci_submitted", f"{len(ids)} local rules → {out['branch']} @ {out['commit'][:7]}")
        return out

    reviews = reviews_api.Reviews(cfg, store, drafts)
    app.include_router(reviews.router)

    app.include_router(sync_api.build_router(holder, store, local_only=hosts <= LOCAL_HOSTS))  # U1, ADR 0006

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
