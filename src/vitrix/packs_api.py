"""HTTP API of content packs (ADR 0004, 0007): SigmaHQ rules into local rule files, via a background job.

    GET  /api/packs/sources      sources, cached archives, limits (viewer; `enabled:false` when off)
    POST /api/packs/jobs         start a `preview` or `import` job (editor; `refresh` needs admin)
    GET  /api/packs/jobs/{id}    job state for polling (viewer)

An import writes local rule files (`rules/<into>/...` + cases) through `local_rules.create` (same path
guards as Save; an existing file is never overwritten) and the cached archive under
`<data_dir>/cache/packs/`. See packs.py for the archive guards.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from . import auth_api, local_rules, packs
from .config import Config
from .pack_jobs import Job, JobBusy, PackJobs
from .service import ChangeError, normalize_rule_path

MAX_RULES = 50
MAX_PREVIEW_ITEMS = 500
MAX_SKIPPED = 200
_JOB_ID = re.compile(r"^[0-9a-f]{32}$")


class Filters(BaseModel):
    product: str | None = Field(default=None, max_length=100)
    category: str | None = Field(default=None, max_length=100)
    service: str | None = Field(default=None, max_length=100)
    statuses: list[str] = Field(default_factory=lambda: ["stable", "test"], max_length=10)
    text: str | None = Field(default=None, max_length=200)


class JobRequest(BaseModel):
    mode: Literal["preview", "import"]
    source: Literal["sigmahq"] = "sigmahq"
    ref: str = Field(default="master", pattern=r"^(master|r\d{4}-\d{2}-\d{2})$")
    refresh: bool = False
    filters: Filters = Field(default_factory=Filters)
    into: str = Field(default="sigmahq", max_length=100)
    paths: list[str] | None = Field(default=None, max_length=MAX_RULES)
    include_untested: bool = False
    owner: str | None = Field(default=None, max_length=100)


def build_router(cfg: Config, *, off: Callable[[Request], str | None], auth_on: bool,
                 jobs: PackJobs | None = None, audit: Callable[[object, str, str], None] | None = None) -> APIRouter:
    """`off(request)` is the local-rules availability rule (api.local_writes_off); packs follow it exactly."""
    router = APIRouter()
    audited: set[str] = set()
    jobs = jobs or PackJobs()
    cache_dir = (cfg.data_dir / "cache" / "packs") if cfg.data_dir else None

    def ready(request: Request) -> None:
        reason = off(request)
        if reason or cache_dir is None:
            raise HTTPException(status_code=403, detail=f"Content packs are off: {reason or 'no data directory'}")

    def author_of(request: Request) -> dict | None:
        who = auth_api.who(request)
        return {"id": who.user_id, "email": who.email, "name": who.name} if who else None

    def free_slots() -> int:
        used = sum(1 for p in cfg.rules_dir.rglob("*") if p.suffix.lower() in (".yml", ".yaml")) if cfg.rules_dir.is_dir() else 0
        return max(0, local_rules.MAX_FILES - used)

    @router.get("/api/packs/sources")
    def sources(request: Request) -> dict:
        reason = off(request)
        base = {"enabled": False, "reason": reason or "no data directory", "sources": [], "limits": {"max_rules": MAX_RULES, "files_free": None}}
        if reason or cache_dir is None:
            return base
        cached = packs.cached_refs(cache_dir)
        refs = ["master"] + [c["ref"] for c in cached if c["ref"] != "master"]
        return {"enabled": True, "reason": None,
                "sources": [{"id": "sigmahq", "name": "SigmaHQ", "url": packs.SIGMAHQ_REPO, "license": "DRL 1.1", "refs": refs, "cached": cached}],
                "limits": {"max_rules": MAX_RULES, "files_free": free_slots()}}

    @router.post("/api/packs/jobs", status_code=202)
    def start_job(req: JobRequest, request: Request) -> dict:
        ready(request)
        author = author_of(request)
        who = auth_api.who(request)
        if req.refresh and auth_on and not (who and who.can("admin")):
            raise HTTPException(status_code=403, detail="Forcing a new download needs the admin role.")
        try:
            normalize_rule_path(f"{req.into}/x.yml")
        except ChangeError:
            raise HTTPException(status_code=422, detail="'into' must be a folder name inside rules/ (letters, digits, '.', '_', '-')") from None
        paths = None
        if req.paths is not None:
            paths = list(dict.fromkeys(req.paths))
            if not paths or any(len(p) > 300 for p in paths):
                raise HTTPException(status_code=422, detail="paths must be 1..50 rule paths from a preview")
        free = free_slots()
        if req.mode == "import" and (free <= 0 or (paths and len(paths) > free)):
            raise HTTPException(status_code=409, detail=f"too many rule files ({local_rules.MAX_FILES}): {free} free")
        batch = {"req": req, "paths": paths, "free": free}
        try:
            job = jobs.start(req.mode, author, lambda j: _run(j, cfg, cache_dir, author, **batch))  # type: ignore[arg-type]
        except JobBusy as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return job.public()

    @router.get("/api/packs/jobs/{job_id}")
    def get_job(job_id: str, request: Request) -> dict:
        ready(request)
        job = jobs.get(job_id) if _JOB_ID.match(job_id) else None
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        if audit and isinstance(job.result, dict) and job.result.get("audit") and job_id not in audited:
            audited.add(job_id)  # once per finished job, whoever polls first
            starter = job.created_by or {}  # the user who started the import, not whoever polls
            audit(starter.get("name") or starter.get("email") or "system", "packs.imported_local", job.result["audit"])
        return job.public()

    return router


def _run(job: Job, cfg: Config, cache_dir, author: dict | None, *, req: JobRequest,  # noqa: ANN001
         paths: list[str] | None, free: int) -> None:
    def on_bytes(done: int, total: int | None) -> None:
        job.progress["bytes"], job.progress["total"] = done, total

    job.state = "downloading"
    archive = packs.fetch_sigmahq(cache_dir, req.ref, refresh=req.refresh, progress=on_bytes)
    job.state = "scanning"
    files = packs._from_zip(archive, "rules")  # noqa: SLF001 - guarded reader of this package
    if not files:
        raise packs.PackError("no Sigma rules found in the archive")
    job.progress["scanned"] = len(files)
    skipped: list[dict] = []
    f = req.filters
    if paths is not None:  # an explicit selection from a preview: the paths decide, not the filters
        kw: dict = {"statuses": None, "only": set(paths)}
    else:
        kw = {"product": f.product, "category": f.category, "service": f.service, "statuses": tuple(f.statuses), "text": f.text}
    candidates = []
    for cand in packs.iter_candidates(files, into=req.into, rules_dir=cfg.rules_dir, skipped=skipped, **kw):
        candidates.append(cand)
        job.progress["matched"] = len(candidates)

    if req.mode == "preview":
        job.result = {"matched": len(candidates), "items": [{**c.public(), "rule": None} for c in candidates[:MAX_PREVIEW_ITEMS]],
                      "skipped": skipped[:MAX_SKIPPED]}
        return

    job.state = "importing"
    chosen = []
    limit = min(MAX_RULES, free)
    for c in candidates:
        if c.exists and not (paths and c.path in paths):
            skipped.append({"path": c.path, "reason": "already exists in rules/ (select it explicitly to import anyway)"})
        elif c.cases is None and not req.include_untested:
            skipped.append({"path": c.path, "reason": f"no test cases could be generated ({c.reason})"})
        elif len(chosen) < limit:
            chosen.append(c)
        else:
            skipped.append({"path": c.path, "reason": f"over the limit of {limit} rules for this import"})
    written: list[tuple] = []
    for c in chosen:
        try:
            made = local_rules.create(cfg, c.path, packs.with_owner(c.text, req.owner), packs.cases_text(c.cases) if c.cases else None)
        except local_rules.LocalRuleError as exc:
            skipped.append({"path": c.path, "reason": str(exc)})
            continue
        written.append((c, made["id"]))
        job.progress["imported"] = len(written)
    job.result = {"matched": len(candidates),
                  "items": [{**c.public(), "rule": rid} for c, rid in written],
                  "skipped": skipped[:MAX_SKIPPED],
                  "audit": f"{len(written)} rules into rules/{req.into}"}
