"""HTTP API of the GitHub sync (ADR 0006).

    GET  /api/sync    local state only, no network (viewer)
    POST /api/sync    start a throttled background fetch + safe fast-forward (viewer); `force` needs editor
"""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from . import auth_api
from .config import ConfigHolder
from .sync import SyncManager


class SyncRequest(BaseModel):
    force: bool = False


def build_router(holder: ConfigHolder, store, *, local_only: bool, manager: SyncManager | None = None) -> APIRouter:  # noqa: ANN001
    router = APIRouter()
    mgr = manager or SyncManager(holder)
    if store is not None:
        mgr.audit = lambda action, detail: store.log(None, action, detail)
    router.sync_manager = mgr  # type: ignore[attr-defined]

    def off(request: Request) -> str | None:
        """Why POST is not allowed for this request. Without accounts only a loopback client of a localhost-only server may."""
        if store is not None:
            return None
        host = request.client.host if request.client else ""
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            return "accounts are off, so sync only runs for a client on this machine"
        if not local_only:
            return "accounts are off and this server accepts non-local hosts"
        return None

    @router.get("/api/sync")
    def sync_status(request: Request) -> dict:
        out = mgr.status(holder.get())
        reason = off(request)
        return {**out, "enabled": False, "reason": reason} if reason and out["enabled"] else out

    @router.post("/api/sync")
    def sync_trigger(request: Request, req: SyncRequest | None = None) -> dict:
        reason = off(request)
        if reason:
            raise HTTPException(status_code=403, detail=f"Sync is off: {reason}")
        who = auth_api.who(request)
        force = bool(req and req.force)
        if force and store is not None and (who is None or not who.can("editor")):
            raise HTTPException(status_code=403, detail="Forcing a sync needs the editor role.")
        return mgr.trigger(holder.get(), force=force)

    return router
