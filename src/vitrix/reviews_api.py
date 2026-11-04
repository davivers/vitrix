"""HTTP routes of workspace reviews and comments (ADR 0005), as a FastAPI router.

    GET  /api/reviews[?scope=&state=&kind=&ref=]   GET /api/reviews/counts   GET /api/reviews/reviewers
    GET  /api/reviews/{id}                          POST /api/reviews
    POST /api/reviews/{id}/decision|rerequest|cancel|read|unread      POST /api/reviews/read-all
    GET|POST /api/comments                          PATCH|DELETE /api/comments/{id}

Needs accounts: without them the lists answer `enabled: false` and every other route 403s. Role
floors are in `auth_api.required_role`; who may act on a given review/comment is checked here.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Literal

import yaml
from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from . import auth, auth_api, governance, service
from . import drafts as drafts_mod
from .auth import Identity
from .config import Config
from .reviews import OPEN_STATES, ReviewError, ReviewStore, text_hash

_ID = re.compile(r"^[0-9a-f]{32}$")
_STATE_FILTERS = {"open": OPEN_STATES, "pending": ("pending",), "approved": ("approved",),
                  "changes_requested": ("changes_requested",), "cancelled": ("cancelled",)}


class ReviewRequest(BaseModel):
    target_kind: Literal["rule", "draft"]
    target_ref: str = Field(min_length=1, max_length=300)
    reviewer_id: int
    note: str | None = Field(default=None, max_length=2000)


class DecisionRequest(BaseModel):
    decision: Literal["approved", "changes_requested"]
    note: str | None = Field(default=None, max_length=2000)
    version: int = Field(ge=1)


class VersionRequest(BaseModel):
    version: int = Field(ge=1)


class RerequestRequest(VersionRequest):
    note: str | None = Field(default=None, max_length=2000)


class CommentRequest(BaseModel):
    target_kind: Literal["rule", "draft"]
    target_ref: str = Field(min_length=1, max_length=300)
    body: str = Field(min_length=1, max_length=5000)
    review_id: str | None = Field(default=None, max_length=32)


class CommentEdit(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


@contextmanager
def _errors() -> Iterator[None]:
    try:
        yield
    except ReviewError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from None


def _person(who: Identity) -> dict:
    return {"id": who.user_id, "email": who.email, "name": who.name or who.email}


MAX_DIFF_LINES = 2000


def _diff(base: str | None, current: str | None, name: str = "rule.yml") -> dict:
    """Unified diff base -> current. `changed_lines` = added + removed; None when there is no baseline (old reviews)."""
    if base is None or current is None:
        return {"diff": None, "changed_lines": None, "added": None, "removed": None, "diff_too_large": False}
    lines = list(difflib.unified_diff(base.splitlines(), current.splitlines(), f"{name} (at request)", f"{name} (now)", lineterm="", n=3))
    added = sum(1 for ln in lines if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in lines if ln.startswith("-") and not ln.startswith("---"))
    too_big = len(lines) > MAX_DIFF_LINES
    return {"diff": "" if too_big else "\n".join(lines), "changed_lines": added + removed, "added": added, "removed": removed, "diff_too_large": too_big}


def _clean(text: str) -> str:
    return re.sub(r"[\r\n<>]", " ", text).strip()[:100]


class Reviews:
    """The reviews feature of one running app: availability, target lookup, router and trailers."""

    def __init__(self, cfg: Config, auth_store: auth.AuthStore | None, drafts: drafts_mod.DraftStore | None):
        self.cfg = cfg
        self.auth = auth_store
        self.drafts = drafts
        self.store = ReviewStore(cfg.data_dir / "reviews.db") if cfg.data_dir else None
        self.router = self._router()

    # ------------------------------------------------------------------ availability

    def off_reason(self) -> str | None:
        if self.auth is None or self.store is None:
            return "Reviews need accounts (auth.enabled)"
        if not self.cfg.reviews_enabled:
            return "Reviews are off (reviews.enabled)"
        return None

    # ------------------------------------------------------------------ targets

    def _rule_text(self, ref: str) -> str | None:
        try:
            rel = service.normalize_rule_path(ref)
        except service.ChangeError:
            return None
        root = self.cfg.rules_dir.resolve()
        target = (root / rel).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            return None
        return target.read_bytes().decode("utf-8", errors="replace")

    def _target(self, kind: str, ref: str) -> dict | None:
        """{"title","hash","version","doc"} of the current target, or None when it does not exist."""
        if kind == "rule":
            text = self._rule_text(ref)
            if text is None:
                return None
            rel = service.normalize_rule_path(ref)
            return {"ref": rel, "title": drafts_mod.resolve_title(None, text, rel), "hash": drafts_mod.rule_hash(self.cfg.rules_dir, rel),
                    "version": None, "text": text}
        return None  # drafts are private scratch (ADR 0007): legacy draft reviews/comments are closed and invisible to everyone

    def _need_target(self, kind: str, ref: str) -> dict:
        found = self._target(kind, ref)
        if found is None:
            raise HTTPException(status_code=404, detail=f"{kind} not found")
        return found

    def _governance(self, text: str) -> dict | None:
        try:
            doc = next(iter(yaml.safe_load_all(text)), None)
        except yaml.YAMLError:
            return None
        g = governance.rule_governance(doc)
        return {"owner": g["owner"], "review_by": g["review_by"], "review_state": g["review_state"]}

    # ------------------------------------------------------------------ payloads

    def _review_json(self, row: dict, me_id: int, cache: dict | None = None, unread: set[str] | None = None, detail: bool = False) -> dict:
        key = (row["target_kind"], row["target_ref"])
        cache = cache if cache is not None else {}
        if key not in cache:
            cache[key] = self._target(*key)
        current = cache[key]
        if unread is None:
            unread = self.store.unread_ids(me_id) if self.store else set()
        d = _diff(row.get("base_text"), current["text"] if current else None)
        out = {
            "id": row["id"],
            "target": {"kind": row["target_kind"], "ref": row["target_ref"], "title": current["title"] if current else row["target_title"], "missing": current is None},
            "requester": {"id": row["requester_id"], "email": row["requester_email"], "name": row["requester_name"]},
            "reviewer": {"id": row["reviewer_id"], "email": row["reviewer_email"], "name": row["reviewer_name"]},
            "note": row["note"],
            "state": row["state"],
            "decision_note": row["decision_note"],
            "created_at": drafts_mod.iso(row["created_at"]),
            "updated_at": drafts_mod.iso(row["updated_at"]),
            "decided_at": drafts_mod.iso(row["decided_at"]) if row["decided_at"] else None,
            "version": row["version"],
            "stale": current is not None and current["hash"] != row["target_hash"],
            "mine_to_review": row["reviewer_id"] == me_id,
            "mine_requested": row["requester_id"] == me_id,
            "governance": self._governance(current["text"]) if current and row["target_kind"] == "rule" else None,
            "unread": row["id"] in unread,
            "snapshot": {"changed_lines": d["changed_lines"], "added": d["added"], "removed": d["removed"], "stale": current is not None and current["hash"] != row["target_hash"]},
        }
        if detail:
            out.update(diff=d["diff"], diff_too_large=d["diff_too_large"], snapshot_text=row.get("snapshot_text"), base_text=row.get("base_text"),
                       current_text=current["text"] if current else None,
                       events=[{"id": e["id"], "type": e["type"], "actor": {"id": e["actor_id"], "name": e["actor_name"]}, "text": e["text"],
                                "at": drafts_mod.iso(e["at"])} for e in self.store.events(row["id"])] if self.store else [])
        return out

    def _comment_json(self, row: dict, me_id: int, cache: dict | None = None) -> dict:
        key = (row["target_kind"], row["target_ref"])
        cache = cache if cache is not None else {}
        if key not in cache:
            cache[key] = self._target(*key)
        current = cache[key]
        return {
            "id": row["id"],
            "target": {"kind": row["target_kind"], "ref": row["target_ref"]},
            "review_id": row["review_id"],
            "author": {"id": row["author_id"], "email": row["author_email"], "name": row["author_name"]},
            "body": "" if row["deleted"] else row["body"],
            "deleted": bool(row["deleted"]),
            "created_at": drafts_mod.iso(row["created_at"]),
            "edited_at": drafts_mod.iso(row["edited_at"]) if row["edited_at"] else None,
            "outdated": bool(row["target_hash"]) and current is not None and current["hash"] != row["target_hash"],
            "mine": row["author_id"] == me_id,
        }

    # ------------------------------------------------------------------ publish trailers

    def trailers(self, content: dict[tuple[str, str], str]) -> list[str]:
        """`Reviewed-by` lines for approved reviews whose reviewed content equals what is being published.
        `content` maps (kind, ref) -> the text sent. Empty when reviews are unavailable."""
        if self.off_reason() or self.store is None:
            return []
        seen: dict[str, str] = {}
        for (kind, ref), text in content.items():
            for r in self.store.approved(kind, ref, text_hash(text)):
                seen.setdefault(r["reviewer_email"], f"Reviewed-by: {_clean(r['reviewer_name'] or r['reviewer_email'])} <{_clean(r['reviewer_email'])}>")
        return list(seen.values())

    # ------------------------------------------------------------------ routes

    def _router(self) -> APIRouter:
        router = APIRouter()
        outer = self

        def identity(request: Request) -> Identity:
            reason = outer.off_reason()
            if reason:
                raise HTTPException(status_code=403, detail=reason)
            who = auth_api.who(request)
            if who is None:
                raise HTTPException(status_code=401, detail="Sign in to continue.")
            return who

        def member(user_id: int) -> dict | None:
            return next((m for m in outer.auth.members() if m["id"] == user_id), None)  # type: ignore[union-attr]

        def audit(who: Identity, action: str, detail: str) -> None:
            outer.auth.log(who, action, detail)  # type: ignore[union-attr]

        @router.get("/api/reviews")
        def reviews_list(request: Request, scope: Literal["to_review", "requested", "all"] = "to_review",
                         state: Literal["open", "pending", "approved", "changes_requested", "cancelled"] = "open",
                         kind: Literal["rule", "draft"] | None = None, ref: str | None = Query(default=None, max_length=300)) -> dict:
            reason = outer.off_reason()
            if reason:
                return {"enabled": False, "reason": reason, "reviews": []}
            who = identity(request)
            rows = outer.store.list(  # type: ignore[union-attr]
                reviewer_id=who.user_id if scope == "to_review" else None,
                requester_id=who.user_id if scope == "requested" else None,
                states=_STATE_FILTERS[state], kind=kind, ref=ref)
            rows = [r for r in rows if r["target_kind"] != "draft"]  # legacy draft reviews would expose private drafts
            cache: dict = {}
            unread = outer.store.unread_ids(who.user_id)  # type: ignore[union-attr]
            return {"enabled": True, "reason": None, "reviews": [outer._review_json(r, who.user_id, cache, unread) for r in rows]}

        @router.get("/api/reviews/counts")
        def reviews_counts(request: Request) -> dict:
            reason = outer.off_reason()
            if reason:
                return {"enabled": False, "reason": reason, "to_review": 0, "requested": 0, "unread": 0, "latest": []}
            uid = identity(request).user_id
            summary = outer.store.unread_summary(uid)  # type: ignore[union-attr]
            latest = [{"id": r["id"], "title": r["title"], "requester": r["requester_name"], "actor": r["actor_name"] or r["requester_name"],
                       "created_at": drafts_mod.iso(r["at"]), "kind": r["kind"], "state": r["state"]} for r in summary["latest"]]
            return {"enabled": True, "reason": None, **outer.store.counts(uid), "unread": summary["unread"], "latest": latest}  # type: ignore[union-attr]

        @router.post("/api/reviews/read-all")
        def reviews_read_all(request: Request) -> dict:
            return {"marked": outer.store.read_all(identity(request).user_id)}  # type: ignore[union-attr]

        @router.get("/api/reviews/reviewers")
        def reviews_reviewers(request: Request) -> list[dict]:
            who = identity(request)
            return [{"id": m["id"], "email": m["email"], "name": m["name"] or m["email"], "role": m["role"]}
                    for m in outer.auth.members()  # type: ignore[union-attr]
                    if m["id"] != who.user_id and auth.ROLE_LEVEL[m["role"]] >= auth.ROLE_LEVEL["editor"]]

        @router.get("/api/reviews/{review_id}")
        def reviews_get(review_id: str, request: Request) -> dict:
            who = identity(request)
            with _errors():
                row = outer.store.get(review_id)  # type: ignore[union-attr]
                if row["target_kind"] == "draft":
                    raise HTTPException(status_code=404, detail="review not found")
                cache: dict = {}
                comments = outer.store.comments(row["target_kind"], row["target_ref"], review_id)  # type: ignore[union-attr]
            return {**outer._review_json(row, who.user_id, cache, detail=True), "comments": [outer._comment_json(c, who.user_id, cache) for c in comments]}

        @router.post("/api/reviews", status_code=201)
        def reviews_create(req: ReviewRequest, request: Request) -> dict:
            who = identity(request)
            if req.reviewer_id == who.user_id:
                raise HTTPException(status_code=422, detail="You cannot review your own request.")
            if req.target_kind == "draft":  # drafts are private scratch, never reviewable (ADR 0007)
                raise HTTPException(status_code=422, detail="Drafts are private; save the rule as a local rule to request a review.")
            reviewer = member(req.reviewer_id)
            if reviewer is None or auth.ROLE_LEVEL[reviewer["role"]] < auth.ROLE_LEVEL["editor"]:
                raise HTTPException(status_code=422, detail="Reviewers need the editor role or higher.")
            target = outer._need_target(req.target_kind, req.target_ref)
            with _errors():
                row = outer.store.request(  # type: ignore[union-attr]
                    kind=req.target_kind, ref=target["ref"], title=target["title"], target_hash=target["hash"], target_version=target["version"],
                    requester=_person(who), reviewer={"id": reviewer["id"], "email": reviewer["email"], "name": reviewer["name"] or reviewer["email"]},
                    note=req.note, snapshot_text=target["text"])
            audit(who, "review.requested", f"{req.target_kind} {target['ref']} → {reviewer['email']}")
            return outer._review_json(row, who.user_id)

        @router.post("/api/reviews/{review_id}/decision")
        def reviews_decide(review_id: str, req: DecisionRequest, request: Request) -> dict:
            who = identity(request)
            with _errors():
                row = outer.store.get(review_id)  # type: ignore[union-attr]
                if row["reviewer_id"] != who.user_id:
                    raise HTTPException(status_code=403, detail="Only the assigned reviewer can decide this review.")
                if row["requester_id"] == who.user_id:
                    raise HTTPException(status_code=403, detail="You cannot review your own request.")
                if not who.can("editor"):
                    raise HTTPException(status_code=403, detail="Reviewers need the editor role or higher.")
                current = outer._target(row["target_kind"], row["target_ref"])
                done = outer.store.decide(review_id, decision=req.decision, note=req.note, version=req.version,  # type: ignore[union-attr]
                                          current_hash=current["hash"] if current else None)
            audit(who, "review.decided", f"{req.decision}: {row['target_kind']} {row['target_ref']}")
            return outer._review_json(done, who.user_id)

        @router.post("/api/reviews/{review_id}/rerequest")
        def reviews_rerequest(review_id: str, req: RerequestRequest, request: Request) -> dict:
            who = identity(request)
            with _errors():
                row = outer.store.get(review_id)  # type: ignore[union-attr]
                if row["requester_id"] != who.user_id:
                    raise HTTPException(status_code=403, detail="Only the requester can ask for a new review.")
                target = outer._need_target(row["target_kind"], row["target_ref"])
                done = outer.store.rerequest(review_id, version=req.version, title=target["title"],  # type: ignore[union-attr]
                                             target_hash=target["hash"], target_version=target["version"],
                                             snapshot_text=target["text"], note=req.note)
            audit(who, "review.rerequested", f"{row['target_kind']} {row['target_ref']}")
            return outer._review_json(done, who.user_id)

        def participant(review_id: str, who: Identity) -> None:
            row = outer.store.get(review_id)  # type: ignore[union-attr]
            if who.user_id not in (row["reviewer_id"], row["requester_id"]):
                raise HTTPException(status_code=403, detail="This review is not yours.")

        @router.post("/api/reviews/{review_id}/read")
        def reviews_read(review_id: str, request: Request) -> dict:
            who = identity(request)
            with _errors():
                participant(review_id, who)
                outer.store.mark_read(review_id, who.user_id)  # type: ignore[union-attr]
            return {"id": review_id, "unread": False}

        @router.post("/api/reviews/{review_id}/unread")
        def reviews_unread(review_id: str, request: Request) -> dict:
            who = identity(request)
            with _errors():
                outer.store.mark_unread(review_id, who.user_id)  # type: ignore[union-attr]
            return {"id": review_id, "unread": True}

        @router.post("/api/reviews/{review_id}/cancel")
        def reviews_cancel(review_id: str, req: VersionRequest, request: Request) -> dict:
            who = identity(request)
            with _errors():
                row = outer.store.get(review_id)  # type: ignore[union-attr]
                if row["requester_id"] != who.user_id and not who.can("admin"):
                    raise HTTPException(status_code=403, detail="Only the requester or an admin can cancel this review.")
                done = outer.store.cancel(review_id, version=req.version, actor=_person(who))  # type: ignore[union-attr]
            audit(who, "review.cancelled", f"{row['target_kind']} {row['target_ref']}")
            return outer._review_json(done, who.user_id)

        @router.get("/api/comments")
        def comments_list(request: Request, kind: Literal["rule", "draft"] | None = None, ref: str | None = None) -> dict:
            reason = outer.off_reason()
            if reason:
                return {"enabled": False, "reason": reason, "comments": []}
            who = identity(request)
            if kind is None or not ref or len(ref) > 300:
                raise HTTPException(status_code=422, detail="kind and ref are required")
            if kind == "draft":
                return {"enabled": True, "reason": None, "comments": []}
            cache: dict = {}
            return {"enabled": True, "reason": None,
                    "comments": [outer._comment_json(c, who.user_id, cache) for c in outer.store.comments(kind, ref)]}  # type: ignore[union-attr]

        @router.post("/api/comments", status_code=201)
        def comments_create(req: CommentRequest, request: Request) -> dict:
            who = identity(request)
            if req.target_kind == "draft":
                raise HTTPException(status_code=422, detail="Drafts are private and cannot be commented on.")
            target = outer._need_target(req.target_kind, req.target_ref)
            with _errors():
                if req.review_id is not None:
                    review = outer.store.get(req.review_id) if _ID.match(req.review_id) else None  # type: ignore[union-attr]
                    if review is None or (review["target_kind"], review["target_ref"]) != (req.target_kind, target["ref"]):
                        raise HTTPException(status_code=422, detail="review_id does not belong to this target")
                row = outer.store.add_comment(kind=req.target_kind, ref=target["ref"], body=req.body, author=_person(who),  # type: ignore[union-attr]
                                              target_hash=target["hash"], review_id=req.review_id)
            return outer._comment_json(row, who.user_id)

        @router.patch("/api/comments/{comment_id}")
        def comments_edit(comment_id: str, req: CommentEdit, request: Request) -> dict:
            who = identity(request)
            with _errors():
                if outer.store.get_comment(comment_id)["author_id"] != who.user_id:  # type: ignore[union-attr]
                    raise HTTPException(status_code=403, detail="Only the author can edit a comment.")
                return outer._comment_json(outer.store.edit_comment(comment_id, req.body), who.user_id)  # type: ignore[union-attr]

        @router.delete("/api/comments/{comment_id}", status_code=204)
        def comments_delete(comment_id: str, request: Request) -> Response:
            who = identity(request)
            with _errors():
                if outer.store.get_comment(comment_id)["author_id"] != who.user_id and not who.can("admin"):  # type: ignore[union-attr]
                    raise HTTPException(status_code=403, detail="Only the author or an admin can delete a comment.")
                outer.store.delete_comment(comment_id)  # type: ignore[union-attr]
            return Response(status_code=204)

        return router

