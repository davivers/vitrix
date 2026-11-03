"""Governance inside the rule: who owns it, when it must be reviewed, why each exclusion exists.

Everything lives in the rule's `vitrix:` block, so it is versioned and reviewed with the rule:

    vitrix:
      owner: soc-windows               # team or person accountable for the rule
      review_by: 2027-03-01            # review deadline (Detection SLA)
      suppressions:                    # one entry per exclusion selection (filter_*)
        filter_sccm:
          reason: SCCM agent runs encoded PowerShell on every host
          owner: it-endpoint
          expires: 2027-01-31          # after this date the quality gate blocks the rule
          ticket: CHG-1234

The quality gate reads it (owner, review deadline, documented and unexpired suppressions) and
the Governance page aggregates it across the repository.
"""

from __future__ import annotations

import re
from datetime import date, datetime

from .evaluator import exclusion_selections

KEYS = {"owner", "review_by", "suppressions"}
SUPPRESSION_KEYS = {"reason", "owner", "expires", "ticket"}
EXPIRING_DAYS = 30  # "expiring soon" / "review due soon" window
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _as_date(value: object) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str) and _DATE.match(value.strip()):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


def _block(doc: object) -> dict:
    block = doc.get("vitrix") if isinstance(doc, dict) else None
    return block if isinstance(block, dict) else {}


def problems(doc: object) -> list[tuple[str, str]]:
    """(severity, message) for the governance keys of the `vitrix` block (used by the lint)."""
    block = _block(doc)
    out: list[tuple[str, str]] = []
    if "owner" in block and (not isinstance(block["owner"], str) or not block["owner"].strip()):
        out.append(("error", "vitrix.owner must be a team or person name"))
    if "review_by" in block and _as_date(block["review_by"]) is None:
        out.append(("error", "vitrix.review_by must be a date in YYYY-MM-DD format"))
    if "suppressions" in block:
        sup = block["suppressions"]
        if not isinstance(sup, dict):
            return out + [("error", "vitrix.suppressions must map each filter selection to {reason, owner, expires, ticket}")]
        selections = set((doc.get("detection") or {}).keys()) - {"condition", "timeframe"} if isinstance(doc, dict) else set()
        for name, entry in sup.items():
            where = f"vitrix.suppressions.{name}"
            if name not in selections:
                out.append(("error", f"{where}: no selection named '{name}' in detection"))
            if not isinstance(entry, dict):
                out.append(("error", f"{where} must be a mapping with reason, owner, expires, ticket"))
                continue
            for key in entry:
                if key not in SUPPRESSION_KEYS:
                    out.append(("error", f"{where}: unknown key '{key}' (use {', '.join(sorted(SUPPRESSION_KEYS))})"))
            if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
                out.append(("warning", f"{where}: missing reason"))
            if "expires" in entry and _as_date(entry["expires"]) is None:
                out.append(("error", f"{where}.expires must be a date in YYYY-MM-DD format"))
    return out


def rule_governance(doc: object, today: date | None = None) -> dict:
    """Owner, review deadline and the state of every exclusion of one rule."""
    today = today or date.today()
    block = _block(doc)
    owner = block.get("owner").strip() if isinstance(block.get("owner"), str) and block["owner"].strip() else None
    review_by = _as_date(block.get("review_by"))
    review_state = None
    if review_by:
        days = (review_by - today).days
        review_state = "overdue" if days < 0 else "due_soon" if days <= EXPIRING_DAYS else "ok"

    documented = block.get("suppressions") if isinstance(block.get("suppressions"), dict) else {}
    exclusions = sorted(exclusion_selections(doc)) if isinstance(doc, dict) and isinstance(doc.get("detection"), dict) else []
    suppressions = []
    for name in sorted(set(exclusions) | set(documented)):
        entry = documented.get(name) if isinstance(documented.get(name), dict) else {}
        expires = _as_date(entry.get("expires"))
        reason = entry.get("reason").strip() if isinstance(entry.get("reason"), str) and entry["reason"].strip() else None
        if name not in exclusions:
            state = "orphan"  # documented, but the selection no longer excludes anything
        elif not reason:
            state = "undocumented"
        elif expires is None:
            state = "active"
        else:
            days = (expires - today).days
            state = "expired" if days < 0 else "expiring" if days <= EXPIRING_DAYS else "active"
        suppressions.append({
            "selection": name, "reason": reason, "owner": entry.get("owner") if isinstance(entry.get("owner"), str) else None,
            "expires": expires.isoformat() if expires else None, "ticket": str(entry["ticket"]) if entry.get("ticket") else None,
            "state": state,
        })
    return {
        "owner": owner,
        "review_by": review_by.isoformat() if review_by else None,
        "review_state": review_state,
        "suppressions": suppressions,
    }
