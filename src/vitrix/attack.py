"""Local MITRE ATT&CK Enterprise catalogue (packaged JSON, see data/attack/README.md)."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources


@lru_cache(maxsize=1)
def catalog() -> dict:
    """{version, source, tactics:[{id,name,order}], techniques:[{id,name,tactics,parent?}]}.

    Empty lists (version "unknown") when the data file is missing, so callers never crash.
    """
    try:
        text = resources.files("vitrix").joinpath("data/attack/enterprise.json").read_text(encoding="utf-8")
        return json.loads(text)
    except (OSError, ValueError, ModuleNotFoundError):
        return {"version": "unknown", "source": "", "tactics": [], "techniques": []}


@lru_cache(maxsize=1)
def technique_ids() -> frozenset[str]:
    return frozenset(t["id"] for t in catalog()["techniques"])


def is_known_technique(tid: str) -> bool:
    """True if `tid` (e.g. T1059.001, any case) is in the catalogue; True when no catalogue is shipped."""
    ids = technique_ids()
    return not ids or tid.upper() in ids
