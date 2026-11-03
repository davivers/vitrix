#!/usr/bin/env python3
"""Refresh src/vitrix/data/attack/enterprise.json from MITRE's Enterprise ATT&CK STIX bundle.

    python scripts/update_attack_catalog.py [--from bundle.json] [--out path]

Keeps only non-revoked, non-deprecated tactics and (sub-)techniques, in a compact deterministic
form: {version, source, tactics:[{id,name,order}], techniques:[{id,name,tactics:[TAxxxx],parent?}]}.
ATT&CK(R) is a registered trademark of The MITRE Corporation (see src/vitrix/data/attack/README.md).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUT = Path(__file__).resolve().parent.parent / "src" / "vitrix" / "data" / "attack" / "enterprise.json"


def ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def active(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def build(bundle: dict) -> dict:
    objs = bundle["objects"]
    tactics = {o["x_mitre_shortname"]: o for o in objs if o.get("type") == "x-mitre-tactic" and active(o)}
    matrix = next((o for o in objs if o.get("type") == "x-mitre-matrix" and active(o)), None)
    by_stix = {o["id"]: o for o in tactics.values()}
    order = [by_stix[r]["x_mitre_shortname"] for r in (matrix or {}).get("tactic_refs", []) if r in by_stix]
    order += sorted(set(tactics) - set(order))
    tactic_list = [{"id": ext_id(tactics[s]), "name": tactics[s]["name"], "order": i} for i, s in enumerate(order)]
    shortname_to_id = {s: ext_id(tactics[s]) for s in order}

    techs = [o for o in objs if o.get("type") == "attack-pattern" and active(o) and ext_id(o)]
    by_stix_t = {o["id"]: ext_id(o) for o in techs}
    parents = {r["source_ref"]: r["target_ref"] for r in objs
               if r.get("type") == "relationship" and r.get("relationship_type") == "subtechnique-of" and not r.get("revoked")}
    out = []
    for o in techs:
        tids = sorted({shortname_to_id[p["phase_name"]] for p in o.get("kill_chain_phases", [])
                       if p.get("kill_chain_name") == "mitre-attack" and p["phase_name"] in shortname_to_id},
                      key=lambda t: tactic_list[[x["id"] for x in tactic_list].index(t)]["order"])
        item = {"id": ext_id(o), "name": o["name"], "tactics": tids}
        if o["id"] in parents and parents[o["id"]] in by_stix_t:
            item["parent"] = by_stix_t[parents[o["id"]]]
        out.append(item)
    out.sort(key=lambda t: t["id"])
    spec = next((o for o in objs if o.get("type") == "x-mitre-collection"), {})
    return {"version": spec.get("x_mitre_version") or matrix and matrix.get("x_mitre_version") or "unknown",
            "source": URL, "tactics": tactic_list, "techniques": out}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="src", help="local STIX bundle instead of downloading")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()
    if args.src:
        bundle = json.loads(Path(args.src).read_text(encoding="utf-8"))
    else:
        with urllib.request.urlopen(URL, timeout=120) as resp:  # nosec B310 - fixed https URL
            bundle = json.load(resp)
    data = build(bundle)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    print(f"ATT&CK {data['version']}: {len(data['tactics'])} tactics, {len(data['techniques'])} techniques -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
