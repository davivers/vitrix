#!/usr/bin/env python3
"""Capture the JSON fixtures for the static public demo (ADR 0003).

Creates a `vitrix init` repository in a temp dir, makes a Git history, runs the REAL app in-process
(FastAPI TestClient, auth off, no GitHub token) and saves every GET the UI needs plus the compute
POSTs of each unchanged example rule. Output (gitignored, regenerated in CI):

    web/demo/public/fixtures/manifest.json  {"captured_at", "vitrix_version", "routes": {"GET /api/rules": "0001.json", ...}}
    web/demo/public/fixtures/NNNN.json      response bodies; compute POSTs are {"rule_sha256", "body"}

Usage: python scripts/capture_demo_fixtures.py [--out DIR]     (exit 1 if a required GET is not 200)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "web" / "demo" / "public" / "fixtures"
DEMO_REASON = "Read-only demo"
GIT_ENV = {
    "GIT_AUTHOR_NAME": "Vitrix Demo", "GIT_AUTHOR_EMAIL": "demo@example.com",
    "GIT_COMMITTER_NAME": "Vitrix Demo", "GIT_COMMITTER_EMAIL": "demo@example.com",
}


def git(cwd: Path, *args: str, date: str | None = None) -> None:
    env = {**os.environ, **GIT_ENV}
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True)


def make_repo(tmp: Path) -> Path:
    from vitrix.cli import main

    if main(["init", str(tmp)]) != 0:
        sys.exit("vitrix init failed")
    git(tmp, "init", "-q", "-b", "main")
    git(tmp, "add", "-A")
    git(tmp, "commit", "-qm", "Initial detections", date="2026-01-05T10:00:00+00:00")
    # second commit so history/drift have something to show (touch the README-style notes file, not the rules)
    (tmp / "NOTES.md").write_text("Sample detections repository created by `vitrix init`.\n", encoding="utf-8")
    git(tmp, "add", "-A")
    git(tmp, "commit", "-qm", "Add notes", date="2026-01-12T10:00:00+00:00")
    return tmp / "vitrix.yml"


def seg(path: str) -> str:
    return "/".join(quote(p, safe="") for p in path.split("/"))  # same as api.ts `path()`


HIDDEN_QUERY = "-- converted queries are not shown in the public demo --"
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")


def scrub(value: object, tmp: Path) -> object:
    """Strip anything environment-specific or query-like before it reaches the public demo:
    converted queries, the vitrix.yml text, absolute paths of the capture machine and e-mail addresses."""
    roots = {str(tmp), str(tmp.resolve()), str(tmp).replace("\\", "/"), str(tmp.resolve()).replace("\\", "/")}
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in ("query", "queries") and isinstance(v, str):
                out[k] = HIDDEN_QUERY
            elif k == "text" and isinstance(v, str) and "schema_version" in v:  # the vitrix.yml shown in Settings
                out[k] = "# vitrix.yml is not shown in the public demo\n"
            elif k == "file" and isinstance(v, str) and Path(v).is_absolute():
                out[k] = "vitrix.yml"
            elif k == "publication" and isinstance(v, dict):  # the sample rules stand for a repo already on GitHub
                out[k] = {**{kk: None for kk in v}, "state": "published"}
            else:
                out[k] = scrub(v, tmp)
        return out
    if isinstance(value, list):
        return [scrub(v, tmp) for v in value]
    if isinstance(value, str):
        for root in roots:
            value = value.replace(root, "<repo>")
        return _EMAIL.sub("someone@example.com", value)
    return value


def main_() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    out: Path = ap.parse_args().out

    # Hermetic: no accounts, no GitHub, no gh CLI, no inherited tokens.
    for k in ("VITRIX_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "VITRIX_BOOTSTRAP_TOKEN"):
        os.environ.pop(k, None)
    os.environ.update({"VITRIX_AUTH": "off", "VITRIX_GH_CLI": "0"})

    from fastapi.testclient import TestClient

    import vitrix
    from vitrix.api import create_app

    tmp = Path(tempfile.mkdtemp(prefix="vitrix-demo-"))
    try:
        cfg = make_repo(tmp)
        client = TestClient(create_app(str(cfg)), base_url="http://127.0.0.1")
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        routes: dict[str, str] = {}
        failures: list[str] = []

        def save(key: str, body: object) -> None:
            name = f"{len(routes) + 1:04d}.json"
            body = scrub(body, tmp)  # public demo: no queries, paths, identities or config text
            (out / name).write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")
            routes[key] = name

        def get(url: str, rewrite=None, required: bool = True):  # noqa: ANN001
            r = client.get(url)
            if r.status_code != 200:
                if required:
                    failures.append(f"GET {url} -> {r.status_code}")
                return None
            body = r.json()
            save(f"GET {url}", rewrite(body) if rewrite else body)
            return body

        readonly = {"enabled": False, "reason": DEMO_REASON}
        for url in ("/api/auth/config", "/api/health", "/api/config", "/api/targets", "/api/stats", "/api/quality",
                    "/api/tests", "/api/coverage", "/api/datasets", "/api/replay/datasets"):
            get(url)
        # Environment-specific data never goes into the public demo: Git history (names, e-mails), GitHub
        # connection state and drift (git refs) are replaced by an explicit "not in the demo" state.
        hidden = {"available": False, "state": "demo", "message": DEMO_REASON, "reason": DEMO_REASON}
        get("/api/history", lambda _b: {**hidden, "rules": [], "commits": [], "contributors": [], "coverage": []}, required=False)
        get("/api/github", lambda _b: {"configured": False, "reason": DEMO_REASON}, required=False)
        get("/api/github/activity", lambda _b: {"configured": False, "reason": DEMO_REASON}, required=False)
        get("/api/drift", lambda _b: {**hidden, "rules": [], "datasets": [], "summary": {}}, required=False)
        get("/api/drafts", lambda _b: {**readonly, "drafts": []})
        # Sprint 2 routes that may not exist yet: optional, always rewritten to disabled.
        get("/api/reviews", lambda _b: {**readonly, "reviews": []}, required=False)
        get("/api/packs/sources", lambda _b: {**readonly, "sources": []}, required=False)

        rules = get("/api/rules") or []
        for rule in rules:
            rid = rule["id"]
            detail = get(f"/api/rules/{seg(rid)}")
            get(f"/api/quality/{seg(rid)}")
            get(f"/api/history/{seg(rid)}")
            get(f"/api/drift?rule={quote(rid, safe='')}")
            if not detail:
                continue
            text = detail["text"]
            sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
            cases = (detail.get("tests") or {}).get("cases_text") or None
            posts = [
                ("/api/validate", {"rule": text, "cases": cases if (cases or "").strip() else None, "path": rid}),
                ("/api/impact", {"rule": text, "path": rid}),
                ("/api/replay/draft", {"rule": text, "path": rid}),
            ]
            for url, body in posts:
                r = client.post(url, json=body)
                if r.status_code != 200:
                    failures.append(f"POST {url} [{rid}] -> {r.status_code}")
                    continue
                save(f"POST {url}#{rid}", {"rule_sha256": sha, "body": r.json()})

        for ds in client.get("/api/datasets").json():
            name = ds["name"] if isinstance(ds, dict) else str(ds)
            get(f"/api/datasets/{seg(name)}/replay")

        if failures:
            print("capture failed:\n  " + "\n  ".join(failures), file=sys.stderr)
            return 1
        manifest = {"captured_at": "2026-01-12T10:00:00Z", "vitrix_version": vitrix.__version__, "routes": routes}
        (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
        print(f"captured {len(routes)} fixtures for {len(rules)} rules into {out}")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main_())
