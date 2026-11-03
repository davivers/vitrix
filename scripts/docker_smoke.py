#!/usr/bin/env python3
"""First-run smoke test of the Docker image (ADR 0002). Usage: docker_smoke.py BASE_URL LOGS_FILE

Waits for health, reads the setup link from the container logs, registers the owner with it, creates a
draft, and checks that requests without the token / without a session are refused. Never prints the token.
"""
from __future__ import annotations

import http.cookiejar
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def call(opener, method: str, url: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def check(ok: bool, what: str) -> None:
    print(("ok   " if ok else "FAIL ") + what, flush=True)
    if not ok:
        sys.exit(1)


def main() -> None:
    base, logs = sys.argv[1].rstrip("/"), Path(sys.argv[2])
    anon = urllib.request.build_opener()
    owner = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    for _ in range(60):
        try:
            if call(anon, "GET", f"{base}/api/health")[0] == 200:
                break
        except OSError:
            pass
        time.sleep(1)
    else:
        check(False, "server became healthy")
    check(True, "server healthy")

    m = re.search(r"/\?setup=([A-Za-z0-9_-]{16,})", logs.read_text(encoding="utf-8", errors="replace"))
    check(m is not None, "setup link is printed in the container logs")
    token = m.group(1)  # type: ignore[union-attr]

    status, cfg = call(anon, "GET", f"{base}/api/auth/config")
    check(status == 200 and cfg.get("enabled") is True and cfg.get("bootstrap") is True, "accounts are on and the workspace has no owner yet")
    check(call(anon, "GET", f"{base}/api/rules")[0] == 401, "API refuses requests without a session (401)")

    reg = {"email": "owner@example.com", "name": "CI Owner", "password": "correct horse battery staple"}
    check(call(anon, "POST", f"{base}/api/auth/register", reg)[0] in (401, 403, 422), "register WITHOUT the setup token is refused")
    status, _ = call(owner, "POST", f"{base}/api/auth/register", {**reg, "setup_token": token})
    check(status == 201, "register the owner WITH the setup token")
    check(call(anon, "POST", f"{base}/api/auth/register", {**reg, "email": "x@example.com", "setup_token": token})[0] >= 400, "a second registration is refused")

    status, me = call(owner, "GET", f"{base}/api/auth/me")
    check(status == 200 and "owner" in json.dumps(me), "owner session works")
    rule = "title: Smoke\nid: 00000000-0000-4000-8000-000000000001\nstatus: test\nlogsource: {product: windows, category: process_creation}\ndetection:\n  sel: {Image|endswith: 'evil.exe'}\n  condition: sel\n"
    status, draft = call(owner, "POST", f"{base}/api/drafts", {"title": "smoke", "rule": rule})
    check(status == 201 and draft.get("id"), "owner can create a draft over the container network")
    check(call(anon, "GET", f"{base}/api/drafts")[0] == 401, "drafts are not readable without a session")
    print("docker smoke passed")


if __name__ == "__main__":
    main()
