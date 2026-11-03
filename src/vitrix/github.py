"""GitHub integration: CI-validated pull requests and a read-only connector.

Nothing is written to the local disk. A change made in the UI goes through two steps:

1. **Validate in CI** (`push_branch`): the files go to a new `vitrix/...` branch in one commit.
   The repository's own GitHub Actions workflow runs on that push (`vitrix check --gate`).
2. **Open pull request** (`open_validated_pull_request`): allowed only when every workflow run
   for that exact commit finished successfully, and the branch still points to that commit.
   The server checks both right before opening the PR, so the UI cannot skip the real CI.

Configuration in vitrix.yml:

    github:
      repo: my-org/detections    # required
      base: main                 # target branch (default: main)
      path: ""                   # folder of the Vitrix project inside the repository (default: root)
      workflow: vitrix           # optional: only runs of this workflow (name or file) count as CI

Without a `github:` section, the repository is read from `git remote origin` (see gitremote.py).
The token NEVER comes from vitrix.yml: `VITRIX_GITHUB_TOKEN` / `GITHUB_TOKEN`, else the GitHub CLI
login (`gh auth login`). Minimum fine-grained permissions on the repository: Contents (read/write),
Pull requests (read/write) and Actions (read).

The workflow must run on pushes to `vitrix/**` branches (see .github/workflows/vitrix.yml).
Standard library only (urllib), no new dependencies.
"""

from __future__ import annotations

import json
import re
import secrets
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from statistics import median
from typing import Any
from urllib.parse import quote

API_URL = "https://api.github.com"
TOKEN_ENVS = ("VITRIX_GITHUB_TOKEN", "GITHUB_TOKEN")
BRANCH_PREFIX = "vitrix/"
_REPO = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")
_BRANCH = re.compile(r"^[A-Za-z0-9._/-]+$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


class GitHubError(Exception):
    """Failure talking to GitHub. `status` is the HTTP status suggested for the Vitrix API."""

    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


@dataclass
class GitHubConfig:
    repo: str
    base: str = "main"
    path: str = ""  # prefix of the Vitrix project inside the repository
    workflow: str | None = None  # only runs of this workflow count as CI (None = every workflow)

    def repo_path(self, rel: str) -> str:
        """Repository path of a file relative to the Vitrix project root."""
        return str(PurePosixPath(self.path, rel)) if self.path else rel


def parse_config(data: object) -> GitHubConfig | None:
    """Validate the `github:` section of vitrix.yml. Raises ValueError with a user-facing message."""
    if data is None:
        return None
    if not isinstance(data, dict):
        raise ValueError("'github' must be a mapping with repo, base and path")
    repo = data.get("repo")
    if not isinstance(repo, str) or not _REPO.match(repo.strip()):
        raise ValueError("github.repo must look like owner/repository")
    base = data.get("base", "main")
    if not isinstance(base, str) or not _BRANCH.match(base) or ".." in base:
        raise ValueError("github.base must be a branch name")
    path = data.get("path", "") or ""
    if not isinstance(path, str) or path.startswith("/") or "\\" in path or ".." in PurePosixPath(path).parts:
        raise ValueError("github.path must be a relative folder inside the repository")
    workflow = data.get("workflow")
    if workflow is not None and (not isinstance(workflow, str) or not workflow.strip()):
        raise ValueError("github.workflow must be a workflow name or file name")
    return GitHubConfig(repo=repo.strip(), base=base, path=path.strip("/"), workflow=workflow.strip() if workflow else None)


def token_from_env() -> str | None:
    """VITRIX_GITHUB_TOKEN / GITHUB_TOKEN, else the GitHub CLI login (`gh auth token`)."""
    from .gitremote import token

    return token()[0]


# Transport signature: (method, url, body) -> (status, json). Injectable in tests.
Transport = Callable[[str, str, dict | None], tuple[int, object]]


def _urllib_transport(token: str) -> Transport:
    def send(method: str, url: str, body: dict | None) -> tuple[int, object]:
        # the token may only go to the GitHub API over HTTPS (never file:, http: or another host)
        if not url.startswith(API_URL + "/"):
            raise GitHubError(f"refused URL outside the GitHub API: {url[:80]}")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "vitrix",
            **({"Content-Type": "application/json"} if data else {}),
        })
        try:
            # URL checked above: only https://api.github.com/
            with urllib.request.urlopen(req, timeout=20) as res:  # nosec B310
                return res.status, json.loads(res.read() or b"null")
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read() or b"null")
            except ValueError:
                payload = None
            return exc.code, payload
        except (urllib.error.URLError, TimeoutError) as exc:
            raise GitHubError(f"could not reach GitHub: {exc}") from exc

    return send


class GitHubClient:
    def __init__(self, cfg: GitHubConfig, token: str | None = None, transport: Transport | None = None):
        token = token or token_from_env()
        if transport is None:
            if not token:
                raise GitHubError(
                    "no GitHub token: run `gh auth login` (GitHub CLI) or set VITRIX_GITHUB_TOKEN, then restart `vitrix serve`. `vitrix connect` checks the whole setup",
                    status=503,
                )
            transport = _urllib_transport(token)
        self.cfg = cfg
        self._send = transport

    def _call(self, method: str, path: str, body: dict | None = None, ok: tuple[int, ...] = (200, 201)) -> Any:
        status, payload = self._send(method, f"{API_URL}/repos/{self.cfg.repo}{path}", body)
        if status not in ok:
            message = payload.get("message") if isinstance(payload, dict) else None
            hint = {
                401: "GitHub token is invalid or expired",
                403: "the token lacks permission (Contents, Pull requests and Actions) on this repository",
                404: f"repository {self.cfg.repo} or branch {self.cfg.base} not found (or the token has no access)",
            }.get(status)
            raise GitHubError(f"GitHub answered {status}: {hint or message or 'unknown error'}")
        return payload

    def probe(self, path: str = "") -> tuple[int, object]:
        """GET /repos/{repo}{path} without raising on HTTP errors (used by `vitrix connect`)."""
        return self._send("GET", f"{API_URL}/repos/{self.cfg.repo}{path}", None)

    # ----------------------------------------------------------------------- step 1: CI validation

    def push_branch(self, files: dict[str, str], message: str, branch_hint: str) -> dict:
        """Create a `vitrix/...` branch with one commit holding `files` (repo path -> text).

        The push triggers the repository's CI. Nothing is merged and no PR is opened yet.
        """
        base_ref = self._call("GET", f"/git/ref/heads/{quote(self.cfg.base, safe='/')}")
        base_sha = base_ref["object"]["sha"]
        base_commit = self._call("GET", f"/git/commits/{base_sha}")
        tree = self._call("POST", "/git/trees", {
            "base_tree": base_commit["tree"]["sha"],
            "tree": [{"path": p, "mode": "100644", "type": "blob", "content": text} for p, text in sorted(files.items())],
        })
        commit = self._call("POST", "/git/commits", {"message": message, "tree": tree["sha"], "parents": [base_sha]})
        branch = f"{BRANCH_PREFIX}{branch_hint}-{secrets.token_hex(3)}"
        self._call("POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": commit["sha"]})
        return {"branch": branch, "commit": commit["sha"], "base": self.cfg.base, "base_commit": base_sha,
                "url": f"https://github.com/{self.cfg.repo}/tree/{quote(branch, safe='/')}"}

    def ci_status(self, commit: str) -> dict:
        """Aggregate state of the real CI (GitHub Actions) for one exact commit.

        none: no workflow run yet (queued on GitHub, or the workflow does not run on vitrix/**)
        pending: at least one run still going · failure: any run failed · success: all passed
        """
        if not _SHA.match(commit):
            raise GitHubError("invalid commit id", status=422)
        data = self._call("GET", f"/actions/runs?head_sha={commit}&per_page=50") or {}
        runs = [r for r in data.get("workflow_runs", []) if r.get("head_sha") == commit]
        if self.cfg.workflow:
            wanted = self.cfg.workflow
            runs = [r for r in runs if r.get("name") == wanted or str(r.get("path", "")).endswith("/" + wanted)
                    or str(r.get("path", "")).endswith("/" + wanted + ".yml")]
        # a re-run creates a new run for the same workflow: keep the newest per workflow
        latest: dict[str, dict] = {}
        for r in sorted(runs, key=lambda r: r.get("run_attempt", 1) * 10**12 + int(r.get("id") or 0)):
            latest[str(r.get("workflow_id") or r.get("name"))] = r
        items = [_run(r) for r in latest.values()]
        states = [i["state"] for i in items]
        if not items:
            state = "none"
        elif "pending" in states:
            state = "pending"
        elif "failure" in states:
            state = "failure"
        else:
            state = "success"
        return {"commit": commit, "state": state, "runs": items, "workflow": self.cfg.workflow}

    # ----------------------------------------------------------------------- step 2: pull request

    def open_validated_pull_request(self, branch: str, commit: str, title: str | None = None) -> dict:
        """Open the PR only if the real CI passed for `commit` and `branch` still points to it.

        Title and description come from the commit message written in step 1 (`title` overrides
        the first line).
        """
        if not branch.startswith(BRANCH_PREFIX) or not _BRANCH.match(branch) or ".." in branch:
            raise GitHubError(f"only {BRANCH_PREFIX}* branches created by Vitrix can be proposed", status=422)
        ref = self._call("GET", f"/git/ref/heads/{quote(branch, safe='/')}")
        if (ref.get("object") or {}).get("sha") != commit:
            raise GitHubError("the branch changed after CI validation; validate again", status=409)
        ci = self.ci_status(commit)
        if ci["state"] != "success":
            reason = {"none": "CI has not run for this commit yet", "pending": "CI is still running",
                      "failure": "CI failed for this commit"}[ci["state"]]
            raise GitHubError(f"pull request blocked: {reason}", status=409)
        message = (self._call("GET", f"/git/commits/{commit}") or {}).get("message") or ""
        first, _, rest = message.partition("\n")
        runs = "\n".join(f"- [{r['name']} #{r['number']}]({r['url']}): {r['conclusion']}" for r in ci["runs"])
        pr = self._call("POST", "/pulls", {"title": title or first.strip() or branch, "head": branch, "base": self.cfg.base,
                                            "body": f"{rest.strip()}\n\n**Validated by CI before opening:**\n{runs}".strip()})
        return {"url": pr.get("html_url"), "number": pr.get("number"), "branch": branch, "commit": commit, "ci": ci}

    # ----------------------------------------------------------------------- read-only connector

    def activity(self, now: datetime | None = None) -> dict:
        """Repository state on GitHub: base HEAD, open PRs, time to merge and CI.

        Read-only. Six API calls; callers should cache the result.
        """
        now = now or datetime.now(timezone.utc)
        base = quote(self.cfg.base, safe="")
        repo = self._call("GET", "")
        head = self._call("GET", f"/commits/{base}")
        open_prs = self._call("GET", f"/pulls?state=open&base={base}&per_page=50") or []
        closed = self._call("GET", f"/pulls?state=closed&base={base}&sort=updated&direction=desc&per_page=50") or []
        base_runs = (self._call("GET", f"/actions/runs?branch={base}&per_page=20") or {}).get("workflow_runs", [])
        pr_runs = (self._call("GET", "/actions/runs?event=pull_request&per_page=50") or {}).get("workflow_runs", [])

        # newest run per PR branch (the API returns newest first)
        latest_by_branch: dict[str, dict] = {}
        for run in pr_runs:
            latest_by_branch.setdefault(run.get("head_branch") or "", run)

        pulls = []
        for pr in open_prs:
            branch = (pr.get("head") or {}).get("ref") or ""
            created = _parse_time(pr.get("created_at"))
            pulls.append({
                "number": pr.get("number"),
                "title": pr.get("title") or "",
                "author": (pr.get("user") or {}).get("login"),
                "url": pr.get("html_url"),
                "branch": branch,
                "draft": bool(pr.get("draft")),
                "created_at": pr.get("created_at"),
                "age_hours": _hours(created, now),
                "ci": _run_state(latest_by_branch.get(branch)),
                "from_vitrix": branch.startswith(BRANCH_PREFIX),
            })

        merge_hours = [
            h for pr in closed
            if pr.get("merged_at") and (h := _hours(_parse_time(pr.get("created_at")), _parse_time(pr.get("merged_at")))) is not None
        ]
        runs = [_run(r) for r in base_runs]
        completed = [r for r in runs if r["state"] in ("success", "failure")]
        commit = head.get("commit") or {}
        return {
            "repo": {"name": self.cfg.repo, "url": repo.get("html_url"), "default_branch": repo.get("default_branch"),
                     "private": bool(repo.get("private")), "base": self.cfg.base},
            "head": {"sha": head.get("sha"), "message": (commit.get("message") or "").splitlines()[0] if commit.get("message") else "",
                     "author": (head.get("author") or {}).get("login") or (commit.get("author") or {}).get("name"),
                     "date": (commit.get("author") or {}).get("date"), "url": head.get("html_url")},
            "pulls": {
                "open": len(pulls),
                "failing": sum(p["ci"] == "failure" for p in pulls),
                "from_vitrix": sum(p["from_vitrix"] for p in pulls),
                "items": pulls,
            },
            "merge": {
                "sample": len(merge_hours),  # merged PRs among the 50 most recently closed
                "median_hours": round(median(merge_hours), 1) if merge_hours else None,
                "p90_hours": round(sorted(merge_hours)[max(0, -(-len(merge_hours) * 9 // 10) - 1)], 1) if merge_hours else None,
            },
            "ci": {
                "runs": runs,
                "sample": len(completed),
                "success_rate": round(100 * sum(r["state"] == "success" for r in completed) / len(completed)) if completed else None,
                "last": runs[0] if runs else None,
            },
        }


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _hours(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    return round((end - start).total_seconds() / 3600, 1)


def _run_state(run: dict | None) -> str | None:
    """success | failure | pending | None (no run). Cancelled and the like count as failure."""
    if not run:
        return None
    if run.get("status") != "completed":
        return "pending"
    return "success" if run.get("conclusion") in ("success", "skipped", "neutral") else "failure"


def _run(run: dict) -> dict:
    started, updated = _parse_time(run.get("run_started_at") or run.get("created_at")), _parse_time(run.get("updated_at"))
    state = _run_state(run)
    return {
        "id": run.get("id"),
        "number": run.get("run_number"),
        "name": run.get("name") or run.get("display_title") or "",
        "title": run.get("display_title") or "",
        "state": state,
        "conclusion": run.get("conclusion"),
        "sha": (run.get("head_sha") or "")[:7],
        "created_at": run.get("created_at"),
        "duration_s": int((updated - started).total_seconds()) if state != "pending" and started and updated else None,
        "url": run.get("html_url"),
    }


def branch_slug(rel: str) -> str:
    """Short, safe branch name derived from the rule path."""
    stem = PurePosixPath(rel).with_suffix("").as_posix()
    slug = re.sub(r"[^A-Za-z0-9]+", "-", stem).strip("-").lower()
    return slug[:48] or "rule"
