"""Zero-config GitHub: read the repository from `git remote origin` and the token from the GitHub CLI.

So a user does not have to edit vitrix.yml or export variables when the folder is already a
clone of their GitHub repository:

- `detect(root)`: repo from `origin`, base from `origin/HEAD` (or the current branch), path of the
  project inside the repository, workflow `vitrix` when `.github/workflows/vitrix.yml` exists.
- `token()`: `VITRIX_GITHUB_TOKEN` / `GITHUB_TOKEN`, else `gh auth token` (if the GitHub CLI is
  installed and logged in). The token is never written anywhere.

An explicit `github:` section in vitrix.yml always wins; `github: false` turns detection off.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404
import time
from pathlib import Path

from .github import TOKEN_ENVS, GitHubConfig

_REMOTE = re.compile(r"^(?:https://(?:[^@/]+@)?github\.com/|ssh://git@github\.com/|git@github\.com:)"
                     r"(?P<repo>[A-Za-z0-9-]+/[A-Za-z0-9._-]+?)(?:\.git)?/?$")
_CACHE_TTL = 30.0
_cache: dict[str, tuple[float, GitHubConfig | None]] = {}


def parse_remote(url: str) -> str | None:
    """owner/repo of a github.com remote URL (https or ssh), else None."""
    m = _REMOTE.match(url.strip())
    return m.group("repo") if m else None


def git(root: Path, *args: str, timeout: float = 10) -> str | None:
    """Output of a git command in `root`, or None when git is missing or the command fails."""
    exe = shutil.which("git")
    if not exe:
        return None
    try:
        # fixed executable and arguments, no shell
        proc = subprocess.run([exe, "-C", str(root), *args], capture_output=True, text=True, timeout=timeout)  # nosec B603
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def detect(root: Path) -> GitHubConfig | None:
    """GitHub settings inferred from the git clone that contains `root` (cached for 30 s)."""
    key = str(root.resolve())
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < _CACHE_TTL:
        return hit[1]
    result = _detect(root)
    _cache[key] = (time.monotonic(), result)
    return result


def _detect(root: Path) -> GitHubConfig | None:
    url = git(root, "remote", "get-url", "origin")
    repo = parse_remote(url) if url else None
    if not repo:
        return None
    top = git(root, "rev-parse", "--show-toplevel")
    path = ""
    if top:
        try:
            path = root.resolve().relative_to(Path(top).resolve()).as_posix()
        except ValueError:
            path = ""
        path = "" if path == "." else path
    head = git(root, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")  # e.g. origin/main
    base = head.split("/", 1)[1] if head and "/" in head else (git(root, "branch", "--show-current") or "main")
    workflow = "vitrix" if top and (Path(top) / ".github" / "workflows" / "vitrix.yml").is_file() else None
    return GitHubConfig(repo=repo, base=base, path=path, workflow=workflow)


_gh_cache: tuple[float, str | None] | None = None


def token() -> tuple[str | None, str | None]:
    """(token, where it came from). Never logged, never stored on disk."""
    global _gh_cache
    for name in TOKEN_ENVS:
        value = os.environ.get(name, "").strip()
        if value:
            return value, name
    if os.environ.get("VITRIX_GH_CLI", "1") == "0":
        return None, None
    if _gh_cache and time.monotonic() - _gh_cache[0] < 60:
        return (_gh_cache[1], "gh CLI") if _gh_cache[1] else (None, None)
    value = _gh_token()
    _gh_cache = (time.monotonic(), value)
    return (value, "gh CLI") if value else (None, None)


def _gh_token() -> str | None:
    exe = shutil.which("gh")
    if not exe:
        return None
    try:
        # fixed executable and arguments, no shell
        proc = subprocess.run([exe, "auth", "token"], capture_output=True, text=True, timeout=10)  # nosec B603
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = proc.stdout.strip()
    return value if proc.returncode == 0 and value else None
