"""Abre pull requests no GitHub com as regras editadas na interface.

Nada é gravado no disco local: os arquivos vão direto para um branch novo no GitHub, em um
único commit, e o pull request é aberto contra o branch base. O CI do próprio repositório
valida a regra como em qualquer outro PR.

Configuração no vitrix.yml:

    github:
      repo: minha-org/deteccoes   # obrigatório
      base: main                  # branch de destino (padrão: main)
      path: ""                    # pasta do projeto Vitrix dentro do repositório (padrão: raiz)

O token vem SEMPRE do ambiente (`VITRIX_GITHUB_TOKEN` ou `GITHUB_TOKEN`), nunca do vitrix.yml.
Permissões mínimas de um token fine-grained: Contents (leitura e escrita) e Pull requests
(leitura e escrita) no repositório configurado.

Usa só a biblioteca padrão (urllib), sem dependências novas.
"""

from __future__ import annotations

import json
import os
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
_REPO = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")
_BRANCH = re.compile(r"^[A-Za-z0-9._/-]+$")


class GitHubError(Exception):
    """Falha ao falar com o GitHub. `status` é o código HTTP sugerido para a API do Vitrix."""

    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


@dataclass
class GitHubConfig:
    repo: str
    base: str = "main"
    path: str = ""  # prefixo do projeto Vitrix dentro do repositório

    def repo_path(self, rel: str) -> str:
        """Caminho no repositório de um arquivo relativo à raiz do projeto Vitrix."""
        return str(PurePosixPath(self.path, rel)) if self.path else rel


def parse_config(data: object) -> GitHubConfig | None:
    """Valida a seção `github:` do vitrix.yml. Levanta ValueError com a mensagem para o usuário."""
    if data is None:
        return None
    if not isinstance(data, dict):
        raise ValueError("'github' deve ser um mapa com repo, base e path")
    repo = data.get("repo")
    if not isinstance(repo, str) or not _REPO.match(repo.strip()):
        raise ValueError("github.repo deve ter o formato dono/repositorio")
    base = data.get("base", "main")
    if not isinstance(base, str) or not _BRANCH.match(base) or ".." in base:
        raise ValueError("github.base deve ser o nome de um branch")
    path = data.get("path", "") or ""
    if not isinstance(path, str) or path.startswith("/") or "\\" in path or ".." in PurePosixPath(path).parts:
        raise ValueError("github.path deve ser uma pasta relativa dentro do repositório")
    return GitHubConfig(repo=repo.strip(), base=base, path=path.strip("/"))


def token_from_env() -> str | None:
    for name in TOKEN_ENVS:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


# Assinatura do transporte: (método, url, corpo) -> (status, json). Injetável nos testes.
Transport = Callable[[str, str, dict | None], tuple[int, object]]


def _urllib_transport(token: str) -> Transport:
    def send(method: str, url: str, body: dict | None) -> tuple[int, object]:
        # o token só pode ir para a API do GitHub, por HTTPS (nunca file:, http: ou outro host)
        if not url.startswith(API_URL + "/"):
            raise GitHubError(f"URL fora da API do GitHub recusada: {url[:80]}")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "vitrix",
            **({"Content-Type": "application/json"} if data else {}),
        })
        try:
            # URL conferida acima: só https://api.github.com/
            with urllib.request.urlopen(req, timeout=20) as res:  # nosec B310
                return res.status, json.loads(res.read() or b"null")
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read() or b"null")
            except ValueError:
                payload = None
            return exc.code, payload
        except (urllib.error.URLError, TimeoutError) as exc:
            raise GitHubError(f"não consegui falar com o GitHub: {exc}") from exc

    return send


class GitHubClient:
    def __init__(self, cfg: GitHubConfig, token: str | None = None, transport: Transport | None = None):
        token = token or token_from_env()
        if transport is None:
            if not token:
                raise GitHubError(
                    f"defina {TOKEN_ENVS[0]} (ou GITHUB_TOKEN) no ambiente do `vitrix serve` para abrir pull requests",
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
                401: "token do GitHub inválido ou expirado",
                403: "o token não tem permissão de escrita (Contents e Pull requests) neste repositório",
                404: f"repositório {self.cfg.repo} ou branch {self.cfg.base} não encontrado (ou o token não tem acesso)",
            }.get(status)
            raise GitHubError(f"GitHub respondeu {status}: {hint or message or 'erro desconhecido'}")
        return payload

    def open_pull_request(self, files: dict[str, str], title: str, body: str, branch_hint: str) -> dict:
        """Cria branch + um commit com `files` (caminho no repositório -> texto) e abre o PR."""
        base_ref = self._call("GET", f"/git/ref/heads/{self.cfg.base}")
        base_sha = base_ref["object"]["sha"]
        base_commit = self._call("GET", f"/git/commits/{base_sha}")
        tree = self._call("POST", "/git/trees", {
            "base_tree": base_commit["tree"]["sha"],
            "tree": [{"path": p, "mode": "100644", "type": "blob", "content": text} for p, text in sorted(files.items())],
        })
        commit = self._call("POST", "/git/commits", {"message": title, "tree": tree["sha"], "parents": [base_sha]})
        branch = f"vitrix/{branch_hint}-{secrets.token_hex(3)}"
        self._call("POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": commit["sha"]})
        pr = self._call("POST", "/pulls", {"title": title, "head": branch, "base": self.cfg.base, "body": body})
        return {"url": pr.get("html_url"), "number": pr.get("number"), "branch": branch, "commit": commit["sha"]}



    # ----------------------------------------------------------------------- leitura (conector)

    def activity(self, now: datetime | None = None) -> dict:
        """Estado do repositório no GitHub: HEAD do base, PRs abertos, tempo até o merge e CI.

        Só leitura. São 6 chamadas à API; quem chama deve guardar o resultado em cache.
        """
        now = now or datetime.now(timezone.utc)
        base = quote(self.cfg.base, safe="")
        repo = self._call("GET", "")
        head = self._call("GET", f"/commits/{base}")
        open_prs = self._call("GET", f"/pulls?state=open&base={base}&per_page=50") or []
        closed = self._call("GET", f"/pulls?state=closed&base={base}&sort=updated&direction=desc&per_page=50") or []
        base_runs = (self._call("GET", f"/actions/runs?branch={base}&per_page=20") or {}).get("workflow_runs", [])
        pr_runs = (self._call("GET", "/actions/runs?event=pull_request&per_page=50") or {}).get("workflow_runs", [])

        # último run de cada branch de PR (a API devolve do mais novo para o mais antigo)
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
                "from_vitrix": branch.startswith("vitrix/"),
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
                "sample": len(merge_hours),  # PRs mesclados entre os 50 fechados mais recentes
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
    """success | failure | pending | None (sem execução). Cancelado e afins contam como falha."""
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
    """Nome curto e seguro para o branch, a partir do caminho da regra."""
    stem = PurePosixPath(rel).with_suffix("").as_posix()
    slug = re.sub(r"[^A-Za-z0-9]+", "-", stem).strip("-").lower()
    return slug[:48] or "regra"
