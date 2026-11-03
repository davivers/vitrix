"""API HTTP do Vitrix (FastAPI) e servidor da interface web.

Nada aqui grava no disco local. A única escrita é abrir um pull request no GitHub com o
token do ambiente (ver github.py). A API não tem autenticação, então o `vitrix serve` escuta
apenas em localhost por padrão, e toda requisição passa por `request_problem` (Host, Origin e
JSON obrigatório em POST: contra DNS rebinding e CSRF).

    GET  /api/health
    GET  /api/config
    GET  /api/targets
    GET  /api/stats                    números dos dashboards
    GET  /api/rules                    lista com estado de cada regra
    GET  /api/rules/{id}               regra, lint, queries por SIEM e testes
    POST /api/validate                 valida uma regra ainda não salva
    GET  /api/github                   repositório configurado e se há token (nunca o token)
    GET  /api/github/activity          PRs abertos, tempo até o merge e CI (cache de 60 s)
    POST /api/pull-requests            abre um PR com a regra e os casos editados
    POST /api/config/validate          valida um vitrix.yml editado
    POST /api/config/pull-requests     abre um PR alterando o vitrix.yml
    GET  /api/quality[/{id}]           fluxo e quality gate, regra a regra
    GET  /api/tests                    test suites: todos os casos, por tipo
    GET  /api/coverage                 matriz ATT&CK
    GET  /api/datasets                 datasets de replay em datasets/
    GET  /api/datasets/{nome}/replay   replay de um dataset, com as expectativas
    POST /api/replay                   replay de eventos colados (todas as regras ou a regra em edição)
    GET  /api/report?format=md|json    relatório consolidado
    POST /api/regex                    Regex Workbench: testa uma regex (subprocesso com tempo limite)
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, flow, regex_lab, service
from .backends import available_targets
from .config import load_config
from .github import GitHubError
from .replay import ReplayError

MAX_TEXT = 200_000  # caracteres por campo de texto
UI_DIR = Path(__file__).parent / "ui"  # build da interface (web/ -> npm run build)


class ValidateRequest(BaseModel):
    rule: str = Field(max_length=MAX_TEXT, description="YAML Sigma da regra")
    cases: str | None = Field(default=None, max_length=MAX_TEXT, description="YAML com os casos de teste (opcional)")
    targets: list[str] | None = Field(default=None, max_length=10, description="alvos; padrão: os do vitrix.yml")


class PullRequestRequest(BaseModel):
    path: str = Field(min_length=1, max_length=300, description="caminho da regra dentro de rules/, ex.: windows/x.yml")
    rule: str = Field(min_length=1, max_length=MAX_TEXT, description="YAML Sigma da regra")
    cases: str | None = Field(default=None, max_length=MAX_TEXT, description="YAML dos casos de teste (opcional)")
    title: str | None = Field(default=None, max_length=200, description="título do PR (opcional)")


class ReplayRequest(BaseModel):
    events: str = Field(max_length=5_000_000, description="eventos em JSON, JSON Lines ou YAML")
    rule: str | None = Field(default=None, max_length=MAX_TEXT, description="só esta regra (Editor); padrão: todas")


class RegexRequest(BaseModel):
    pattern: str = Field(max_length=2_000)
    flags: str = Field(default="", max_length=3, description="i, m e/ou s (os do Sigma: |re|i|m|s)")
    samples: list[str] = Field(default_factory=list, max_length=50)


class ConfigTextRequest(BaseModel):
    text: str = Field(max_length=MAX_TEXT, description="conteúdo do vitrix.yml")
    title: str | None = Field(default=None, max_length=200, description="título do PR (opcional)")


LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


def _host_only(value: str) -> str:
    value = value.strip().lower()
    if value.startswith("["):
        return value.split("]")[0] + "]"
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def allowed_hosts() -> set[str]:
    """localhost e o que estiver em VITRIX_ALLOWED_HOSTS (o `vitrix serve --host X` acrescenta X)."""
    extra = {_host_only(h) for h in os.environ.get("VITRIX_ALLOWED_HOSTS", "").split(",") if h.strip()}
    return LOCAL_HOSTS | extra


def request_problem(method: str, path: str, headers: dict[str, str], hosts: set[str], allowed_origins: list[str]) -> tuple[int, str] | None:
    """Defesa de toda requisição (a API não tem autenticação):

    - Host fora da lista → 403. Barra DNS rebinding: um site que aponte o próprio domínio para
      127.0.0.1 não consegue ler regras nem configuração pelo navegador da vítima.
    - POST/PUT/PATCH/DELETE de outra origem → 403, e corpo que não seja JSON → 415. Barra CSRF,
      inclusive o "simple request" text/plain que não passa pelo preflight de CORS.
    """
    host = _host_only(headers.get("host", ""))
    if host not in hosts:
        return 403, "host não permitido"
    if method in ("POST", "PUT", "PATCH", "DELETE") and path.startswith("/api/"):
        origin = headers.get("origin")
        if origin and origin not in allowed_origins and _host_only(origin.split("://", 1)[-1]) != host:
            return 403, "origem não permitida"
        if headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            return 415, "envie o corpo como application/json"
    return None


def create_app(config_path: str | None = None) -> FastAPI:
    cfg = load_config(config_path or os.environ.get("VITRIX_CONFIG"))
    app = FastAPI(title="Vitrix API", version=__version__)

    origins = [o.strip() for o in os.environ.get("VITRIX_CORS_ORIGINS", "").split(",") if o.strip()]
    if origins:
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
    hosts = allowed_hosts()

    @app.middleware("http")
    async def _guard(request: Request, call_next):  # noqa: ANN001, ANN202
        from fastapi.responses import JSONResponse

        problem = request_problem(request.method, request.url.path, {k.lower(): v for k, v in request.headers.items()}, hosts, origins)
        if problem:
            return JSONResponse(status_code=problem[0], content={"detail": problem[1]})
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.exception_handler(service.ServiceError)
    def _service_error(_, exc: service.ServiceError):  # noqa: ANN001
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=500, content={"detail": str(exc)})

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True, "version": __version__}

    @app.get("/api/config")
    def config() -> dict:
        return service.config_view(cfg)

    @app.post("/api/config/validate")
    def config_validate(req: ConfigTextRequest) -> dict:
        return service.validate_config_text(cfg, req.text)

    @app.post("/api/config/pull-requests", status_code=201)
    def config_pull_request(req: ConfigTextRequest) -> dict:
        try:
            return service.propose_config_change(cfg, req.text, req.title)
        except service.ChangeError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except GitHubError as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from None

    @app.get("/api/targets")
    def targets() -> list[dict]:
        return [
            {"name": name, "label": t.label, "extension": t.extension, "active": name in cfg.targets}
            for name, t in sorted(available_targets().items())
        ]

    @app.get("/api/stats")
    def stats() -> dict:
        return service.repo_stats(cfg)

    @app.get("/api/rules")
    def rules() -> list[dict]:
        return service.list_rules(cfg)

    @app.get("/api/rules/{rid:path}")
    def rule(rid: str) -> dict:
        try:
            return service.rule_detail(cfg, rid)
        except KeyError:
            raise HTTPException(status_code=404, detail="regra não encontrada") from None

    @app.post("/api/validate")
    def validate(req: ValidateRequest) -> dict:
        registry = available_targets()
        unknown = [t for t in (req.targets or []) if t not in registry]
        if unknown:
            raise HTTPException(status_code=422, detail=f"alvo desconhecido: {', '.join(unknown)}")
        result = service.validate_text(cfg, req.rule, req.cases, req.targets)
        result["quality"] = flow.draft_quality(cfg, result, req.rule, bool(req.cases and req.cases.strip()))
        return result

    @app.get("/api/quality")
    def quality() -> dict:
        return flow.quality_report(cfg)

    @app.get("/api/quality/{rid:path}")
    def quality_rule(rid: str) -> dict:
        rules = flow.quality_report(cfg, only=rid)["rules"]
        if not rules:
            raise HTTPException(status_code=404, detail="regra não encontrada")
        return rules[0]

    @app.get("/api/tests")
    def tests() -> dict:
        return flow.test_suites(cfg)

    @app.get("/api/coverage")
    def coverage() -> dict:
        return flow.coverage(cfg)

    @app.get("/api/datasets")
    def datasets() -> list[dict]:
        return flow.list_datasets(cfg)

    @app.get("/api/datasets/{name:path}/replay")
    def dataset_replay(name: str) -> dict:
        try:
            return flow.run_dataset(cfg, name)
        except KeyError:
            raise HTTPException(status_code=404, detail="dataset não encontrado") from None
        except ReplayError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.post("/api/replay")
    def replay_events(req: ReplayRequest) -> dict:
        try:
            return flow.replay_text(cfg, req.events, req.rule)
        except ReplayError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.post("/api/regex")
    def regex(req: RegexRequest) -> dict:
        try:
            return regex_lab.analyze(req.pattern, req.flags, req.samples)
        except regex_lab.RegexLabError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None

    @app.get("/api/report", response_model=None)
    def report_(format: str = "json"):
        data = flow.report(cfg)
        if format == "md":
            return PlainTextResponse(flow.report_markdown(data), media_type="text/markdown; charset=utf-8")
        return data

    @app.get("/api/github")
    def github() -> dict:
        return service.github_status(cfg)

    @app.get("/api/github/activity")
    def github_activity(refresh: bool = False) -> dict:
        return service.github_activity(cfg, refresh=refresh)

    @app.post("/api/pull-requests", status_code=201)
    def pull_request(req: PullRequestRequest) -> dict:
        try:
            return service.propose_change(cfg, req.path, req.rule, req.cases, req.title)
        except service.ChangeError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except GitHubError as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from None

    _mount_ui(app)
    return app


def _mount_ui(app: FastAPI) -> None:
    """Serve a interface web em "/", com fallback para o index.html (rotas do React)."""
    index = UI_DIR / "index.html"
    if not index.is_file():
        return  # pacote sem build da interface: só a API
    ui_root = UI_DIR.resolve()
    app.mount("/assets", StaticFiles(directory=UI_DIR / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def ui(path: str) -> FileResponse:
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status_code=404, detail="rota não encontrada")
        candidate = (UI_DIR / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(ui_root):
            return FileResponse(candidate)
        return FileResponse(index)
