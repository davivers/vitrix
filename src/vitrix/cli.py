"""Linha de comando: vitrix lint | convert | test | check | gate | replay | report | targets | serve.

Códigos de saída: 0 tudo certo, 1 falhas nas regras, 2 erro de uso ou de configuração.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .backends import available_targets, convert_text, load_extra_pipelines, sha256_text
from .cases import CaseResult, run_rule_cases
from .config import Config, ConfigError, load_config
from .lint import Issue, lint_files
from .loader import RuleFile, RuleLoadError, find_rule_files, load_rule
from .routing import Resolved, config_target_names
from .routing import plan as plan_targets


@dataclass
class ConvertResult:
    rule: str
    target: str
    ok: bool
    output: str  # a query, ou a mensagem de erro


class UsageError(Exception):
    pass


# --------------------------------------------------------------------------- etapas


def load_files(cfg: Config, paths: list[str]) -> tuple[list[RuleFile], list[Issue]]:
    try:
        found = find_rule_files(paths, cfg)
    except FileNotFoundError as exc:
        raise UsageError(str(exc)) from exc
    files: list[RuleFile] = []
    issues: list[Issue] = []
    for path in found:
        try:
            files.append(load_rule(path, cfg))
        except RuleLoadError as exc:
            issues.append(Issue("error", cfg.rel(path), str(exc)))
    return files, issues


def run_lint(files: list[RuleFile], load_issues: list[Issue]) -> list[Issue]:
    return [*load_issues, *lint_files(files, set(available_targets()))]


def run_convert(cfg: Config, files: list[RuleFile], override: list[str] | None = None) -> tuple[list[ConvertResult], dict[str, Resolved]]:
    """Converte cada regra para a(s) sua(s) linguagem(ns) final(is). `override` força os alvos (opção -t)."""
    registry = available_targets()
    unknown = sorted(n for n in (set(override) if override else config_target_names(cfg)) if n not in registry)
    if unknown:
        raise UsageError(f"alvo desconhecido: {', '.join(unknown)}. Disponíveis: {', '.join(sorted(registry))}")
    try:
        extra = load_extra_pipelines(cfg.extra_pipelines)
    except Exception as exc:
        raise UsageError(f"não foi possível carregar extra_pipelines: {exc}") from exc

    plan = plan_targets(cfg, files, override)
    results: list[ConvertResult] = []
    for rf in files:
        for name in plan[rf.rel].targets:
            if name not in registry:  # escolha da própria regra; o lint também acusa
                results.append(ConvertResult(rf.rel, name, False, f"alvo desconhecido: {name}"))
                continue
            try:
                results.append(ConvertResult(rf.rel, name, True, convert_text(rf.text, registry[name], extra)))
            except Exception as exc:  # erros do pySigma e de backends de plugins
                message = " ".join(str(exc).split()) or type(exc).__name__
                results.append(ConvertResult(rf.rel, name, False, f"{type(exc).__name__}: {message}"))
    return results, plan


def write_dist(cfg: Config, files: list[RuleFile], results: list[ConvertResult], plan: dict[str, Resolved]) -> None:
    registry = available_targets()
    for name in registry:  # limpa tudo: a regra pode ter trocado de linguagem final desde a última execução
        shutil.rmtree(cfg.output_dir / name, ignore_errors=True)
    outputs: dict[str, dict[str, str]] = {}
    for r in results:
        if not r.ok:
            continue
        rf_path = next(rf.path for rf in files if rf.rel == r.rule)
        try:
            rel = rf_path.resolve().relative_to(cfg.rules_dir.resolve()).with_suffix("")
        except ValueError:
            rel = Path(rf_path.stem)
        dest = cfg.output_dir / r.target / rel.parent / f"{rel.name}.{registry[r.target].extension}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(r.output + "\n", encoding="utf-8")
        outputs.setdefault(r.rule, {})[r.target] = cfg.rel(dest)
    manifest = {
        "engine": __version__,
        "targets": sorted({t for p in plan.values() for t in p.targets}),
        "rules": [
            {
                "path": rf.rel,
                "sha256": sha256_text(rf.text),
                "targets": plan[rf.rel].targets,
                "target_source": plan[rf.rel].source,
                "outputs": outputs.get(rf.rel, {}),
            }
            for rf in files
        ],
    }
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    (cfg.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_tests(cfg: Config, files: list[RuleFile]) -> tuple[list[CaseResult], list[Issue]]:
    results: list[CaseResult] = []
    problems: list[Issue] = []
    for rf in files:
        r, p = run_rule_cases(cfg, rf)
        results.extend(r)
        problems.extend(p)
    return results, problems


# --------------------------------------------------------------------------- saída


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def print_issues(issues: list[Issue]) -> None:
    current = None
    for issue in sorted(issues, key=lambda i: (i.rule, i.severity != "error")):
        if issue.rule != current:
            current = issue.rule
            print(current)
        print(f"  {issue}")


def lint_summary(files: list[RuleFile], issues: list[Issue]) -> str:
    errors = sum(i.severity == "error" for i in issues)
    warnings = sum(i.severity == "warning" for i in issues)
    return f"{_plural(len(files), 'regra', 'regras')} · {_plural(errors, 'erro', 'erros')} · {_plural(warnings, 'aviso', 'avisos')}"


def print_cases(results: list[CaseResult], problems: list[Issue]) -> None:
    current = None
    for r in results:
        if r.rule != current:
            current = r.rule
            print(r.rule)
        mark = "✓" if r.passed else "✗"
        print(f"  {mark} {r.name}")
        if not r.passed:
            detail = r.error or f"esperado: {r.expect} · obtido: {r.got}"
            print(f"      {detail}")
    if problems:
        print_issues(problems)


def cases_summary(results: list[CaseResult]) -> str:
    passed = sum(r.passed for r in results)
    return f"{passed} de {len(results)} casos passaram"


def print_convert_failures(results: list[ConvertResult]) -> None:
    for r in results:
        if not r.ok:
            print(f"✗ {r.rule} → {r.target}\n    {r.output}")


def build_markdown(
    files: list[RuleFile],
    lint_issues: list[Issue],
    convert_results: list[ConvertResult],
    case_results: list[CaseResult],
    case_problems: list[Issue],
) -> str:
    errors = [i for i in lint_issues if i.severity == "error"]
    converted_ok = sum(r.ok for r in convert_results)
    cases_ok = sum(r.passed for r in case_results)
    lines = [
        "## Detection-as-Code",
        "",
        "| Etapa | Resultado |",
        "|---|---|",
        f"| Lint | {'✅' if not errors else '❌'} {lint_summary(files, lint_issues)} |",
        f"| Conversão | {'✅' if converted_ok == len(convert_results) else '❌'} {converted_ok} de {len(convert_results)} conversões |",
        f"| Testes | {'✅' if cases_ok == len(case_results) and not case_problems else '❌'} {cases_summary(case_results)} |",
    ]
    problems = [*lint_issues, *case_problems]
    failures = [f"- `{r.rule}` → `{r.target}`: {r.output}" for r in convert_results if not r.ok]
    failures += [
        f"- `{r.rule}` · {r.name}: {r.error or f'esperado {r.expect}, obtido {r.got}'}"
        for r in case_results
        if not r.passed
    ]
    failures += [f"- `{i.rule}`: {i.message}" for i in problems if i.severity == "error"]
    if failures:
        lines += ["", "### O que falhou", "", *dict.fromkeys(failures)]
    warnings = [f"- `{i.rule}`: {i.message}" for i in lint_issues if i.severity == "warning"]
    if warnings:
        lines += ["", "<details><summary>Avisos</summary>", "", *warnings, "", "</details>"]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- comandos


def cmd_lint(cfg: Config, args: argparse.Namespace) -> int:
    files, load_issues = load_files(cfg, args.paths)
    issues = run_lint(files, load_issues)
    print_issues(issues)
    print(lint_summary(files, issues))
    has_errors = any(i.severity == "error" for i in issues)
    has_warnings = any(i.severity == "warning" for i in issues)
    return 1 if has_errors or (args.strict and has_warnings) else 0


def cmd_convert(cfg: Config, args: argparse.Namespace) -> int:
    files, load_issues = load_files(cfg, args.paths)
    if load_issues:
        print_issues(load_issues)
        return 1
    results, plan = run_convert(cfg, files, args.target)
    if args.stdout:
        for r in results:
            if r.ok:
                print(f"# {r.rule} → {r.target}\n{r.output}\n")
    else:
        write_dist(cfg, files, results, plan)
    print_convert_failures(results)
    ok = sum(r.ok for r in results)
    where = "" if args.stdout else f" em {cfg.rel(cfg.output_dir)}/"
    print(f"{ok} de {len(results)} conversões{where}")
    return 0 if ok == len(results) else 1


def cmd_test(cfg: Config, args: argparse.Namespace) -> int:
    files, load_issues = load_files(cfg, args.paths)
    if load_issues:
        print_issues(load_issues)
        return 1
    results, problems = run_tests(cfg, files)
    print_cases(results, problems)
    print(cases_summary(results))
    failed = any(not r.passed for r in results) or any(p.severity == "error" for p in problems)
    return 1 if failed else 0


def cmd_check(cfg: Config, args: argparse.Namespace) -> int:
    files, load_issues = load_files(cfg, args.paths)
    lint_issues = run_lint(files, load_issues)
    print("== lint")
    print_issues(lint_issues)
    print(lint_summary(files, lint_issues))

    print("\n== conversão")
    convert_results, plan = run_convert(cfg, files, args.target)
    write_dist(cfg, files, convert_results, plan)
    print_convert_failures(convert_results)
    print(f"{sum(r.ok for r in convert_results)} de {len(convert_results)} conversões em {cfg.rel(cfg.output_dir)}/")

    print("\n== testes")
    case_results, case_problems = run_tests(cfg, files)
    print_cases(case_results, case_problems)
    print(cases_summary(case_results))

    gate_failed = False
    if args.gate:
        print("\n== quality gate")
        gate_failed = print_gate(cfg) != 0

    if args.markdown:
        with Path(args.markdown).open("a", encoding="utf-8") as fh:
            fh.write(build_markdown(files, lint_issues, convert_results, case_results, case_problems))

    lint_failed = any(i.severity == "error" for i in lint_issues) or (
        args.strict and any(i.severity == "warning" for i in lint_issues)
    )
    convert_failed = any(not r.ok for r in convert_results)
    tests_failed = any(not r.passed for r in case_results) or any(p.severity == "error" for p in case_problems)
    return 1 if lint_failed or convert_failed or tests_failed or gate_failed else 0


_STAGE_MARK = {"ok": "✓", "warn": "!", "fail": "✗", "skip": "·", "pending": "…"}


def print_gate(cfg: Config) -> int:
    """Imprime o quality gate regra a regra. 0 se todas estão prontas para publicação."""
    from .flow import quality_report
    from .gate import STAGE_LABELS, STAGES

    q = quality_report(cfg)
    legend = "  ".join(f"{STAGE_LABELS[s]}" for s in STAGES)
    print(f"etapas: {legend}")
    for r in q["rules"]:
        marks = " ".join(_STAGE_MARK[r["stages"][s]] for s in STAGES)
        print(f"{'✓' if r['ready'] else '✗'} {r['id']}  [{marks}]")
        for c in r["checks"]:
            if c["passed"] is False:
                kind = "bloqueia" if c["blocking"] else "recomendação"
                detail = f": {c['detail']}" if c["detail"] else ""
                print(f"    {kind} · {c['label']}{detail}")
    for d in q["datasets"]:
        if d.get("error"):
            print(f"replay {d['dataset']}: {d['error']}")
    s = q["summary"]
    print(f"{s['ready']} de {s['total']} regras prontas para publicação")
    return 0 if s["blocked"] == 0 and not any(d.get("error") for d in q["datasets"]) else 1


def cmd_gate(cfg: Config, args: argparse.Namespace) -> int:
    return print_gate(cfg)


def cmd_replay(cfg: Config, args: argparse.Namespace) -> int:
    from .flow import list_datasets, run_dataset
    from .replay import ReplayError, load_events, replay

    try:
        if args.file:
            files, load_issues = load_files(cfg, [])
            path = Path(args.file)
            if not path.is_file():
                raise UsageError(f"arquivo não encontrado: {path}")
            from .service import rule_id

            results = [{"dataset": path.name, **replay([(rule_id(cfg, rf.path), rf) for rf in files], load_events(path.read_text(encoding="utf-8"), path.name)), "checks": []}]
        else:
            names = [args.dataset] if args.dataset else [d["name"] for d in list_datasets(cfg)]
            if not names:
                print(f"nenhum dataset em {cfg.rel(cfg.datasets_dir) if cfg.datasets_dir else 'datasets'}/")
                return 0
            results = [run_dataset(cfg, n) for n in names]
    except KeyError as exc:
        raise UsageError(f"dataset não encontrado: {exc.args[0]}") from None
    except ReplayError as exc:
        raise UsageError(str(exc)) from None

    failed = False
    for res in results:
        print(f"== {res['dataset']}: {res['events']} eventos em {res['duration_ms']} ms")
        for r in res["rules"]:
            if r["error"]:
                print(f"  · {r['rule']}: não avaliada ({r['error']})")
            elif r["matches"]:
                print(f"  {r['matches']:>5}  {r['rule']}  (eventos {', '.join(map(str, r['sample']))}{'…' if r['matches'] > len(r['sample']) else ''}) · {r['duration_ms']} ms")
        for c in res["checks"]:
            if not c["passed"]:
                failed = True
                print(f"  ✗ regressão · {c['rule']}: {c['message']}")
        if res["checks"] and all(c["passed"] for c in res["checks"]):
            print(f"  ✓ {len(res['checks'])} expectativas conferidas")
    return 1 if failed else 0


def cmd_report(cfg: Config, args: argparse.Namespace) -> int:
    from .flow import report, report_markdown

    data = report(cfg)
    text = json.dumps(data, ensure_ascii=False, indent=2) if args.format == "json" else report_markdown(data)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"relatório gravado em {args.output}")
    else:
        print(text)
    return 0 if data["quality"]["summary"]["blocked"] == 0 else 1


def _is_unspecified(host: str) -> bool:
    """True para o endereço "todas as interfaces" (IPv4 ou IPv6)."""
    try:
        return ipaddress.ip_address(host).is_unspecified
    except ValueError:
        return False


def cmd_serve(cfg: Config, args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError as exc:
        raise UsageError("a API precisa de dependências extras: pip install 'vitrix[api]'") from exc

    if args.config:
        os.environ["VITRIX_CONFIG"] = str(Path(args.config).resolve())
    elif (cfg.root / "vitrix.yml").is_file():
        os.environ["VITRIX_CONFIG"] = str(cfg.root / "vitrix.yml")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "aviso: a API não tem autenticação. Fora do localhost, qualquer um na rede lê suas regras e pode abrir PRs "
            "com o seu token. Use só atrás de um proxy com autenticação.",
            file=sys.stderr,
        )
        if not _is_unspecified(args.host):
            current = os.environ.get("VITRIX_ALLOWED_HOSTS", "")
            os.environ["VITRIX_ALLOWED_HOSTS"] = ",".join(filter(None, [current, args.host]))
        elif not os.environ.get("VITRIX_ALLOWED_HOSTS"):
            print("aviso: com --host 0.0.0.0, defina VITRIX_ALLOWED_HOSTS com o nome ou IP usado no navegador; os demais recebem 403.", file=sys.stderr)
    uvicorn.run("vitrix.api:create_app", factory=True, host=args.host, port=args.port, log_level="info")
    return 0


def cmd_targets(cfg: Config, args: argparse.Namespace) -> int:
    for name, target in sorted(available_targets().items()):
        marker = "*" if name in cfg.targets else " "
        print(f"{marker} {name:<16} {target.label}")
    print("\n* = ativo no vitrix.yml")
    return 0


# --------------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vitrix", description="Detection-as-Code: valida, converte e testa regras Sigma.")
    parser.add_argument("--version", action="version", version=f"vitrix {__version__}")
    parser.add_argument("-c", "--config", help="caminho do vitrix.yml (padrão: ./vitrix.yml)")
    sub = parser.add_subparsers(dest="command", required=True)

    def paths(p: argparse.ArgumentParser) -> None:
        p.add_argument("paths", nargs="*", help="arquivos ou pastas de regras (padrão: rules_dir do vitrix.yml)")

    p = sub.add_parser("lint", help="valida schema, condição e metadados")
    paths(p)
    p.add_argument("--strict", action="store_true", help="avisos também fazem o comando falhar")
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("convert", help="converte para os SIEMs configurados")
    paths(p)
    p.add_argument("-t", "--target", action="append", help="alvo (repita para vários; padrão: os do vitrix.yml)")
    p.add_argument("--all", action="store_true", help="todos os alvos do vitrix.yml (já é o padrão)")
    p.add_argument("--stdout", action="store_true", help="imprime em vez de gravar em dist/")
    p.set_defaults(func=cmd_convert)

    p = sub.add_parser("test", help="roda os casos de teste contra o avaliador local")
    paths(p)
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("check", help="lint + convert + test, para usar no CI")
    paths(p)
    p.add_argument("-t", "--target", action="append")
    p.add_argument("--strict", action="store_true")
    p.add_argument("--markdown", metavar="ARQUIVO", help="acrescenta um resumo em Markdown (ex.: $GITHUB_STEP_SUMMARY)")
    p.add_argument("--gate", action="store_true", help="também aplica o quality gate (replay, falsos positivos, exclusões)")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("gate", help="quality gate: a regra está pronta para ser publicada?")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("replay", help="roda as regras contra logs locais (datasets/) e confere as expectativas")
    p.add_argument("dataset", nargs="?", help="nome do dataset em datasets/ (padrão: todos)")
    p.add_argument("-f", "--file", help="um arquivo de eventos fora de datasets/ (JSON, JSONL ou YAML)")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("report", help="relatório de quality gate, testes, cobertura e replay")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("-o", "--output", help="arquivo de saída (padrão: imprime)")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("targets", help="lista os alvos de SIEM disponíveis")
    p.set_defaults(func=cmd_targets)

    p = sub.add_parser("serve", help="sobe a API local para a interface (precisa do extra [api])")
    p.add_argument("--host", default="127.0.0.1", help="padrão: 127.0.0.1 (a API não tem autenticação)")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_serve)
    return parser


def _utf8_console() -> None:
    """No Windows o console padrão é cp1252 e não imprime ✓/✗/·: força UTF-8 (sem quebrar se não der)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _utf8_console()
    args = build_parser().parse_args(argv)
    try:
        cfg = load_config(args.config)
        return args.func(cfg, args)
    except (ConfigError, UsageError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
