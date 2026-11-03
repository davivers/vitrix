"""Command line: vitrix init | lint | convert | test | check | gate | replay | report | targets | serve.

Exit codes: 0 all good, 1 rule failures, 2 usage or configuration error.
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
    output: str  # the query, or the error message


class UsageError(Exception):
    pass


# --------------------------------------------------------------------------- stages


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
    """Convert each rule to its final language(s). `override` forces the targets (-t)."""
    registry = available_targets()
    unknown = sorted(n for n in (set(override) if override else config_target_names(cfg)) if n not in registry)
    if unknown:
        raise UsageError(f"unknown target: {', '.join(unknown)}. Available: {', '.join(sorted(registry))}")
    try:
        extra = load_extra_pipelines(cfg.extra_pipelines)
    except Exception as exc:
        raise UsageError(f"could not load extra_pipelines: {exc}") from exc

    plan = plan_targets(cfg, files, override)
    results: list[ConvertResult] = []
    for rf in files:
        for name in plan[rf.rel].targets:
            if name not in registry:  # chosen by the rule itself; the lint reports it too
                results.append(ConvertResult(rf.rel, name, False, f"unknown target: {name}"))
                continue
            try:
                results.append(ConvertResult(rf.rel, name, True, convert_text(rf.text, registry[name], extra)))
            except Exception as exc:  # pySigma and plugin backend errors
                message = " ".join(str(exc).split()) or type(exc).__name__
                results.append(ConvertResult(rf.rel, name, False, f"{type(exc).__name__}: {message}"))
    return results, plan


def write_dist(cfg: Config, files: list[RuleFile], results: list[ConvertResult], plan: dict[str, Resolved]) -> None:
    registry = available_targets()
    for name in registry:  # clean everything: a rule may have changed its final language since the last run
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


# --------------------------------------------------------------------------- output


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
    return f"{_plural(len(files), 'rule', 'rules')} · {_plural(errors, 'error', 'errors')} · {_plural(warnings, 'warning', 'warnings')}"


def print_cases(results: list[CaseResult], problems: list[Issue]) -> None:
    current = None
    for r in results:
        if r.rule != current:
            current = r.rule
            print(r.rule)
        mark = "✓" if r.passed else "✗"
        print(f"  {mark} {r.name}")
        if not r.passed:
            detail = r.error or f"expected: {r.expect} · got: {r.got}"
            print(f"      {detail}")
    if problems:
        print_issues(problems)


def cases_summary(results: list[CaseResult]) -> str:
    passed = sum(r.passed for r in results)
    return f"{passed} of {len(results)} cases passed"


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
        "| Stage | Result |",
        "|---|---|",
        f"| Lint | {'✅' if not errors else '❌'} {lint_summary(files, lint_issues)} |",
        f"| Conversion | {'✅' if converted_ok == len(convert_results) else '❌'} {converted_ok} of {len(convert_results)} conversions |",
        f"| Tests | {'✅' if cases_ok == len(case_results) and not case_problems else '❌'} {cases_summary(case_results)} |",
    ]
    problems = [*lint_issues, *case_problems]
    failures = [f"- `{r.rule}` → `{r.target}`: {r.output}" for r in convert_results if not r.ok]
    failures += [
        f"- `{r.rule}` · {r.name}: {r.error or f'expected {r.expect}, got {r.got}'}"
        for r in case_results
        if not r.passed
    ]
    failures += [f"- `{i.rule}`: {i.message}" for i in problems if i.severity == "error"]
    if failures:
        lines += ["", "### What failed", "", *dict.fromkeys(failures)]
    warnings = [f"- `{i.rule}`: {i.message}" for i in lint_issues if i.severity == "warning"]
    if warnings:
        lines += ["", "<details><summary>Warnings</summary>", "", *warnings, "", "</details>"]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- commands


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
    where = "" if args.stdout else f" in {cfg.rel(cfg.output_dir)}/"
    print(f"{ok} of {len(results)} conversions{where}")
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

    print("\n== conversion")
    convert_results, plan = run_convert(cfg, files, args.target)
    write_dist(cfg, files, convert_results, plan)
    print_convert_failures(convert_results)
    print(f"{sum(r.ok for r in convert_results)} of {len(convert_results)} conversions in {cfg.rel(cfg.output_dir)}/")

    print("\n== tests")
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
    """Print the quality gate rule by rule. 0 if every rule is ready to publish."""
    from .flow import quality_report
    from .gate import STAGE_LABELS, STAGES

    q = quality_report(cfg)
    legend = "  ".join(f"{STAGE_LABELS[s]}" for s in STAGES)
    print(f"stages: {legend}")
    for r in q["rules"]:
        marks = " ".join(_STAGE_MARK[r["stages"][s]] for s in STAGES)
        print(f"{'✓' if r['ready'] else '✗'} {r['id']}  [{marks}]  health {r['score']}/100")
        for c in r["checks"]:
            if c["passed"] is False:
                kind = "blocks" if c["blocking"] else "recommendation"
                detail = f": {c['detail']}" if c["detail"] else ""
                print(f"    {kind} · {c['label']}{detail}")
    for d in q["datasets"]:
        if d.get("error"):
            print(f"replay {d['dataset']}: {d['error']}")
    s = q["summary"]
    print(f"{s['ready']} of {s['total']} rules ready to publish")
    return 0 if s["blocked"] == 0 and not any(d.get("error") for d in q["datasets"]) else 1


def cmd_gate(cfg: Config, args: argparse.Namespace) -> int:
    return print_gate(cfg)


def cmd_replay(cfg: Config, args: argparse.Namespace) -> int:
    from .flow import list_datasets, run_dataset
    from .replay import ReplayError, load_events, replay
    from .service import rule_id

    try:
        if args.file:
            files, _ = load_files(cfg, [])
            path = Path(args.file)
            if not path.is_file():
                raise UsageError(f"file not found: {path}")
            events = load_events(path.read_text(encoding="utf-8"), path.name)
            results = [{"dataset": path.name, **replay([(rule_id(cfg, rf.path), rf) for rf in files], events), "checks": []}]
        else:
            names = [args.dataset] if args.dataset else [d["name"] for d in list_datasets(cfg)]
            if not names:
                print(f"no dataset in {cfg.rel(cfg.datasets_dir) if cfg.datasets_dir else 'datasets'}/")
                return 0
            results = [run_dataset(cfg, n) for n in names]
    except KeyError as exc:
        raise UsageError(f"dataset not found: {exc.args[0]}") from None
    except ReplayError as exc:
        raise UsageError(str(exc)) from None

    failed = False
    for res in results:
        print(f"== {res['dataset']}: {res['events']} events in {res['duration_ms']} ms")
        for r in res["rules"]:
            if r["error"]:
                print(f"  · {r['rule']}: not evaluated ({r['error']})")
            elif r["matches"]:
                more = "…" if r["matches"] > len(r["sample"]) else ""
                print(f"  {r['matches']:>5}  {r['rule']}  (events {', '.join(map(str, r['sample']))}{more}) · {r['duration_ms']} ms")
        for c in res["checks"]:
            if not c["passed"]:
                failed = True
                print(f"  ✗ regression · {c['rule']}: {c['message']}")
        if res["checks"] and all(c["passed"] for c in res["checks"]):
            print(f"  ✓ {len(res['checks'])} expectations met")
    return 1 if failed else 0


def cmd_report(cfg: Config, args: argparse.Namespace) -> int:
    from .flow import report, report_markdown

    data = report(cfg)
    text = json.dumps(data, ensure_ascii=False, indent=2) if args.format == "json" else report_markdown(data)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"report written to {args.output}")
    else:
        print(text)
    return 0 if data["quality"]["summary"]["blocked"] == 0 else 1


def _is_unspecified(host: str) -> bool:
    """True for the "all interfaces" address (IPv4 or IPv6)."""
    try:
        return ipaddress.ip_address(host).is_unspecified
    except ValueError:
        return False


def cmd_serve(cfg: Config, args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError as exc:
        raise UsageError("the API needs extra dependencies: pip install 'vitrix[api]'") from exc

    if args.config:
        os.environ["VITRIX_CONFIG"] = str(Path(args.config).resolve())
    elif (cfg.root / "vitrix.yml").is_file():
        os.environ["VITRIX_CONFIG"] = str(cfg.root / "vitrix.yml")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "warning: the API has no authentication. Outside localhost anyone on the network can read your rules and "
            "push branches with your token. Only use it behind an authenticating proxy.",
            file=sys.stderr,
        )
        if not _is_unspecified(args.host):
            current = os.environ.get("VITRIX_ALLOWED_HOSTS", "")
            os.environ["VITRIX_ALLOWED_HOSTS"] = ",".join(filter(None, [current, args.host]))
        elif not os.environ.get("VITRIX_ALLOWED_HOSTS"):
            print("warning: with --host 0.0.0.0, set VITRIX_ALLOWED_HOSTS to the name or IP used in the browser; others get 403.",
                  file=sys.stderr)
    uvicorn.run("vitrix.api:create_app", factory=True, host=args.host, port=args.port, log_level="info")
    return 0


TEMPLATE_DIR = Path(__file__).parent / "template"


def _template_files() -> list[tuple[Path, str]]:
    """(source file, relative destination). A leading `_` in a template name becomes `.`
    (`_github` → `.github`, `_gitignore` → `.gitignore`) so packaging never drops dotfiles."""
    out = []
    for src in sorted(p for p in TEMPLATE_DIR.rglob("*") if p.is_file()):
        parts = [("." + part[1:] if part.startswith("_") else part) for part in src.relative_to(TEMPLATE_DIR).parts]
        out.append((src, "/".join(parts)))
    return out


def cmd_init(cfg: Config, args: argparse.Namespace) -> int:
    """Create a new detections repository: vitrix.yml, example rules, cases, replay logs and the CI workflow."""
    files = _template_files()
    if not files:
        raise UsageError("this installation has no project template")
    target = Path(args.directory).resolve()
    clashes = [rel for _, rel in files if (target / rel).exists()]
    if clashes and not args.force:
        raise UsageError(f"{target} already has: {', '.join(clashes[:5])}{'…' if len(clashes) > 5 else ''}. Use --force to overwrite or pick an empty folder.")
    for src, rel in files:
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(src.read_bytes())
    print(f"created a Vitrix detections repository in {target} ({len(files)} files)")
    here = "" if target == Path.cwd() else f"cd {args.directory}\n  "
    print(f"\nnext steps:\n  {here}vitrix check --strict --gate     # validate the example rules\n  vitrix serve                      # open the web UI\n"
          "  git init && git add -A && git commit -m \"Initial detections\"\n"
          "then push it to YOUR repository and set `github.repo` in vitrix.yml (see README.md).")
    return 0


def cmd_targets(cfg: Config, args: argparse.Namespace) -> int:
    for name, target in sorted(available_targets().items()):
        marker = "*" if name in cfg.targets else " "
        print(f"{marker} {name:<16} {target.label}")
    print("\n* = active in vitrix.yml")
    return 0


# --------------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vitrix", description="Detection-as-Code: validate, convert and test Sigma rules.")
    parser.add_argument("--version", action="version", version=f"vitrix {__version__}")
    parser.add_argument("-c", "--config", help="path to vitrix.yml (default: ./vitrix.yml)")
    sub = parser.add_subparsers(dest="command", required=True)

    def paths(p: argparse.ArgumentParser) -> None:
        p.add_argument("paths", nargs="*", help="rule files or folders (default: rules_dir from vitrix.yml)")

    p = sub.add_parser("init", help="create a new detections repository (vitrix.yml, example rules, CI workflow)")
    p.add_argument("directory", nargs="?", default=".", help="where to create it (default: the current folder)")
    p.add_argument("--force", action="store_true", help="overwrite files that already exist")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("lint", help="validate schema, condition and metadata")
    paths(p)
    p.add_argument("--strict", action="store_true", help="warnings also fail the command")
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("convert", help="convert to the configured SIEMs")
    paths(p)
    p.add_argument("-t", "--target", action="append", help="target (repeat for several; default: those in vitrix.yml)")
    p.add_argument("--all", action="store_true", help="every target in vitrix.yml (already the default)")
    p.add_argument("--stdout", action="store_true", help="print instead of writing to dist/")
    p.set_defaults(func=cmd_convert)

    p = sub.add_parser("test", help="run the test cases with the local evaluator")
    paths(p)
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("check", help="lint + convert + test, for CI")
    paths(p)
    p.add_argument("-t", "--target", action="append")
    p.add_argument("--strict", action="store_true")
    p.add_argument("--markdown", metavar="FILE", help="append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    p.add_argument("--gate", action="store_true", help="also apply the quality gate (replay, false positives, exclusions)")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("gate", help="quality gate: is each rule ready to be published?")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("replay", help="run the rules against local logs (datasets/) and check the expectations")
    p.add_argument("dataset", nargs="?", help="dataset name in datasets/ (default: all)")
    p.add_argument("-f", "--file", help="an events file outside datasets/ (JSON, JSONL or YAML)")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("report", help="quality gate, tests, coverage and replay report")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("-o", "--output", help="output file (default: print)")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("targets", help="list the available SIEM targets")
    p.set_defaults(func=cmd_targets)

    p = sub.add_parser("serve", help="start the local API and web UI (needs the [api] extra)")
    p.add_argument("--host", default="127.0.0.1", help="default: 127.0.0.1 (the API has no authentication)")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_serve)
    return parser


def _utf8_console() -> None:
    """The Windows console defaults to cp1252 and cannot print ✓/✗/·: force UTF-8 (never fail)."""
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
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
