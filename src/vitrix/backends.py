"""Conversion targets (SIEMs) and plugins.

Each target knows how to build a pySigma backend with its default field pipeline.
Third-party plugins register new targets through the `vitrix.targets` entry point.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

from .mapping_names import valid_table


@dataclass(frozen=True)
class Target:
    name: str  # nome usado no vitrix.yml e na CLI
    label: str  # human-readable name
    extension: str  # extension of the generated file
    factory: Callable[[list], Any]  # takes extra pipelines and returns a pySigma backend


def _combine(extra: list, default: Any) -> Any:
    """User pipelines run before the default one, to rename fields before the SIEM mapping."""
    combined = None
    for pipeline in [*extra, default]:
        combined = pipeline if combined is None else combined + pipeline
    return combined


def _splunk(extra: list) -> Any:
    from sigma.backends.splunk import SplunkBackend
    from sigma.pipelines.splunk import splunk_windows_pipeline

    return SplunkBackend(processing_pipeline=_combine(extra, splunk_windows_pipeline()))


def _kql(extra: list) -> Any:
    from sigma.backends.kusto import KustoBackend
    from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline

    return KustoBackend(processing_pipeline=_combine(extra, microsoft_365_defender_pipeline()))


def _eql(extra: list) -> Any:
    from sigma.backends.elasticsearch import EqlBackend
    from sigma.pipelines.elasticsearch.windows import ecs_windows

    return EqlBackend(processing_pipeline=_combine(extra, ecs_windows()))


def _lucene(extra: list) -> Any:
    from sigma.backends.elasticsearch import LuceneBackend
    from sigma.pipelines.elasticsearch.windows import ecs_windows

    return LuceneBackend(processing_pipeline=_combine(extra, ecs_windows()))


SIGMA = "sigma"  # pseudo-target: keep the Sigma rule as the final artifact (no conversion, nothing can fail)


def _no_backend(extra: list) -> Any:
    raise RuntimeError("the sigma target has no backend")


BUILTIN: dict[str, Target] = {
    t.name: t
    for t in (
        Target(SIGMA, "Keep as Sigma (no conversion)", "yml", _no_backend),
        Target("splunk", "Splunk (SPL)", "spl", _splunk),
        Target("kql", "Microsoft Defender / Sentinel (KQL)", "kql", _kql),
        Target("elastic-eql", "Elastic (EQL)", "eql", _eql),
        Target("elastic-lucene", "Elastic (Lucene)", "lucene", _lucene),
    )
}


# pySigma backend id (and flavor) and pip package of the built-in targets; plugins may set the same
# attributes on their Target object (`backend`, `plugin`).
BUILTIN_INFO: dict[str, tuple[str, str]] = {
    "splunk": ("splunk", "pysigma-backend-splunk"),
    "kql": ("kusto", "pysigma-backend-kusto"),
    "elastic-eql": ("elasticsearch (eql)", "pysigma-backend-elasticsearch"),
    "elastic-lucene": ("elasticsearch (lucene)", "pysigma-backend-elasticsearch"),
}


def target_info(target: Target) -> dict:
    """{backend, plugin, status: ok|missing_plugin|error, message}: can the backend be built right now?"""
    if target.name == SIGMA:
        return {"backend": None, "plugin": None, "status": "ok", "message": None}
    backend, plugin = BUILTIN_INFO.get(target.name, (getattr(target, "backend", "") or target.name, getattr(target, "plugin", "") or ""))
    try:
        target.factory([])
        status, message = "ok", None
    except ImportError as exc:
        status, message = "missing_plugin", f"{exc}" + (f". Install it with: pip install {plugin}" if plugin else "")
    except Exception as exc:  # noqa: BLE001 - a broken plugin must not break the list
        status, message = "error", str(exc)[:300]
    return {"backend": backend, "plugin": plugin, "status": status, "message": message}


def available_targets() -> dict[str, Target]:
    """Alvos embutidos mais os registrados por plugins (entry point `vitrix.targets`)."""
    targets = dict(BUILTIN)
    for ep in metadata.entry_points(group="vitrix.targets"):
        try:
            obj = ep.load()
            target = obj if isinstance(obj, Target) else obj()
        except Exception as exc:  # a broken plugin must not take the others down
            print(f"warning: plugin '{ep.name}' could not be loaded: {exc}")
            continue
        targets[target.name] = target
    return targets


def load_extra_pipelines(paths: list[Path]) -> list:
    from sigma.processing.pipeline import ProcessingPipeline

    return [ProcessingPipeline.from_yaml(p.read_text(encoding="utf-8")) for p in paths]


# Tables for logsources the Kusto backend cannot place by itself (no mapped category, no EventID).
# Used only as a fallback, after the rule's `vitrix.kql_table` and vitrix.yml `kql.tables`. Keys are
# `product/service`, `product/category`, `product/*`, or a bare service/category for rules without a product.
# Only Microsoft first-party tables (docs: learn.microsoft.com/azure/azure-monitor/reference/tables) and the
# standard CEF/Syslog tables are built in; third-party sources (Okta, Zeek, GitHub...) depend on how the user
# ingests them, so they stay an actionable `kql-table` issue with a suggested table in the hint.
KQL_DEFAULT_TABLES: dict[str, str] = {
    "windows/security": "SecurityEvent",
    "windows/*": "Event",  # every other Windows channel / Sysmon category arrives in the Event table
    "linux/*": "Syslog",
    "macos/*": "Syslog",
    "azure/activitylogs": "AzureActivity",
    "azure/auditlogs": "AuditLogs",
    "azure/pim": "AuditLogs",
    "azure/signinlogs": "SigninLogs",
    "azure/riskdetection": "AADUserRiskEvents",
    "azure/*": "AzureActivity",
    "m365/*": "OfficeActivity",
    "aws/*": "AWSCloudTrail",
    "gcp/gcp.audit": "GCPAuditLogs",
    "kubernetes/audit": "AKSAudit",
    "cisco/*": "Syslog",
    "juniper/*": "Syslog",
    "huawei/*": "Syslog",
    "fortigate/*": "CommonSecurityLog",
    "apache": "Syslog",
    "nginx": "Syslog",
    "proxy": "CommonSecurityLog",
    "firewall": "CommonSecurityLog",
    "dns": "DnsEvents",
    "webserver": "W3CIISLog",
}
# Shown in the hint when nothing resolves; these depend on the user's connector, so they are suggestions only.
KQL_SUGGESTED_TABLES: dict[str, str] = {
    "okta": "Okta_CL", "github": "GitHubAuditLogPolling_CL", "onelogin": "OneLogin_CL", "zeek": "Corelight_v2_<service>",
    "gcp": "GoogleWorkspaceReports", "antivirus": "SecurityAlert", "application": "AppTraces",
}


def suggest_table(ls: dict) -> str | None:
    """Table to suggest for a logsource: the known connector table when there is one, otherwise
    `<Product><Service>_CL` (Azure Monitor custom-log naming, e.g. bitbucket/audit -> BitbucketAudit_CL)."""
    product, category, service = ls.get("product"), ls.get("category"), ls.get("service")
    known = next((KQL_SUGGESTED_TABLES[v] for v in (product, category, service) if v in KQL_SUGGESTED_TABLES), None)
    if known:
        known = known.replace("<service>", re.sub(r"[^A-Za-z0-9_]", "", service or "") or "logs")
        if valid_table(known):
            return known
    parts = [re.sub(r"[^A-Za-z0-9]", "", w).capitalize() for w in (product, service or category) if w]
    name = "".join(p for p in parts if p)
    if not name:
        return None
    if name[0].isdigit():
        name = "T" + name
    candidate = f"{name[:60]}_CL"
    return candidate if valid_table(candidate) else None


class ConversionError(Exception):
    """A conversion failure with where/how-to-fix details (issue model: code, path, line, column, hint)."""

    def __init__(self, message: str, *, code: str, path: str | None = None, line: int | None = None, hint: str | None = None,
                 fix: dict | None = None):
        super().__init__(message)
        self.code, self.path, self.line, self.column, self.hint, self.fix = code, path, line, 1 if line else None, hint, fix

    def details(self) -> dict:
        return {"code": self.code, "path": self.path, "line": self.line, "column": self.column, "hint": self.hint, "fix": self.fix}


def _logsource(doc: object) -> dict:
    ls = doc.get("logsource") if isinstance(doc, dict) else None
    return {k: str(v).strip().lower() for k, v in ls.items() if v} if isinstance(ls, dict) else {}


def _logsource_keys(doc: object) -> list[str]:
    """Lookup keys of a rule, most specific first: `product/service`, `product/category`, `product/*`
    (or the bare service / category when the rule has no product)."""
    ls = _logsource(doc)
    product = ls.get("product", "")
    if not product:
        return [ls[k] for k in ("service", "category") if k in ls]
    return [*(f"{product}/{ls[k]}" for k in ("service", "category") if k in ls), f"{product}/*"]


def _first_doc(text: str) -> object:
    import yaml

    try:
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError:
        return None
    return next((d for d in docs if "detection" in d), docs[0] if docs else None)


def _table_pipeline(table: str, fields: dict | None = None) -> Any:
    """Sets the KQL table and, when mappings.yml maps fields for it, renames Sigma fields to its columns."""
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import FieldMappingTransformation, SetStateTransformation

    items = [ProcessingItem(identifier="vitrix_kql_table", transformation=SetStateTransformation("query_table", table))]
    if fields:
        items.append(ProcessingItem(identifier="vitrix_kql_fields", transformation=FieldMappingTransformation(dict(fields))))
    return ProcessingPipeline(items=items)


def _kql_table_error(text: str, doc: object) -> ConversionError:
    keys = _logsource_keys(doc)
    ls = _logsource(doc)
    key = next((k for k in keys if not k.endswith("/*")), keys[0] if keys else "windows/system")
    line = next((i for i, row in enumerate(text.splitlines(), 1) if row.startswith("logsource:")), None)
    where = f" ({key})" if keys else ""
    suggest = suggest_table(ls)
    tip = f" Likely table for this source: {suggest} (depends on your connector)." if suggest else ""
    return ConversionError(
        f"KQL needs a table for this rule's logsource{where} and none is configured.",
        code="kql-table", path="logsource", line=line,
        hint=f"Pick the table in the Editor: for this rule (`vitrix: {{kql_table: {suggest or 'Event'}}}`) or for every `{key}` rule (saved in mappings.yml).{tip}",
        fix={"kind": "kql-table", "key": key, "suggestion": suggest})


_FIELD_TABLE = re.compile(r"for the (\w+) table")
_FIELD_ERR = re.compile(r"Invalid SigmaDetectionItem field name encountered: (\S+?)\.")


def _explain(exc: Exception, text: str, target: Target, table: str | None = None) -> ConversionError:
    """Turn any pySigma / plugin exception into an actionable issue (never the raw exception string)."""
    msg = " ".join(str(exc).split())
    name = type(exc).__name__
    line = next((i for i, row in enumerate(text.splitlines(), 1) if row.startswith("detection:")), None)
    m = _FIELD_ERR.search(msg)
    if m:
        fld = m.group(1)
        if table is None and (tm := _FIELD_TABLE.search(msg)):
            table = tm.group(1)  # the backend names the table it inferred
        return ConversionError(
            f"{target.label} has no mapping for field `{fld}` in the table chosen for this rule's logsource.",
            code="kql-field", path="detection", line=line,
            hint=f"Map `{fld}` to a column of the table in the Editor (saved in mappings.yml), "
                 "or pick another table with `vitrix: {kql_table: ...}` whose columns match the rule's fields.",
            fix={"kind": "kql-field", "table": table, "field": fld, "suggestion": None})
    if "No valid hash algo" in msg:
        return ConversionError("The rule's Hashes values use an algorithm this KQL table cannot match (only MD5, SHA1 and SHA256 are supported).",
                               code="kql-hash", path="detection", line=line,
                               hint="Use `Hashes|contains: 'SHA256=...'` (or MD5/SHA1) values, or drop other algorithms such as IMPHASH from the rule.")
    if "correlation" in msg.lower() or "Correlation" in name:
        return ConversionError(f"{target.label} cannot convert this correlation rule yet.", code="conversion-correlation", path="correlation", line=line,
                               hint="Keep this rule for the targets that support correlation, or split it into plain detection rules.")
    if "not supported" in msg or "Unsupported" in name or "unsupported" in msg:
        return ConversionError(f"{target.label} does not support a construct in this rule: {msg[:160]}", code="conversion-unsupported", path="detection", line=line,
                               hint="Rewrite the offending field/modifier with ones the target supports (e.g. contains/startswith instead of re/cidr), or drop this target for the rule.")
    return ConversionError(f"{target.label} could not convert this rule ({name}).", code="conversion-failed", path="detection", line=line,
                           hint=f"Check the rule's logsource, fields and modifiers against the {target.label} backend. Detail: {msg[:200]}")


def _convert(text: str, target: Target, extra: list) -> str:
    from sigma.collection import SigmaCollection

    collection = SigmaCollection.from_yaml(text)
    queries = target.factory(extra).convert(collection)
    if not isinstance(queries, list):
        queries = [str(queries)]
    return "\n\n".join(str(q) for q in queries)


def convert_text(text: str, target: Target, extra: list, kql: Any = None) -> str:
    if target.name == SIGMA:
        return text.rstrip("\n")  # the rule itself; CI copies it to dist/sigma/
    try:
        return _convert_text(text, target, extra, kql)
    except ConversionError:
        raise
    except Exception as exc:
        raise _explain(exc, text, target) from None


def _convert_text(text: str, target: Target, extra: list, kql: Any) -> str:
    """Convert the text of a Sigma file for the target.

    pySigma mutates the rule while converting (it renames fields). So every call parses the
    YAML again: reusing one collection across targets would contaminate the second one.

    KQL table (`kql` is a `config.KqlConfig`): the rule's `vitrix.kql_table` and `kql.tables` always win;
    the table the backend infers (category / EventID) comes next; then the built-in defaults and
    `kql.default_table`. Nothing found: `ConversionError` (code `kql-table`).
    """
    if target.name != "kql":
        return _convert(text, target, extra)
    doc = _first_doc(text)
    block = doc.get("vitrix") if isinstance(doc, dict) else None
    tables = getattr(kql, "tables", {}) or {}
    keys = _logsource_keys(doc)
    explicit = (block.get("kql_table") if isinstance(block, dict) else None) or next((tables[k] for k in keys if k in tables), None)
    mapped = getattr(kql, "fields", {}) or {}

    def with_table(table: str) -> str:
        try:
            return _convert(text, target, [_table_pipeline(table, mapped.get(table)), *extra])
        except ConversionError:
            raise
        except Exception as exc:
            raise _explain(exc, text, target, table) from None

    if isinstance(explicit, str) and valid_table(explicit.strip()):  # identifiers only: the name is pasted into the query
        return with_table(explicit.strip())
    try:
        out = _convert(text, target, extra)
    except Exception as exc:
        msg = str(exc)
        if "Unable to determine table name" not in msg:
            tm = _FIELD_TABLE.search(msg)
            if tm and mapped.get(tm.group(1)):  # an inferred table with mapped fields: retry with them
                return with_table(tm.group(1))
            raise
    else:
        inferred = out.split("\n", 1)[0].strip()
        return with_table(inferred) if mapped.get(inferred) and valid_table(inferred) else out
    fallback = next((KQL_DEFAULT_TABLES[k] for k in keys if k in KQL_DEFAULT_TABLES), None) or getattr(kql, "default_table", None)
    if not fallback:
        raise _kql_table_error(text, doc) from None
    return with_table(fallback)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
