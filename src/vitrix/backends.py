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


BUILTIN: dict[str, Target] = {
    t.name: t
    for t in (
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


class ConversionError(Exception):
    """A conversion failure with where/how-to-fix details (issue model: code, path, line, column, hint)."""

    def __init__(self, message: str, *, code: str, path: str | None = None, line: int | None = None, hint: str | None = None):
        super().__init__(message)
        self.code, self.path, self.line, self.column, self.hint = code, path, line, 1 if line else None, hint

    def details(self) -> dict:
        return {"code": self.code, "path": self.path, "line": self.line, "column": self.column, "hint": self.hint}


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


def _table_pipeline(table: str) -> Any:
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import SetStateTransformation

    return ProcessingPipeline(items=[ProcessingItem(identifier="vitrix_kql_table", transformation=SetStateTransformation("query_table", table))])


def _kql_table_error(text: str, doc: object) -> ConversionError:
    keys = _logsource_keys(doc)
    ls = _logsource(doc)
    key = next((k for k in keys if not k.endswith("/*")), keys[0] if keys else "windows/system")
    line = next((i for i, row in enumerate(text.splitlines(), 1) if row.startswith("logsource:")), None)
    where = f" ({key})" if keys else ""
    suggest = next((KQL_SUGGESTED_TABLES[v] for v in (ls.get("product"), ls.get("category"), ls.get("service")) if v in KQL_SUGGESTED_TABLES), None)
    tip = f" Likely table for this source: {suggest} (depends on your connector)." if suggest else ""
    return ConversionError(
        f"KQL needs a table for this rule's logsource{where} and none is configured.",
        code="kql-table", path="logsource", line=line,
        hint=f"Add `vitrix: {{kql_table: Event}}` to the rule, or `kql: {{tables: {{{key}: Event}}}}` (or `kql: {{default_table: Event}}`) to vitrix.yml.{tip}")


_FIELD_ERR = re.compile(r"Invalid SigmaDetectionItem field name encountered: (\S+?)\.")


def _explain(exc: Exception, text: str, target: Target) -> ConversionError:
    """Turn any pySigma / plugin exception into an actionable issue (never the raw exception string)."""
    msg = " ".join(str(exc).split())
    name = type(exc).__name__
    line = next((i for i, row in enumerate(text.splitlines(), 1) if row.startswith("detection:")), None)
    m = _FIELD_ERR.search(msg)
    if m:
        fld = m.group(1)
        return ConversionError(
            f"{target.label} has no mapping for field `{fld}` in the table chosen for this rule's logsource.",
            code="kql-field", path="detection", line=line,
            hint=f"Map it with a field-mapping pipeline listed under `pipelines:` in vitrix.yml (`transformations: [{{type: field_name_mapping, mapping: {{{fld}: <column>}}}}]`), "
                 "or pick another table with `vitrix: {kql_table: ...}` whose columns match the rule's fields.")
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
    if isinstance(explicit, str) and explicit.strip():
        return _convert(text, target, [_table_pipeline(explicit.strip()), *extra])
    try:
        return _convert(text, target, extra)
    except Exception as exc:
        if "Unable to determine table name" not in str(exc):
            raise
    fallback = next((KQL_DEFAULT_TABLES[k] for k in keys if k in KQL_DEFAULT_TABLES), None) or getattr(kql, "default_table", None)
    if not fallback:
        raise _kql_table_error(text, doc) from None
    return _convert(text, target, [_table_pipeline(fallback), *extra])


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
