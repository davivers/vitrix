"""Conversion targets (SIEMs) and plugins.

Each target knows how to build a pySigma backend with its default field pipeline.
Third-party plugins register new targets through the `vitrix.targets` entry point.
"""

from __future__ import annotations

import hashlib
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
# Used only as a fallback, after the rule's `vitrix.kql_table` and vitrix.yml `kql.tables`.
KQL_DEFAULT_TABLES: dict[str, str] = {
    "windows/security": "SecurityEvent",
    **{f"windows/{svc}": "Event" for svc in (
        "system", "application", "powershell", "powershell-classic", "taskscheduler", "windefend", "wmi", "bits-client",
        "dns-server", "dns-server-analytic", "sysmon", "applocker", "firewall-as", "codeintegrity-operational",
        "driver-framework", "ntlm", "smbclient-security", "terminalservices-localsessionmanager", "msexchange-management")},
    "linux/*": "Syslog",
    "azure/activitylogs": "AzureActivity",
    "azure/auditlogs": "AuditLogs",
    "azure/signinlogs": "SigninLogs",
    "m365/audit": "OfficeActivity",
    "aws/cloudtrail": "AWSCloudTrail",
    "gcp/gcp.audit": "GCPAuditLogs",
}


class ConversionError(Exception):
    """A conversion failure with where/how-to-fix details (issue model: code, path, line, column, hint)."""

    def __init__(self, message: str, *, code: str, path: str | None = None, line: int | None = None, hint: str | None = None):
        super().__init__(message)
        self.code, self.path, self.line, self.column, self.hint = code, path, line, 1 if line else None, hint

    def details(self) -> dict:
        return {"code": self.code, "path": self.path, "line": self.line, "column": self.column, "hint": self.hint}


def _logsource_keys(doc: object) -> list[str]:
    """`product/service`, `product/category` lookup keys of a rule, most specific first."""
    ls = doc.get("logsource") if isinstance(doc, dict) else None
    if not isinstance(ls, dict):
        return []
    product = str(ls.get("product") or "").strip().lower()
    return [f"{product}/{str(ls[k]).strip().lower()}" for k in ("service", "category") if product and ls.get(k)]


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
    key = keys[0] if keys else "windows/system"
    line = next((i for i, row in enumerate(text.splitlines(), 1) if row.startswith("logsource:")), None)
    where = f" ({keys[0]})" if keys else ""
    return ConversionError(
        f"KQL needs a table for this rule's logsource{where} and none is configured.",
        code="kql-table", path="logsource", line=line,
        hint=f"Add `vitrix: {{kql_table: Event}}` to the rule, or `kql: {{tables: {{{key}: Event}}}}` (or `kql: {{default_table: Event}}`) to vitrix.yml.")


def _convert(text: str, target: Target, extra: list) -> str:
    from sigma.collection import SigmaCollection

    collection = SigmaCollection.from_yaml(text)
    queries = target.factory(extra).convert(collection)
    if not isinstance(queries, list):
        queries = [str(queries)]
    return "\n\n".join(str(q) for q in queries)


def convert_text(text: str, target: Target, extra: list, kql: Any = None) -> str:
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
    product = keys[0].split("/")[0] if keys else ""
    fallback = next((KQL_DEFAULT_TABLES[k] for k in [*keys, f"{product}/*"] if k in KQL_DEFAULT_TABLES), None) or getattr(kql, "default_table", None)
    if not fallback:
        raise _kql_table_error(text, doc) from None
    return _convert(text, target, [_table_pipeline(fallback), *extra])


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
