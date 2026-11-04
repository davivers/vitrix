"""Allow-lists for names that end up inside generated queries or as keys of `mappings.yml`.

A table or column name is pasted into KQL text, so only plain identifiers are accepted: no quotes, brackets,
pipes, semicolons, spaces, newlines or comments. Used by the `PUT /api/mappings` validator (and anything that reads
the file back). All checks use `fullmatch`, so a trailing newline cannot slip through.
"""

from __future__ import annotations

import re

_TABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_COLUMN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,3}")  # EventData.CommandLine
_SIGMA_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]{0,63}(\.[A-Za-z_][A-Za-z0-9_\-]{0,63}){0,3}")
_SCOPE = re.compile(r"[a-z0-9][a-z0-9_.\-]{0,63}(/[a-z0-9][a-z0-9_.\-]{0,63})?")  # product[/service|category]


def valid_table(name: object) -> bool:
    return isinstance(name, str) and _TABLE.fullmatch(name) is not None


def valid_column(name: object) -> bool:
    return isinstance(name, str) and _COLUMN.fullmatch(name) is not None


def valid_sigma_field(name: object) -> bool:
    return isinstance(name, str) and _SIGMA_FIELD.fullmatch(name) is not None


def valid_scope(key: object) -> bool:
    return isinstance(key, str) and _SCOPE.fullmatch(key) is not None


def problems(kql: object) -> list[str]:
    """Every invalid name in a `kql: {tables, fields}` mapping (empty list = safe to store and to paste into queries)."""
    if not isinstance(kql, dict):
        return ["kql must be a mapping"]
    out: list[str] = []
    tables, fields = kql.get("tables") or {}, kql.get("fields") or {}
    if not isinstance(tables, dict) or not isinstance(fields, dict):
        return ["kql.tables and kql.fields must be mappings"]
    for scope, table in tables.items():
        if not valid_scope(scope):
            out.append(f"invalid logsource key {str(scope)[:40]!r}")
        if not valid_table(table):
            out.append(f"invalid table name {str(table)[:40]!r}")
    for table, cols in fields.items():
        if not valid_table(table):
            out.append(f"invalid table name {str(table)[:40]!r}")
        if not isinstance(cols, dict):
            out.append(f"fields for {str(table)[:40]!r} must be a mapping")
            continue
        for sigma, col in cols.items():
            if not valid_sigma_field(sigma):
                out.append(f"invalid Sigma field {str(sigma)[:40]!r}")
            if not valid_column(col):
                out.append(f"invalid column name {str(col)[:40]!r}")
    return out
