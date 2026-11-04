"""Query mappings: `mappings.yml` at the detections repo root, written only by the app.

    schema_version: 1
    kql:
      tables:                       # "<product>/<service|category>": Table
        bitbucket/audit: BitbucketAudit
      fields:                       # Table: {SigmaField: Column}
        BitbucketAudit:
          actor.name: ActorName

The file is a normal versioned repo file (the Editor fixes a `kql-table` or `kql-field` issue by
editing it); `vitrix.yml` `kql.tables` keeps working and `mappings.yml` wins on a conflict. Writes go
through `update()`: patch semantics, atomic, `sha` optimistic lock, held under `sync.REPO_LOCK`.
"""

from __future__ import annotations

import hashlib
import re
import stat
from pathlib import Path

import yaml

FILE = "mappings.yml"
SCHEMA_VERSION = 1
MAX_BYTES = 256 * 1024
MAX_TABLES = 500
MAX_FIELDS_PER_TABLE = 500
_LANG_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
_GLOB = re.compile(r"^[A-Za-z0-9_./*?\[\]-]{1,200}$")
_LOGSOURCE_KEY = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.*-]+$")
_TABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_COLUMN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SIGMA_FIELD = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@\-]{0,199}$")
HEADER = "# Query mappings managed by Vitrix (Editor -> fix a KQL table or field). Safe to review in a pull request.\n"


class MappingsError(Exception):
    """A refused operation. `status` is the HTTP status (422 invalid, 409 conflict, 503 not writable)."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


def path_of(root: Path) -> Path:
    return root / FILE


def sha_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_link(path: Path) -> bool:
    """Symlink, junction or any reparse point (the same check the writes use)."""
    try:
        st = path.lstat()
    except OSError:
        return False
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def empty() -> dict:
    return {"schema_version": SCHEMA_VERSION, "kql": {"tables": {}, "fields": {}}, "final_language": {"default": None, "folders": {}}}


def parse(text: str) -> dict:
    """Validated, normalised document `{schema_version, kql: {tables, fields}}`. Raises MappingsError(422)."""
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise MappingsError("mappings.yml is too large (max 256 KiB)")
    try:
        data = yaml.safe_load(text) if text.strip() else {}
    except yaml.YAMLError as exc:  # never echo the source line or the parser's detail
        mark = getattr(exc, "problem_mark", None)
        raise MappingsError("mappings.yml is not valid YAML" + (f" (line {mark.line + 1})" if mark else "")) from None
    return normalise(data if data is not None else {})


def normalise(data: object) -> dict:
    if not isinstance(data, dict):
        raise MappingsError("mappings.yml must be a YAML mapping")
    extra = set(data) - {"schema_version", "kql", "final_language"}
    if extra:
        raise MappingsError("mappings.yml has an unknown top-level key (allowed: schema_version, kql, final_language)")
    if data.get("schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
        raise MappingsError(f"schema_version {data.get('schema_version')!r} is not supported (expected {SCHEMA_VERSION})")
    kql = data.get("kql") or {}
    if not isinstance(kql, dict) or set(kql) - {"tables", "fields"}:
        raise MappingsError("'kql' must be a mapping with only 'tables' and/or 'fields'")
    tables_raw = kql.get("tables") or {}
    if not isinstance(tables_raw, dict):
        raise MappingsError("kql.tables must map 'product/service' (or 'product/category') to a table name")
    if len(tables_raw) > MAX_TABLES:
        raise MappingsError(f"too many kql.tables entries (max {MAX_TABLES})")
    tables: dict[str, str] = {}
    for key, table in tables_raw.items():
        if not isinstance(key, str) or not _LOGSOURCE_KEY.match(key.strip().lower()):
            raise MappingsError(f"kql.tables key {key!r} must look like 'product/service' or 'product/category' (e.g. bitbucket/audit)")
        if not isinstance(table, str) or not _TABLE.match(table.strip()):
            raise MappingsError(f"kql.tables.{key}: {table!r} is not a valid table name (letters, digits and _ only)")
        tables[key.strip().lower()] = table.strip()
    fields_raw = kql.get("fields") or {}
    if not isinstance(fields_raw, dict):
        raise MappingsError("kql.fields must map a table name to {SigmaField: Column}")
    if len(fields_raw) > MAX_TABLES:
        raise MappingsError(f"too many kql.fields tables (max {MAX_TABLES})")
    fields: dict[str, dict[str, str]] = {}
    for table, mapping in fields_raw.items():
        if not isinstance(table, str) or not _TABLE.match(table.strip()):
            raise MappingsError(f"kql.fields table {table!r} is not a valid table name (letters, digits and _ only)")
        if not isinstance(mapping, dict):
            raise MappingsError(f"kql.fields.{table} must map Sigma field names to column names")
        if len(mapping) > MAX_FIELDS_PER_TABLE:
            raise MappingsError(f"too many fields for {table} (max {MAX_FIELDS_PER_TABLE})")
        clean: dict[str, str] = {}
        for sigma_field, column in mapping.items():
            if not isinstance(sigma_field, str) or not _SIGMA_FIELD.match(sigma_field.strip()):
                raise MappingsError(f"kql.fields.{table}: {sigma_field!r} is not a valid Sigma field name")
            if not isinstance(column, str) or not _COLUMN.match(column.strip()):
                raise MappingsError(f"kql.fields.{table}.{sigma_field}: {column!r} is not a valid column name (letters, digits and _ only)")
            clean[sigma_field.strip()] = column.strip()
        if clean:
            fields[table.strip()] = clean
    from .mapping_names import problems

    bad = problems({"tables": tables, "fields": fields})  # identifiers only: these names are pasted into KQL text
    if bad:
        raise MappingsError("invalid names: " + "; ".join(bad[:10]))
    return {"schema_version": SCHEMA_VERSION, "kql": {"tables": tables, "fields": fields}, "final_language": _final(data.get("final_language"))}


def _final(raw: object) -> dict:
    """`final_language: {default: <id>, folders: {"<glob under rules/>": <id>}}` -> normalised."""
    raw = raw or {}
    if not isinstance(raw, dict) or set(raw) - {"default", "folders"}:
        raise MappingsError("final_language must be a mapping with 'default' and/or 'folders'")
    default = raw.get("default")
    if default is not None and not (isinstance(default, str) and _LANG_ID.match(default.strip())):
        raise MappingsError(f"final_language.default: {default!r} is not a language id (e.g. splunk, kql, sigma)")
    folders_raw = raw.get("folders") or {}
    if not isinstance(folders_raw, dict) or len(folders_raw) > MAX_TABLES:
        raise MappingsError("final_language.folders must map a folder pattern (e.g. windows/*) to a language id")
    folders: dict[str, str] = {}
    for glob, lang in folders_raw.items():
        if not isinstance(glob, str) or not _GLOB.match(glob.strip()) or glob.strip().startswith("/") or ".." in glob:
            raise MappingsError(f"final_language.folders key {glob!r} must be a pattern inside rules/ (letters, digits, '/', '*', '.', '_', '-')")
        if not isinstance(lang, str) or not _LANG_ID.match(lang.strip()):
            raise MappingsError(f"final_language.folders.{glob}: {lang!r} is not a language id")
        folders[glob.strip()] = lang.strip()
    return {"default": default.strip() if default else None, "folders": folders}


def stale_languages(doc: dict, known: set[str]) -> list[dict]:
    """Languages named in the file that are no longer active targets (warnings, never errors)."""
    fl = doc["final_language"]
    found = ([("final_language.default", fl["default"])] if fl["default"] else []) + [(f"final_language.folders.{g}", lang) for g, lang in fl["folders"].items()]
    return [{"code": "inactive-language", "where": where, "language": lang,
             "message": f"{lang} is not an active language any more; rules using this entry fall back to their conversion error"} for where, lang in found if lang not in known]


def dump(doc: dict) -> str:
    out = {"schema_version": doc["schema_version"],
           "kql": {"tables": dict(sorted(doc["kql"]["tables"].items())),
                   "fields": {t: dict(sorted(m.items())) for t, m in sorted(doc["kql"]["fields"].items())}}}
    fl = doc["final_language"]
    if fl["default"] or fl["folders"]:
        out["final_language"] = {**({"default": fl["default"]} if fl["default"] else {}), "folders": dict(sorted(fl["folders"].items()))}
    body = yaml.safe_dump(out, sort_keys=False, default_flow_style=False, allow_unicode=True)
    return HEADER + body


def read(root: Path) -> tuple[dict, str | None, str]:
    """THE guarded reader of mappings.yml (config loader, API, publish): no link or junction, size cap,
    safe_load, generic errors. Returns (document, sha of the file bytes or None when absent, raw text)."""
    path = path_of(root)
    if is_link(path):
        raise MappingsError("mappings.yml must be a regular file (links are not allowed)")
    try:
        if not path.is_file():
            return empty(), None, ""
        if path.stat().st_size > MAX_BYTES:
            raise MappingsError("mappings.yml is too large (max 256 KiB)")
        with open(path, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
    except OSError:
        raise MappingsError("mappings.yml cannot be read", 503) from None
    if len(raw) > MAX_BYTES:
        raise MappingsError("mappings.yml is too large (max 256 KiB)")
    text = raw.decode("utf-8", "replace")
    return parse(text), sha_of(raw), text


def _flat(doc: dict) -> dict[tuple, str]:
    out: dict[tuple, str] = {}
    for k, v in doc["kql"]["tables"].items():
        out[("tables", k)] = v
    for t, m in doc["kql"]["fields"].items():
        for f, c in m.items():
            out[("fields", t, f)] = c
    fl = doc["final_language"]
    if fl["default"]:
        out[("final", "default")] = fl["default"]
    for g, lang in fl["folders"].items():
        out[("final", "folders", g)] = lang
    return out


def _unflat(flat: dict[tuple, str]) -> dict:
    doc = empty()
    for key, value in flat.items():
        if key[0] == "tables":
            doc["kql"]["tables"][key[1]] = value
        elif key[0] == "fields":
            doc["kql"]["fields"].setdefault(key[1], {})[key[2]] = value
        elif key[1] == "default":
            doc["final_language"]["default"] = value
        else:
            doc["final_language"]["folders"][key[2]] = value
    return doc


def merge3(base: dict, local: dict, theirs: dict) -> dict:
    """Three-way merge of mapping ENTRIES: what the local file changed since `base` is applied on top of `theirs`
    (origin). Entries only `theirs` changed are kept. Both sides changing the same entry differently raises
    MappingsError(409): nobody's entries are dropped silently."""
    b, lo, th = _flat(base), _flat(local), _flat(theirs)
    out = dict(th)
    for key in set(b) | set(lo):
        if lo.get(key) == b.get(key):
            continue  # not changed locally: keep origin's
        if th.get(key) not in (b.get(key), lo.get(key)):
            raise MappingsError("mappings.yml changed on GitHub - sync first", 409)
        if lo.get(key) is None:
            out.pop(key, None)
        else:
            out[key] = lo[key]
    return normalise(_unflat(out))


def apply_patch(doc: dict, patch: dict) -> dict:
    """Merge-patch of `{kql: {tables: {key: Table|None}, fields: {Table: {Field: Column|None}|None}}}`.
    `None` removes the entry; absent keys are untouched."""
    if not isinstance(patch, dict) or set(patch) - {"kql", "schema_version", "final_language"}:
        raise MappingsError("the patch must be {kql: {tables, fields}, final_language: {default, folders}}")
    kql = patch.get("kql") or {}
    if not isinstance(kql, dict) or set(kql) - {"tables", "fields"}:
        raise MappingsError("kql must contain 'tables' and/or 'fields'")
    if not isinstance(kql.get("tables") or {}, dict) or not isinstance(kql.get("fields") or {}, dict):
        raise MappingsError("kql.tables and kql.fields must be mappings")
    tables = dict(doc["kql"]["tables"])
    fields = {t: dict(m) for t, m in doc["kql"]["fields"].items()}
    for key, table in (kql.get("tables") or {}).items():
        if table is None:
            tables.pop(str(key).strip().lower(), None)
        else:
            tables[key] = table
    for table, mapping in (kql.get("fields") or {}).items():
        if mapping is None:
            fields.pop(table, None)
            continue
        if not isinstance(mapping, dict):
            raise MappingsError(f"kql.fields.{table} must map Sigma field names to column names")
        cur = fields.setdefault(table, {})
        for sigma_field, column in mapping.items():
            if column is None:
                cur.pop(sigma_field, None)
            else:
                cur[sigma_field] = column
    fl_patch = patch.get("final_language")
    final = {"default": doc["final_language"]["default"], "folders": dict(doc["final_language"]["folders"])}
    if fl_patch is not None:
        if not isinstance(fl_patch, dict) or set(fl_patch) - {"default", "folders"}:
            raise MappingsError("final_language must contain 'default' and/or 'folders'")
        if "default" in fl_patch:
            final["default"] = fl_patch["default"]  # null clears it
        folders_patch = fl_patch.get("folders") or {}
        if not isinstance(folders_patch, dict):
            raise MappingsError("final_language.folders must be a mapping")
        for glob, lang in folders_patch.items():
            if lang is None:
                final["folders"].pop(str(glob).strip(), None)
            else:
                final["folders"][glob] = lang
    return normalise({"schema_version": SCHEMA_VERSION, "kql": {"tables": tables, "fields": fields}, "final_language": final})


def update(root: Path, patch: dict, sha: str | None, known_languages: set[str] | None = None) -> tuple[dict, str, str]:
    """Apply `patch` to mappings.yml and write it atomically. `sha`: what the caller loaded (None = the file did not exist).
    Returns (document, new sha, text)."""
    from .local_rules import LocalRuleError, _atomic_write
    from .sync import REPO_LOCK

    path = path_of(root)
    with REPO_LOCK:
        if is_link(path):
            raise MappingsError("invalid path: links are not allowed for mappings.yml")
        doc, current, _ = read(root)
        if current != sha:
            raise MappingsError("mappings.yml changed on disk since you loaded it", 409)
        new_doc = apply_patch(doc, patch)
        if known_languages is not None:  # only the entries being changed; stale ones elsewhere are reported as warnings
            fl_patch = patch.get("final_language") or {}
            used = ([fl_patch["default"]] if fl_patch.get("default") else []) + [v for v in (fl_patch.get("folders") or {}).values() if v]
            unknown = sorted({u for u in used if u not in known_languages})
            if unknown:
                raise MappingsError(f"unknown or inactive language: {', '.join(map(str, unknown))} (available: {', '.join(sorted(known_languages))})")
        text = dump(new_doc)
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise MappingsError("mappings.yml would be too large (max 256 KiB)")
        try:
            _atomic_write(path, text)
        except LocalRuleError as exc:
            raise MappingsError(str(exc), exc.status) from None
    return new_doc, sha_of(text.encode("utf-8")), text
