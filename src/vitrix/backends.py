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


def convert_text(text: str, target: Target, extra: list) -> str:
    """Convert the text of a Sigma file for the target.

    pySigma mutates the rule while converting (it renames fields). So every call parses the
    YAML again: reusing one collection across targets would contaminate the second one.
    """
    from sigma.collection import SigmaCollection

    collection = SigmaCollection.from_yaml(text)
    backend = target.factory(extra)
    queries = backend.convert(collection)
    if not isinstance(queries, list):
        queries = [str(queries)]
    return "\n\n".join(str(q) for q in queries)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
