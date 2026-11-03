"""Alvos de conversão (SIEMs) e plugins.

Cada alvo sabe criar um backend do pySigma já com o pipeline de campos padrão.
Plugins de terceiros registram novos alvos pelo entry point `vitrix.targets`.
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
    label: str  # nome para humanos
    extension: str  # extensão do arquivo gerado
    factory: Callable[[list], Any]  # recebe pipelines extras e devolve um backend do pySigma


def _combine(extra: list, default: Any) -> Any:
    """Pipelines do usuário vêm antes do padrão, para renomear campos antes do mapeamento do SIEM."""
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
        except Exception as exc:  # um plugin quebrado não pode derrubar os outros
            print(f"aviso: plugin '{ep.name}' não pôde ser carregado: {exc}")
            continue
        targets[target.name] = target
    return targets


def load_extra_pipelines(paths: list[Path]) -> list:
    from sigma.processing.pipeline import ProcessingPipeline

    return [ProcessingPipeline.from_yaml(p.read_text(encoding="utf-8")) for p in paths]


def convert_text(text: str, target: Target, extra: list) -> str:
    """Converte o texto de um arquivo Sigma para o alvo.

    O pySigma altera a regra durante a conversão (renomeia campos). Por isso cada
    chamada lê o YAML do zero: reaproveitar a mesma coleção entre alvos contamina o segundo.
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
