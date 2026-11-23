from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ..models.metadata import Metadata, SourceStatusKind


def write_metadata(
    path: Path,
    version: str,
    generated_at: datetime,
    source_ids: list[str],
    source_status: dict[str, SourceStatusKind],
    ioc_counts: dict[str, int],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata = Metadata(
        version=version,
        generated_at=generated_at,
        sources=source_ids,
        source_status=source_status,
        ioc_counts=ioc_counts,
    )
    path.write_text(metadata.model_dump_json(indent=2) + "\n", encoding="utf-8")
