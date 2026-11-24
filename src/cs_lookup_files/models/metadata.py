from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SourceStatusKind = Literal["ok", "partial", "skipped", "failed"]


class SourceResult(BaseModel):
    """Outcome of one source in a run."""

    model_config = ConfigDict(extra="forbid")

    source_id: str
    status: SourceStatusKind
    records: int = 0
    error: str | None = None


class Metadata(BaseModel):
    """``metadata.json`` shipped with every release."""

    model_config = ConfigDict(extra="forbid")

    version: str
    generated_at: datetime
    sources: list[str]
    source_status: dict[str, SourceStatusKind] = Field(default_factory=dict)
    ioc_counts: dict[str, int] = Field(default_factory=dict)


class RunResult(BaseModel):
    """Aggregate outcome of a full pipeline run."""

    model_config = ConfigDict(extra="forbid")

    version: str
    generated_at: datetime
    source_results: list[SourceResult] = Field(default_factory=list)
    output_files: list[str] = Field(default_factory=list)
