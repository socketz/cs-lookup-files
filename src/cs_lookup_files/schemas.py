"""Generate JSON Schema from the Pydantic config models.

These schemas document the accepted structure of ``config/sources.yaml`` and
``config/settings.yaml`` for linters/editors, and exist alongside the runtime
Pydantic validation (which remains the source of truth). ``cs-lookup-files
schema`` regenerates them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models.config import Settings, SourcesFile


def _bases(schema: dict[str, Any]) -> dict[str, Any]:
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = schema.get("title", "cs-lookup-files config")
    schema["description"] = (
        "Regenerated from the Pydantic models in cs_lookup_files.models.config. "
        "Runtime validation is authoritative; this schema is for editors/linting."
    )
    return schema


def sources_schema() -> dict[str, Any]:
    return _bases(SourcesFile.model_json_schema())


def settings_schema() -> dict[str, Any]:
    return _bases(Settings.model_json_schema())


def write_schemas(out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / "sources.schema.json"
    cfg = out_dir / "settings.schema.json"
    src.write_text(json.dumps(sources_schema(), indent=2) + "\n", encoding="utf-8", newline="\n")
    cfg.write_text(json.dumps(settings_schema(), indent=2) + "\n", encoding="utf-8", newline="\n")
    return src, cfg
