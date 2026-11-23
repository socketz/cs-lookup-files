from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from yaml import safe_load

from ..collectors import fetch
from ..etl.engine import run_source
from ..models.config import Settings, SourceConfig, SourcesFile
from ..pipeline import Pipeline, PipelineError

app = typer.Typer(
    help="Aggregate free threat-intel feeds into CrowdStrike Falcon lookup files.",
    no_args_is_help=True,
)


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def _load_paths(config_dir: Path) -> tuple[SourcesFile, Settings]:
    settings_path = config_dir / "settings.yaml"
    sources_path = config_dir / "sources.yaml"
    if not settings_path.exists():
        raise typer.BadParameter(f"settings not found: {settings_path}")
    if not sources_path.exists():
        raise typer.BadParameter(f"sources not found: {sources_path}")
    settings = Settings.model_validate(safe_load(settings_path.read_text(encoding="utf-8")))
    sources = SourcesFile.model_validate(safe_load(sources_path.read_text(encoding="utf-8")))
    return sources, settings


def _run_time_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _version_from(run_time: datetime) -> str:
    return run_time.strftime("%Y.%m.%d.%H%M")


@app.command()
def build(
    config_dir: Annotated[
        Path, typer.Option("--config-dir", help="Directory with settings.yaml + sources.yaml")
    ] = Path("config"),
    output_dir: Annotated[
        Path, typer.Option("--output-dir", help="Where CSV/JSON/metadata is written")
    ] = Path("output"),
    state: Annotated[
        Path | None, typer.Option("--state", help="Previous state.json to merge history from")
    ] = None,
    cache_dir: Annotated[
        Path, typer.Option("--cache-dir", help="Location for ip2asn downloads")
    ] = Path("cache"),
    offline: Annotated[
        bool, typer.Option("--offline", help="Read fixture files instead of fetching feeds")
    ] = False,
    offline_dir: Annotated[
        Path | None, typer.Option("--offline-dir", help="Fixture directory used with --offline")
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Fetch + normalize but do not write files")
    ] = False,
    version: Annotated[
        str | None, typer.Option("--version", help="Override the release version")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
) -> None:
    """Run the full ETL pipeline and export the three lookup datasets."""
    _configure_logging(verbose)
    run_time = _run_time_now()
    version = version or _version_from(run_time)

    try:
        sources, settings = _load_paths(config_dir)
        pipeline = Pipeline(
            settings,
            sources,
            output_dir=output_dir,
            state_path=state,
            cache_dir=cache_dir,
            offline=offline,
            offline_dir=offline_dir,
            dry_run=dry_run,
            run_time=run_time,
            version=version,
        )
        result = pipeline.run()
    except PipelineError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except (ValueError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    for src in result.source_results:
        typer.echo(f"  {src.source_id:<20} {src.status:<8} records={src.records}")
    if result.output_files:
        typer.echo(f"version {result.version} wrote: {', '.join(result.output_files)}")


@app.command()
def collect(
    source_id: Annotated[str | None, typer.Argument(help="Collect only this source")] = None,
    config_dir: Annotated[Path, typer.Option("--config-dir")] = Path("config"),
    offline: Annotated[bool, typer.Option("--offline")] = False,
    offline_dir: Annotated[Path | None, typer.Option("--offline-dir")] = None,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
) -> None:
    """Fetch and normalize each source, printing row counts without exporting."""
    _configure_logging(verbose)
    run_time = _run_time_now()
    sources, _settings = _load_paths(config_dir)

    def fetcher(cfg: SourceConfig) -> str:
        if offline:
            base = Path(offline_dir) if offline_dir else Path("fixtures")
            return (base / cfg.id).read_text(encoding="utf-8")
        return fetch.fetch_text(cfg.fetch, cfg.parse)

    for cfg in sources.sources:
        if not cfg.enabled:
            continue
        if source_id and cfg.id != source_id:
            continue
        try:
            out = run_source(cfg, fetcher, run_time)
            typer.echo(
                f"  {out.source_id:<20} {out.status:<8} "
                f"ip_rows={out.ip_df.height} net_rows={out.network_df.height}"
            )
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"  {cfg.id:<20} failed: {exc}", err=True)


@app.command()
def validate(
    config_dir: Annotated[Path, typer.Option("--config-dir")] = Path("config"),
) -> None:
    """Validate settings.yaml and sources.yaml against the Pydantic schemas."""
    try:
        _load_paths(config_dir)
    except (typer.BadParameter, ValueError) as exc:
        typer.echo(f"config invalid: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("config OK")


def main() -> None:
    app()
