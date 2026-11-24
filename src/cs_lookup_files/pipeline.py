from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

import polars as pl

from .collectors import fetch
from .enrichers.asn import AsnTables, enrich_frame, load_asn_tables
from .etl.engine import ALL_COLUMNS, SourceOutput, run_source
from .exporters.exports import write_csv, write_json
from .exporters.metadata import write_metadata
from .models.config import FeedConfig, Settings, SourceConfig, SourcesFile
from .models.metadata import RunResult, SourceResult, SourceStatusKind
from .scoring import score
from .state import merge_categories_fn, merge_state

logger = logging.getLogger("cs_lookup_files")

FETCHER = Callable[[SourceConfig, FeedConfig], str]

UTC_DT = pl.Datetime(time_unit="us", time_zone="UTC")

# One dataset per indicator type + the ASN rollup.
DATASET_TYPES = {
    "ip": "malicious_ips",
    "network": "malicious_networks",
    "domain": "malicious_domains",
    "url": "malicious_urls",
    "md5": "malicious_md5",
    "sha256": "malicious_sha256",
    "email": "malicious_emails",
}
_OUTPUT_COLUMNS = {
    "ip": "ip_columns",
    "network": "network_columns",
    "domain": "domain_columns",
    "url": "url_columns",
    "md5": "md5_columns",
    "sha256": "sha256_columns",
    "email": "email_columns",
}
_SORT_COLUMNS = {
    "ip": ["ip_version", "ip_key"],
    "network": ["family", "start_key", "prefix"],
    "domain": ["domain"],
    "url": ["url"],
    "md5": ["md5"],
    "sha256": ["sha256"],
    "email": ["email"],
}


class PipelineError(RuntimeError):
    pass


def _ensure_schema(df: pl.DataFrame) -> pl.DataFrame:
    from .etl.engine import _dtype

    out = df
    scope = (*ALL_COLUMNS, "first_seen", "confidence_score", "source_count")
    for col in scope:
        if col not in out.columns:
            dtype = _dtype(col) if col in ALL_COLUMNS else (
                UTC_DT if col == "first_seen" else pl.Int64()
            )
            out = out.with_columns(pl.lit(None, dtype=dtype).alias(col))
    return out


class Pipeline:
    def __init__(
        self,
        settings: Settings,
        sources: SourcesFile,
        *,
        output_dir: Path,
        state_path: Path | None = None,
        cache_dir: Path,
        offline: bool = False,
        offline_dir: Path | None = None,
        dry_run: bool = False,
        run_time: datetime,
        version: str,
        fetch_impl: FETCHER | None = None,
        asn_tables: AsnTables | None = None,
    ):
        self.settings = settings
        self.sources = sources
        self.output_dir = output_dir
        self.state_path = state_path
        self.cache_dir = cache_dir
        self.offline = offline
        self.offline_dir = offline_dir
        self.dry_run = dry_run
        self.run_time = run_time
        self.version = version
        self.fetch_impl = fetch_impl or self._default_fetch
        self.asn_tables = asn_tables
        self._state: Any = None
        self._outputs: list[SourceOutput] = []

    # ------------------------------------------------------------------ fetch

    def _default_fetch(self, source: SourceConfig, feed: FeedConfig) -> str:
        if self.offline:
            return self._offline_fetch(feed)
        return fetch.fetch_text(feed.fetch, feed.parse)

    def _offline_fetch(self, feed: FeedConfig) -> str:
        base = Path(self.offline_dir) if self.offline_dir else Path("fixtures")
        path = base / feed.fixture_key()
        try:
            return path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise fetch.FetchError(f"no offline fixture at {path}") from exc

    # ------------------------------------------------------------------ run

    def run(self) -> RunResult:
        source_results = self._collect()
        active = [r for r in source_results if r.status in ("ok", "partial")]
        if not active:
            raise PipelineError("no source succeeded; nothing to publish")

        df = self._union_results()
        asn_tables = self.asn_tables
        if asn_tables is None:
            asn_tables = load_asn_tables(
                self.settings.asn,
                self.cache_dir,
                offline=self.offline,
                offline_dir=self.offline_dir,
            )

        state, df, carried = self._merge_state(df)
        self._state = state
        df = _ensure_schema(df)

        # Idempotent safety net: never publish private/bogon network/ip values.
        df = self._filter_bogon(df)

        if self.dry_run:
            counts = df.group_by("type").len().sort("type")
            logger.info("dry run: collected indicators:\n%s", counts)
            return RunResult(
                version=self.version,
                generated_at=self.run_time,
                source_results=source_results,
                output_files=[],
            )

        df = enrich_frame(df, asn_tables)

        weights = {c.id: c.weight for c in self.sources.sources}
        ioc_weights = {c.id: dict(c.ioc_weights) for c in self.sources.sources if c.ioc_weights}
        max_scores = self.settings.scoring.max_single_source_score
        scoring = self.settings.scoring

        df = score.score_df(
            df, weights, scoring, max_scores, self.run_time, "sort_key",
            ioc_weights=ioc_weights or None,
        )

        df = self._prune(df)

        asn_df = self._aggregate_asns(df)
        files = self._export(df, asn_df, source_results)
        self._export_state(state)

        return RunResult(
            version=self.version,
            generated_at=self.run_time,
            source_results=source_results,
            output_files=[f.name for f in files],
        )

    # ------------------------------------------------------------------ steps

    def _collect(self) -> list[SourceResult]:

        enabled = [cfg for cfg in self.sources.sources if cfg.enabled]
        results: list[SourceResult] = []
        outputs: list[SourceOutput] = []
        max_workers = min(self.settings.max_workers, max(len(enabled), 1))

        def _one(cfg: SourceConfig) -> SourceOutput:
            logger.info("collecting source %s", cfg.id)
            return run_source(cfg, self.fetch_impl, self.run_time)

        if len(enabled) == 1:
            for cfg in enabled:
                try:
                    output = _one(cfg)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("source %s failed: %s", cfg.id, exc)
                    results.append(SourceResult(source_id=cfg.id, status="failed", records=0, error=str(exc)))
                    continue
                results.append(SourceResult(source_id=output.source_id, status=output.status,
                                            records=output.records, error=None))
                outputs.append(output)
                logger.info("source %s: status=%s records=%d rows=%d",
                            output.source_id, output.status, output.records, output.df.height)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(_one, cfg): cfg for cfg in enabled}
                done = 0
                for fut in as_completed(futures):
                    cfg = futures[fut]
                    try:
                        output = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("source %s failed: %s", cfg.id, exc)
                        results.append(SourceResult(source_id=cfg.id, status="failed", records=0, error=str(exc)))
                        continue
                    results.append(SourceResult(source_id=output.source_id, status=output.status,
                                                records=output.records, error=None))
                    outputs.append(output)
                    logger.info("source %s: status=%s rows=%d", output.source_id, output.status, output.df.height)
                    done += 1
        self._outputs = outputs
        return results

    def _union_results(self) -> pl.DataFrame:
        frames = [o.df for o in self._outputs if not o.df.is_empty()]
        if not frames:
            from .etl.engine import _empty_df

            return _empty_df()
        combined = pl.concat(frames, how="vertical_relaxed")
        extras = [
            c
            for c in combined.columns
            if c != "type" and c != "value" and c != "sort_key"
            and c not in ("sources", "categories", "last_seen")
        ]
        return combined.group_by(["type", "value"]).agg(
            pl.col("sort_key").first().alias("sort_key"),
            pl.col("sources").explode().unique().sort().alias("sources"),
            pl.col("categories").explode().unique().sort().alias("categories"),
            pl.col("last_seen").max().alias("last_seen"),
            *[pl.col(c).first().alias(c) for c in extras],
        )

    def _merge_state(
        self,
        df: pl.DataFrame,
    ) -> tuple[Any, pl.DataFrame, int]:
        from .state import load_state

        prev = load_state(self.state_path)
        categories_fn = merge_categories_fn(
            {c.id: list(c.categories.default) for c in self.sources.sources}
        )
        state, df, carried = merge_state(
            prev,
            df,
            self.run_time,
            self.settings.scoring.ttl_days,
            categories_fn,
        )
        logger.info("state merged; carried=%d", carried)
        return state, df, carried

    def _filter_bogon(self, df: pl.DataFrame) -> pl.DataFrame:
        if df.is_empty():
            return df
        from .normalizers import ipaddr

        def keep_row(row: dict[str, Any]) -> bool:
            t = row.get("type")
            v = row.get("value")
            if t in ("ip", "network"):
                return bool(v) and ipaddr.is_globally_routable(str(v))
            return True

        keep = [keep_row(row) for row in df.to_dicts()]
        return df.filter(pl.Series("keep", keep))

    def _prune(self, df: pl.DataFrame) -> pl.DataFrame:
        if df.is_empty():
            return df
        ttl = self.settings.scoring.ttl_days
        min_conf = self.settings.scoring.min_confidence
        now_ts = int(self.run_time.timestamp())
        stale = (pl.lit(now_ts) - pl.col("last_seen").dt.epoch("s")) / 86400.0 > ttl
        return df.filter(~stale).filter(pl.col("confidence_score") >= min_conf)

    def _aggregate_asns(self, df: pl.DataFrame) -> pl.DataFrame:
        """Roll ip/network rows into per-ASN output rows."""
        members = df.filter(pl.col("asn").is_not_null())
        if members.is_empty():
            return pl.DataFrame(
                schema={
                    "asn": pl.Int64(), "asn_name": pl.String(), "country": pl.String(),
                    "confidence_score": pl.Int64(), "malicious_ip_count": pl.Int64(),
                    "source_count": pl.Int64(), "sources": pl.List(pl.String()),
                }
            )
        g = members.group_by("asn").agg(
            pl.col("sources").explode().unique().sort().alias("sources"),
            pl.col("asn_name").drop_nulls().first().alias("asn_name"),
            pl.col("country").drop_nulls().first().alias("country"),
        )
        ip_count = (
            members.filter(pl.col("type") == "ip")
            .group_by("asn").agg(pl.len().alias("malicious_ip_count"))
        )
        g = g.join(ip_count, on="asn", how="left").with_columns(
            pl.col("malicious_ip_count").fill_null(0).alias("malicious_ip_count")
        )
        # Reuse per-source scoring on the unioned sources of each ASN.
        weights = {c.id: c.weight for c in self.sources.sources}
        max_scores = self.settings.scoring.max_single_source_score
        g = score.score_df(g, weights, self.settings.scoring, max_scores, self.run_time, "asn")
        return g

    # ------------------------------------------------------------------ output

    def _export(
        self,
        df: pl.DataFrame,
        asn_df: pl.DataFrame,
        source_results: list[SourceResult],
    ) -> list[Path]:
        out = self.output_dir
        out.mkdir(parents=True, exist_ok=True)
        settings_out = self.settings.output

        files: list[Path] = []
        counts: dict[str, int] = {}
        for type_, name in DATASET_TYPES.items():
            part = df.filter(pl.col("type") == type_)
            cols = list(getattr(settings_out, _OUTPUT_COLUMNS[type_]))
            # The unified frame stores the IOC under ``value``; present it under
            # the dataset's identity column (ip/network/domain/url/md5/sha256/email).
            alias_col = cols[0]
            if (
                alias_col in part.columns
                and "value" in part.columns
                and alias_col != "value"
            ):
                # Prefer the identity column, e.g. ip/network, when populated.
                part = part.with_columns(pl.col("value").fill_null(pl.col(alias_col))).drop("value")
            elif "value" in part.columns:
                part = part.rename({"value": alias_col})
            files.append(self._write_ds(part, name, cols, _SORT_COLUMNS[type_]))
            counts[name] = int(part.height)
        files.append(self._write_ds(asn_df, "malicious_asns", settings_out.asn_columns, ["asn"]))
        counts["malicious_asns"] = int(asn_df.height)

        meta = out / "metadata.json"
        status: dict[str, SourceStatusKind] = {r.source_id: r.status for r in source_results}
        write_metadata(
            meta,
            self.version,
            self.run_time,
            [r.source_id for r in source_results],
            status,
            counts,
        )
        files.append(meta)
        logger.info("exported %d dataset files + metadata", len(files))
        return files

    def _write_ds(self, df: pl.DataFrame, name: str, columns: list[str], sort_cols: list[str]) -> Path:
        out = self.output_dir
        csv_path = out / f"{name}.csv"
        json_path = out / f"{name}.json"
        wanted = [c for c in columns if c in df.columns]
        if df.is_empty() or not wanted:
            arranged = df.select(*columns) if set(columns) <= set(df.columns) else df
            write_csv(arranged, csv_path, [c for c in columns if c in arranged.columns])
            write_json(arranged, json_path, [c for c in columns if c in arranged.columns])
            return csv_path
        avail_sort = [c for c in sort_cols if c in df.columns]
        arranged = df.sort(*avail_sort) if avail_sort else df
        write_csv(arranged.select(wanted), csv_path, wanted)
        write_json(arranged.select(wanted), json_path, wanted)
        return csv_path

    def _export_state(self, state: Any) -> None:
        from .state import dump_state

        dump_state(state, self.output_dir / "state.json")
