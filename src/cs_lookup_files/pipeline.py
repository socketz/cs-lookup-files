from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import polars as pl

from .collectors import fetch
from .enrichers.asn import AsnTables, enrich_frame, load_asn_tables
from .etl.engine import ALL_COLUMNS, SourceOutput, run_source
from .exporters.exports import write_csv, write_json
from .exporters.metadata import write_metadata
from .models.config import FeedConfig, Settings, SourceConfig, SourcesFile
from .models.metadata import FeedStatus, RunResult, SourceResult, SourceStatusKind
from .scoring import score
from .state import merge_categories_fn, merge_state

logger = logging.getLogger("cs_lookup_files")

FETCHER = Callable[[SourceConfig, FeedConfig], str]

UTC_DT = pl.Datetime(time_unit="us", time_zone="UTC")

# One dataset per indicator type. ``asn`` is a first-class type fed only by
# authoritative ASN lists (Spamhaus ASN-DROP); it is never derived from IPs.
DATASET_TYPES = {
    "ip": "malicious_ips",
    "network": "malicious_networks",
    "asn": "malicious_asns",
    "domain": "malicious_domains",
    "url": "malicious_urls",
    "md5": "malicious_md5",
    "sha256": "malicious_sha256",
    "email": "malicious_emails",
}
_OUTPUT_COLUMNS = {
    "ip": "ip_columns",
    "network": "network_columns",
    "asn": "asn_columns",
    "domain": "domain_columns",
    "url": "url_columns",
    "md5": "md5_columns",
    "sha256": "sha256_columns",
    "email": "email_columns",
}
_SORT_COLUMNS = {
    "ip": ["ip_version", "ip_key"],
    "network": ["family", "start_key", "prefix"],
    "asn": ["sort_key"],
    "domain": ["domain"],
    "url": ["url"],
    "md5": ["md5"],
    "sha256": ["sha256"],
    "email": ["email"],
}

# Datasets populated primarily by OTX; used to explain an empty export.
_OTX_PRIMARY = {"malicious_md5", "malicious_sha256", "malicious_emails"}


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
        return fetch.fetch_text(feed.fetch, feed.parse, cache_dir=self.cache_dir)

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

        allowlist: set[str] = set()
        for output in self._outputs:
            allowlist.update(output.allowlist)

        state, df, carried = self._merge_state(df)
        if allowlist:
            state = self._filter_state_allowlist(state, allowlist)
        self._state = state
        df = _ensure_schema(df)

        # Idempotent safety net: never publish private/bogon network/ip values,
        # and discard indicators covered by an allowlist feed.
        df = self._filter_rows(df, allowlist)

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

        files, empty_datasets = self._export(df, source_results)
        self._export_state(state)

        return RunResult(
            version=self.version,
            generated_at=self.run_time,
            source_results=source_results,
            output_files=[f.name for f in files],
            empty_datasets=empty_datasets,
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

        def _record(output: SourceOutput) -> None:
            results.append(SourceResult(source_id=output.source_id, status=output.status,
                                        records=output.records, error=None))
            outputs.append(output)

        if len(enabled) == 1:
            for cfg in enabled:
                try:
                    output = _one(cfg)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("source %s failed: %s", cfg.id, exc)
                    results.append(SourceResult(source_id=cfg.id, status="failed", records=0, error=str(exc)))
                    continue
                _record(output)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(_one, cfg): cfg for cfg in enabled}
                for fut in as_completed(futures):
                    cfg = futures[fut]
                    try:
                        output = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("source %s failed: %s", cfg.id, exc)
                        results.append(SourceResult(source_id=cfg.id, status="failed", records=0, error=str(exc)))
                        continue
                    _record(output)
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

    @staticmethod
    def _allowlist_host(value: str, ioc_type: str) -> str | None:
        if ioc_type == "domain":
            return value.strip().lower().rstrip(".")
        if ioc_type == "url":
            try:
                host = urlsplit(value).hostname
            except ValueError:
                return None
            return host.strip().lower().rstrip(".") if host else None
        return None

    @classmethod
    def _is_allowlisted(cls, value: str, ioc_type: str, allowlist: set[str]) -> bool:
        host = cls._allowlist_host(value, ioc_type)
        if not host:
            return False
        if host in allowlist:
            return True
        # The top1M list is usually registrable/apex names; tolerate a leading
        # "www." so "www.example.com" matches "example.com" without suppressing
        # arbitrary subdomains (e.g. user content on blogspot.com).
        return host.startswith("www.") and host[4:] in allowlist

    def _filter_rows(self, df: pl.DataFrame, allowlist: set[str]) -> pl.DataFrame:
        if df.is_empty():
            return df
        from .normalizers import ipaddr

        def keep_row(row: dict[str, Any]) -> bool:
            t = row.get("type")
            v = row.get("value")
            if t in ("ip", "network") and (not v or not ipaddr.is_globally_routable(str(v))):
                return False
            return not (allowlist and self._is_allowlisted(str(v), str(t), allowlist))

        keep = [keep_row(row) for row in df.to_dicts()]
        return df.filter(pl.Series("keep", keep))

    def _filter_state_allowlist(self, state: Any, allowlist: set[str]) -> Any:
        if not allowlist or not state.indicators:
            return state
        kept = {
            key: entry
            for key, entry in state.indicators.items()
            if not self._is_allowlisted(entry.value, entry.type, allowlist)
        }
        return state.model_copy(update={"indicators": kept})

    def _prune(self, df: pl.DataFrame) -> pl.DataFrame:
        if df.is_empty():
            return df
        scoring = self.settings.scoring
        ttl = scoring.ttl_days
        now_ts = int(self.run_time.timestamp())
        stale = (pl.lit(now_ts) - pl.col("last_seen").dt.epoch("s")) / 86400.0 > ttl
        # Per-type floors override the global precision floor for listed types.
        floor = pl.lit(scoring.min_confidence)
        for ioc_type, value in scoring.min_confidence_by_type.items():
            floor = pl.when(pl.col("type") == ioc_type).then(pl.lit(value)).otherwise(floor)
        return df.filter(~stale).filter(pl.col("confidence_score") >= floor)

    # ------------------------------------------------------------------ output

    def _source_feeds(self) -> dict[str, list[FeedStatus]]:
        # Engine already emits ``FeedStatus`` per feed; no field-by-field copy.
        return {output.source_id: list(output.feeds) for output in self._outputs}

    def _floor_for(self, type_: str) -> int:
        scoring = self.settings.scoring
        return scoring.min_confidence_by_type.get(type_, scoring.min_confidence)

    def _empty_reason(self, type_: str, name: str, status: dict[str, SourceStatusKind]) -> str:
        floor = self._floor_for(type_)
        if name in _OTX_PRIMARY:
            otx = status.get("alienvault_otx")
            if otx is not None and otx != "ok":
                return f"alienvault_otx {otx}"
            return f"no OTX-corroborated rows at or above min_confidence={floor}"
        return f"no rows at or above min_confidence={floor}"

    def _export(
        self,
        df: pl.DataFrame,
        source_results: list[SourceResult],
    ) -> tuple[list[Path], list[str]]:
        out = self.output_dir
        out.mkdir(parents=True, exist_ok=True)
        settings_out = self.settings.output

        files: list[Path] = []
        counts: dict[str, int] = {}
        empty_datasets: list[str] = []
        status: dict[str, SourceStatusKind] = {r.source_id: r.status for r in source_results}

        for type_, name in DATASET_TYPES.items():
            part = df.filter(pl.col("type") == type_)
            cols = list(getattr(settings_out, _OUTPUT_COLUMNS[type_]))
            alias_col = cols[0]
            if type_ == "asn":
                # Authoritative ASN rows carry the ASN as Int64 in ``asn`` so
                # JSON stays numeric; ``value`` is only a string fallback.
                if "asn" in part.columns and "value" in part.columns:
                    part = part.with_columns(
                        pl.col("asn").fill_null(pl.col("value").cast(pl.Int64, strict=False))
                    ).drop("value")
                elif "value" in part.columns:
                    part = part.rename({"value": "asn"})
            elif (
                alias_col in part.columns
                and "value" in part.columns
                and alias_col != "value"
            ):
                # Prefer the identity column, e.g. ip/network, when populated.
                part = part.with_columns(pl.col("value").fill_null(pl.col(alias_col))).drop("value")
            elif "value" in part.columns:
                part = part.rename({"value": alias_col})
            written = self._write_ds(part, name, cols, _SORT_COLUMNS[type_])
            counts[name] = int(part.height)
            if written is None:
                empty_datasets.append(name)
                logger.warning("dataset %s empty: %s", name, self._empty_reason(type_, name, status))
            else:
                files.append(written)

        meta = out / "metadata.json"
        write_metadata(
            meta,
            self.version,
            self.run_time,
            [r.source_id for r in source_results],
            status,
            counts,
            source_feeds=self._source_feeds(),
            empty_datasets=empty_datasets,
        )
        files.append(meta)
        total = sum(counts.values())
        logger.info(
            "run version=%s datasets=%d non_empty=%d indicators=%d",
            self.version,
            len(counts),
            len(counts) - len(empty_datasets),
            total,
        )
        return files, empty_datasets

    def _write_ds(self, df: pl.DataFrame, name: str, columns: list[str], sort_cols: list[str]) -> Path | None:
        """Write CSV+JSON for one dataset; return None (and remove stale files) when empty."""
        out = self.output_dir
        csv_path = out / f"{name}.csv"
        json_path = out / f"{name}.json"
        if df.is_empty():
            for stale in (csv_path, json_path):
                if stale.exists():
                    stale.unlink()
            return None
        wanted = [c for c in columns if c in df.columns]
        if not wanted:
            return None
        avail_sort = [c for c in sort_cols if c in df.columns]
        arranged = df.sort(*avail_sort) if avail_sort else df
        write_csv(arranged.select(wanted), csv_path, wanted)
        write_json(arranged.select(wanted), json_path, wanted)
        logger.info("dataset %s rows=%d", name, df.height)
        return csv_path

    def _export_state(self, state: Any) -> None:
        from .state import dump_state

        dump_state(state, self.output_dir / "state.json")
