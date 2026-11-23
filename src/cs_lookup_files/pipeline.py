from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import polars as pl

from .collectors import fetch
from .enrichers.asn import AsnTables, enrich_ips, enrich_networks, load_asn_tables
from .etl.engine import SourceOutput, run_source
from .exporters.exports import write_csv, write_json
from .exporters.metadata import write_metadata
from .models.config import Settings, SourceConfig, SourcesFile
from .models.metadata import RunResult, SourceResult, SourceStatusKind
from .scoring import score
from .state import merge_categories_fn, merge_state

logger = logging.getLogger("cs_lookup_files")

FETCHER = Callable[[SourceConfig], str]

UTC_DT = pl.Datetime(time_unit="us", time_zone="UTC")


class PipelineError(RuntimeError):
    pass


_EMPTY_IP_SCHEMA: dict[str, pl.DataType] = {
    "ip": pl.String(),
    "ip_int": pl.Int64(),
    "ip_version": pl.Int8(),
    "ip_key": pl.String(),
    "sources": pl.List(pl.String()),
    "categories": pl.List(pl.String()),
    "first_seen": UTC_DT,
    "last_seen": UTC_DT,
}
_EMPTY_NET_SCHEMA: dict[str, pl.DataType] = {
    "network": pl.String(),
    "family": pl.Int8(),
    "start_key": pl.String(),
    "start_int": pl.Int64(),
    "prefix": pl.Int32(),
    "sources": pl.List(pl.String()),
    "categories": pl.List(pl.String()),
    "first_seen": UTC_DT,
    "last_seen": UTC_DT,
}
_EMPTY_ASN_SCHEMA: dict[str, pl.DataType] = {
    "asn": pl.Int64(),
    "asn_name": pl.String(),
    "country": pl.String(),
    "confidence_score": pl.Int64(),
    "malicious_ip_count": pl.Int64(),
    "source_count": pl.Int64(),
    "sources": pl.List(pl.String()),
    "first_seen": UTC_DT,
    "last_seen": UTC_DT,
}


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

    def _default_fetch(self, cfg: SourceConfig) -> str:
        if self.offline:
            return self._offline_fetch(cfg)
        return fetch.fetch_text(cfg.fetch, cfg.parse)

    def _offline_fetch(self, cfg: SourceConfig) -> str:
        base = Path(self.offline_dir) if self.offline_dir else Path("fixtures")
        path = base / cfg.id
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

        ip_df, net_df = self._union_results()
        asn_tables = self.asn_tables
        if asn_tables is None:
            asn_tables = load_asn_tables(
                self.settings.asn,
                self.cache_dir,
                offline=self.offline,
                offline_dir=self.offline_dir,
            )

        state, ip_df, net_df, carried_ips, carried_nets = self._merge_state(ip_df, net_df)
        self._state = state

        ip_df = self._normalize_ip(ip_df)
        net_df = self._normalize_net(net_df)

        # Idempotent safety net: never publish private/bogon indicators even if a
        # source config omits the drop ops.
        ip_df = self._filter_bogon(ip_df)
        net_df = self._filter_bogon(net_df)

        if self.dry_run:
            logger.info(
                "dry run: %d ips, %d networks after merge (carried ips=%d, nets=%d)",
                ip_df.height,
                net_df.height,
                carried_ips,
                carried_nets,
            )
            return RunResult(
                version=self.version,
                generated_at=self.run_time,
                source_results=source_results,
                output_files=[],
            )

        ip_df = enrich_ips(ip_df, asn_tables)
        net_df = enrich_networks(net_df, asn_tables)

        weights = {c.id: c.weight for c in self.sources.sources}
        max_scores = self.settings.scoring.max_single_source_score
        scoring = self.settings.scoring

        ip_df = score.score_df(ip_df, weights, scoring, max_scores, self.run_time, "ip")
        net_df = score.score_df(net_df, weights, scoring, max_scores, self.run_time, "network")

        ip_df = self._prune(ip_df)
        net_df = self._prune(net_df)

        asn_df = self._aggregate_asns(ip_df, net_df)
        files = self._export(ip_df, net_df, asn_df, source_results)
        self._export_state(state)

        return RunResult(
            version=self.version,
            generated_at=self.run_time,
            source_results=source_results,
            output_files=[f.name for f in files],
        )

    # ------------------------------------------------------------------ steps

    def _collect(self) -> list[SourceResult]:
        results: list[SourceResult] = []
        outputs: list[SourceOutput] = []
        for cfg in self.sources.sources:
            if not cfg.enabled:
                continue
            logger.info("collecting source %s", cfg.id)
            try:
                out: SourceOutput = run_source(cfg, self.fetch_impl, self.run_time)
            except Exception as exc:  # noqa: BLE001
                logger.warning("source %s failed: %s", cfg.id, exc)
                results.append(SourceResult(source_id=cfg.id, status="failed", records=0, error=str(exc)))
                continue
            results.append(
                SourceResult(
                    source_id=out.source_id,
                    status=out.status,
                    records=out.records,
                    error=None,
                )
            )
            outputs.append(out)
            logger.info(
                "source %s: status=%s records=%d ip_rows=%d net_rows=%d",
                out.source_id,
                out.status,
                out.records,
                out.ip_df.height,
                out.network_df.height,
            )
        self._outputs = outputs
        return results

    def _union_results(self) -> tuple[pl.DataFrame, pl.DataFrame]:
        ip_frames = [o.ip_df for o in self._outputs if not o.ip_df.is_empty()]
        net_frames = [o.network_df for o in self._outputs if not o.network_df.is_empty()]
        ip_df = self._dedupe(ip_frames) if ip_frames else pl.DataFrame(schema=_EMPTY_IP_SCHEMA)
        net_df = self._dedupe(net_frames) if net_frames else pl.DataFrame(schema=_EMPTY_NET_SCHEMA)
        return ip_df, net_df

    @staticmethod
    def _dedupe(frames: list[pl.DataFrame]) -> pl.DataFrame:
        combined = pl.concat(frames, how="vertical_relaxed")
        identity = [c for c in combined.columns if c not in ("sources", "categories", "last_seen")]
        aggs: list[pl.Expr] = [
            pl.col("last_seen").max().alias("last_seen"),
            pl.col("sources").explode().unique().sort().alias("sources"),
            pl.col("categories").explode().unique().sort().alias("categories"),
        ]
        return combined.group_by(identity).agg(aggs)

    def _merge_state(
        self,
        ip_df: pl.DataFrame,
        net_df: pl.DataFrame,
    ) -> tuple[Any, pl.DataFrame, pl.DataFrame, int, int]:
        from .state import load_state

        prev = load_state(self.state_path)
        categories_fn = merge_categories_fn(
            {c.id: list(c.categories.default) for c in self.sources.sources}
        )
        state, ip_df, net_df, carried_ips, carried_nets = merge_state(
            prev,
            ip_df,
            net_df,
            self.run_time,
            self.settings.scoring.ttl_days,
            categories_fn,
        )
        logger.info("state merged; carried ips=%d nets=%d", carried_ips, carried_nets)
        return state, ip_df, net_df, carried_ips, carried_nets

    def _normalize_ip(self, df: pl.DataFrame) -> pl.DataFrame:
        return _ensure_schema(df, _EMPTY_IP_SCHEMA)

    def _normalize_net(self, df: pl.DataFrame) -> pl.DataFrame:
        return _ensure_schema(df, _EMPTY_NET_SCHEMA)

    def _filter_bogon(self, df: pl.DataFrame) -> pl.DataFrame:
        if df.is_empty():
            return df
        from .normalizers import ipaddr

        key = "ip" if "ip" in df.columns else "network"
        keep: list[bool] = [
            ipaddr.is_globally_routable(str(v)) if v is not None else False
            for v in df[key].to_list()
        ]
        return df.filter(pl.Series("keep", keep))

    def _prune(self, df: pl.DataFrame) -> pl.DataFrame:
        if df.is_empty():
            return df
        ttl = self.settings.scoring.ttl_days
        min_conf = self.settings.scoring.min_confidence
        now_ts = int(self.run_time.timestamp())
        stale = (pl.lit(now_ts) - pl.col("last_seen").dt.epoch("s")) / 86400.0 > ttl
        return df.filter(~stale).filter(pl.col("confidence_score") >= min_conf)

    def _aggregate_asns(self, ip_df: pl.DataFrame, net_df: pl.DataFrame) -> pl.DataFrame:
        """Roll member IP/network rows up into per-ASN rows.

        ``malicious_ip_count`` counts IP members only; ``sources`` is the union
        of all member sources; ASN confidence reuses the indicator scoring so
        multi-source ASNs outrank single-source ones.
        """
        members_ip = ip_df.select("asn", "sources", "first_seen", "last_seen")
        members_net = net_df.select("asn", "sources", "first_seen", "last_seen")
        members = pl.concat([members_ip, members_net], how="vertical_relaxed").filter(
            pl.col("asn").is_not_null()
        )
        if members.is_empty():
            return pl.DataFrame(schema=_EMPTY_ASN_SCHEMA)

        g = members.group_by("asn").agg(
            pl.col("sources").explode().unique().sort().alias("sources"),
            pl.col("first_seen").min().alias("first_seen"),
            pl.col("last_seen").max().alias("last_seen"),
        )
        ip_counts = (
            ip_df.filter(pl.col("asn").is_not_null())
            .group_by("asn")
            .agg(pl.len().alias("malicious_ip_count"))
        )
        g = g.join(ip_counts, on="asn", how="left").with_columns(
            pl.col("malicious_ip_count").fill_null(0).alias("malicious_ip_count")
        )

        weights = {c.id: c.weight for c in self.sources.sources}
        max_scores = self.settings.scoring.max_single_source_score
        g = score.score_df(
            g,
            weights,
            self.settings.scoring,
            max_scores,
            self.run_time,
            "asn",
        )
        naming = ip_df.select("asn", "asn_name", "country").drop_nulls()
        if naming.is_empty():
            naming = net_df.select("asn", "asn_name", "country").drop_nulls()
        if not naming.is_empty():
            naming = naming.group_by("asn").agg(
                pl.col("asn_name").drop_nulls().first().alias("asn_name"),
                pl.col("country").drop_nulls().first().alias("country"),
            )
            g = g.join(naming, on="asn", how="left")
        else:
            g = g.with_columns(
                pl.lit(None, dtype=pl.String()).alias("asn_name"),
                pl.lit(None, dtype=pl.String()).alias("country"),
            )
        return g

    # ------------------------------------------------------------------ output

    def _export(
        self,
        ip_df: pl.DataFrame,
        net_df: pl.DataFrame,
        asn_df: pl.DataFrame,
        source_results: list[SourceResult],
    ) -> list[Path]:
        out = self.output_dir
        out.mkdir(parents=True, exist_ok=True)

        ip_df = ip_df.sort(["ip_version", "ip_key"])
        net_df = net_df.sort(["family", "start_key", "prefix"])
        asn_df = asn_df.sort("asn")

        files: list[Path] = []
        files.append(self._write_ds(ip_df, "malicious_ips", self.settings.output.ip_columns))
        files.append(self._write_ds(net_df, "malicious_networks", self.settings.output.network_columns))
        files.append(self._write_ds(asn_df, "malicious_asns", self.settings.output.asn_columns))

        meta = out / "metadata.json"
        status: dict[str, SourceStatusKind] = {r.source_id: r.status for r in source_results}
        counts = {"ips": int(ip_df.height), "networks": int(net_df.height), "asns": int(asn_df.height)}
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

    def _write_ds(self, df: pl.DataFrame, name: str, columns: list[str]) -> Path:
        out = self.output_dir
        csv_path = out / f"{name}.csv"
        json_path = out / f"{name}.json"
        wanted = [c for c in columns if c in df.columns]
        write_csv(df.select(wanted), csv_path, wanted)
        write_json(df.select(wanted), json_path, wanted)
        return csv_path

    def _export_state(self, state: Any) -> None:
        from .state import dump_state

        dump_state(state, self.output_dir / "state.json")


def _ensure_schema(df: pl.DataFrame, schema: dict[str, pl.DataType]) -> pl.DataFrame:
    """Ensure a frame has every column in ``schema`` (null-filled)."""
    out = df
    for name, dtype in schema.items():
        if name not in out.columns:
            out = out.with_columns(pl.lit(None, dtype=dtype).alias(name))
    return out.select(list(schema))
