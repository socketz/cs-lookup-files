from __future__ import annotations

import bisect
import csv
import gzip
import io
import ipaddress
import os
import time
from dataclasses import dataclass
from pathlib import Path

import polars as pl

from ..collectors import fetch
from ..models.config import AsnSettings

TsvTable = pl.DataFrame


@dataclass
class AsnTables:
    v4: TsvTable
    v6: TsvTable


_EMPTY_MARKERS = {"", "None", "Not routed"}

# Empty rows in ip2asn use these sentinel ASNs; we treat them as "unassigned".
_NULL_ASN_MAX = 0

_COLUMNS = ["start_ip", "end_ip", "asn", "country", "asn_name"]


def _cache_path(cache_dir: Path, url: str) -> Path:
    name = url.rsplit("/", 1)[-1]
    return cache_dir / name


def _fresh(path: Path, ttl_hours: int) -> bool:
    return path.exists() and (time.time() - os.stat(path).st_mtime) < ttl_hours * 3600


def _parse_tsv_lines(lines: list[str]) -> list[tuple[str, str, int | None, str | None, str | None]]:
    """Parse ip2asn TSV rows with Python's csv reader (robust to large files)."""
    rows: list[tuple[str, str, int | None, str | None, str | None]] = []
    for cells in csv.reader(lines, delimiter="\t"):
        if not cells or len(cells) < 5:
            continue
        start, end, asn, country, name = cells[0], cells[1], cells[2], cells[3], cells[4]
        asn_int: int | None = None
        try:
            parsed_asn = int(asn)
            if parsed_asn > _NULL_ASN_MAX:
                asn_int = parsed_asn
        except ValueError:
            asn_int = None
        country_n: str | None = None if country in _EMPTY_MARKERS else str(country)
        name_n: str | None = None if name in _EMPTY_MARKERS else str(name)
        rows.append((start, end, asn_int, country_n, name_n))
    return rows


def _rows_to_df(rows: list[tuple[str, str, int | None, str | None, str | None]], *, ipv6: bool) -> TsvTable:
    if ipv6:
        return pl.DataFrame(
            {
                "start_key": [f"{int(ipaddress.IPv6Address(r[0])):032x}" if r[0] else None for r in rows],
                "end_key": [f"{int(ipaddress.IPv6Address(r[1])):032x}" if r[1] else None for r in rows],
                "asn": [r[2] for r in rows],
                "country": [r[3] for r in rows],
                "asn_name": [r[4] for r in rows],
            },
            schema={"start_key": pl.Utf8, "end_key": pl.Utf8, "asn": pl.Int64, "country": pl.Utf8, "asn_name": pl.Utf8},
        )
    return pl.DataFrame(
        {
            "start_int": [int(ipaddress.IPv4Address(r[0])) if r[0] else None for r in rows],
            "end_int": [int(ipaddress.IPv4Address(r[1])) if r[1] else None for r in rows],
            "asn": [r[2] for r in rows],
            "country": [r[3] for r in rows],
            "asn_name": [r[4] for r in rows],
        },
        schema={"start_int": pl.Int64, "end_int": pl.Int64, "asn": pl.Int64, "country": pl.Utf8, "asn_name": pl.Utf8},
    )


def _load_stream(stream: io.TextIOBase, *, ipv6: bool) -> TsvTable:
    return _rows_to_df(_parse_tsv_lines(stream.readlines()), ipv6=ipv6)


def _load_gz_path(gz_path: Path, *, ipv6: bool) -> TsvTable:
    """Load an ip2asn gzipped table via Python csv parsing (robust, streaming)."""
    with gzip.open(gz_path, "rt", encoding="utf-8", errors="replace") as handle:
        return _rows_to_df(_parse_tsv_lines(handle.readlines()), ipv6=ipv6)


def _load_text(text: str, *, ipv6: bool) -> TsvTable:
    return _rows_to_df(_parse_tsv_lines(text.splitlines()), ipv6=ipv6)


def load_asn_tables(
    settings: AsnSettings,
    cache_dir: Path,
    *,
    offline: bool = False,
    offline_dir: Path | None = None,
) -> AsnTables:
    """Load ip2asn v4/v6 tables, downloading when the cache is stale.

    In ``offline`` mode plain TSV fixtures (``ip2asn-v4.tsv``/``ip2asn-v6.tsv``)
    are read from ``offline_dir`` so tests never touch the network.
    """
    if offline:
        base = Path(offline_dir) if offline_dir else Path("fixtures")
        v4_text = (base / "ip2asn-v4.tsv").read_text(encoding="utf-8")
        v6_text = (base / "ip2asn-v6.tsv").read_text(encoding="utf-8")
        return AsnTables(_load_text(v4_text, ipv6=False), _load_text(v6_text, ipv6=True))

    cache_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for url in (settings.ipv4_url, settings.ipv6_url):
        path = _cache_path(cache_dir, url)
        if not _fresh(path, settings.cache_ttl_hours):
            fetch.stream_to_file(url, str(path))
        paths.append(path)
    return AsnTables(_load_gz_path(paths[0], ipv6=False), _load_gz_path(paths[1], ipv6=True))


def _asof_v4(
    left: pl.DataFrame,
    left_key: str,
    right_key: str,
    table: TsvTable,
) -> pl.DataFrame:
    """asof-join ``left`` against the v4 table on an integer key.

    Matches the closest range whose ``start <= key``; rows beyond the range end
    have their ASN blanked (unlisted gap).
    """
    right = table.sort("start_int").select(
        pl.col("start_int").alias("_r_start"),
        pl.col("end_int").alias("_r_end"),
        "asn", "country", "asn_name",
    )
    joined = left.sort(left_key).join_asof(
        right,
        left_on=left_key,
        right_on="_r_start",
        strategy="backward",
    )
    ok = pl.col(left_key).is_not_null() & (pl.col(left_key) <= pl.col("_r_end"))
    return joined.with_columns(
        pl.when(ok).then(pl.col("asn")).otherwise(pl.lit(None, dtype=pl.Int64)).alias("asn"),
        pl.when(ok).then(pl.col("country")).otherwise(pl.lit(None, dtype=pl.Utf8)).alias("country"),
        pl.when(ok).then(pl.col("asn_name")).otherwise(pl.lit(None, dtype=pl.Utf8)).alias("asn_name"),
    ).drop("_r_start", "_r_end")


class _V6Index:
    __slots__ = ("starts", "rows")

    def __init__(self, table: TsvTable):
        rows = table.sort("start_key").select("start_key", "end_key", "asn", "country", "asn_name").iter_rows()
        self.starts: list[str] = []
        self.rows: list[tuple[str, str, int | None, str | None, str | None]] = []
        for start, end, asn, country, name in rows:
            self.starts.append(start)
            self.rows.append((start, end, asn, country, name))

    def lookup(self, key: str) -> tuple[int | None, str | None, str | None]:
        """Return (asn, country, asn_name) for an IPv6 key or None-tuple."""
        hi = bisect.bisect_right(self.starts, key) - 1
        if hi < 0:
            return (None, None, None)
        start, end, asn, country, name = self.rows[hi]
        if key < start or key > end:
            return (None, None, None)
        return (asn, country, name)


def _enrich_v6(
    df: pl.DataFrame,
    key_col: str,
    index: _V6Index,
) -> pl.DataFrame:
    keys = df[key_col].to_list()
    rows = [index.lookup(k) for k in keys]
    return df.with_columns(
        pl.Series("asn", [r[0] for r in rows], dtype=pl.Int64),
        pl.Series("country", [r[1] for r in rows], dtype=pl.Utf8),
        pl.Series("asn_name", [r[2] for r in rows], dtype=pl.Utf8),
    )


def _with_asn_columns(df: pl.DataFrame) -> pl.DataFrame:
    return df.with_columns(
        pl.lit(None, dtype=pl.Int64).alias("asn"),
        pl.lit(None, dtype=pl.Utf8).alias("country"),
        pl.lit(None, dtype=pl.Utf8).alias("asn_name"),
    )


def enrich_ips(ip_df: pl.DataFrame, tables: AsnTables) -> pl.DataFrame:
    """Attach asn/asn_name/country to an IP frame keyed on ``ip_version``/``ip_int``."""
    if ip_df.is_empty():
        return _with_asn_columns(ip_df)

    is_v4 = pl.col("ip_version") == 4
    v4_df = ip_df.filter(is_v4)
    v6_df = ip_df.filter(~is_v4)

    v4_df = _asof_v4(v4_df, "ip_int", "start_int", tables.v4) if not v4_df.is_empty() else _with_asn_columns(v4_df)

    v6_df = _enrich_v6(v6_df, "ip_key", _V6Index(tables.v6)) if not v6_df.is_empty() else _with_asn_columns(v6_df)

    return pl.concat([v4_df, v6_df], how="vertical_relaxed")


def enrich_networks(net_df: pl.DataFrame, tables: AsnTables) -> pl.DataFrame:
    """Attach ASN data to a network frame keyed on ``family``/``start_int`` (v4)
    or ``family``/``start_key`` (v6). All existing columns are preserved."""
    if net_df.is_empty():
        return _with_asn_columns(net_df)

    is_v4 = pl.col("family") == 4
    v4_df = net_df.filter(is_v4)
    v6_df = net_df.filter(~is_v4)

    v4_df = _asof_v4(v4_df, "start_int", "start_int", tables.v4) if not v4_df.is_empty() else _with_asn_columns(v4_df)

    v6_df = _enrich_v6(v6_df, "start_key", _V6Index(tables.v6)) if not v6_df.is_empty() else _with_asn_columns(v6_df)

    return pl.concat([v4_df, v6_df], how="vertical_relaxed")
