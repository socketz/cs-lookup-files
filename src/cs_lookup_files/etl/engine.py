from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import polars as pl

from ..models.config import SourceConfig
from ..normalizers import ipaddr
from ..normalizers.ops import OpContext, apply_clean_ops
from ..normalizers.parsers import parse_rows

FetchFn = Callable[[SourceConfig], str]

SourceStatus = Literal["ok", "partial", "failed"]

IP_COLUMNS = ("ip", "ip_int", "ip_version", "ip_key", "sources", "categories", "last_seen")
NETWORK_COLUMNS = ("network", "family", "start_key", "start_int", "prefix", "sources", "categories", "last_seen")


@dataclass
class SourceOutput:
    source_id: str
    status: SourceStatus
    records: int
    ip_df: pl.DataFrame
    network_df: pl.DataFrame


Row = dict[str, Any]


def _resolve_raw(raw_row: Row, ref: str) -> Any | None:
    if ref in raw_row:
        return raw_row[ref]
    return None


def _attach_categories(row: Row, source: SourceConfig) -> list[str]:
    cats = source.categories
    if cats.field:
        raw = row.get(cats.field)
        label = str(raw) if raw is not None else ""
        mapped = cats.mapping.get(label)
        if mapped is not None:
            return sorted(set(mapped))
    return list(cats.default)


def _parse_last_seen(value: Any | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except ValueError:
        return None


def _build_ip_row(raw_row: Row, source: SourceConfig) -> Row | None:
    ip_value = raw_row.get("ip")
    if not isinstance(ip_value, str) or "/" in ip_value:
        return None
    parsed = ipaddr.parse_ip_or_cidr(ip_value)
    if parsed is None or isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return None
    ip_str = str(parsed)
    ip_int = ipaddr.ip_int(parsed) if parsed.version == 4 else None
    return {
        "ip": ip_str,
        "ip_int": ip_int,
        "ip_version": parsed.version,
        "ip_key": ipaddr.ip_sort_key(parsed),
        "sources": [source.id],
        "categories": _attach_categories(raw_row, source),
        "last_seen": _parse_last_seen(raw_row.get("last_seen")),
    }


def _build_network_row(raw_row: Row, source: SourceConfig) -> Row | None:
    net_value = raw_row.get("network")
    if not isinstance(net_value, str) or "/" not in net_value:
        return None
    try:
        net = ipaddress.ip_network(net_value, strict=False)
    except ValueError:
        return None
    if not ipaddr.is_globally_routable(net):
        return None
    family, start_key, prefix = ipaddr.network_sort_key(str(net))
    start_int = int(net.network_address) if net.version == 4 else None
    return {
        "network": str(net),
        "family": family,
        "start_key": start_key,
        "start_int": start_int,
        "prefix": prefix,
        "sources": [source.id],
        "categories": _attach_categories(raw_row, source),
        "last_seen": _parse_last_seen(raw_row.get("last_seen")),
    }


def run_source(source: SourceConfig, fetch_fn: FetchFn, run_time: datetime) -> SourceOutput:
    """Run one source through fetch -> parse -> map -> clean -> classify.

    A failing fetch or parse marks the source ``failed`` but never raises, so a
    single source cannot bring the whole run down.
    """
    try:
        text = fetch_fn(source)
    except Exception:  # noqa: BLE001 - intentionally tolerant
        return SourceOutput(source.id, "failed", 0, _empty_ip(), _empty_network())

    if not text.strip():
        return SourceOutput(source.id, "partial", 0, _empty_ip(), _empty_network())

    try:
        raw_rows = parse_rows(text, source.parse)
    except Exception:  # noqa: BLE001
        return SourceOutput(source.id, "partial", 0, _empty_ip(), _empty_network())

    ctx = OpContext(source_id=source.id, run_time=run_time)

    mapped: list[Row] = []
    for raw_row in raw_rows:
        row: Row = dict(raw_row)
        for normalized, ref in source.fields.items():
            row[normalized] = _resolve_raw(raw_row, ref)
        mapped.append(row)

    cleaned = apply_clean_ops(mapped, source.clean, ctx)

    ip_rows: list[Row] = []
    net_rows: list[Row] = []
    ip_output = "ip" in source.output_types
    net_output = "network" in source.output_types
    for row in cleaned:
        if ip_output:
            ip_row = _build_ip_row(row, source)
            if ip_row is not None:
                ip_rows.append(ip_row)
        if net_output:
            net_row = _build_network_row(row, source)
            if net_row is not None:
                net_rows.append(net_row)

    ip_df = _df_from_rows(ip_rows, IP_COLUMNS, ip=True)
    net_df = _df_from_rows(net_rows, NETWORK_COLUMNS, ip=False)
    return SourceOutput(source.id, "ok", len(cleaned), ip_df, net_df)


def _empty_ip() -> pl.DataFrame:
    return _df_from_rows([], IP_COLUMNS, ip=True)


def _empty_network() -> pl.DataFrame:
    return _df_from_rows([], NETWORK_COLUMNS, ip=False)


def _df_from_rows(rows: list[Row], columns: tuple[str, ...], ip: bool) -> pl.DataFrame:
    if not rows:
        schema: dict[str, pl.DataType] = {}
        for col in columns:
            if col == "sources" or col == "categories":
                schema[col] = pl.List(pl.Utf8())
            elif col == "last_seen":
                schema[col] = pl.Datetime(time_unit="us", time_zone="UTC")
            elif col in ("ip_int", "start_int"):
                schema[col] = pl.Int64()
            elif col in ("ip_version", "family"):
                schema[col] = pl.Int8()
            elif col == "prefix":
                schema[col] = pl.Int32()
            else:
                schema[col] = pl.Utf8()
        return pl.DataFrame(schema=schema)
    df = pl.DataFrame(rows)
    return df.select(*columns)
