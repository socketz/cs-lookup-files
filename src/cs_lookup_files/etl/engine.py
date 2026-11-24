from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import polars as pl

from ..collectors.fetch import MissingSecret, PartialFetchError
from ..models.config import FeedConfig, SourceConfig
from ..normalizers import indicators, ipaddr
from ..normalizers.indicators import IndicatorType
from ..normalizers.ops import OpContext, apply_clean_ops
from ..normalizers.parsers import parse_rows

logger = logging.getLogger("cs_lookup_files.engine")

FetchFn = Callable[[SourceConfig, FeedConfig], str]

SourceStatus = Literal["ok", "partial", "skipped", "failed"]

TypeKey = str  # "ip", "network", "domain", "md5", "sha256"

# Unified accumulator frame columns across all indicator types.
COMMON_COLUMNS = ("value", "sort_key", "type", "sources", "categories", "last_seen")
# Per-type informational columns (nullable outside their type).
EXTRA_COLUMNS = ("ip", "network", "asn", "asn_name", "country", "ip_int", "ip_version", "ip_key",
                 "start_int", "family", "start_key", "prefix")

ALL_COLUMNS = (*COMMON_COLUMNS, *EXTRA_COLUMNS)


@dataclass
class SourceOutput:
    source_id: str
    status: SourceStatus
    records: int
    df: pl.DataFrame


Row = dict[str, Any]


def _resolve_raw(raw_row: Row, ref: str) -> Any | None:
    return raw_row.get(ref)


def _attach_categories(row: Row, source: SourceConfig, feed: FeedConfig) -> list[str]:
    cats = feed.categories or source.categories
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
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except ValueError:
        return None


def _common_row(
    type_: IndicatorType,
    value: str,
    raw_row: Row,
    source: SourceConfig,
    feed: FeedConfig,
) -> Row | None:
    canon = indicators.canonical_indicator(type_, value)
    if canon is None:
        return None
    return {
        "value": canon,
        "sort_key": indicators.sort_key(type_, canon),
        "type": type_,
        # Scoring identity is the origin, not the individual file/URL.
        "sources": [source.id],
        "categories": _attach_categories(raw_row, source, feed),
        "last_seen": _parse_last_seen(raw_row.get("last_seen")),
    }


def _with_extras(row: Row, raw_row: Row) -> Row:
    """Attach per-type informative columns (IP/network identity, ASN extras)."""
    type_ = row["type"]
    value: str = row["value"]
    if type_ == "ip":
        parsed = ipaddr.parse_ip_or_cidr(value)
        if parsed is not None and not isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            row["ip"] = str(parsed)
            row["ip_int"] = ipaddr.ip_int(parsed) if parsed.version == 4 else None
            row["ip_version"] = parsed.version
            row["ip_key"] = ipaddr.ip_sort_key(parsed)
    elif type_ == "network":
        try:
            net = ipaddress.ip_network(value, strict=False)
            if ipaddr.is_globally_routable(net):
                row["network"] = str(net)
                row["family"] = net.version
                row["prefix"] = net.prefixlen
                row["start_key"] = ipaddr.ip_sort_key(net.network_address)
                row["start_int"] = int(net.network_address) if net.version == 4 else None
        except ValueError:
            pass
    return row


def run_source(source: SourceConfig, fetch_fn: FetchFn, run_time: datetime) -> SourceOutput:
    """Run every feed of a source, producing one unified indicator frame.

    Each feed is fetched/parsed independently and its status aggregated:
    ``ok`` if all feeds succeed, ``partial`` if some succeed/fail/skip, ``skipped``
    if every feed lacks its required secret, ``failed`` if none succeed. The
    ``sources`` column carries the origin id, so indicators confirmed by several
    feeds of the same origin count as one confirming source for scoring.
    """
    frames: list[pl.DataFrame] = []
    statuses: list[SourceStatus] = []
    records = 0
    for feed in source.feeds:
        status, df, recs = _run_feed(source, feed, fetch_fn, run_time)
        statuses.append(status)
        records += recs
        if not df.is_empty():
            frames.append(df)

    if not frames:
        return SourceOutput(source.id, _aggregate_status(statuses), records, _empty_df())
    combined = pl.concat(frames, how="vertical_relaxed") if len(frames) > 1 else frames[0]
    return SourceOutput(source.id, _aggregate_status(statuses), records, combined)


def _aggregate_status(statuses: list[SourceStatus]) -> SourceStatus:
    if not statuses:
        return "failed"
    if "ok" in statuses:
        return "ok" if all(s == "ok" for s in statuses) else "partial"
    if "partial" in statuses:
        return "partial"
    if all(s == "skipped" for s in statuses):
        return "skipped"
    return "failed"


def _run_feed(
    source: SourceConfig,
    feed: FeedConfig,
    fetch_fn: FetchFn,
    run_time: datetime,
) -> tuple[SourceStatus, pl.DataFrame, int]:
    text = ""
    partial = False
    try:
        text = fetch_fn(source, feed)
    except PartialFetchError as exc:
        text = exc.partial_text
        partial = True
    except MissingSecret as exc:
        logger.warning("%s", exc)
        return ("skipped", _empty_df(), 0)
    except Exception as exc:  # noqa: BLE001 - intentionally tolerant
        logger.warning("source %s feed %s failed: %s", source.id, feed.fixture_key(), exc)
        return ("failed", _empty_df(), 0)

    if not text.strip():
        return ("partial", _empty_df(), 0)

    try:
        raw_rows = parse_rows(text, feed.parse)
    except Exception:  # noqa: BLE001
        return ("partial", _empty_df(), 0)

    ctx = OpContext(source_id=f"{source.id}:{feed.fixture_key()}", run_time=run_time)

    mapped: list[Row] = []
    for raw_row in raw_rows:
        row: Row = dict(raw_row)
        for norm, ref in feed.fields.items():
            row[norm] = _resolve_raw(raw_row, ref)
        mapped.append(row)

    cleaned = apply_clean_ops(mapped, feed.clean, ctx)

    built: list[Row] = []
    if feed.value_field and feed.type_field:
        built = _route_by_type(cleaned, source, feed)
    else:
        for row in cleaned:
            for type_ in feed.output_types:
                if feed.fields.get(type_) is None:
                    continue
                # Read the *normalized* value (clean ops may have rewritten it,
                # e.g. regex_extract on a plain-line feed).
                raw_val = row.get(type_)
                if raw_val is None:
                    continue
                rec = _common_row(type_, str(raw_val), row, source, feed)
                if rec is not None:
                    built.append(_with_extras(rec, row))

    df = _df_from_rows(built)
    status: SourceStatus = "partial" if partial else "ok"
    return (status, df, len(cleaned))


def _route_by_type(rows: list[Row], source: SourceConfig, feed: FeedConfig) -> list[Row]:
    """Type-routed feeds (OTX): classify each row by its type field value."""
    assert feed.value_field and feed.type_field
    allowed = set(feed.output_types)
    out: list[Row] = []
    for row in rows:
        raw_type = row.get(feed.type_field)
        mapped = feed.type_map.get(str(raw_type))
        if mapped is None or mapped not in allowed:
            continue
        value = row.get(feed.value_field)
        if value is None:
            continue
        rec = _common_row(mapped, str(value), row, source, feed)
        if rec is not None:
            out.append(_with_extras(rec, row))
    return out


def _empty_df() -> pl.DataFrame:
    schema = {c: _dtype(c) for c in ALL_COLUMNS}
    return pl.DataFrame(schema=schema)


def _dtype(col: str) -> pl.DataType:
    if col in ("sources", "categories"):
        return pl.List(pl.Utf8())
    if col == "last_seen":
        return pl.Datetime(time_unit="us", time_zone="UTC")
    if col in ("ip_int", "start_int", "asn"):
        return pl.Int64()
    if col in ("ip_version", "family"):
        return pl.Int8()
    if col == "prefix":
        return pl.Int32()
    return pl.Utf8()


def _df_from_rows(rows: list[Row]) -> pl.DataFrame:
    if not rows:
        return _empty_df()
    df = pl.DataFrame(rows)
    for col in ALL_COLUMNS:
        if col not in df.columns:
            df = df.with_columns(pl.lit(None, dtype=_dtype(col)).alias(col))
    return df.select(*ALL_COLUMNS)
