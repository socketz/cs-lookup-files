from __future__ import annotations

import ipaddress
import logging
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import polars as pl

from ..collectors.fetch import MissingSecret, PartialFetchError, RateLimited
from ..models.config import FeedConfig, SourceConfig
from ..models.metadata import FeedStatus, SourceStatusKind
from ..normalizers import indicators, ipaddr
from ..normalizers.indicators import IndicatorType
from ..normalizers.ops import OpContext, apply_clean_ops
from ..normalizers.parsers import parse_rows

logger = logging.getLogger("cs_lookup_files.engine")

FetchFn = Callable[[SourceConfig, FeedConfig], str]

# Per-feed status. ``empty`` means the fetch+parse succeeded but produced no
# rows (informative; it never degrades the origin). ``partial`` is reserved for
# a truncated download (pagination cut short by the wall-clock budget/failure).
# Defined once in ``models.metadata`` so engine and metadata cannot drift.
SourceStatus = SourceStatusKind

TypeKey = str  # "ip", "network", "domain", "md5", "sha256", "email", "asn"

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
    feeds: list[FeedStatus] = field(default_factory=list)
    # Canonical domains from ``role: allowlist`` feeds. These are never scored
    # or exported; the pipeline uses them to suppress matching indicators.
    allowlist: set[str] = field(default_factory=set)


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
    elif type_ == "asn":
        # Authoritative ASN rows (Spamhaus ASN-DROP) carry their own name and
        # country; keep the ASN as an integer for the shared ``asn`` column.
        row["asn"] = int(value)
        asn_name = raw_row.get("asn_name")
        country = raw_row.get("country")
        if asn_name is not None and str(asn_name).strip():
            row["asn_name"] = str(asn_name).strip()
        if country is not None and str(country).strip():
            row["country"] = str(country).strip()
    return row


def run_source(source: SourceConfig, fetch_fn: FetchFn, run_time: datetime) -> SourceOutput:
    """Run every feed of a source, producing one unified indicator frame.

    Each feed is fetched/parsed independently and its own status recorded;
    statuses are aggregated for the origin: ``failed`` only when every feed
    failed, ``skipped`` only when every feed was skipped, ``partial`` when any
    feed was truncated, otherwise ``ok`` (empty feeds alone do not degrade the
    origin). The ``sources`` column carries the origin id, so indicators
    confirmed by several feeds of the same origin count as one confirming source.

    ``role: allowlist`` feeds are parsed into ``SourceOutput.allowlist`` and do
    not contribute rows to the unified frame. The pipeline uses that set to
    suppress matching indicators before scoring and export.
    """
    frames: list[pl.DataFrame] = []
    statuses: list[SourceStatus] = []
    feed_runs: list[FeedStatus] = []
    allowlist: set[str] = set()
    records = 0
    started = time.monotonic()
    for feed in source.feeds:
        status, df, recs, types, reason = _run_feed(source, feed, fetch_fn, run_time)
        statuses.append(status)
        records += recs
        feed_runs.append(
            FeedStatus(feed=feed.fixture_key(), status=status, rows=df.height, types=types, reason=reason)
        )
        if feed.role == "allowlist":
            if not df.is_empty():
                allowlist.update(str(value) for value in df["value"].to_list())
        elif not df.is_empty():
            frames.append(df)

    status = _aggregate_status(statuses)
    duration_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "origin=%s status=%s feeds=%d ok=%d empty=%d failed=%d skipped=%d partial=%d rows=%d duration=%dms",
        source.id,
        status,
        len(statuses),
        statuses.count("ok"),
        statuses.count("empty"),
        statuses.count("failed"),
        statuses.count("skipped"),
        statuses.count("partial"),
        records,
        duration_ms,
    )
    if not frames:
        return SourceOutput(source.id, status, records, _empty_df(), feed_runs, allowlist)
    combined = pl.concat(frames, how="vertical_relaxed") if len(frames) > 1 else frames[0]
    return SourceOutput(source.id, status, records, combined, feed_runs, allowlist)


def _aggregate_status(statuses: list[SourceStatus]) -> SourceStatus:
    if not statuses:
        return "failed"
    if all(s == "failed" for s in statuses):
        return "failed"
    if all(s == "skipped" for s in statuses):
        return "skipped"
    if any(s == "partial" for s in statuses):
        return "partial"
    return "ok"


def _run_feed(
    source: SourceConfig,
    feed: FeedConfig,
    fetch_fn: FetchFn,
    run_time: datetime,
) -> tuple[SourceStatus, pl.DataFrame, int, dict[str, int], str | None]:
    started = time.monotonic()
    text = ""
    partial = False
    try:
        text = fetch_fn(source, feed)
    except PartialFetchError as exc:
        text = exc.partial_text
        partial = True
    except RateLimited as exc:
        logger.warning("%s", exc)
        _log_feed(source, feed, "skipped", 0, {}, started, "rate limit")
        return ("skipped", _empty_df(), 0, {}, "rate limit")
    except MissingSecret as exc:
        logger.warning("%s", exc)
        _log_feed(source, feed, "skipped", 0, {}, started, "missing secret")
        return ("skipped", _empty_df(), 0, {}, "missing secret")
    except Exception as exc:  # noqa: BLE001 - intentionally tolerant
        reason = f"{type(exc).__name__}: {exc}"
        logger.warning("source %s feed %s failed: %s", source.id, feed.fixture_key(), exc)
        _log_feed(source, feed, "failed", 0, {}, started, reason)
        return ("failed", _empty_df(), 0, {}, reason)

    if logger.isEnabledFor(logging.DEBUG):
        head = [line[:200] for line in text.splitlines()[:2]]
        logger.debug("feed=%s raw sample=%s", feed.fixture_key(), head)

    if not text.strip():
        reason = "empty body"
        _log_feed(source, feed, "empty", 0, {}, started, reason)
        return ("empty", _empty_df(), 0, {}, reason)

    try:
        raw_rows = parse_rows(text, feed.parse)
    except Exception as exc:  # noqa: BLE001
        reason = f"parse error: {type(exc).__name__}: {exc}"
        logger.warning("source %s feed %s parse failed: %s", source.id, feed.fixture_key(), exc)
        _log_feed(source, feed, "failed", 0, {}, started, reason)
        return ("failed", _empty_df(), 0, {}, reason)

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
    types = dict(Counter(str(row["type"]) for row in built))
    feed_reason: str | None
    if df.is_empty():
        status: SourceStatus = "partial" if partial else "empty"
        feed_reason = "truncated fetch produced no rows" if partial else "no rows after parsing/cleaning"
    else:
        status = "partial" if partial else "ok"
        feed_reason = "truncated fetch" if partial else None
    _log_feed(source, feed, status, df.height, types, started, feed_reason)
    return (status, df, len(cleaned), types, feed_reason)


def _log_feed(
    source: SourceConfig,
    feed: FeedConfig,
    status: SourceStatus,
    rows: int,
    types: dict[str, int],
    started: float,
    reason: str | None,
) -> None:
    logger.info(
        "source=%s feed=%s status=%s rows=%d types=%s duration=%dms reason=%s",
        source.id,
        feed.fixture_key(),
        status,
        rows,
        types,
        int((time.monotonic() - started) * 1000),
        reason or "-",
    )


def _route_by_type(rows: list[Row], source: SourceConfig, feed: FeedConfig) -> list[Row]:
    """Type-routed feeds (OTX): classify each row by its type field value.

    The raw label is looked up case-insensitively so canonical OTX labels such
    as ``FileHash-MD5``, ``URL`` or ``URI`` match without a case-sensitive map.
    """
    assert feed.value_field and feed.type_field
    allowed = set(feed.output_types)
    type_map = {str(k).strip().lower(): v for k, v in feed.type_map.items()}
    out: list[Row] = []
    for row in rows:
        raw_type = row.get(feed.type_field)
        mapped = type_map.get(str(raw_type).strip().lower())
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
