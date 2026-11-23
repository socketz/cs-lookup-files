from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import polars as pl

from .models.state import IndicatorState, State
from .normalizers.ipaddr import ip_sort_key

Row = dict[str, Any]
KeyFn = Callable[[Row], str]
CategoriesFn = Callable[[list[str]], list[str]]


def _ip_key(row: dict[str, Any]) -> str:
    version = int(str(row["ip_version"]))
    ident = row["ip_int"] if version == 4 else row["ip_key"]
    return f"ip:{ident}"


def _net_key(row: Row) -> str:
    return f"net:{row['network']}"


def load_state(path: Path | None) -> State:
    """Load the previous release's state; a missing/corrupt file means no history."""
    if path is None or not path.exists():
        return State()
    try:
        return State.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception:
        return State()


def dump_state(state: State, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(state.model_dump_json(indent=2), encoding="utf-8")


def _update_entry(
    entry: IndicatorState | None,
    value: str,
    run_time: datetime,
) -> IndicatorState:
    if entry is None:
        return IndicatorState(value=value, first_seen=run_time, last_seen=run_time, sources={})
    first_seen = min(entry.first_seen, run_time)
    last_seen = max(entry.last_seen, run_time)
    return IndicatorState(value=value, first_seen=first_seen, last_seen=last_seen, sources=dict(entry.sources))


def merge_state(
    prev: State,
    ip_df: pl.DataFrame,
    net_df: pl.DataFrame,
    run_time: datetime,
    ttl_days: int,
    categories_fn: CategoriesFn,
) -> tuple[State, pl.DataFrame, pl.DataFrame, int, int]:
    """Merge a run into persistent history and attach first/last seen + sources.

    Every key observed this run is updated (first_seen = min, last_seen = max,
    per-source counts incremented). Keys present in history but NOT observed
    now are carried over into the dataset until their last_seen falls outside
    the TTL window, then pruned from state.

    The ``sources`` list on output rows is the union of all historical sources,
    so source overlap/confidence reflects cumulative observation.
    """
    indicators: dict[str, IndicatorState] = {
        key: IndicatorState.model_validate(item) for key, item in prev.indicators.items()
    }
    cutoff = int(run_time.timestamp() - ttl_days * 86400)

    merged_ip = _merge_frame(ip_df, indicators, _ip_key, run_time, categories_fn)
    merged_net = _merge_frame(net_df, indicators, _net_key, run_time, categories_fn)

    observed_keys = _frame_keys(ip_df, _ip_key) | _frame_keys(net_df, _net_key)

    carried_ip_rows: list[Row] = []
    carried_net_rows: list[Row] = []
    pruned: list[str] = []
    for key, entry in indicators.items():
        if key in observed_keys:
            continue
        if int(entry.last_seen.timestamp()) < cutoff:
            pruned.append(key)
            continue
        if key.startswith("ip:"):
            carried_ip_rows.append(_carryover_ip_row(key, entry, categories_fn))
        else:
            carried_net_rows.append(_carryover_net_row(key, entry, categories_fn))

    if carried_ip_rows:
        carried_ip_df = _ip_df_schema(carried_ip_rows)
        if merged_ip.is_empty():
            merged_ip = carried_ip_df
        else:
            merged_ip = pl.concat([carried_ip_df, merged_ip], how="vertical_relaxed")
    if carried_net_rows:
        carried_net_df = _net_df_schema(carried_net_rows)
        if merged_net.is_empty():
            merged_net = carried_net_df
        else:
            merged_net = pl.concat([carried_net_df, merged_net], how="vertical_relaxed")

    kept = {k: v for k, v in indicators.items() if k not in pruned}
    new_state = State(generated_at=run_time, indicators=kept)
    return new_state, merged_ip, merged_net, len(carried_ip_rows), len(carried_net_rows)


def _frame_keys(df: pl.DataFrame, key_fn: KeyFn) -> set[str]:
    if df.is_empty():
        return set()
    return {key_fn(row) for row in df.to_dicts()}


def _merge_frame(
    df: pl.DataFrame,
    indicators: dict[str, IndicatorState],
    key_fn: KeyFn,
    run_time: datetime,
    categories_fn: CategoriesFn,
) -> pl.DataFrame:
    if df.is_empty():
        return df
    merged: list[Row] = []
    for row in df.to_dicts():
        key = key_fn(row)
        sources = sorted(set(row["sources"]))
        value = str(row.get("ip") or row.get("network"))
        entry = _update_entry(indicators.get(key), value, run_time)
        for source in sources:
            entry.sources[source] = entry.sources.get(source, 0) + 1
        indicators[key] = entry
        hist_sources = sorted(entry.sources)
        categories = row["categories"] if row["categories"] else categories_fn(hist_sources)
        merged.append(
            {
                **row,
                "first_seen": entry.first_seen,
                "last_seen": entry.last_seen,
                "sources": hist_sources,
                "categories": categories,
            }
        )
    return pl.DataFrame(merged)


def _carryover_ip_row(
    key: str,
    entry: IndicatorState,
    categories_fn: CategoriesFn,
) -> Row:
    addr = ipaddress.ip_address(entry.value)
    version = addr.version
    ident = int(addr) if version == 4 else None
    return {
        "ip": str(addr),
        "ip_int": ident,
        "ip_version": version,
        "ip_key": ip_sort_key(str(addr)),
        "sources": sorted(entry.sources),
        "categories": categories_fn(sorted(entry.sources)),
        "last_seen": entry.last_seen,
        "first_seen": entry.first_seen,
    }


def _carryover_net_row(
    key: str,
    entry: IndicatorState,
    categories_fn: CategoriesFn,
) -> Row:
    net = ipaddress.ip_network(entry.value, strict=False)
    start = net.network_address
    family = start.version
    # sort keys mirror engine._build_network_row
    from .normalizers.ipaddr import ip_sort_key

    start_key = ip_sort_key(str(start))
    start_int = int(start) if family == 4 else None
    return {
        "network": str(net),
        "family": family,
        "start_key": start_key,
        "start_int": start_int,
        "prefix": net.prefixlen,
        "sources": sorted(entry.sources),
        "categories": categories_fn(sorted(entry.sources)),
        "last_seen": entry.last_seen,
        "first_seen": entry.first_seen,
    }


def _ip_df_schema(rows: list[Row]) -> pl.DataFrame:
    return pl.DataFrame(
        rows,
        schema={
            "ip": pl.Utf8,
            "ip_int": pl.Int64,
            "ip_version": pl.Int8,
            "ip_key": pl.Utf8,
            "sources": pl.List(pl.Utf8),
            "categories": pl.List(pl.Utf8),
            "last_seen": pl.Datetime(time_unit="us", time_zone="UTC"),
            "first_seen": pl.Datetime(time_unit="us", time_zone="UTC"),
        },
    )


def _net_df_schema(rows: list[Row]) -> pl.DataFrame:
    return pl.DataFrame(
        rows,
        schema={
            "network": pl.Utf8,
            "family": pl.Int8,
            "start_key": pl.Utf8,
            "start_int": pl.Int64,
            "prefix": pl.Int32,
            "sources": pl.List(pl.Utf8),
            "categories": pl.List(pl.Utf8),
            "last_seen": pl.Datetime(time_unit="us", time_zone="UTC"),
            "first_seen": pl.Datetime(time_unit="us", time_zone="UTC"),
        },
    )


def merge_categories_fn(sources_by_id: dict[str, list[str]]) -> CategoriesFn:
    """Return a categories_fn mapping source ids to their configured categories."""

    def fn(ids: list[str]) -> list[str]:
        out: set[str] = set()
        for sid in ids:
            out.update(sources_by_id.get(sid, ["other"]))
        return sorted(out)

    return fn
