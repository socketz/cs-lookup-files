from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import polars as pl

from .models.state import IndicatorState, State
from .normalizers.indicators import INDICATOR_TYPES, IndicatorType, sort_key

Row = dict[str, Any]
KeyFn = Callable[[Row], str]
CategoriesFn = Callable[[list[str]], list[str]]


def _indicator_key(row: Row) -> str:
    """Unified state key: ``{type}:{value}`` for every indicator type."""
    return f"{row['type']}:{row['value']}"


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
    type_: str,
    value: str,
    run_time: datetime,
) -> IndicatorState:
    if entry is None:
        return IndicatorState(type=type_, value=value, first_seen=run_time, last_seen=run_time, sources={})
    first_seen = min(entry.first_seen, run_time)
    last_seen = max(entry.last_seen, run_time)
    return IndicatorState(
        type=entry.type or type_, value=entry.value or value,
        first_seen=first_seen, last_seen=last_seen, sources=dict(entry.sources),
    )


def merge_state(
    prev: State,
    df: pl.DataFrame,
    run_time: datetime,
    ttl_days: int,
    categories_fn: CategoriesFn,
) -> tuple[State, pl.DataFrame, int]:
    """Merge a run's indicators into persistent history.

    ``first_seen = min``, ``last_seen = max`` and per-source counts increment
    for observed indicators. Indicators in history not observed now are carried
    over until their last_seen leaves the TTL window, then pruned from state.

    The ``sources`` column on output rows is the union of all historical sources.
    """
    indicators: dict[str, IndicatorState] = {
        key: IndicatorState.model_validate(item) for key, item in prev.indicators.items()
    }
    cutoff = int(run_time.timestamp() - ttl_days * 86400)

    observed: dict[str, IndicatorState] = {}
    if not df.is_empty():
        for row in df.to_dicts():
            key = _indicator_key(row)
            type_ = str(row["type"])
            value = str(row["value"])
            entry = _update_entry(indicators.get(key), type_, value, run_time)
            for source in row["sources"]:
                entry.sources[str(source)] = entry.sources.get(str(source), 0) + 1
            indicators[key] = entry
            observed[key] = entry

    carried_rows: list[Row] = []
    pruned: list[str] = []
    for key, entry in indicators.items():
        if key in observed:
            continue
        if int(entry.last_seen.timestamp()) < cutoff:
            pruned.append(key)
            continue
        if entry.type in INDICATOR_TYPES:
            carried_rows.append(_carryover_row(entry, categories_fn))

    kept = {k: v for k, v in indicators.items() if k not in pruned}
    new_state = State(generated_at=run_time, indicators=kept)

    merged = _attach_history(df, observed, categories_fn) if not df.is_empty() else df
    if carried_rows:
        carried_df = _rows_to_df(carried_rows)
        merged = carried_df.vstack(merged) if not merged.is_empty() else carried_df
    return new_state, merged, len(carried_rows)


def _carryover_row(entry: IndicatorState, categories_fn: CategoriesFn) -> Row:
    sources = sorted(entry.sources)
    return {
        "value": entry.value,
        "sort_key": sort_key(cast(IndicatorType, entry.type), entry.value),
        "type": entry.type,
        "sources": sources,
        "categories": categories_fn(sources),
        "last_seen": entry.last_seen,
        "first_seen": entry.first_seen,
        "ip": None, "network": None, "asn": None, "asn_name": None, "country": None,
        "ip_int": None, "ip_version": None, "ip_key": None,
        "start_int": None, "family": None, "start_key": None, "prefix": None,
    }


def _attach_history(
    df: pl.DataFrame,
    observed: dict[str, IndicatorState],
    categories_fn: CategoriesFn,
) -> pl.DataFrame:
    rows: list[Row] = []
    for row in df.to_dicts():
        key = _indicator_key(row)
        entry = observed[key]
        sources = sorted(entry.sources)
        categories = row["categories"] if row["categories"] else categories_fn(sources)
        sort_key_v = sort_key(cast(IndicatorType, str(row["type"])), str(row["value"]))
        rows.append(
            {
                **row,
                "sort_key": sort_key_v,
                "first_seen": entry.first_seen,
                "last_seen": entry.last_seen,
                "sources": sources,
                "categories": categories,
            }
        )
    return _rows_to_df(rows)


def merge_categories_fn(sources_by_id: dict[str, list[str]]) -> CategoriesFn:
    def fn(ids: list[str]) -> list[str]:
        out: set[str] = set()
        for sid in ids:
            out.update(sources_by_id.get(sid, ["other"]))
        return sorted(out)

    return fn


def _rows_to_df(rows: list[Row]) -> pl.DataFrame:
    from .etl.engine import ALL_COLUMNS, _dtype

    schema = {c: _dtype(c) for c in ALL_COLUMNS}
    schema["first_seen"] = pl.Datetime(time_unit="us", time_zone="UTC")
    all_cols = (*ALL_COLUMNS, "first_seen")
    if not rows:
        return pl.DataFrame(schema=schema, )

    scaffold: list[Row] = []
    for row in rows:
        out = dict(row)
        for col in all_cols:
            if col not in out:
                out[col] = None
        scaffold.append(out)
    return pl.DataFrame(scaffold, schema=schema).select(*all_cols)
