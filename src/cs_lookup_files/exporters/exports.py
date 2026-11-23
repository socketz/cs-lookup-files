from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

import polars as pl


def _join_lists(value: object) -> str:
    if isinstance(value, (list, tuple)):
        return ";".join(str(v) for v in value)
    return "" if value is None else str(value)


def _iso(dt: object | None) -> str:
    """Render a UTC datetime as ISO-8601 with a 'Z' suffix (Falcon-friendly)."""
    if dt is None:
        return ""
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(dt)


def write_csv(df: pl.DataFrame, path: Path, columns: list[str]) -> None:
    """Deterministic CSV export with a fixed header and exact column order."""
    path.parent.mkdir(parents=True, exist_ok=True)

    def _row_data(row: dict[str, object]) -> list[str]:
        out: list[str] = []
        for col in columns:
            if col == "sources" or col == "categories":
                out.append(_join_lists(row.get(col)))
            elif col in ("first_seen", "last_seen"):
                out.append(_iso(row.get(col)))
            else:
                value = row.get(col)
                out.append("" if value is None else str(value))
        return out

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(columns)
        for row in df.iter_rows(named=True):
            writer.writerow(_row_data(row))


def write_json(df: pl.DataFrame, path: Path, columns: list[str]) -> None:
    """Deterministic JSON array export preserving the column order as keys."""
    path.parent.mkdir(parents=True, exist_ok=True)

    def _iso_json(value: object | None) -> str | None:
        if value is None:
            return None
        return _iso(value)

    records: list[dict[str, object]] = []
    for row in df.iter_rows(named=True):
        record: dict[str, object] = {}
        for col in columns:
            value = row.get(col)
            if col == "sources" or col == "categories":
                record[col] = _join_lists(value)
            elif col in ("first_seen", "last_seen"):
                record[col] = _iso_json(value)
            else:
                record[col] = value
        records.append(record)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(records, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
