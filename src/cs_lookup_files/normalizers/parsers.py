from __future__ import annotations

import csv as _csv
import io
import json
from collections.abc import Callable, Iterator
from typing import Any

from ..models.config import ParseConfig

RawRow = dict[str, Any]

# Values that indicate a CSV "header" row present in a headerless data stream
# such as the OTX indicator export (first cell is a data type, not a column name).
_INDICATOR_TYPE_MARKERS = {"ipv4", "ipv6"}


def _lines_without_comments(text: str, prefix: str | None) -> Iterator[str]:
    for line in io.StringIO(text).readlines():
        stripped = line.strip()
        if not stripped:
            continue
        if prefix and stripped.startswith(prefix):
            continue
        yield stripped


def _parse_plain_lines(text: str, cfg: ParseConfig) -> Iterator[RawRow]:
    for line in _lines_without_comments(text, cfg.comment_prefix):
        yield {"line": line}


def _parse_ipset(text: str, cfg: ParseConfig) -> Iterator[RawRow]:
    for line in _lines_without_comments(text, cfg.comment_prefix):
        yield {"ip_or_cidr": line}


def _parse_cidr_lines(text: str, cfg: ParseConfig) -> Iterator[RawRow]:
    for line in _lines_without_comments(text, cfg.comment_prefix):
        body = line.split(";")[0].strip()
        if not body:
            continue
        token = body.split()[0]
        yield {"cidr": token}


def _parse_delimited(text: str, cfg: ParseConfig, delimiter: str) -> Iterator[RawRow]:
    reader = _csv.reader(io.StringIO(text), delimiter=delimiter, quotechar='"')
    for _ in range(cfg.skip_lines):
        next(reader, None)
    try:
        first = next(reader)
    except StopIteration:
        return
    rows = [first, *reader]

    header: list[str] | None = None
    if cfg.has_header:
        if first and first[0].strip().lower() in _INDICATOR_TYPE_MARKERS:
            rows = [first, *rows[1:]]  # "header" is actually a data row (OTX-style)
        else:
            header = [cell.strip() for cell in first]
            rows = rows[1:]

    for cells in rows:
        if not cells or all(not c.strip() for c in cells):
            continue
        row: dict[str, str] = {}
        if header is not None:
            for i, value in enumerate(cells):
                if i < len(header):
                    row[header[i]] = value
        # Index-based keys are always present so field mapping can reference a
        # column position (e.g. OTX's "type","indicator" stream) even when a
        # header row exists.
        row.update({str(i): value for i, value in enumerate(cells)})
        yield row


def _walk_path(obj: Any, path: str) -> Any:
    if path == "$" or path == "":
        return obj
    current = obj
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _parse_json(text: str, cfg: ParseConfig) -> Iterator[RawRow]:
    assert cfg.records  # validated at config load
    payload = json.loads(text)
    records = _walk_path(payload, cfg.records)
    if not isinstance(records, list):
        return
    yield from (record for record in records if isinstance(record, dict))


def _parse_jsonl(text: str, cfg: ParseConfig) -> Iterator[RawRow]:
    """Parse newline-delimited JSON: one object per non-empty line.

    Blank lines and non-object/malformed lines are skipped. Feeds such as
    Spamhaus ASN-DROP append a trailing ``{"type": "metadata", ...}`` line;
    callers drop it naturally because it lacks the mapped indicator field.
    """
    for line in io.StringIO(text).readlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            yield payload


def _parse_csv(text: str, cfg: ParseConfig) -> Iterator[RawRow]:
    delimiter = cfg.delimiter if cfg.delimiter is not None else ","
    yield from _parse_delimited(text, cfg, delimiter)


def _parse_tsv(text: str, cfg: ParseConfig) -> Iterator[RawRow]:
    delimiter = cfg.delimiter if cfg.delimiter is not None else "\t"
    yield from _parse_delimited(text, cfg, delimiter)


ParserFn = Callable[[str, ParseConfig], Iterator[RawRow]]

_PARSERS: dict[str, ParserFn] = {
    "plain_lines": _parse_plain_lines,
    "ipset": _parse_ipset,
    "cidr_lines": _parse_cidr_lines,
    "csv": _parse_csv,
    "tsv": _parse_tsv,
    "json": _parse_json,
    "jsonl": _parse_jsonl,
}


def parse_rows(text: str, cfg: ParseConfig) -> list[RawRow]:
    """Parse ``text`` into raw rows (dict of raw field name -> value)."""
    return list(_PARSERS[cfg.format](text, cfg))
