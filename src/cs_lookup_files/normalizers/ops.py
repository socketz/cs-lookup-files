from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..models.config import CleanOp
from . import ipaddr

Row = dict[str, Any]


@dataclass
class OpContext:
    """Per-source mutable state threaded through the clean-op pipeline."""

    source_id: str
    run_time: datetime
    seen: set[str] = field(default_factory=set)
    kept: int = 0

    def bump(self) -> None:
        self.kept += 1


def _operand(row: Row, op: CleanOp) -> Any | None:
    if op.field:
        return row.get(op.field)
    # Fall back to whichever mapped value is present.
    for key in ("ip", "network", "ip_or_cidr", "line", "cidr"):
        if key in row:
            return row[key]
    return None


def _op_strip(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    if op.field:
        value = row.get(op.field)
        if isinstance(value, str):
            row[op.field] = value.strip()
        return row
    for key, value in row.items():
        if isinstance(value, str):
            row[key] = value.strip()
    return row


def _op_drop_empty(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    if op.field:
        value = row.get(op.field)
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        return row
    for key in ("ip", "network", "ip_or_cidr", "line", "cidr"):
        if key in row:
            value = row[key]
            if value is None or (isinstance(value, str) and not value.strip()):
                return None
    return row


def _op_drop_comments(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    prefix = op.prefix if op.prefix is not None else "#"
    for value in row.values():
        if isinstance(value, str) and value.lstrip().startswith(prefix):
            return None
    return row


def _op_parse_and_validate_ip(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    field = op.field or "ip"
    value = row.get(field)
    if not isinstance(value, str):
        return None
    parsed = ipaddr.parse_ip_or_cidr(value)
    if not isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return None
    row[field] = str(parsed)
    return row


def _op_parse_and_validate_cidr(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    field = op.field or "network"
    value = row.get(field)
    if not isinstance(value, str):
        return None
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    row[field] = str(net)
    return row


def _op_drop_private(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    value = _operand(row, op)
    if isinstance(value, str):
        parsed = ipaddr.parse_ip_or_cidr(value)
        if parsed is None:
            # Not an IP/CIDR (domain, url, hash, email, ...): keep untouched.
            return row
        if not ipaddr.is_globally_routable(parsed):
            return None
    return row


def _op_drop_bogon_networks(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    field = op.field or "network"
    value = row.get(field)
    if isinstance(value, str):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        if not ipaddr.is_globally_routable(net):
            return None
    return row


def _op_require_globally_routable(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    return _op_drop_private(row, ctx, op)


def _op_field_ge(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    if not op.field or op.value is None:
        return None
    raw = row.get(op.field)
    try:
        value = float(str(raw))
    except (TypeError, ValueError):
        return None
    return row if value >= float(op.value) else None


def _op_field_in(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    if not op.field or not op.values:
        return None
    value = row.get(op.field)
    return row if str(value) in op.values else None


def _op_map_values(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    if not op.field or not op.mapping or not op.output:
        return None
    value = str(row.get(op.field, ""))
    mapped = op.mapping.get(value)
    if mapped is None:
        return None
    row[op.output] = mapped
    return row


def _op_regex_extract(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    if not op.field or not op.pattern or not op.output:
        return None
    value = row.get(op.field)
    if not isinstance(value, str):
        return None
    match = re.search(op.pattern, value)
    if match is None:
        return None
    row[op.output] = match.group(1) if match.lastindex else match.group(0)
    return row


def _op_dedupe_in_run(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    value = _operand(row, op)
    if value is None:
        return None
    key = str(value)
    if key in ctx.seen:
        return None
    ctx.seen.add(key)
    return row


def _op_limit(row: Row, ctx: OpContext, op: CleanOp) -> Row | None:
    if op.limit is not None and ctx.kept >= op.limit:
        return None
    ctx.bump()
    return row


OP_MAP: dict[str, Callable[[Row, OpContext, CleanOp], Row | None]] = {
    "strip": _op_strip,
    "drop_empty": _op_drop_empty,
    "drop_comments": _op_drop_comments,
    "parse_and_validate_ip": _op_parse_and_validate_ip,
    "parse_and_validate_cidr": _op_parse_and_validate_cidr,
    "drop_private": _op_drop_private,
    "drop_bogon_networks": _op_drop_bogon_networks,
    "require_globally_routable": _op_require_globally_routable,
    "field_ge": _op_field_ge,
    "field_in": _op_field_in,
    "map_values": _op_map_values,
    "regex_extract": _op_regex_extract,
    "dedupe_in_run": _op_dedupe_in_run,
    "limit": _op_limit,
}

OP_NAMES: frozenset[str] = frozenset(OP_MAP)


def apply_clean_ops(
    rows: list[Row],
    clean: list[CleanOp],
    ctx: OpContext,
) -> list[Row]:
    """Apply a source's declared clean ops in order, dropping dropped rows."""
    kept = rows
    for op in clean:
        fn = OP_MAP.get(op.op)
        if fn is None:  # config validation prevents this in practice
            continue
        next_rows: list[Row] = []
        for row in kept:
            result = fn(dict(row), ctx, op)
            if result is not None:
                next_rows.append(result)
        kept = next_rows
    return kept
