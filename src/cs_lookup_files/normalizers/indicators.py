"""Indicator type registry: normalization + sort keys for each supported IOC type."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit

from . import ipaddr

IndicatorType = Literal["ip", "network", "domain", "url", "md5", "sha256", "email", "asn"]

INDICATOR_TYPES: tuple[IndicatorType, ...] = (
    "ip", "network", "domain", "url", "md5", "sha256", "email", "asn",
)

_MAX_ASN = 4294967295

# Common, conservative domain pattern. We do not validate DNS existence, just
# reject obvious junk / non-domain values.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$")

# Minimal email pattern (local@domain).
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,63}$")

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_MD5_LEN = 32
_SHA256_LEN = 64


def canonical_domain(value: str) -> str | None:
    """Lowercase and validate a domain; returns None when not a valid domain."""
    v = value.strip().lower()
    if not v or not _DOMAIN_RE.match(v):
        return None
    return v


def canonical_hash(value: str, *, size: int) -> str | None:
    v = value.strip().lower()
    if len(v) != size or not _HEX_RE.match(v):
        return None
    return v


def canonical_email(value: str) -> str | None:
    v = value.strip().lower()
    if not v or not _EMAIL_RE.match(v):
        return None
    return v


def canonical_url(value: str) -> str | None:
    """Canonicalize an http(s) URL: lowercase scheme+host, keep default-port-omitted path."""
    v = value.strip()
    if not v.lower().startswith(("http://", "https://")):
        return None
    try:
        parsed = urlsplit(v)
    except ValueError:
        return None
    if not parsed.hostname:
        return None
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    default_port = (scheme == "http" and (parsed.port or 80) == 80) or (
        scheme == "https" and (parsed.port or 443) == 443
    )
    port = f":{parsed.port}" if not default_port else ""
    path = parsed.path
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{host}{port}{path}{query}"


def canonical_asn(value: str) -> str | None:
    """Canonicalize an ASN (``AS12345`` or ``12345``) to bare digits.

    Returns ``None`` for out-of-range, non-numeric or otherwise invalid input.
    """
    v = value.strip()
    if v[:2].upper() == "AS":
        v = v[2:].strip()
    if not v.isdigit():
        return None
    number = int(v)
    if not 1 <= number <= _MAX_ASN:
        return None
    return str(number)


def canonical_indicator(kind: IndicatorType, value: str) -> str | None:
    """Return the canonical string for an indicator of ``kind`` or None."""
    if kind == "domain":
        return canonical_domain(value)
    if kind in ("md5", "sha256"):
        return canonical_hash(value, size=_MD5_LEN if kind == "md5" else _SHA256_LEN)
    if kind == "email":
        return canonical_email(value)
    if kind == "url":
        return canonical_url(value)
    if kind == "asn":
        return canonical_asn(value)
    if kind == "ip":
        if "/" in value:
            return None
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            return None
    if kind == "network":
        if "/" not in value:
            return None
        try:
            return str(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError:
            return None
    return None


def sort_key(kind: IndicatorType, value: str) -> str:
    """Deterministic ordering key; IP/network/ASN use numeric keys."""
    if kind == "ip":
        try:
            return f"{ipaddr.ip_version(value)}:{ipaddr.ip_sort_key(value)}"
        except ValueError:
            return f"4:{value}"
    if kind == "network":
        v, start, prefix = ipaddr.network_sort_key(value)
        return f"{v}:{start}:{prefix:02d}"
    if kind == "asn":
        try:
            return f"{int(value):010d}"
        except ValueError:
            return value
    return value


def asn_relevant(kind: IndicatorType) -> bool:
    # ASN indicators are authoritative rows themselves; they are never derived
    # from ip2asn enrichment (that would turn an entire ASN malicious from a
    # single flagged IP).
    return kind in ("ip", "network")
