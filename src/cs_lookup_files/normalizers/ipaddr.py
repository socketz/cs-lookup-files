from __future__ import annotations

import ipaddress

type IPObject = (
    ipaddress.IPv4Address
    | ipaddress.IPv6Address
    | ipaddress.IPv4Network
    | ipaddress.IPv6Network
)

# Additional bogon ranges that some Python versions do not flag via is_global.
_BOGON_V4: tuple[str, ...] = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
)

_BOGON_V6: tuple[str, ...] = (
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "100::/64",
    "2001:10::/28",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)

_BOGON_RANGES: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(r) for r in (*_BOGON_V4, *_BOGON_V6)
)


def parse_ip_or_cidr(value: str) -> IPObject | None:
    """Parse an IP or CIDR string; returns None when invalid."""
    value = value.strip()
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False)
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_globally_routable(value: str | IPObject) -> bool:
    """True when an IP or network is publicly routable and not bogon.

    Combines ``ipaddress.is_global`` with an explicit bogon overlay list so the
    behaviour is deterministic regardless of the Python patch level.
    """
    if isinstance(value, str):
        parsed = parse_ip_or_cidr(value)
        if parsed is None:
            return False
        obj: IPObject = parsed
    else:
        obj = value
    if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        if not obj.is_global:
            return False
        return all(
            not (obj.version == bogon.version and obj.subnet_of(bogon))  # type: ignore[arg-type]
            for bogon in _BOGON_RANGES
        )
    if not obj.is_global:
        return False
    return all(not (obj.version == bogon.version and obj in bogon) for bogon in _BOGON_RANGES)


def ip_version(value: str | IPObject) -> int:
    if isinstance(value, str):
        parsed = parse_ip_or_cidr(value)
        if parsed is None:
            raise ValueError(f"invalid IP/CIDR: {value!r}")
        return parsed.version
    return value.version


def ip_sort_key(value: str | IPObject) -> str:
    """Fixed-width lowercase hex key so lexicographic order == numeric order.

    IPv4 uses 8 hex digits, IPv6 uses 32. IPv4 keys always sort before IPv6
    keys when combined with a (version, key) sort.
    """
    result: ipaddress.IPv4Address | ipaddress.IPv6Address
    if isinstance(value, str):
        parsed = parse_ip_or_cidr(value)
        if parsed is None or "/" in value:
            raise ValueError(f"not a bare IP address: {value!r}")
        result = ipaddress.ip_address(value)
    elif isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        result = value.network_address
    else:
        result = value
    width = 8 if result.version == 4 else 32
    return f"{int(result):0{width}x}"


def network_sort_key(cidr: str) -> tuple[int, str, int]:
    """Sort key ``(version, start_key, prefix_len)`` that groups families."""
    net = ipaddress.ip_network(cidr, strict=False)
    start = ip_sort_key(net.network_address)
    return (net.version, start, net.prefixlen)


def ip_int(value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> int:
    """Integer value of an IP address (v4 only, guaranteed to fit Int64)."""
    addr = ipaddress.ip_address(value) if isinstance(value, str) else value
    if addr.version != 4:
        raise ValueError("ip_int only supports IPv4")
    return int(addr)


def network_int_range(cidr: str) -> tuple[int, int]:
    """(start_int, end_int) for a v4 network (both fit Int64)."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        raise ValueError("network_int_range only supports IPv4")
    return (int(net.network_address), int(net.broadcast_address))
