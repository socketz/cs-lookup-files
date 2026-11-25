"""Indicator canonicalization tests for the ``asn`` type (tests/unit)."""
from cs_lookup_files.normalizers.indicators import (
    canonical_indicator,
    sort_key,
)


def test_asn_accepts_prefix_and_bare_digits():
    assert canonical_indicator("asn", "AS60971") == "60971"
    assert canonical_indicator("asn", "as60971") == "60971"
    assert canonical_indicator("asn", " 60971 ") == "60971"


def test_asn_rejects_invalid_values():
    assert canonical_indicator("asn", "AS") is None
    assert canonical_indicator("asn", "AS-1") is None
    assert canonical_indicator("asn", "0") is None
    assert canonical_indicator("asn", "-5") is None
    assert canonical_indicator("asn", "4294967296") is None
    assert canonical_indicator("asn", "not-an-asn") is None


def test_asn_boundaries():
    assert canonical_indicator("asn", "1") == "1"
    assert canonical_indicator("asn", "4294967295") == "4294967295"


def test_asn_sort_key_is_numeric_deterministic():
    values = ["64512", "1234", "4294967295"]
    ordered = sorted(values, key=lambda v: int(v))
    keys = [sort_key("asn", v) for v in ordered]
    assert keys == sorted(keys)
    assert sort_key("asn", "1234") == "0000001234"
