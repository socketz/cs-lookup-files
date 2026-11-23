"""Parser + cleaning-op unit tests (tests/unit)."""
from datetime import UTC

from cs_lookup_files.models.config import ParseConfig
from cs_lookup_files.normalizers import ipaddr, parsers
from cs_lookup_files.normalizers.ops import (
    CleanOp,
    OpContext,
    apply_clean_ops,
)


def test_parse_ipset():
    text = "# comment\nipv4 hash:net\n1.2.3.0/24\n10.0.0.5\n"
    cfg = ParseConfig(format="ipset", comment_prefix="#")
    rows = parsers.parse_rows(text, cfg)
    # Header line is a data row in this parser; engine validation drops it later.
    assert len(rows) == 3
    assert rows[1]["ip_or_cidr"] == "1.2.3.0/24"


def test_parse_cidr_lines_handles_spamhaus():
    text = "1.2.3.0/24 ; SBL123\n; pure comment\n10.0.0.0/8 ; SBL999\n"
    cfg = ParseConfig(format="cidr_lines", comment_prefix=";")
    rows = parsers.parse_rows(text, cfg)
    assert [r["cidr"] for r in rows] == ["1.2.3.0/24", "10.0.0.0/8"]


def test_parse_json_records_path():
    text = '{"data": {"list": [{"ip": "1.2.3.4"}, {"ip": "8.8.8.8"}]}}'
    cfg = ParseConfig(format="json", records="data.list")
    rows = parsers.parse_rows(text, cfg)
    assert [r["ip"] for r in rows] == ["1.2.3.4", "8.8.8.8"]


def test_parse_csv_with_otx_header():
    text = '"type","indicator","pulse"\n"IPv4","1.2.3.4","p"\n"IPv4","5.6.7.8","q"\n'
    cfg = ParseConfig(format="csv", delimiter=",", has_header=True)
    rows = parsers.parse_rows(text, cfg)
    # Bracket both name-keyed and index-keyed access.
    assert rows[0]["indicator"] == "1.2.3.4"
    assert rows[0]["1"] == "1.2.3.4"
    assert rows[0]["type"] == "IPv4"


def test_parse_csv_otx_header_missing_first_cell():
    # A headerless data stream whose first row already looks like data.
    text = '"IPv4","1.2.3.4","p"\n"IPv4","5.6.7.8","q"\n'
    cfg = ParseConfig(format="csv", delimiter=",", has_header=True)
    rows = parsers.parse_rows(text, cfg)
    assert len(rows) == 2
    assert rows[0]["1"] == "1.2.3.4"


def test_ipaddr_sort_key_ordering():
    # Within a family, lexicographic key order == numeric order.
    assert ipaddr.ip_sort_key("1.2.3.4") < ipaddr.ip_sort_key("9.9.9.9")
    # Mixed lists sort by (version, key): all v4 before all v6.
    keys = [(4, ipaddr.ip_sort_key("255.255.255.255")), (6, ipaddr.ip_sort_key("::1"))]
    assert sorted(keys) == [(4, ipaddr.ip_sort_key("255.255.255.255")), (6, ipaddr.ip_sort_key("::1"))]


def test_is_globally_routable_filters_private():
    assert not ipaddr.is_globally_routable("10.0.0.1")
    assert not ipaddr.is_globally_routable("192.168.1.1")
    assert not ipaddr.is_globally_routable("127.0.0.1")
    assert not ipaddr.is_globally_routable("0.0.0.0/8")
    assert ipaddr.is_globally_routable("8.8.8.8")
    assert ipaddr.is_globally_routable("1.2.3.0/24")


def _ctx():
    from datetime import datetime

    return OpContext(source_id="test", run_time=datetime.now(UTC))


def test_clean_field_in():
    rows = [{"type": "IPv4"}, {"type": "domain"}]
    out = apply_clean_ops(rows, [CleanOp(op="field_in", field="type", values=["IPv4"])], _ctx())
    assert len(out) == 1 and out[0]["type"] == "IPv4"


def test_clean_field_ge():
    rows = [{"score": 95}, {"score": 40}]
    out = apply_clean_ops(rows, [CleanOp(op="field_ge", field="score", value=90)], _ctx())
    assert len(out) == 1 and out[0]["score"] == 95


def test_clean_drop_private():
    rows = [{"ip": "1.2.3.4"}, {"ip": "10.0.0.1"}]
    out = apply_clean_ops(rows, [CleanOp(op="drop_private")], _ctx())
    assert [r["ip"] for r in out] == ["1.2.3.4"]


def test_clean_parse_and_validate_ip():
    rows = [{"ip": "1.2.3.4"}, {"ip": "not-an-ip"}]
    out = apply_clean_ops(rows, [CleanOp(op="parse_and_validate_ip")], _ctx())
    assert len(out) == 1 and out[0]["ip"] == "1.2.3.4"


def test_clean_map_values():
    rows = [{"tag": "botnet"}, {"tag": "benign"}]
    op = CleanOp(op="map_values", field="tag", mapping={"botnet": "malware_c2"}, output="category")
    out = apply_clean_ops(rows, [op], _ctx())
    assert len(out) == 1 and out[0]["category"] == "malware_c2"


def test_clean_dedupe_in_run():
    rows = [{"ip": "1.1.1.1"}, {"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}]
    out = apply_clean_ops(rows, [CleanOp(op="dedupe_in_run")], _ctx())
    assert len(out) == 2


def test_clean_limit():
    rows = [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}, {"ip": "3.3.3.3"}]
    out = apply_clean_ops(rows, [CleanOp(op="limit", limit=2)], _ctx())
    assert len(out) == 2
