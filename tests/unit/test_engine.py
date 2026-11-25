"""Engine (run_source) tests (tests/unit)."""
from datetime import UTC, datetime

from cs_lookup_files.etl.engine import run_source
from cs_lookup_files.models.config import FeedConfig, SourceConfig

RUN = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


def _cfg(**overrides) -> SourceConfig:
    feed = {
        "id": "auth_feed",
        "fetch": {"url": "https://api.example.org/feed", "headers": {"Key": "$SOME_KEY"}},
        "parse": {"format": "plain_lines"},
        "output_types": ["ip"],
        "fields": {"ip": "line"},
        "clean": [],
    }
    payload = {
        "id": "auth_source",
        "weight": 70,
        "categories": {"default": ["malware"]},
        "feeds": [feed],
    }
    payload.update(overrides)
    return SourceConfig.model_validate(payload)


def _fetch_text(source: SourceConfig, feed: FeedConfig) -> str:
    from cs_lookup_files.collectors import fetch

    return fetch.fetch_text(feed.fetch, feed.parse)


def test_missing_key_marks_skipped(monkeypatch):
    monkeypatch.delenv("SOME_KEY", raising=False)
    out = run_source(_cfg(), _fetch_text, RUN)
    assert out.status == "skipped"
    assert out.records == 0
    assert out.df.is_empty()


def test_empty_key_marks_skipped(monkeypatch):
    monkeypatch.setenv("SOME_KEY", "")
    out = run_source(_cfg(), _fetch_text, RUN)
    assert out.status == "skipped"


def test_ok_source_produces_rows(monkeypatch):
    monkeypatch.setenv("SOME_KEY", "secret")
    monkeypatch.setattr(
        "cs_lookup_files.collectors.fetch.httpx.Client",
        _FakeClient,
    )
    out = run_source(_cfg(), _fetch_text, RUN)
    assert out.status == "ok"
    vals = sorted(out.df["value"].to_list())
    assert vals == ["8.8.8.8", "9.9.9.9"]


def test_multiple_feeds_share_one_source_identity():
    """Two feeds of the same origin collapse to a single `sources` entry."""

    def fetcher(source: SourceConfig, feed: FeedConfig) -> str:
        return "8.8.8.8\n"

    two_feeds = {
        "id": "multi",
        "weight": 80,
        "categories": {"default": ["blocklist"]},
        "feeds": [
            {
                "id": "f1",
                "fetch": {"url": "https://example.org/a.txt"},
                "parse": {"format": "plain_lines"},
                "output_types": ["ip"],
                "fields": {"ip": "line"},
                "clean": [],
            },
            {
                "id": "f2",
                "fetch": {"url": "https://example.org/b.txt"},
                "parse": {"format": "plain_lines"},
                "output_types": ["ip"],
                "fields": {"ip": "line"},
                "clean": [],
            },
        ],
    }
    out = run_source(SourceConfig.model_validate(two_feeds), fetcher, RUN)
    assert out.status == "ok"
    # Both feeds yielded 8.8.8.8 but scoring identity is the origin.
    assert out.df["sources"].to_list() == [["multi"], ["multi"]]


class _Resp:
    status_code = 200
    text = "8.8.8.8\n9.9.9.9\n"

    def raise_for_status(self):
        pass


class _FakeClient:
    def __init__(self, *a, **k):
        pass

    def get(self, *a, **k):
        return _Resp()

    def close(self):
        pass


def test_empty_feed_is_reported_empty_not_partial():
    def fetcher(source: SourceConfig, feed: FeedConfig) -> str:
        return "\n\n"

    out = run_source(_cfg(), fetcher, RUN)
    assert out.status == "ok"
    assert out.df.is_empty()
    assert out.feeds[0].status == "empty"
    assert out.feeds[0].reason == "empty body"


def test_parse_failure_marks_feed_failed():
    def fetcher(source: SourceConfig, feed: FeedConfig) -> str:
        return "not a usable body"

    cfg_payload = {
        "id": "bad_parse",
        "weight": 70,
        "feeds": [{
            "id": "bad",
            "fetch": {"url": "https://example.org/x"},
            "parse": {"format": "json", "records": "data"},
            "output_types": ["ip"],
            "fields": {"ip": "ip"},
            "clean": [],
        }],
    }
    out = run_source(SourceConfig.model_validate(cfg_payload), fetcher, RUN)
    assert out.status == "failed"
    assert out.feeds[0].status == "failed"
    assert out.feeds[0].reason is not None and out.feeds[0].reason.startswith("parse error")


def test_rate_limited_is_skipped_not_failed():
    from cs_lookup_files.collectors.fetch import RateLimited

    def fetcher(source: SourceConfig, feed: FeedConfig) -> str:
        raise RateLimited("api.example.org", 5)

    out = run_source(_cfg(), fetcher, RUN)
    assert out.status == "skipped"
    assert out.feeds[0].status == "skipped"
    assert out.feeds[0].reason == "rate limit"


def test_mixed_ok_and_empty_origin_stays_ok():
    def fetcher(source: SourceConfig, feed: FeedConfig) -> str:
        return "8.8.8.8\n" if feed.fixture_key() == "f1" else ""

    payload = {
        "id": "mixed",
        "weight": 80,
        "feeds": [
            {
                "id": "f1",
                "fetch": {"url": "https://example.org/a.txt"},
                "parse": {"format": "plain_lines"},
                "output_types": ["ip"],
                "fields": {"ip": "line"},
                "clean": [],
            },
            {
                "id": "f2",
                "fetch": {"url": "https://example.org/b.txt"},
                "parse": {"format": "plain_lines"},
                "output_types": ["ip"],
                "fields": {"ip": "line"},
                "clean": [],
            },
        ],
    }
    out = run_source(SourceConfig.model_validate(payload), fetcher, RUN)
    assert out.status == "ok"
    assert {run.status for run in out.feeds} == {"ok", "empty"}


def test_otx_type_map_is_case_insensitive_and_canonical():
    text = (
        '"FileHash-MD5","d41d8cd98f00b204e9800998ecf8427e","p"\n'
        '"filehash-md5","0cc175b9c0f1b6a831c399e269772661","q"\n'
        '"URI","https://evil.example.org/x","u"\n'
        '"CIDR","1.2.3.0/24","c"\n'
        '"Email","bad@phishy-mail.com","e"\n'
        '"UnsupportedType","ignored","z"\n'
    )
    payload = {
        "id": "otx_like",
        "weight": 70,
        "feeds": [{
            "id": "otx",
            "fetch": {"url": "https://otx.example.org/export"},
            "parse": {"format": "csv", "delimiter": ",", "has_header": False},
            "output_types": ["md5", "url", "network", "email"],
            "type_field": "0",
            "value_field": "1",
            "type_map": {
                "FileHash-MD5": "md5",
                "FileHash-SHA256": "sha256",
                "URL": "url",
                "URI": "url",
                "CIDR": "network",
                "email": "email",
            },
            "fields": {"md5": "1", "url": "1", "network": "1", "email": "1"},
            "clean": [],
        }],
    }

    def fetcher(source: SourceConfig, feed: FeedConfig) -> str:
        return text

    out = run_source(SourceConfig.model_validate(payload), fetcher, RUN)
    assert not out.df.is_empty()
    types = out.df["type"].to_list()
    assert types.count("md5") == 2
    assert types.count("url") == 1
    assert types.count("network") == 1
    assert types.count("email") == 1


def test_allowlist_feed_is_collected_but_not_exported():
    payload = {
        "id": "mixed",
        "weight": 80,
        "feeds": [
            {
                "id": "intel",
                "fetch": {"url": "https://example.org/intel.txt"},
                "parse": {"format": "plain_lines"},
                "output_types": ["domain"],
                "fields": {"domain": "line"},
                "clean": [],
            },
            {
                "id": "allow",
                "role": "allowlist",
                "fetch": {"url": "https://example.org/allow.txt"},
                "parse": {"format": "plain_lines"},
                "output_types": ["domain"],
                "fields": {"domain": "line"},
                "clean": [],
            },
        ],
    }

    def fetcher(source: SourceConfig, feed: FeedConfig) -> str:
        if feed.fixture_key() == "allow":
            return "legit.example.com\ncorp.example.net\n"
        return "evil.example.com\n"

    out = run_source(SourceConfig.model_validate(payload), fetcher, RUN)
    assert out.df["value"].to_list() == ["evil.example.com"]
    assert out.allowlist == {"legit.example.com", "corp.example.net"}
    assert {run.feed: run.rows for run in out.feeds} == {"intel": 1, "allow": 2}


def test_asn_rows_keep_name_and_country_and_drop_metadata_line():
    payload = {
        "id": "asn_source",
        "weight": 100,
        "feeds": [{
            "id": "asndrop",
            "fetch": {"url": "https://example.org/asndrop.json"},
            "parse": {"format": "jsonl"},
            "output_types": ["asn"],
            "fields": {"asn": "asn", "asn_name": "asname", "country": "cc"},
            "clean": [],
        }],
    }
    text = (
        '{"asn": 211468, "asname": "AS211468-MALIWARE", "cc": "DE"}\n'
        '{"type": "metadata", "timestamp": "2026-11-23T00:00:00Z"}\n'
    )

    def fetcher(source: SourceConfig, feed: FeedConfig) -> str:
        return text

    out = run_source(SourceConfig.model_validate(payload), fetcher, RUN)
    assert out.df.height == 1
    row = out.df.to_dicts()[0]
    assert row["type"] == "asn"
    assert row["value"] == "211468"
    assert row["asn"] == 211468
    assert row["asn_name"] == "AS211468-MALIWARE"
    assert row["country"] == "DE"
