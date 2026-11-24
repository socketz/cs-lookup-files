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
