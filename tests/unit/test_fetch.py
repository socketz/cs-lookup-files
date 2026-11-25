"""Fetch + pagination tests (tests/unit)."""
import httpx

from cs_lookup_files.collectors import fetch
from cs_lookup_files.models.config import FetchConfig, PaginationConfig, ParseConfig


def _resp_with_status(status_code: int) -> httpx.Response:
    return httpx.Response(status_code)


def _error(status_code: int, url: str) -> httpx.HTTPStatusError:
    return httpx.HTTPStatusError(
        str(status_code),
        request=httpx.Request("GET", url),
        response=_resp_with_status(status_code),
    )


def test_resolve_env_ref_plain_passthrough(monkeypatch):
    assert fetch.resolve_env_ref("application/json") == "application/json"


def test_resolve_env_ref_present(monkeypatch):
    monkeypatch.setenv("FAKE_KEY", "abcdef")
    assert fetch.resolve_env_ref("$FAKE_KEY") == "abcdef"


def test_resolve_env_ref_missing_is_none(monkeypatch):
    monkeypatch.delenv("DOES_NOT_EXIST", raising=False)
    assert fetch.resolve_env_ref("$DOES_NOT_EXIST") is None


def test_resolve_env_ref_empty_is_none(monkeypatch):
    # A blank `KEY=` in .env must be treated as unconfigured.
    monkeypatch.setenv("EMPTY_KEY", "")
    assert fetch.resolve_env_ref("$EMPTY_KEY") is None


def test_fetch_missing_secret_raises_missing_secret(monkeypatch):
    monkeypatch.delenv("REQUIRED_KEY", raising=False)
    cfg = FetchConfig(url="https://example.org/api", headers={"Key": "$REQUIRED_KEY"})

    class _Client:
        def __init__(self, *a, **k):
            pass

        def get(self, *a, **k):
            raise AssertionError("get should not be called (secret missing)")

        def close(self):
            pass

    monkeypatch.setattr(fetch.httpx, "Client", _Client)
    try:
        fetch.fetch_text(cfg)
    except fetch.MissingSecret as exc:
        assert exc.var == "REQUIRED_KEY"
    else:
        raise AssertionError("expected MissingSecret")


def test_plain_fetch_returns_body(monkeypatch):
    cfg = FetchConfig(url="https://example.org/feed.txt")

    class _Resp:
        status_code = 200
        text = "one\ntwo\n"

        def raise_for_status(self):
            pass

    class _Client:
        def __init__(self, *a, **k):
            pass

        def get(self, *a, **k):
            return _Resp()

        def close(self):
            pass

    monkeypatch.setattr(fetch.httpx, "Client", _Client)
    assert fetch.fetch_text(cfg) == "one\ntwo\n"


def test_partial_pagination_keeps_fetched_pages(monkeypatch):
    """A mid-pagination failure must preserve previously fetched pages."""
    cfg = FetchConfig(
        url="https://otx.example.org/export",
        pagination=PaginationConfig(param="page", size_param="limit", size=2, max_pages=10),
    )

    class _OkResp:
        status_code = 200
        text = '{"data": ["a"]}'

        def raise_for_status(self):
            pass

    class _ErrResp:
        status_code = 504
        text = ""

        def raise_for_status(self):
            raise _error(504, cfg.url)

    class _Client:
        def __init__(self, *a, **k):
            self.calls = 0

        def get(self, *a, params=None, **k):
            self.calls += 1
            if params.get("page") == "3":
                return _ErrResp()
            return _OkResp()

        def close(self):
            pass

    client = _Client()
    monkeypatch.setattr(fetch.httpx, "Client", lambda *a, **k: client)

    try:
        fetch.fetch_text(cfg, ParseConfig(format="json", records="data"))
    except fetch.PartialFetchError as exc:
        # pages 1 and 2 succeeded before page 3 failed.
        assert exc.partial_text.count('"a"') == 2
        assert exc.page == 3
    else:
        raise AssertionError("expected PartialFetchError")


def test_first_page_failure_raises_fetch_error(monkeypatch):
    cfg = FetchConfig(
        url="https://example.org/x",
        retries=0,
        pagination=PaginationConfig(max_pages=10),
    )

    class _ErrResp:
        status_code = 500
        text = ""

        def raise_for_status(self):
            raise _error(500, cfg.url)

    class _Client:
        def __init__(self, *a, **k):
            pass

        def get(self, *a, params=None, **k):
            return _ErrResp()

        def close(self):
            pass

    monkeypatch.setattr(fetch.httpx, "Client", _Client)
    try:
        fetch.fetch_text(cfg)
    except fetch.FetchError:
        pass
    else:
        raise AssertionError("expected FetchError")


def test_fresh_cache_is_reused_without_http(monkeypatch, tmp_path):
    from cs_lookup_files.collectors.cache import HttpCache

    url = "https://api.example.org/blacklist"
    HttpCache(tmp_path).store(url, "cached-body")
    cfg = FetchConfig(url=url, cache_ttl_hours=24)

    class _Client:
        def __init__(self, *a, **k):
            pass

        def get(self, *a, **k):
            raise AssertionError("HTTP must not be called on a cache hit")

        def close(self):
            pass

    monkeypatch.setattr(fetch.httpx, "Client", _Client)
    assert fetch.fetch_text(cfg, None, cache_dir=tmp_path) == "cached-body"


def test_expired_cache_triggers_request_and_rewrites(monkeypatch, tmp_path):
    import json
    from datetime import UTC, datetime

    from cs_lookup_files.collectors.cache import HttpCache

    url = "https://api.example.org/blacklist"
    cache = HttpCache(tmp_path)
    path = cache.path_for(url)
    path.parent.mkdir(parents=True, exist_ok=True)
    old = datetime(2020, 1, 1, tzinfo=UTC).isoformat()
    path.write_text(json.dumps({"url": url, "fetched_at": old, "body": "stale"}), encoding="utf-8")
    cfg = FetchConfig(url=url, cache_ttl_hours=24)

    class _Resp:
        status_code = 200
        text = "fresh-body"

        def raise_for_status(self):
            pass

    class _Client:
        def __init__(self, *a, **k):
            pass

        def get(self, *a, **k):
            return _Resp()

        def close(self):
            pass

    monkeypatch.setattr(fetch.httpx, "Client", _Client)
    assert fetch.fetch_text(cfg, None, cache_dir=tmp_path) == "fresh-body"
    assert cache.load(url, ttl_hours=24) == "fresh-body"


def test_daily_quota_exhaustion_raises_rate_limited(monkeypatch, tmp_path):
    from urllib.parse import urlparse

    from cs_lookup_files.collectors.cache import DailyQuota

    url = "https://api.example.org/blacklist"
    host = urlparse(url).netloc
    quota = DailyQuota(tmp_path)
    for _ in range(5):
        assert quota.try_acquire(host, 5)
    cfg = FetchConfig(url=url, max_requests_per_day=5)

    class _Client:
        def __init__(self, *a, **k):
            pass

        def get(self, *a, **k):
            raise AssertionError("HTTP must not be called when quota is exhausted")

        def close(self):
            pass

    monkeypatch.setattr(fetch.httpx, "Client", _Client)
    try:
        fetch.fetch_text(cfg, None, cache_dir=tmp_path)
    except fetch.RateLimited as exc:
        assert exc.max_per_day == 5
    else:
        raise AssertionError("expected RateLimited")
