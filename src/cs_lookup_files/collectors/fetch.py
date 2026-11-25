from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

from ..models.config import FetchConfig, ParseConfig
from ..normalizers.parsers import _walk_path
from .cache import DailyQuota, HttpCache

logger = logging.getLogger("cs_lookup_files.fetch")

# Load the local .env file into the environment (if it exists) so `$VAR`
# references in config resolve from it exactly as from real env vars. Existing
# environment variables take precedence over .env values.
load_dotenv()

USER_AGENT = "cs-lookup-files/0.1 (+https://github.com/socketz/cs-lookup-files)"


class _RateLimiter:
    """Per-host token bucket so parallel source fetches stay polite."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # host -> (next_available_epoch, interval_seconds)
        self._last: dict[str, float] = {}

    def wait(self, host: str, requests_per_minute: int | None) -> None:
        if not requests_per_minute or requests_per_minute <= 0:
            return
        interval = 60.0 / requests_per_minute
        with self._lock:
            now = time.monotonic()
            next_ok = max(self._last.get(host, 0.0), now) + interval
            delay = next_ok - now
            if delay > 0:
                time.sleep(delay)
            self._last[host] = next_ok


_RATE = _RateLimiter()


class FetchError(RuntimeError):
    """Raised when a source cannot be fetched (network, auth env, HTTP status)."""


class MissingSecret(FetchError):
    """Raised when a source requires an API key that is not configured.

    The pipeline treats this as a *skip* rather than a failure: the source is
    not downloaded and its status is ``skipped`` until the key is provided in
    the environment or ``.env``.
    """

    def __init__(self, var: str, context: str):
        super().__init__(f"source {context}: required env var {var} is not set (skipping)")
        self.var = var
        self.context = context


class PartialFetchError(FetchError):
    """Some pages were fetched before a mid-pagination failure.

    Carries the successfully fetched pages so the pipeline can still ingest them
    and mark the source ``partial`` instead of discarding everything.
    """

    def __init__(self, partial_text: str, *, page: int, cause: BaseException):
        super().__init__(f"pagination stopped after page {page - 1}")
        self.partial_text = partial_text
        self.page = page
        self.cause = cause


class RateLimited(FetchError):
    """The persisted daily request budget for a host is exhausted.

    Treated as *skipped* (not failed): the source is healthy but intentionally
    not called again until the quota resets, so a free-tier limit never breaks
    the pipeline.
    """

    def __init__(self, host: str, max_per_day: int):
        super().__init__(f"daily request quota exhausted for {host} (max {max_per_day}/day)")
        self.host = host
        self.max_per_day = max_per_day


def resolve_env_ref(value: str) -> str | None:
    """Resolve ``$VAR`` header/param values from the runtime environment.

    Keys are provided via the workflow ``env:`` block, exported in the shell,
    or the local ``.env`` (loaded by python-dotenv). An absent or empty value
    (e.g. a blank ``KEY=`` in ``.env``) resolves to ``None`` so the caller can
    treat the source as *skipped*, not failed. A plain value is returned
    unchanged.
    """
    if value.startswith("$") and len(value) > 1 and not (value.startswith("$$")):
        resolved = os.environ.get(value[1:])
        return resolved if resolved and resolved.strip() else None
    return value


def _finalize_headers(fetch: FetchConfig) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in fetch.headers.items():
        resolved = resolve_env_ref(value)
        if resolved is None:
            raise MissingSecret(value[1:], fetch.url)
        headers[name] = resolved
    if "user-agent" not in {k.lower() for k in headers}:
        headers["User-Agent"] = USER_AGENT
    return headers


def _finalize_params(fetch: FetchConfig, page: int | None = None) -> dict[str, str]:
    params: dict[str, str] = {}
    for name, value in fetch.params.items():
        resolved = resolve_env_ref(str(value))
        if resolved is None:
            raise MissingSecret(str(value).lstrip("$"), fetch.url)
        params[name] = resolved
    if page is not None and fetch.pagination is not None:
        params[fetch.pagination.param] = str(page)
        params[fetch.pagination.size_param] = str(fetch.pagination.size)
    return params


def _nest_path(path: str, records: list[object]) -> object:
    """Nest ``records`` under a dotted ``path`` so the parser can walk it.

    ``"results"`` becomes ``{"results": [...]}`` and ``"data.items"`` becomes
    ``{"data": {"items": [...]}}``. The root path ``"$"`` returns the list
    itself, matching ``_walk_path`` semantics.
    """
    if path in ("$", ""):
        return records
    node: object = records
    for part in reversed(path.split(".")):
        node = {part: node}
    return node


def _merge_json_pages(pages: list[str], records_path: str) -> str:
    """Merge paginated JSON documents into one document at ``records_path``.

    Pagination yields separate JSON documents, so joining them with newlines
    produces invalid JSON. Each page is parsed independently, its records at
    ``records_path`` are concatenated in page order, and the result is re-nested
    under the same path so the configured parser sees one document.
    """
    merged: list[object] = []
    for page in pages:
        try:
            payload = json.loads(page)
        except json.JSONDecodeError:
            logger.warning("skipping unparseable JSON page during pagination merge")
            continue
        records = _walk_path(payload, records_path)
        if isinstance(records, list):
            merged.extend(records)
    return json.dumps(_nest_path(records_path, merged))


def _combine_pages(pages: list[str], parse_cfg: ParseConfig | None) -> str:
    """Join fetched pages, merging JSON documents when pagination is in play."""
    if (
        parse_cfg is not None
        and parse_cfg.format == "json"
        and parse_cfg.records
        and len(pages) > 1
    ):
        return _merge_json_pages(pages, parse_cfg.records)
    return "\n".join(pages)


def _count_records(text: str, parse_cfg: ParseConfig | None) -> int:
    """Heuristic page-emptiness probe used for pagination termination."""
    if not text.strip():
        return 0
    if parse_cfg is not None and parse_cfg.format == "json" and parse_cfg.records:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return 0
        records = _walk_path(payload, parse_cfg.records)
        return len(records) if isinstance(records, list) else 0
    return len(text.splitlines())


def fetch_text(
    fetch: FetchConfig,
    parse_cfg: ParseConfig | None = None,
    cache_dir: Path | None = None,
) -> str:
    """Fetch a source's body (concatenating paginated pages when configured).

    ``parse_cfg`` is used to detect empty JSON pages; text pages stop when a
    page contains no lines. ``cache_dir`` enables the on-disk body cache and the
    persisted daily quota declared by the feed (``cache_ttl_hours`` /
    ``max_requests_per_day``). Raises ``FetchError`` on failure.
    """
    client = httpx.Client(timeout=fetch.timeout_seconds, follow_redirects=True)
    try:
        pages: list[str] = []
        pagination = fetch.pagination
        if pagination is None:
            pages.append(_get_once(client, fetch, page=None, cache_dir=cache_dir))
            return _combine_pages(pages, parse_cfg)
        started = time.monotonic()
        for page in range(1, pagination.max_pages + 1):
            if pagination.max_seconds is not None and (time.monotonic() - started) >= pagination.max_seconds:
                # Wall-clock budget exhausted: keep what we have and stop cleanly.
                return _combine_pages(pages, parse_cfg)
            try:
                body = _get_once(client, fetch, page=page, cache_dir=cache_dir)
            except FetchError as exc:
                # Mid-pagination failure: keep what we already have so an OTX
                # 504 at page N does not discard pages 1..N-1. Mark partial.
                if pages:
                    raise PartialFetchError(
                        _combine_pages(pages, parse_cfg), page=page, cause=exc
                    ) from exc
                raise
            pages.append(body)
            if not pagination.stop_when_empty and pagination.total_pages_field is None:
                continue
            if _count_records(body, parse_cfg) == 0:
                break
        return _combine_pages(pages, parse_cfg)
    except httpx.HTTPError as exc:
        raise FetchError(f"HTTP error: {exc}") from exc
    finally:
        client.close()


def _get_once(
    client: httpx.Client,
    fetch: FetchConfig,
    page: int | None,
    cache_dir: Path | None,
) -> str:
    host = urlparse(fetch.url).netloc
    cache = HttpCache(cache_dir) if cache_dir is not None else None

    # Cache-first: a fresh cached body costs no request and no daily quota.
    if page is None and cache is not None:
        cached = cache.load(fetch.url, fetch.cache_ttl_hours)
        if cached is not None:
            logger.debug("cache hit url=%s", fetch.url)
            return cached

    # Resolve secrets before consuming quota so a missing key never spends a slot.
    params = _finalize_params(fetch, page)
    headers = _finalize_headers(fetch)

    quota = DailyQuota(cache_dir) if (cache_dir is not None and fetch.max_requests_per_day is not None) else None
    if quota is not None and not quota.try_acquire(host, fetch.max_requests_per_day or 0):
        raise RateLimited(host, fetch.max_requests_per_day or 0)

    last: Exception | None = None
    for attempt in range(fetch.retries + 1):
        try:
            _RATE.wait(host, fetch.requests_per_minute)
            response = client.get(fetch.url, params=params, headers=headers)
            if response.status_code == 404:
                raise FetchError(f"404 for {fetch.url}")
            response.raise_for_status()
            body = response.text
            if page is None and cache is not None and fetch.cache_ttl_hours is not None:
                cache.store(fetch.url, body)
            return body
        except httpx.HTTPError as exc:
            last = exc
            if attempt < fetch.retries:
                time.sleep(min(2 ** attempt, 8))
    raise FetchError(f"request failed after retries: {last}") from last


def stream_to_file(
    url: str,
    destination: str,
    *,
    timeout_seconds: float = 600.0,
    retries: int = 3,
) -> None:
    """Stream a large binary asset (e.g. ip2asn TSV gz) to ``destination``."""
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with httpx.stream(
                "GET",
                url,
                timeout=timeout_seconds,
                follow_redirects=True,
                headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"},
            ) as response:
                response.raise_for_status()
                with open(destination, "wb") as out:
                    for chunk in response.iter_bytes():
                        out.write(chunk)
                return
        except httpx.HTTPError as exc:
            last = exc
            if attempt < retries:
                time.sleep(min(2 ** attempt, 8))
    raise FetchError(f"stream download failed for {url}: {last}") from last
