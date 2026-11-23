from __future__ import annotations

import json
import os
import time

import httpx

from ..models.config import FetchConfig, ParseConfig
from ..normalizers.parsers import _walk_path

USER_AGENT = "cs-lookup-files/0.1 (+https://github.com/socketz/cs-lookup-files)"


class FetchError(RuntimeError):
    """Raised when a source cannot be fetched (network, auth env, HTTP status)."""


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


def resolve_env_ref(value: str) -> str | None:
    """Resolve ``$VAR`` header/param values from the runtime environment.

    Keys are passed via the workflow ``env:`` block and never live in the
    repository. A plain value is returned unchanged.
    """
    if value.startswith("$"):
        return os.environ.get(value[1:])
    return value


def _finalize_headers(fetch: FetchConfig) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in fetch.headers.items():
        resolved = resolve_env_ref(value)
        if resolved is None:
            raise FetchError(f"required env var {value[1:]} is not set")
        headers[name] = resolved
    if "user-agent" not in {k.lower() for k in headers}:
        headers["User-Agent"] = USER_AGENT
    return headers


def _finalize_params(fetch: FetchConfig, page: int | None = None) -> dict[str, str]:
    params: dict[str, str] = {}
    for name, value in fetch.params.items():
        resolved = resolve_env_ref(str(value))
        if resolved is None:
            raise FetchError(f"required env var {value} is not set")
        params[name] = resolved
    if page is not None and fetch.pagination is not None:
        params[fetch.pagination.param] = str(page)
        params[fetch.pagination.size_param] = str(fetch.pagination.size)
    return params


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


def fetch_text(fetch: FetchConfig, parse_cfg: ParseConfig | None = None) -> str:
    """Fetch a source's body (concatenating paginated pages when configured).

    ``parse_cfg`` is used to detect empty JSON pages; text pages stop when a
    page contains no lines. Raises ``FetchError`` on failure.
    """
    client = httpx.Client(timeout=fetch.timeout_seconds, follow_redirects=True)
    try:
        pages: list[str] = []
        pagination = fetch.pagination
        if pagination is None:
            pages.append(_get_once(client, fetch, page=None))
            return "\n".join(pages)
        for page in range(1, pagination.max_pages + 1):
            try:
                body = _get_once(client, fetch, page=page)
            except FetchError as exc:
                # Mid-pagination failure: keep what we already have so an OTX
                # 504 at page N does not discard pages 1..N-1. Mark partial.
                if pages:
                    raise PartialFetchError("\n".join(pages), page=page, cause=exc) from exc
                raise
            pages.append(body)
            if not pagination.stop_when_empty and pagination.total_pages_field is None:
                continue
            if _count_records(body, parse_cfg) == 0:
                break
        return "\n".join(pages)
    except httpx.HTTPError as exc:
        raise FetchError(f"HTTP error: {exc}") from exc
    finally:
        client.close()


def _get_once(client: httpx.Client, fetch: FetchConfig, page: int | None) -> str:
    last: Exception | None = None
    for attempt in range(fetch.retries + 1):
        try:
            response = client.get(
                fetch.url,
                params=_finalize_params(fetch, page),
                headers=_finalize_headers(fetch),
            )
            if response.status_code == 404:
                raise FetchError(f"404 for {fetch.url}")
            response.raise_for_status()
            return response.text
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
