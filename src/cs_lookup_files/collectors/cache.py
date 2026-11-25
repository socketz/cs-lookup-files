"""On-disk HTTP body cache and persisted daily request quota.

Both are used for rate-limited bulk APIs (AbuseIPDB free tier: 5 requests/day).
Freshness is read from the ``fetched_at`` timestamp *embedded in the file*, not
from the filesystem mtime, because CI cache restores do not preserve mtimes
reliably. The quota is keyed by UTC date so it resets at midnight UTC.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


class HttpCache:
    """Cache a response body per URL under ``<cache_dir>/http/<sha256(url)>.json``."""

    def __init__(self, cache_dir: Path):
        self.root = Path(cache_dir) / "http"

    def path_for(self, url: str) -> Path:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self.root / f"{digest}.json"

    def load(self, url: str, ttl_hours: float | None) -> str | None:
        """Return a cached body younger than ``ttl_hours``, else ``None``."""
        if ttl_hours is None:
            return None
        path = self.path_for(url)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(payload, dict) or payload.get("url") != url:
            return None
        fetched_at = _parse_timestamp(payload.get("fetched_at"))
        body = payload.get("body")
        if fetched_at is None or not isinstance(body, str):
            return None
        age_seconds = max(0.0, (_utc_now() - fetched_at).total_seconds())
        if age_seconds >= ttl_hours * 3600:
            return None
        return body

    def store(self, url: str, body: str) -> None:
        path = self.path_for(url)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"url": url, "fetched_at": _utc_now().isoformat(), "body": body}
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(path)


class DailyQuota:
    """Persist a per-host request counter under ``<cache_dir>/ratelimit/<host>.json``."""

    def __init__(self, cache_dir: Path):
        self.root = Path(cache_dir) / "ratelimit"

    def path_for(self, host: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", host) or "host"
        digest = hashlib.sha256(host.encode("utf-8")).hexdigest()[:8]
        return self.root / f"{safe}-{digest}.json"

    def _load(self, host: str) -> tuple[str, int]:
        try:
            payload = json.loads(self.path_for(host).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return "", 0
        if not isinstance(payload, dict):
            return "", 0
        date = payload.get("date")
        count = payload.get("count")
        if not isinstance(date, str) or not isinstance(count, int):
            return "", 0
        return date, count

    def try_acquire(self, host: str, max_per_day: int) -> bool:
        """Consume one request slot for today; ``False`` when the budget is spent."""
        today = _utc_now().strftime("%Y-%m-%d")
        date, count = self._load(host)
        if date != today:
            date, count = today, 0
        if count >= max_per_day:
            return False
        path = self.path_for(host)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"date": date, "count": count + 1}), encoding="utf-8")
        return True
