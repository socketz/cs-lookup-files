from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..normalizers.indicators import INDICATOR_TYPES

CATEGORY_VOCAB = ("blocklist", "malware_c2", "malware", "abuse", "scanner", "botnet", "phishing", "spam", "other")

KNOWN_TRAFFIC_LIGHT_LABELS = frozenset(CATEGORY_VOCAB)

_OUTPUT_TYPE_NAMES: tuple[str, ...] = ("ip", "network")


class CategoriesConfig(BaseModel):
    """How raw category labels map into the canonical vocabulary for a source.

    ``default`` applies to every row when no per-row label is available. When
    ``field`` is set, the engine reads that raw column and maps each value via
    ``mapping``; values missing from the mapping fall back to ``default``.
    """

    model_config = ConfigDict(extra="forbid")

    default: list[str] = Field(default_factory=lambda: ["other"])
    field: str | None = None
    mapping: dict[str, list[str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_vocab(self) -> CategoriesConfig:
        bad: set[str] = set()
        for cat in self.default:
            if cat not in CATEGORY_VOCAB:
                bad.add(cat)
        for cats in self.mapping.values():
            for cat in cats:
                if cat not in CATEGORY_VOCAB:
                    bad.add(cat)
        if bad:
            raise ValueError(f"categories must use the canonical vocabulary {CATEGORY_VOCAB}; got {sorted(bad)}")
        return self


class PaginationConfig(BaseModel):
    """Loop-based pagination for text/JSON feeds.

    ``param`` is the query parameter incremented per page (default ``page``).
    ``size_param``/``size`` set the per-page size. Fetching stops when a page
    returns nothing, ``max_pages`` is reached, or the wall-clock budget
    ``max_seconds`` is exhausted (so one slow feed cannot break the pipeline
    SLA). Whatever was fetched before the budget is kept.
    """

    model_config = ConfigDict(extra="forbid")

    param: str = "page"
    size_param: str = "limit"
    size: int = 1000
    max_pages: int = 100
    stop_when_empty: bool = True
    total_pages_field: str | None = None
    # Optional wall-clock cap for the whole pagination loop (seconds).
    max_seconds: float | None = None


class FetchConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(pattern=r"^https?://")
    params: dict[str, str | int] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    pagination: PaginationConfig | None = None
    timeout_seconds: float = 60.0
    retries: int = 3
    # Optional polite rate limiting: max requests per minute to this host.
    requests_per_minute: int | None = None


class ParseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: Literal["plain_lines", "ipset", "cidr_lines", "csv", "tsv", "json"]
    comment_prefix: str | None = None
    has_header: bool = False
    delimiter: str | None = None
    records: str | None = None
    skip_lines: int = 0

    @model_validator(mode="after")
    def _check_consistency(self) -> ParseConfig:
        if self.format in ("csv", "tsv") and self.delimiter is None:
            raise ValueError(f"parse.format {self.format!r} requires an explicit delimiter")
        if self.format == "json" and not self.records:
            raise ValueError("parse.format 'json' requires a records path")
        return self


class CleanOp(BaseModel):
    """One row-level operation, e.g. ``{op: field_in, field: type, values: [IPv4]}``.

    Parameters are intentionally generic; each op in ``normalizers.ops`` reads
    the keys it needs and configuration validation rejects unknown op names.
    """

    model_config = ConfigDict(extra="forbid")

    op: str
    # Generic parameters shared by several ops.
    field: str | None = None
    values: list[str] | None = None
    value: str | int | float | None = None
    pattern: str | None = None
    output: str | None = None
    mapping: dict[str, str] | None = None
    prefix: str | None = None
    limit: int | None = None


class FeedConfig(BaseModel):
    """One file/URL within a source: how to fetch, parse and clean it.

    A *source* (e.g. ``firehol``) groups several feeds (URLs); each feed declares
    the IOC types it yields and its own parser/field mapping/clean ops.
    """

    model_config = ConfigDict(extra="forbid")

    # Optional stable id used for offline fixtures and logging; defaults to the
    # URL basename when omitted.
    id: str | None = Field(default=None, pattern=r"^[a-z0-9_]+$", max_length=64)
    fetch: FetchConfig
    parse: ParseConfig
    output_types: list[Literal["ip", "network", "domain", "url", "md5", "sha256", "email"]]
    # Field mapping from a normalized field name to a raw row key/column.
    fields: dict[str, str] = Field(default_factory=dict)
    # Type routing: for feeds that classify each row by a "type"/"value" pair
    # (e.g. OTX export), map raw type labels to indicator types.
    type_field: str | None = None
    value_field: str | None = None
    type_map: dict[str, str] = Field(default_factory=dict)
    # Optional per-feed category override; inherits the source default when None.
    categories: CategoriesConfig | None = None
    clean: list[CleanOp] = Field(default_factory=list)

    def fixture_key(self) -> str:
        """Stable key for offline fixtures: the feed id or the URL basename."""
        if self.id:
            return self.id
        from urllib.parse import urlparse

        base = urlparse(self.fetch.url).path.rsplit("/", 1)[-1]
        return base or "feed"

    @model_validator(mode="after")
    def _check_feed(self) -> FeedConfig:
        types = set(self.output_types)
        if not types:
            raise ValueError("feed output_types must not be empty")
        unknown = types - set(INDICATOR_TYPES)
        if unknown:
            raise ValueError(f"feed {self.fixture_key()!r}: unknown output_types {sorted(unknown)}")
        for kind in types:
            if kind not in self.fields:
                raise ValueError(
                    f"feed {self.fixture_key()!r}: output_types includes {kind!r} "
                    f"but fields has no {kind!r}"
                )
        for norm_field, raw_ref in self.fields.items():
            if not raw_ref:
                raise ValueError(f"feed {self.fixture_key()!r}: field {norm_field!r} has an empty raw reference")
        if self.type_field or self.value_field:
            if not (self.type_field and self.value_field):
                raise ValueError(f"feed {self.fixture_key()!r}: type_field and value_field must be set together")
            for _raw, tkind in self.type_map.items():
                if tkind not in INDICATOR_TYPES:
                    raise ValueError(f"feed {self.fixture_key()!r}: type_map value {tkind!r} is not a known type")
        return self


class SourceConfig(BaseModel):
    """An intelligence source/origin (e.g. ``firehol``) and its feed URLs.

    The scoring identity is the **source** (origin), so indicators coming from
    several feeds of the same origin count as one confirming source.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9_]+$", min_length=1, max_length=64)
    enabled: bool = True
    # Global source-reliability weight (0..100) used for all output types unless
    # overridden per type via ``ioc_weights``.
    weight: int = Field(ge=0, le=100)
    # Optional per-IOC-type weight (0..100), keyed by indicator type (ip, domain,
    # url, md5, sha256, email, network). Reflects the source's reliability for
    # *that* indicator type. Falls back to ``weight`` for any type not listed.
    ioc_weights: dict[str, int] = Field(default_factory=dict)
    # Default categories for feeds that do not override them.
    categories: CategoriesConfig = Field(default_factory=CategoriesConfig)
    feeds: list[FeedConfig]

    @model_validator(mode="after")
    def _check_source(self) -> SourceConfig:
        if not self.feeds:
            raise ValueError(f"source {self.id!r}: must declare at least one feed")
        for ioc_type_override, ioc_weight in self.ioc_weights.items():
            if ioc_type_override not in INDICATOR_TYPES:
                raise ValueError(f"source {self.id!r}: ioc_weights key {ioc_type_override!r} is not a known type")
            if not 0 <= ioc_weight <= 100:
                raise ValueError(f"source {self.id!r}: ioc_weights[{ioc_type_override}] must be 0..100")
        seen: set[str] = set()
        for feed in self.feeds:
            if feed.id:
                if feed.id in seen:
                    raise ValueError(f"source {self.id!r}: duplicate feed id {feed.id!r}")
                seen.add(feed.id)
        return self


class SourcesFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources: list[SourceConfig]

    @model_validator(mode="after")
    def _check_unique_ids(self) -> SourcesFile:
        ids = [s.id for s in self.sources]
        seen: set[str] = set()
        for sid in ids:
            if sid in seen:
                raise ValueError(f"duplicate source id {sid!r}")
            seen.add(sid)
        return self


class ScoringSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    half_life_days: float = 30.0
    ttl_days: int = 90
    persistence_bonus_max: float = 5.0
    persistence_half_life_days: float = 60.0
    default_single_source_score: int = 70
    max_single_source_score: dict[str, int] = Field(default_factory=dict)
    source_count_caps: dict[int, int] = Field(default_factory=lambda: {1: 70, 2: 90, 3: 100})
    min_confidence: int = 0


class AsnSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ipv4_url: str = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
    ipv6_url: str = "https://iptoasn.com/data/ip2asn-v6.tsv.gz"
    cache_ttl_hours: int = 6


class OutputSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dir: str = "output"
    ip_columns: list[str] = Field(
        default_factory=lambda: [
            "ip", "asn", "asn_name", "country", "confidence_score", "source_count", "sources", "categories",
            "first_seen", "last_seen",
        ]
    )
    network_columns: list[str] = Field(
        default_factory=lambda: [
            "network", "asn", "asn_name", "confidence_score", "source_count", "sources", "categories",
        ]
    )
    asn_columns: list[str] = Field(
        default_factory=lambda: [
            "asn", "asn_name", "country", "confidence_score", "malicious_ip_count", "source_count", "sources",
        ]
    )
    domain_columns: list[str] = Field(
        default_factory=lambda: [
            "domain", "confidence_score", "source_count", "sources", "categories", "first_seen", "last_seen",
        ]
    )
    md5_columns: list[str] = Field(
        default_factory=lambda: [
            "md5", "confidence_score", "source_count", "sources", "categories", "first_seen", "last_seen",
        ]
    )
    sha256_columns: list[str] = Field(
        default_factory=lambda: [
            "sha256", "confidence_score", "source_count", "sources", "categories", "first_seen", "last_seen",
        ]
    )
    url_columns: list[str] = Field(
        default_factory=lambda: [
            "url", "confidence_score", "source_count", "sources", "categories", "first_seen", "last_seen",
        ]
    )
    email_columns: list[str] = Field(
        default_factory=lambda: [
            "email", "confidence_score", "source_count", "sources", "categories", "first_seen", "last_seen",
        ]
    )


class Settings(BaseModel):
    """Runtime thresholds; loaded from ``config/settings.yaml``."""

    model_config = ConfigDict(extra="forbid")

    scoring: ScoringSettings = Field(default_factory=ScoringSettings)
    asn: AsnSettings = Field(default_factory=AsnSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    # Source downloads run concurrently but bounded, keeping fetches polite.
    max_workers: int = 6


def load_yaml_model(model_type: type[BaseModel], data: Mapping[str, Any] | str) -> BaseModel:
    """Load a mapping (already parsed YAML) or YAML text into ``model_type``.

    Passed a mapping, ``data`` is validated directly. Passed a string it is
    interpolated through ``yaml.safe_load`` first so YAML booleans such as
    ``on`` do not silently become strings.
    """
    from yaml import safe_load

    payload: Any = safe_load(data) if isinstance(data, str) else data
    return model_type.model_validate(payload)
