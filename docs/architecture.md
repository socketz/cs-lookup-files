# Architecture

`cs-lookup-files` is an offline-first, config-driven ETL pipeline. It consumes
free public feeds, normalises and scores indicators, and publishes a small set
of lookup files. One failed source never fails a run.

## Pipeline

```
                    ┌─────────────────────────────────────────────────┐
   sources.yaml     │  Collect ── Parse ── Clean ── Classify           │
   (config)  ──────▶│  (per source, stateless; downloads run in        │
                    │   concurrent worker threads, rate-limited)       │
                    └───────────────┬─────────────────────────────────┘
                                    ▼
                    Union + dedupe  (unified frame: type + value,
                                     union source + category lists)
                                    ▼
                    State merge    (first_seen = min, last_seen = max,
                                     per-source counts; carry-over within TTL)
                                    ▼
                    Allowlist state filter  (drop allowlisted domains/urls
                                     carried over from previous runs)
                                    ▼
                    Bogon/private safety net + allowlist suppression
                                    ▼
                    ASN enrichment  (ip2asn v4/v6 range join; ip/network only)
                                    ▼
                    Scoring        (confidence 0..100 — see docs/scoring.md)
                                    ▼
                    Prune          (drop stale beyond TTL; apply global and
                                     per-type min_confidence floors)
                                    ▼
                    Export          (CSV + JSON per IOC type; datasets with 0
                                     rows are omitted; metadata.json + state.json)
                                    ▼
                    GitHub Release (versioned; auto-`latest`)
```

The order matters: state merge happens before suppression so indicators carried
from previous runs are filtered with the same allowlist, and scoring only sees
the surviving candidate set.

### Directory layout

```
config/
  settings.yaml         # scoring, ASN, output column order, max_workers
  sources.yaml          # per-feed ETL definition
  sources.schema.json   # JSON Schema of sources.yaml (regenerate: `schema`)
  settings.schema.json  # JSON Schema of settings.yaml
src/cs_lookup_files/
  collectors/fetch.py   # HTTP fetch, pagination, $VAR headers, rate limit
  collectors/cache.py   # on-disk HTTP body cache + persisted daily quota
  etl/engine.py         # config-driven per-source run (multi-type)
  normalizers/          # ipaddr helpers, indicators registry, parsers, ops
  enrichers/asn.py      # ip2asn range join (v4 asof, v6 binary search)
  scoring/score.py      # confidence model
  exporters/            # deterministic CSV/JSON + metadata
  models/               # Pydantic schemas
  state.py              # observation-history merge + persistence
  pipeline.py           # orchestration (concurrent collect)
  cli/main.py           # Typer CLI (build/collect/validate/schema)
tests/  fixtures/       # offline test feeds + ip2asn tables
docs/                   # this documentation
```

## Design decisions

### Config-driven sources
Every source is described entirely in `config/sources.yaml`: how to fetch it,
which parser to use, the field mapping, cleaning ops, categories, output types,
a global `weight` and an optional per-IOC-type `ioc_weights` override.
**Adding a source requires zero core-code changes** (proven by
`tests/integration/test_pipeline.py::test_config_only_new_source`). The planned
expansion from external feed catalogues is phased in `docs/roadmap.md`.

Each entry is an **origin** with a `feeds` array. The origin `id` is the scoring
identity: several feeds of the same origin count as one confirming source, and
the exported `sources`/`source_count` columns contain origin ids, not feed ids.
A feed may set `role: allowlist`; it is parsed into a suppression set instead of
the unified frame.

### Deterministic outputs
- IPs are stored as integers (`ip_int`) and keyed by a fixed-width hex key so
  sorting is numeric and stable across runs (`ip_key`).
- Networks are canonical CIDRs (`ip_network(...).__str__`), e.g.
  `1.2.3.4/24 → 1.2.3.0/24`.
- Domains/URLs/hashes/emails are canonicalised (lowercased, URL scheme+host
  normalised) and validated before ingestion.
- The inter-stage frame is a unified layout keyed by `(type, value)` plus a
  per-type `sort_key`, so dedupe/score/state are type-agnostic.
- CSV writes a fixed header with exact column order; JSON is an array of objects
  with the same keys/order. `sources`/`categories` are `;`-joined strings and
  timestamps are ISO-8601 UTC in both formats.
- Row order: IPv4 before IPv6 ascending; nets by (family, start, prefix); ASNs
  ascending; other sets ascending by value.

### Failure isolation
`run_source` wraps fetch/parse/clean per feed in try/except and records a
per-feed status: `ok`, `empty` (fetch/parse fine, 0 rows), `partial` (pagination
truncated), `skipped` (missing key or daily quota) or `failed`. A failing feed
never fails the origin unless *every* feed failed; per-feed detail (rows, types,
reason) is published in `metadata.source_feeds`. A mid-pagination failure keeps
already-fetched pages and marks the feed `partial`. The run aborts only when no
source is `ok` or `partial` (for example, every origin failed or was skipped),
refusing to publish a release with no usable source.

### Concurrency and rate limiting
Source downloads run in bounded worker threads (`max_workers` in
`settings.yaml`, default 6). Each source may set `requests_per_minute`; a
per-host token bucket spaces requests so parallel fetches do not violate a
feed's rate limits or get throttled/blocked.

### Free-tier sustainability
- Feeds are bulk downloads / paginated pulls — never per-indicator lookups.
- AbuseIPDB uses the blacklist export only, keyed to an `$ABUSEIPDB_API_KEY`
  header; no per-IP endpoints. The body is cached for 24h and a persisted
  daily quota (5/day) lives under `cache/`, restored in CI via `actions/cache`.
  An exhausted quota is `skipped`, never `failed`.
- OTX pulls the paginated, rate-limited indicator export (`page`/`limit`, 500
  records per page, bounded by `max_pages: 200` and `max_seconds: 240`), merges
  each JSON page's `results` array, and classifies rows by case-insensitive type
  routing into ip/network/domain/url/md5/sha256/email.
- alphaMountain's top1M and threat CSVs are cached for 24 hours; the top1M file
  is ~22 MB and does not change intraday.
- ip2asn tables are cached for 6 hours.

### Security
Secrets enter via the workflow `env:` block, the shell environment, or a local
`.env` loaded at startup (python-dotenv). They are referenced as `$VAR` in
config and resolved at fetch time. A source whose key is missing is **skipped**
(not failed), so a fresh clone runs without secrets. A global bogon filter
removes private/reserved ranges even when a source omits it. Feeds declared
with `role: allowlist` (e.g. alphaMountain top1M) are parsed but never scored;
their hostnames suppress matching domain/url indicators from the fresh frame
and from carried-over state, so legitimate-but-compromised sites are discarded
rather than down-weighted.

### Export floors and state

`config/settings.yaml` applies `min_confidence: 75` at export. A per-type
override (`min_confidence_by_type`) raises or lowers the floor for one dataset;
today `email: 55` keeps `malicious_emails` useful while OTX is its only source.
`ttl_days: 90` drops indicators whose last observation is older than 90 days.

State is persisted as `output/state.json` next to the datasets and published so
the next scheduled run can merge history. It carries `first_seen`, `last_seen`
and per-origin observation counts; with the current feed set it can be large
(tens to hundreds of MB). Treat it as an internal build artifact, not a hunting
lookup, and see `docs/roadmap.md` for planned compaction.

### Interoperability

The release contract is intentionally small: CSV/JSON datasets, `metadata.json`
and `state.json`. It is designed to be composed with adjacent lookup projects
(for example `logscale-lookup-files` for IP usage classification and package
coverage) rather than duplicating them. See [`integration.md`](integration.md)
for the mapping and guardrails.

### Number and nature of lookup files
One dataset per supported IOC type (ip, network, asn, domain, url, md5, sha256,
email) — 8 lookup datasets in total. `asn` is authoritative-only (Spamhaus
ASN-DROP); the ASN columns on ip/network rows are context, not a malicious-ASN
claim. No source-specific exports; everything is consolidated so Falcon
consumers have a predictable surface. Datasets with zero rows are omitted and
reported in `metadata.json` (`empty_datasets`), because an empty lookup can
overwrite a Falcon table with nothing. The JSON Schema in
`config/*.schema.json` documents the config surface and is regenerated by
`cs-lookup-files schema`.