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
                    Bogon/private safety net + allowlist suppression
                                    ▼
                    State merge    (first_seen = min, last_seen = max,
                                     per-source counts; carry-over within TTL)
                                    ▼
                    ASN enrichment  (ip2asn v4/v6 range join; ip/network only)
                                    ▼
                    Scoring        (confidence 0..100 — see docs/scoring.md)
                                    ▼
                    Prune          (drop stale beyond TTL, apply min_confidence)
                                    ▼
                    Export          (CSV + JSON per IOC type; datasets with 0
                                     rows are omitted; metadata.json + state.json)
                                    ▼
                    GitHub Release (versioned; auto-`latest`)
```

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

### Deterministic outputs
- IPs are stored as integers (`ip_int`) and keyed by a fixed-width hex key so
  sorting is numeric and stable across runs (`ip_key`).
- Networks are canonical CIDRs (`ip_network(...).__str__`), e.g.
  `1.2.3.4/24 → 1.2.3.0/24`.
- Domains/URLs/hashes/emails are canonicalised (lowercased, URL scheme+host
  normalised) and validated before ingestion.
- The inter-stage frame is a unified layout keyed by `(type, value)` plus a
  per-type `sort_key`, so dedupe/score/state are type-agnostic.
- CSV writes a fixed header with exact column order; JSON mirrors it.
- Row order: IPv4 before IPv6 ascending; nets by (family, start, prefix); ASNs
  ascending; other sets ascending by value.

### Failure isolation
`run_source` wraps fetch/parse/clean per feed in try/except and records a
per-feed status: `ok`, `empty` (fetch/parse fine, 0 rows), `partial` (pagination
truncated), `skipped` (missing key or daily quota) or `failed`. A failing feed
never fails the origin unless *every* feed failed; per-feed detail (rows, types,
reason) is published in `metadata.source_feeds`. A mid-pagination failure keeps
already-fetched pages and marks the feed `partial`. The pipeline only aborts
when no source succeeded (refusing to publish an empty release).

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
- OTX pulls the paginated, rate-limited indicator export and classifies rows by
  case-insensitive type routing into ip/network/domain/url/md5/sha256/email.
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