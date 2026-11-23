# Architecture

`cs-lookup-files` is an offline-first, config-driven ETL pipeline. It consumes
free public feeds, normalises and scores indicators, and publishes a small set
of lookup files. One failed source never fails a run.

## Pipeline

```
                   ┌─────────────────────────────────────────────────┐
   sources.yaml    │  Collect ── Parse ── Clean ── Classify           │
   (config)  ─────▶│            (per source, stateless)              │
                   └───────────────┬─────────────────────────────────┘
                                   ▼
                   Union + dedupe  (merge identical IPs/networks,
                                    union source + category lists)
                                   ▼
                   Bogon/private safety net (idempotent)
                                   ▼
                   State merge    (first_seen = min, last_seen = max,
                                   per-source counts; carry-over within TTL)
                                   ▼
                   ASN enrichment  (ip2asn v4/v6 range join)
                                   ▼
                   Scoring        (confidence 0..100 — see docs/scoring.md)
                                   ▼
                   Prune          (drop stale beyond TTL, apply min_confidence)
                                   ▼
                   ASN rollup + Export (CSV + JSON + metadata.json + state.json)
                                   ▼
                   GitHub Release (versioned; auto-`latest`)
```

### Directory layout

```
config/
  settings.yaml          # scoring, ASN, output column order
  sources.yaml           # per-feed ETL definition
src/cs_lookup_files/
  collectors/fetch.py    # HTTP fetch, pagination, $VAR secret headers
  etl/engine.py          # config-driven per-source run
  normalizers/           # ipaddr helpers, generic parsers, row ops
  enrichers/asn.py       # ip2asn range join (v4 asof, v6 binary search)
  scoring/score.py       # confidence model
  exporters/             # deterministic CSV/JSON + metadata
  models/                # Pydantic schemas
  state.py               # observation-history merge + persistence
  pipeline.py            # orchestration
  cli/main.py            # Typer CLI (build/collect/validate)
tests/  fixtures/        # offline test feeds + ip2asn tables
docs/                    # this documentation
```

## Design decisions

### Config-driven sources
Every source is described entirely in `config/sources.yaml`: how to fetch it,
which parser to use, the field mapping, cleaning ops, weights, categories and
output types. **Adding a source requires zero core-code changes** (proven by
`tests/integration/test_pipeline.py::test_config_only_new_source`).

### Deterministic outputs
- IPs are stored as integers (`ip_int`) and keyed by a fixed-width hex key so
  sorting is numeric and stable across runs (`ip_key`).
- Networks are canonical CIDRs (`ip_network(...).__str__`), e.g.
  `1.2.3.4/24 → 1.2.3.0/24`.
- CSV writes a fixed header with exact column order; JSON mirrors it.
- Row order: IPv4 before IPv6, ascending; nets by (family, start, prefix);
  ASNs ascending.

### Failure isolation
`run_source` wraps fetch/parse/clean in try/except. A failing source yields an
empty dataset plus a `failed` status in `metadata.json`. The pipeline only
aborts when *all* sources fail (refusing to publish an empty release).

### Free-tier sustainability
- Feeds are bulk downloads / paginated pulls — never per-indicator lookups.
- AbuseIPDB uses the blacklist export only, keyed to a `:$ABUSEIPDB_API_KEY`
  header; no per-IP endpoints. The design tolerates dropped quotas.
- OTX pulls the paginated indicator export; the domain ellipsis of tag maps.
- ip2asn tables are cached for 6 hours.

### Security
Secrets enter via the workflow `env:` block and are referenced as `$VAR` in
config; they are resolved at fetch time from the process environment. A global
bogon filter removes private/reserved ranges even when a source omits it.

### Number and nature of lookup files
Deliberately only three datasets are produced. No source-specific exports.
Everything is consolidated so Falcon consumers have a tiny, predictable surface.