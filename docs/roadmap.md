# Roadmap

The MVP ships a sustainable, automated pipeline. This page tracks the
direction of the project while keeping the *small number of datasets* promise.
Source ideas are evaluated against operational usefulness and free-tier
sustainability, not raw feed count.

## Shipped (MVP)

- [x] Config-driven source framework (`sources.yaml` parsing model).
- [x] Five MVP sources: FireHOL, Spamhaus DROP, Abuse.ch Feodo, AbuseIPDB
      blacklist, AlienVault OTX.
- [x] Normalisation, deduplication, bogon filtering, ASN enrichment.
- [x] Deterministic confidence scoring with banded caps and decay.
- [x] State persistence (`state.json`) for cross-run first/last seen.
- [x] CSV + JSON exports + `metadata.json`.
- [x] Offline fixtures and integration tests (config-only new-source proof).
- [x] GitHub Actions build + release (every 6h).
- [x] Docker image.
- [x] Documentation: architecture, scoring, sources, CrowdStrike integration.

## Near-term

- **Source plugins** — Blocklist.de, DShield, CINS Army (all config-only).
- **Delta reports** — a small `changes.json` comparing current vs previous run
  (new/removed indicators) for SOAR alerting on newly-seen infrastructure.
- **Lookup file linting** — a CI job that validates row counts, ASN coverage and
  bogon-free output before release.

## Medium-term

- **IPv6 enrichment** integration with ip2asn v6 (already parsed) into reported
  ASN columns.
- **Category expansion** — more granular mapping tables (e.g. OTX pulse tags →
  canonical categories) via `map_values`, still vocab-bounded.
- **Optional TTL/min-confidence config surface** exposed through released
  metadata so consumers can pick higher-precision subsets.

## Explicitly out of scope

Per the project charter, **no** plans for:

- Domain / URL / file-hash intelligence.
- Malware-family attribution.
- Case management or a full TIP.
- Per-indicator live lookups or paid data sources.

## Contributing

Source requests are welcome as issues. Follow `CONTRIBUTING.md`; changes stay
behind `config/sources.yaml` unless they belong in the small core.