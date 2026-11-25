# Roadmap

The MVP ships a sustainable, automated pipeline. This page tracks the direction
of the project while keeping the *small number of datasets* promise (one lookup
file per IOC type, no source-specific exports).

Source expansion is **config-only**: each new feed is just an entry in
`config/sources.yaml` with a `weight` (global reliability) and optional
`ioc_weights` (per-IOC-type reliability). No core-logic changes are required.
Rollout is phased to keep review simple and avoid rate-limit/format surprises.

## Shipped (MVP)

- [x] Config-driven source framework (`sources.yaml` parsing model) + JSON Schema.
- [x] Multi-IOC pipeline: ip/network/asn/domain/url/md5/sha256/email.
- [x] Sources: FireHOL level1 + per-category sets, Spamhaus DROP and ASN-DROP,
      Abuse.ch Feodo, AbuseIPDB blacklist, AlienVault OTX (multi-type), DShield
      intelfeed.
- [x] Confident scoring with global + per-IOC-type (`ioc_weights`) weights,
      banded caps and decay.
- [x] State persistence (`state.json`), CSV + JSON + `metadata.json` export.
- [x] Offline fixtures + integration tests (config-only new-source proof).
- [x] Concurrent, rate-limited downloads; `.env` secrets (skipped when absent).
- [x] GitHub Actions build + release (every 6h), Docker image.
- [x] Docs: architecture, scoring, sources, CrowdStrike integration.

### Precision changes (anti-false-positive)

- `malicious_asns` is now **only** the authoritative Spamhaus ASN-DROP list
  (JSONL). The previous ASN rollup (flagged IP -> whole ASN malicious) was
  removed because a single IP marked thousands of unrelated addresses.
  `asn`/`asn_name`/`country` on IP/network rows remain context only.
- Export uses `min_confidence: 75`; single non-authoritative sources (cap 70)
  and OTX-only rows (cap 55) are not published. `md5`/`sha256`/`email` therefore
  appear only when corroborated by a second source.
- Empty datasets are omitted (not written as empty lookups) and reported in
  `metadata.json` (`ioc_counts` = 0, `empty_datasets`).
- Per-feed statuses and reasons are recorded in `metadata.source_feeds`; an
  empty feed no longer marks a whole origin `partial`.

The focus remains **threat hunting**: read-only lookup context, never IOC
mutation. Precision decisions above reduce noise in hunting joins.

## Expansion plan (phased)

The catalogue of ~390 active feeds in
[threat-intelligence-feeds.csv](https://github.com/kraloveckey/threat-intelligence-feeds/raw/refs/heads/main/threat-intelligence-feeds.csv)
plus the curated lists at
[hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence/)
and [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists) is triaged
here in waves. Each wave is config-only, reviewed independently, and adds
coverage of a specific IOC type without touching the core.

### Wave 0 — already shipped

The aggregate / hardest-to-source IOC types are live:

- `ip` / `network`: FireHOL level1 + per-category IP sets, Spamhaus DROP,
  Feodo, DShield intelfeed, AbuseIPDB.
- `domain|url|md5|sha256|email`: AlienVault OTX (multi-type).

### Wave 1 — IP/network refinements (no auth, plain/CSV)

Shipped: CINS Army, IPsum, C2IntelFeeds (ip) plus the threatfeeds.io additions
AlienVault reputation, BBcan177, Botvrij (ips), James Brine brute-force hosts,
Hancitor IPs, and Viriback (ip). More candidates:

| Source | Type | Suggested `weight` | Notes |
|--------|------|--------------------|-------|
| Emerging Threats Block IPs | ip | 75 | Community firewall blocklist |
| Binarydefense banlist | ip | 72 | Threat list |
| OffSeq Mirage ipv4-7d | ip | 80 | Honeypot attackers |
| NetAPI compromised/ip/live | ip | 78 | Honeypot IPs, hourly |

### Wave 2 — domains & urls (no auth)

Shipped: OpenPhish, PhishTank, Botvrij (domains/hostnames/urls), joewein,
minerchk, NoCoin, disconnect, BBcan177 DNSBL, Viriback (url). Candidates:

| Source | Type | Suggested `weight` | Notes |
|--------|------|--------------------|-------|
| Phishing Army extended | url | 75 | Broad phishing URLs |
| C2IntelFeeds domainC2s-30day | domain | 80 | Verified C2 domains |
| Cert.PL malicious domains | domain | 78 | CERT-grade domains |
| spydisec malicious domains | domain | 72 | Domains blocklist |
| threatview URL/domain high-confidence | url,domain | 75 | OSINT-derived |

### Wave 3 — multi-IOC community + hashes

Feeds shipping several IOC types in one file; inspect format first.

| Source | Type | `weight` | `ioc_weights` | Notes |
|--------|------|----------|---------------|-------|
| tweetfeed today.csv | ip,domain,url,md5,sha256 | 72 | — | Community Twitter IOCs; type-routed |
| Botvrij.eu IOC lists | ip,domain,md5,sha256 | 74 | — | Per-type raw files |
| WSTNPHX malware-email-addresses | email | 70 | email:85 | Email IOCs |
| threatview MD5/SHA256 | md5,sha256 | 70 | — | Hash blocklists |
| OffSeq Mirage urls-7d / hashes-sha256-30d | url,sha256 | 78 | — | Honeypot-captured |

### Wave 4 — TOR / proxies / contextual (optional)

Optional sets that are operationally useful but may need label filtering.

- Tor exit/all nodes (dan.me.uk, SecOps-Institute, TorProject exit-addresses).
- Open proxies (opsxcq) — `ip`.
- VPN exit IP lists (`mthcht/awesome-lists` NordVPN/MullVad/ProtonVPN,
  X4BNet) — contextual; useful for VPN-abuse detections.
- Emerging Threats Tor rules — extract IPs from Snort-style rule text (needs a
  small parse; may require a `regex_extract` clean op).

### Wave 5 — authenticated / higher-effort

These require a key or more parsing and are gated behind `$VAR` secrets so they
are *skipped* until configured.

- GreyNoise, Shadowserver (authenticated bulk).
- Malshare current hashes (API key for larger pulls).
- snort.org ip-block-list (Cisco account).

## Impediments to review (per wave)

- **Format parsing**: some feeds expose IPs inside rule/HTML formats
  (Emerging Threats rules, ProjectHoneypot RSS, CleanTalk pages). Need a new
  parser or a `regex_extract` clean op; handled only when a feed is added.
- **Rate limits**: per-host `requests_per_minute` already applied; keep any
  new feed's setting conservative (e.g. `dan.me.uk` is rate-limited).
- **File size / memory**: large composite feeds (IPsum, OffSeq) are fine but
  watch total download size vs the 30-minute budget; `requests_per_minute` and
  `max_workers` keep the pipeline polite.
- **Multi-type split**: feeds like tweetfeed need `type_field`/`value_field`/
  `type_map` routing (already supported).
- **Authenticated-only feeds**: add the secret to `.env.example`; when absent,
  the source is skipped, so CI remains green without keys.

## Near-term (non-source)

- **Delta reports** — a small `changes.json` comparing current vs previous run
  (new/removed indicators) for SOAR alerting.
- **Lookup file linting** — CI job validating row counts, ASN coverage and
  bogon-free output before release.

## Medium-term

- **Category expansion** — richer `categories.field`/`mapping` tables for
  multi-type feeds (e.g. OTX pulse tags → canonical categories).
- **Optional per-dataset TTL/min-confidence** surface exposed via metadata so
  consumers can pick higher-precision subsets.
- **Feed drift alerting** — flag sources whose expected row-count range or
  update latency drifts, to catch stale/broken feeds early.

## Explicitly out of scope

Per the project charter, **no** plans for:

- Malware-family attribution.
- Case management or a full TIP.
- Per-indicator live lookups or paid data sources.

## Contributing

Source requests are welcome as issues. Follow `CONTRIBUTING.md`; every change
stays behind `config/sources.yaml` (plus a fixture for offline testing). When
adding a source, set `weight` and, where the feed's reliability differs by IOC
type, `ioc_weights`.