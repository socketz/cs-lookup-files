# Roadmap and Status

Status snapshot: **2026-11-27**. This page is the operational ledger for the
repository: what ships today, what is deliberately pending, and how the datasets
compose with adjacent lookup projects. It is a documentation artifact only; the
authoritative machine-readable state remains `config/sources.yaml`,
`config/settings.yaml` and the `metadata.json` of each release.

## 1. What is done (shipped)

### 1.1 Platform and pipeline

- **Config-driven ETL.** 23 origins / 41 feeds in `config/sources.yaml`; adding a
  feed is config-only. Each origin has one scoring identity and a `feeds` array.
- **Eight consolidated datasets**: `malicious_ips`, `malicious_networks`,
  `malicious_asns`, `malicious_domains`, `malicious_urls`, `malicious_md5`,
  `malicious_sha256`, `malicious_emails`, each with CSV and JSON mirrors, plus
  `metadata.json` and `state.json`.
- **Pipeline stages**: fetch → parse/clean/classify → union/dedupe → state merge
  → allowlist/bogon filtering → ASN enrichment (ip2asn v4/v6) → scoring → TTL and
  precision-floor pruning → deterministic CSV/JSON export.
- **ASN is authoritative only.** `malicious_asns` comes exclusively from Spamhaus
  ASN-DROP; ASN columns on IP/network rows are context.
- **Allowlist suppression.** `role: allowlist` feeds (alphaMountain top1M) are
  parsed into a suppression set, never scored or exported, and applied to the
  fresh frame and carried-over state. Matching is exact plus the `www.` variant.
- **State and history.** `first_seen`/`last_seen` and per-origin counts persist in
  `state.json`; recency and persistence drive scoring instead of rebuild noise.
- **Fetch resilience.** Pagination with `max_pages`/`max_seconds`, partial-page
  retention, exponential retries, per-host rate limiting, on-disk body cache and
  a persisted daily quota (AbuseIPDB 5/day). Missing keys and exhausted quotas are
  `skipped`, never `failed`.
- **Operational CLI**: `build`, `collect`, `validate`, `schema`; `--offline`,
  `--dry-run`, `--state`, `--cache-dir`, `--version`.
- **Packaging**: Dockerfile, `uv` lockfile, JSON Schemas for both config files.

### 1.2 Source coverage (shipped)

| IOC type | Origins |
|----------|---------|
| IP | `firehol`, `abusech`, `abuseipdb`, `dshield`, `alienvault_otx`, `cins`, `ipsum`, `c2intelfeeds`, `alienvault_reputation`, `bbcan177`, `botvrij`, `jamesbrine`, `linuxtracker`, `viriback`, `tweetfeed` |
| Network | `firehol`, `spamhaus`, `alienvault_otx` |
| ASN | `spamhaus` (ASN-DROP only) |
| Domain | `alienvault_otx`, `bbcan177`, `botvrij`, `joewein`, `minerchk`, `nocoin`, `disconnect`, `tweetfeed`, `alphamountain` |
| URL | `alienvault_otx`, `botvrij`, `openphish`, `phishtank`, `viriback`, `tweetfeed` |
| MD5 | `alienvault_otx`, `tweetfeed` |
| SHA256 | `alienvault_otx`, `botvrij`, `tweetfeed` |
| Email | `alienvault_otx` |

The exact feeds, weights and `ioc_weights` are in `docs/sources.md`; live
per-feed outcomes are in `metadata.json#source_feeds`.

### 1.3 Precision and reliability changes already applied

- **Authoritative ASNs only**: no IP→ASN rollup, no `malicious_ip_count` field.
- **Precision floors**: global `min_confidence: 75`; per-type
  `min_confidence_by_type.email: 55` so OTX-only emails remain useful. Single
  non-authoritative sources are capped at 70 and pruned.
- **Empty datasets are omitted** (not published as empty lookups) and listed in
  `metadata.empty_datasets` with a reason; stale files are removed.
- **Per-feed statuses** (`ok`/`empty`/`partial`/`skipped`/`failed`) with rows,
  types and reason; one failed feed never fails the origin.
- **OTX fixed**: JSON `results` parsing, multi-page JSON merge, case-insensitive
  canonical type map (`FileHash-MD5`, `URL`, `URI`, ...).
- **Hash/email coverage improved**: TweetFeed and Botvrij SHA256 corroborate OTX;
  `malicious_md5`/`sha256` are no longer invariably empty.
- **Allowlist**: alphaMountain top1M suppresses legitimate-but-compromised
  domains without down-weighting them and without hiding user-content subdomains.
- **Bogon safety net**: private/reserved IPs/networks are never published, even
  if a source omits cleaning.

### 1.4 Automation, tests and docs

- **GitHub Actions**: `Build Lookups` every 6 hours (`0 */6 * * *`) runs ruff,
  mypy, pytest, the build, a “datasets exist” gate, and uploads CSV/JSON;
  `Publish Release` creates a `YYYY.MM.DD.HHMM` release and updates `latest`.
- **Cache persistence**: `actions/cache` restores `cache/` (HTTP bodies, daily
  quota, ip2asn); the previous `state.json` is fetched from the latest release.
- **Tests**: 87 tests across unit and offline integration suites, including
  config-only source addition, allowlist suppression, ASN authority, state
  carry-over, empty-dataset omission, cache/quota, and workflow guardrails.
- **Docs**: README, architecture, scoring, sources, CrowdStrike examples,
  contribution/security guides and issue templates (updated alongside this
  roadmap).

## 2. What is pending

### P0 — correctness and operational hardening

| Item | Why | Acceptance |
|------|-----|------------|
| State compaction | Live builds produce a large `state.json` (observed ~165 MB), which is published and downloaded every run. | Compact state or split it; target a stable, documented size budget and measure build time. |
| Release integrity manifest | Consumers cannot verify artifact bytes from `metadata.json` today. | Add per-file `sha256`, `size_bytes`, `rows` and a `data_hash`; document verification. |
| Delta report | SOAR consumers must diff full releases to know what changed. | Emit `changes.json` (added/removed/score-changed per dataset) with bounded size. |
| Pre-release dataset validation | The workflow checks that datasets exist, not that they are sane. | Validate headers, uniqueness, sort order, bogon-free rows, ASN numeric JSON, row-count drift thresholds. |
| Feed drift/staleness alerts | A feed can silently change format or go stale without failing. | Track expected minimum rows/headers and warn in `metadata.json` or CI. |
| Metadata extensions | Consumers need floors/TTL/weights per dataset to interpret scores. | Publish `settings` snapshot (floors, TTL, weights) and build duration in `metadata.json`. |
| Email/hash/domain coverage | Email is OTX-only at floor 55; hashes rely on a small set; domains are partly single-source. | Add verified corroborating feeds; re-evaluate floors with measured precision. |
| Allowlist matching policy | Exact + `www.` avoids over-suppression but misses some compromised subdomains. | Decide whether to add opt-in parent-domain matching with a user-content exclusion list; document the trade-off. |

### P1 — source expansion

Candidate waves, all config-only once verified. Add a fixture and a test per
feed; record license, rate limits and expected update cadence.

- **IP/network**: Emerging Threats block IPs, Binary Defense, Data-Shield,
  OffSeq Mirage, NetAPI, additional high-churn FireHOL sets.
- **Domain/url**: Cert.PL, Phishing Army, spydisec, threatview, additional
  phishing/URL feeds from the catalogue.
- **Multi-type / hashes / email**: WSTNPHX emails, threatview MD5/SHA256,
  OffSeq Mirage URLs/hashes, additional OSINT hash lists.
- **Contextual (not malicious by default)**: Tor exit/all lists, open proxies,
  VPN/datacenter ranges. These should be categories/context, not automatic
  malicious indicators; see the integration section.
- **Authenticated (skipped until a key exists)**: GreyNoise, Shadowserver,
  Malshare, snort.org.

Verification checklist for every candidate: reachability and final URL, stable
headers/format, indicator types, expected row range, license/terms, rate limits,
secret requirements, fixture, weight/`ioc_weights`, and a live `source_feeds`
entry.

### P2 — integrations and consumption

- **LogScale package**: a documented set of lookups and saved queries that
  consumes the release plus (optionally) `logscale-lookup-files` context.
- **Fusion SOAR template**: version-gated fetch, integrity check, and LogScale
  lookup insert (read-only; no IOC Management).
- **Combined bundle**: a small distribution workflow/repo that validates and
  publishes both lookup families together.
- **Downstream hunting toolkit**: `falcon-hunting-toolkit` consumes the release
  manifest and both lookup families to generate hunts and enrichments.

### P3 — project hygiene

- Changelog/release notes generated from `metadata.json` diffs.
- SBOM and dependency-update automation.
- Runbooks for source outages, quota exhaustion, and emergency rollback.
- Optional release signing/provenance (SLSA or GitHub attestations).

## 3. Integration with a similar repository

The closest sibling is **`socketz/logscale-lookup-files`**. It also publishes
LogScale lookup files from public intel, but its data model is complementary:

| Project | Produces | Identity / contract |
|---------|----------|---------------------|
| `cs-lookup-files` | 8 malicious IOC datasets (ip, network, asn, domain, url, md5, sha256, email) with confidence, sources, categories, first/last seen | GitHub Releases `latest` + pinned `YYYY.MM.DD.HHMM`; `metadata.json` |
| `logscale-lookup-files` | malicious package names/records; `ip_classified_networks.csv` with `network,source,use` (`malicious`, `tor`, `vpn`, `datacenter`) | committed `data/` + `manifest.json` (`data_hash`, per-file `sha256`/`rows`/`size_bytes`) |

### 3.1 Why they compose

- `cs-lookup-files` answers **“is this indicator malicious, how confident, and
  why?”** It owns multi-type IOC scoring and authoritative ASN-DROP.
- `logscale-lookup-files` answers **“what is this network used for, and which
  list reported it?”** It owns usage classification (Tor/VPN/datacenter) and
  malicious-package coverage.
- Their IP sets overlap (FireHOL, Spamhaus, Feodo, IPsum). **Do not count the
  same provider twice as independent confirmation.** Pick one as the scoring
  authority (`cs-lookup-files`) and use the other as context/classification.
- `logscale-lookup-files` deliberately yields **0 rows for Spamhaus ASN-DROP**
  (it classifies networks, not ASNs). `cs-lookup-files` is the ASN authority.

### 3.2 Integration patterns

**A. Consumer-side composition in LogScale (no code changes).**
Upload both lookup families and join events twice: first against
`malicious_ips`/`malicious_networks`, then against `ip_classified_networks`
(`match(..., mode=cidr, include=["use","source"])`). Use `use` to triage
VPN/datacenter/Tor noise and to prioritize true malicious hits. See
`docs/integration.md` for an example query.

**B. Shared manifest/hash contract (small metadata change).**
Align `cs-lookup-files`' `metadata.json` with `logscale-lookup-files`'
`manifest.json`: `generated_at`, per-file `rows`/`sha256`/`size_bytes`,
`data_hash`. This lets one deployment workflow verify both releases and decide
whether to re-import. This is the highest-value, lowest-risk next integration
step.

**C. Combined distribution bundle (new workflow, no producer code change).**
A third workflow/repo downloads both `latest` releases, validates
`metadata.json` and `manifest.json`, checks hashes, and publishes a single
“Falcon lookup bundle” (or uploads directly to LogScale). This keeps both
producers independent and gives consumers one versioned artifact.

**D. Producer-side context import (future code change).**
`cs-lookup-files` could consume `ip_classified_networks.csv` as a **context**
feed to add `use`/provider categories to IP/network rows, or to annotate
datacenter/VPN hits. It must **not** be a generic allowlist: VPN/datacenter/Tor
are not benign. This requires core changes (new contextual columns) and should
follow pattern B/C.

**E. Downstream consumer.**
`falcon-hunting-toolkit` (adjacent planning repo) already treats
`cs-lookup-files` as an input. It should consume both families, gate on
`metadata.version`/`manifest.data_hash`, and generate hunts/enrichments without
ever enrolling IOCs or triggering response.

### 3.3 Field mapping

| `cs-lookup-files` | `logscale-lookup-files` | Semantics |
|-------------------|-------------------------|-----------|
| `malicious_ips.ip` | `ip_classified_networks.network` (CIDR match, `/32` for hosts) | Same address space; join with `mode=cidr`. |
| `malicious_networks.network` | `ip_classified_networks.network` | CIDR overlap/containment; avoid double-counting sources. |
| `malicious_asns.asn` | `spamhaus-asndrop` is present but yields 0 rows | Use `cs-lookup-files` as the ASN authority. |
| `sources` (origin ids) | `source` (feed slug) | Different granularity; map explicitly, never assume equal ids. |
| `categories` | `use` (`malicious`/`tor`/`vpn`/`datacenter`) | Context vs threat category; not interchangeable. |
| `confidence_score` | — | Preserve the `cs-lookup-files` score; classification does not alter it. |
| `first_seen`/`last_seen` | `manifest.generated_at` (build-level) | Indicator history vs dataset build time. |

### 3.4 Guardrails

- **Read-only.** Neither project imports IOCs into Falcon IOC Management,
  blocks, or triggers response. Composition must preserve that.
- **No double confidence.** Overlapping providers must not be treated as
  independent confirmations. Deduplicate before scoring or document the overlap.
- **Version pinning.** Use `latest` for freshness, but pin
  `YYYY.MM.DD.HHMM`/`data_hash` for investigations and audit.
- **Empty datasets.** A missing `cs-lookup-files` dataset means “no qualifying
  rows”, not “safe”; keep the previous lookup on 404 and inspect
  `metadata.empty_datasets`.
- **Classification is not reputation.** Tor/VPN/datacenter membership is context,
  not evidence of malice.
- **Rate limits and licenses.** Verify both upstream terms before combining or
  redistributing feeds.

### 3.5 Suggested sequence

1. **Document the contract** (this roadmap and `docs/integration.md`).
2. **Add hashes/sizes to `metadata.json`** and align field names with
   `manifest.json` (P0).
3. **Publish a combined bundle workflow** that validates both releases (pattern C).
4. **Add LogScale/Fusion examples** that use both lookups (pattern A).
5. **Evaluate contextual ingestion** of `ip_classified_networks.csv` (pattern D)
   only after measuring false-positive impact.

## 4. Out of scope

- Full TIP functionality, case management, malware-family attribution.
- Per-indicator live lookup endpoints or API enrichment per IOC.
- IOC Management import, blocking, containment, or automated response.
- Source-specific exports; the consolidated eight datasets are the contract.
- Merging scoring models across repositories without an explicit, documented
  decision.

## 5. Contributing to the roadmap

Open an issue with the template that matches the work (source request, feature,
bug). For a source, include the verification checklist above. For an integration,
state which contract fields or workflows change and whether it is consumer-side
(no producer change) or producer-side (code change). Keep the project’s bias:
small, high-quality, free-tier-sustainable datasets over feature count.
