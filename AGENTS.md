# Project Specification: cs-lookup-files

Repository:
https://github.com/socketz/cs-lookup-files

Act as a Principal Software Architect, Threat Intelligence Engineer, Security Researcher, and CrowdStrike Falcon expert.

Design and implement an open-source project named **cs-lookup-files**.

The objective is to aggregate multiple threat intelligence feeds, normalize indicators, enrich them, calculate a reputation/confidence score, and publish a small set of lookup files optimized for CrowdStrike Falcon.

The generated datasets will be imported automatically into CrowdStrike using Fusion SOAR workflows.

All code, documentation, comments, commit messages, issues, pull requests, GitHub Actions workflows, and discussions must be written in English.

The solution must prioritize operational usefulness, simplicity, maintainability, reliability, and long-term sustainability over feature count.

---

# Mission

Create a lightweight threat intelligence aggregation platform that consumes free and publicly available feeds, generates consolidated lookup files, and publishes them as GitHub Release artifacts for automated ingestion into CrowdStrike Falcon.

The project is not intended to become a full TIP (Threat Intelligence Platform).

The primary goal is to provide operationally valuable lookup files for:

- Falcon LogScale hunting
- Lookup matching
- Correlation Rules
- Fusion SOAR workflows
- Detection enrichment
- Incident investigations
- Threat hunting

---

# Related Projects

- **`socketz/logscale-lookup-files`** publishes LogScale lookups for malicious
  packages and IP usage classification (`malicious`/`tor`/`vpn`/`datacenter`).
  It is complementary, not a duplicate: `cs-lookup-files` owns multi-type IOC
  scoring and authoritative ASN-DROP, while `logscale-lookup-files` owns package
  coverage and network classification. Overlapping blocklists must not be counted
  as independent confirmations. See `docs/integration.md`.
- **`falcon-hunting-toolkit`** is a downstream consumer that can gate imports on
  `metadata.json` and generate hunts/enrichments from both lookup families. It
  must preserve the read-only contract (no IOC Management, blocking or response).

---

# Design Principles

## Keep It Simple

The platform should generate only a small number of high-quality lookup files.

Do not create source-specific outputs.

Do not create dozens of lookup datasets.

All indicators must be:

- Collected
- Normalized
- Deduplicated
- Enriched
- Scored
- Exported

into consolidated datasets.

---

## Free Tier Sustainability

The platform must be designed to operate indefinitely using free source tiers.

Priority order for data acquisition:

1. Public downloadable files
2. Public JSON feeds
3. TAXII feeds
4. Authenticated APIs
5. Per-indicator lookups only when absolutely required

Avoid architectures that perform enrichment by making API requests for every indicator.

---

## CrowdStrike-First Approach

The project should optimize outputs for:

- Falcon LogScale
- Fusion SOAR
- Lookup matching
- Scheduled imports
- Large-scale hunting

The generated datasets should be directly consumable by CrowdStrike without requiring additional processing.

**Outputs are read-only hunting context.** The datasets enrich events and
support investigations; they do not mutate IOCs, are not imported into IOC
Management, and never trigger blocking or automated response. The pipeline only
publishes release artifacts; it never calls Falcon IOC APIs.

---

# Intelligence Sources

## MVP / Active Sources

Sources are enabled from `config/sources.yaml` only when they are frequently
updated (feeds that go months without updates are excluded). The feeds live as
*consolidated* datasets; no source-specific outputs.

### Source = origin, with an array of feeds

Each `sources.yaml` entry is an **origin** (e.g. `firehol`) whose `id` is the
scoring identity, holding a `feeds` array. Each feed is one file/URL with its
own `fetch`, `parse`, `fields`, `output_types` and `clean`. Indicators confirmed
by several feeds of the same origin count as **one** confirming source. The
origin carries the global `weight` and optional per-IOC-type `ioc_weights`.
Adding a feed is config-only.

Core builders:

### FireHOL

Primary aggregation source.

Used as one of the strongest reputation references.

### Spamhaus DROP

Use DROP exclusively.

Do not implement EDROP separately because it has been merged into DROP.

### Abuse.ch Feodo Tracker

Used for botnet infrastructure and malware C2 visibility.

### AlienVault OTX

Used as an additional confidence source. Multi-type (IP/domain/url/md5/sha256/email).

### AbuseIPDB

Use only blacklist/blocklist exports.

Do not perform individual IP reputation checks.

Do not call the AbuseIPDB CHECK endpoint for every IOC.

Do not depend on AbuseIPDB per-IP enrichment.

The solution must remain sustainable even if AbuseIPDB API quotas are reduced.

The repository owner currently has AbuseIPDB Webmaster status, but the architecture must not depend on elevated API consumption.

**Free-tier safeguard:** the AbuseIPDB feed declares `cache_ttl_hours: 24` and
`max_requests_per_day: 5` (free tier = 5 blacklist requests/day) with
`retries: 0`. The body cache and the persisted daily counter live under
`cache/`, which the CI persists via `actions/cache`. An exhausted quota is
reported as `skipped` (reason `rate limit`), never `failed`.

### DShield (dshield_intelfeed)

`isc.sans.edu/api/intelfeed` — daily IP summary with feed labels; benign
infrastructure labels are filtered out.

### FireHOL per-category sets

Frequently-updated FireHOL `.netset`/`.ipset` sets (feodo_badips, c2_tracker,
cybercrime, et_compromised, blocklist_de, ciarmy, dshield, greensnow,
bruteforceblocker, stopforumspam, cybercure) — high-churn IP feeds selected for
operational value.

### alphaMountain (alphamountain)

Two CSVs from [alphaMountain](https://www.alphamountain.ai/):

- `alphaMountain-community-threat-1000.csv` — community threat domains
  (`hostname`), scored as a normal `domain` source (weight 80).
- `alphaMountain-top1M.csv` — top one million legitimate hostnames
  (`hostname`). Declared with `role: allowlist`: its domains are collected but
  **never scored or exported**; they suppress matching `domain`/`url` indicators
  from every dataset so legitimate-but-compromised sites are discarded rather
  than down-weighted. The allowlist is applied to the fresh frame and to
  carried-over state, so suppressed domains cannot reappear from `state.json`.

Both feeds are cached for 24 hours (`cache_ttl_hours: 24`) because the top1M
file is ~22 MB and does not change intraday.

---

## Future Sources / Feed Catalogue

The intended expansion is driven by the public feed catalogue in
[threat-intelligence-feeds.csv](https://github.com/kraloveckey/threat-intelligence-feeds/raw/refs/heads/main/threat-intelligence-feeds.csv)
(~390 active feeds) plus the curated awesome lists:

- [hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence/)
- [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists)

New sources are added as **config-only** entries with zero core-logic changes;
the roadmap in `docs/roadmap.md` phases their rollout by IOC type and
auth/format requirements.

When adding an origin, set two tunables at origin level:

- `weight` — global source-reliability weight (0..100).
- `ioc_weights` — optional per-IOC-type weight (0..100) keyed by indicator type
  (ip/network/domain/url/md5/sha256/email), reflecting the origin's reliability
  for that *specific* IOC type. Falls back to `weight`.

No modifications to core logic should be required when adding new sources.

---

# Generated Lookup Files

One consolidated dataset per supported IOC type, plus the authoritative ASN
dataset. No source-specific exports; everything converges into these files so
Falcon consumers have a small, predictable surface.

## malicious_ips

Purpose:

Match against network connections, DNS resolutions, proxy logs, firewall events, EDR telemetry, and Falcon events.

Fields:

- ip
- asn
- asn_name
- country
- confidence_score
- source_count
- sources
- categories
- first_seen
- last_seen

Example:

```csv
ip,asn,asn_name,country,confidence_score,source_count,sources
1.2.3.4,13335,CLOUDFLARENET,US,98,4,"spamhaus;firehol;abusech;otx"
```

---

## malicious_networks

Purpose:

Support subnet reputation and network-level investigations.

Fields:

- network
- asn
- asn_name
- confidence_score
- source_count
- sources
- categories

Example:

```csv
network,asn,asn_name,confidence_score
1.2.3.0/24,13335,CLOUDFLARENET,94
```

---

## malicious_asns

Purpose:

Support provider-level threat intelligence and infrastructure reputation analysis.

Fields:

- asn
- asn_name
- country
- confidence_score
- source_count
- sources
- categories
- first_seen
- last_seen

Example:

```csv
asn,asn_name,country,confidence_score
13335,CLOUDFLARENET,US,75
```

**ASN is authoritative only.** `malicious_asns` is a first-class `asn` indicator
type fed exclusively by authoritative ASN-level lists (Spamhaus ASN-DROP,
JSONL). It is never derived by rolling up flagged IPs/networks: a single bad IP
must not mark an entire ASN as malicious. The `asn`/`asn_name`/`country`
columns on `malicious_ips` and `malicious_networks` are **context only** and do
not imply the ASN is malicious. `malicious_ip_count` is not part of the dataset.

---

## malicious_domains

Hostname / domain reputation. Fields: `domain`, `confidence_score`,
`source_count`, `sources`, `categories`, `first_seen`, `last_seen`.

## malicious_urls

URL / URI reputation. Same fields as domains, with `url` as identity.

## malicious_md5 / malicious_sha256

File-hash reputation (MD5 and SHA256). Same fields, identity `md5`/`sha256`.

## malicious_emails

Sender / phishing email reputation. Identity `email`.

---

# Release Structure

GitHub Releases are the distribution mechanism.

Fusion SOAR and other automation platforms will consume artifacts from releases.

Structure:

```text
latest/
├── malicious_ips.csv
├── malicious_ips.json
│
├── malicious_networks.csv
├── malicious_networks.json
│
├── malicious_asns.csv
├── malicious_asns.json
│
├── malicious_domains.csv
├── malicious_domains.json
│
├── malicious_urls.csv
├── malicious_urls.json
│
├── malicious_md5.csv
├── malicious_md5.json
│
├── malicious_sha256.csv
├── malicious_sha256.json
│
├── malicious_emails.csv
├── malicious_emails.json
│
├── metadata.json
└── state.json
```

---

# Versioning Strategy

Maintain versioned snapshots. Distribution uses GitHub Releases tagged
`YYYY.MM.DD.HHMM`; `latest` is the GitHub "latest" release. The tree below is the
conceptual layout.

Example:

```text
releases/
├── 2026.11.23.0000/
├── 2026.11.23.0600/
├── 2026.11.23.1200/
├── 2026.11.23.1800/
└── latest/
```

Consumers should normally download from:

```text
latest/
```

Historical releases must be preserved for:

- Rollback
- Auditing
- Change analysis
- Troubleshooting
- Feed quality validation

---

# Metadata File

Generate metadata.json during each run.

Example:

```json
{
  "version": "2026.11.23.1200",
  "generated_at": "2026-11-23T12:00:00Z",
  "sources": [
    "firehol",
    "spamhaus",
    "abusech",
    "alienvault_otx",
    "abuseipdb",
    "dshield"
  ],
  "source_status": {
    "firehol": "ok",
    "spamhaus": "ok",
    "alienvault_otx": "skipped"
  },
  "source_feeds": {
    "firehol": [
      {"feed": "firehol_level1", "status": "ok", "rows": 1234, "types": {"ip": 1200, "network": 34}, "reason": null}
    ]
  },
  "ioc_counts": {
    "malicious_ips": 125000,
    "malicious_networks": 8200,
    "malicious_asns": 315,
    "malicious_domains": 4000,
    "malicious_urls": 9000,
    "malicious_md5": 300,
    "malicious_sha256": 500,
    "malicious_emails": 120
  },
  "empty_datasets": []
}
```

---

# Confidence Scoring Model

Implement a reputation score from 0 to 100.

Inputs:

- Source reputation
- Source overlap
- Observation recency
- Historical persistence
- Category weighting

Suggested baseline weights:

| Source | Weight |
|----------|----------|
| Spamhaus DROP | 100 |
| Abuse.ch Feodo | 90 |
| FireHOL | 85 |
| AbuseIPDB | 80 |
| AlienVault OTX | 70 |

The full shipped table (23 origins, per-origin `ioc_weights` and single-source
caps) is maintained in `docs/scoring.md` and `config/settings.yaml`.

Every source also accepts an optional `ioc_weights` map so its reliability can
be tuned **per IOC type** (ip/network/domain/url/md5/sha256/email). For a given
row, the effective weight used in scoring is
`ioc_weights[source].get(type, weight)`; the global `weight` remains the
fallback. This lets a C2 tracker weight `ip` above `domain`, or a phishing feed
weight `url`/`domain` above `ip`, without changing core logic.

Scoring Requirements:

- Multiple source confirmations must significantly increase confidence.
- Recent observations should score higher.
- Confidence must decay over time.
- One low-confidence source must never generate a very high score.
- The formula must be fully documented.

Examples (band maxima; actual score depends on weights and recency):

- Single source → capped by `max_single_source_score` (default 70; `spamhaus` 90;
  OTX 55; other explicit caps 45–55)
- Two sources → at most 90
- Three or more sources → at most 100

**Export precision floor:** `min_confidence: 75` is applied at export, so single
non-authoritative sources (default cap 70) and OTX-only
ip/network/domain/url/md5/sha256 rows (cap 55) are not published; `spamhaus`
carries a single-source cap of 90 so DROP/ASN-DROP rows survive. `email` uses
`min_confidence_by_type.email: 55` because OTX is its only source today, so
single-source emails remain publishable. Corroborated rows use the 2/3+ bands.
Datasets that end up empty are omitted and reported in `metadata.json` rather
than published as empty lookups.

**Allowlist feeds** (`role: allowlist`, e.g. alphaMountain top1M) are never
scored. Their hostnames are removed from the candidate set before scoring and
from carried-over state, so matching `domain`/`url` indicators are suppressed
outright rather than down-weighted.

---

# Technical Stack

Language:

- Python 3.13+

Package Management:

- uv

Data Processing:

- Polars

Validation:

- Pydantic v2

CLI:

- Typer

Testing:

- Pytest

Linting:

- Ruff

Type Checking:

- MyPy

Containerization:

- Docker

CI/CD:

- GitHub Actions

Outputs:

- CSV
- JSON

---

# Repository Structure

```text
cs-lookup-files/
│
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
│
├── docs/
│   ├── architecture.md
│   ├── scoring.md
│   ├── sources.md
│   ├── crowdstrike.md
│   └── roadmap.md
│
├── config/
│   ├── settings.yaml
│   └── sources.yaml
│
├── src/
│   ├── collectors/
│   ├── normalizers/
│   ├── enrichers/
│   ├── scoring/
│   ├── exporters/
│   ├── models/
│   └── cli/
│
├── tests/
│   ├── unit/
│   └── integration/
│
├── output/
│
├── pyproject.toml
├── uv.lock
│
└── .github/
    └── workflows/
        ├── build-lookups.yml
        └── publish-release.yml
```

---

# GitHub Actions

Run every 6 hours.

Example schedule:

```yaml
cron:
  - "0 */6 * * *"
```

Pipeline:

1. Download feeds.
2. Normalize data.
3. Deduplicate indicators.
4. Enrich with ASN information.
5. Calculate confidence scores.
6. Export CSV files.
7. Export JSON files.
8. Generate metadata.json.
9. Publish release artifacts.
10. Update latest release.

Requirements:

- Failure of a single source must not fail the entire pipeline.
- Processing should complete in less than 30 minutes.
- All exports must be reproducible.

---

# CrowdStrike Integration

Provide examples for:

- Falcon LogScale lookups
- Fusion SOAR import workflows
- Correlation Rules
- Scheduled enrichment
- Investigation workflows

The project should include real examples demonstrating how to match:

- Remote IP addresses
- CIDR ranges
- ASN values

against the generated lookup files.

---

# MVP

## Included

- FireHOL integration
- Spamhaus DROP integration
- Abuse.ch Feodo integration
- AlienVault OTX integration (multi-type: IP/domain/url/md5/sha256/email)
- AbuseIPDB blacklist integration
- DShield intelfeed integration
- FireHOL per-category IP sets
- alphaMountain threat domains + top1M allowlist
- Config-driven catalogue of 23 origins / 41 feeds (CINS, IPsum, C2IntelFeeds,
  AlienVault reputation, TweetFeed, Botvrij, OpenPhish, PhishTank, viriback,
  miner/adblock lists, etc.)
- ASN enrichment
- Deduplication
- Confidence scoring (global + per-IOC-type weights)
- CSV export
- JSON export
- GitHub Releases publishing
- GitHub Actions automation
- Multi-IOC lookup datasets (ip, network, asn, domain, url, md5, sha256, email)

## Excluded

- AV / sandbox verdict enrichment
- Malware family attribution
- Case management
- Full TIP functionality
- Per-indicator live lookup endpoints

---

# MVP Success Criteria

- Fully automated operation
- No paid dependencies
- Sustainable under free-tier limits
- Direct CrowdStrike Falcon compatibility
- Hundreds of thousands of indicators supported
- Less than 30 minutes total execution time
- Multi-IOC lookup files generated every execution
- Zero manual intervention required
- Expanding source catalogue without core-logic changes

Produce a complete production-ready architecture, implementation plan, data models, workflows, GitHub Actions pipelines, scoring methodology, CrowdStrike integration examples, contributor guidelines, and roadmap for future expansion.