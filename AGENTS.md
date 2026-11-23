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

---

# Intelligence Sources

## MVP Sources

### FireHOL

Primary aggregation source.

Used as one of the strongest reputation references.

### Spamhaus DROP

Use DROP exclusively.

Do not implement EDROP separately because it has been merged into DROP.

### Abuse.ch Feodo Tracker

Used for botnet infrastructure and malware C2 visibility.

### AlienVault OTX

Used as an additional confidence source.

### AbuseIPDB

Use only blacklist/blocklist exports.

Do not perform individual IP reputation checks.

Do not call the AbuseIPDB CHECK endpoint for every IOC.

Do not depend on AbuseIPDB per-IP enrichment.

The solution must remain sustainable even if AbuseIPDB API quotas are reduced.

The repository owner currently has AbuseIPDB Webmaster status, but the architecture must not depend on elevated API consumption.

---

## Future Sources

Implement future providers through plugins:

- Blocklist.de
- DShield
- CINS Army
- Emerging Threats
- GreyNoise
- Shadowserver

No modifications to core logic should be required when adding new sources.

---

# Generated Lookup Files

The MVP should generate only three lookup datasets.

---

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
- malicious_ip_count
- source_count
- sources

Example:

```csv
asn,asn_name,country,confidence_score
13335,CLOUDFLARENET,US,75
```

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
└── metadata.json
```

---

# Versioning Strategy

Maintain versioned snapshots.

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
    "spamhaus_drop",
    "abusech_feodo",
    "alienvault_otx",
    "abuseipdb"
  ],
  "ioc_counts": {
    "ips": 125000,
    "networks": 8200,
    "asns": 315
  }
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

Scoring Requirements:

- Multiple source confirmations must significantly increase confidence.
- Recent observations should score higher.
- Confidence must decay over time.
- One low-confidence source must never generate a very high score.
- The formula must be fully documented.

Examples:

- Single source → 40-70
- Two trusted sources → 75-90
- Three or more trusted sources → 90-100

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
- AlienVault OTX integration
- AbuseIPDB blacklist integration
- ASN enrichment
- Deduplication
- Confidence scoring
- CSV export
- JSON export
- GitHub Releases publishing
- GitHub Actions automation

## Excluded

- Domain intelligence
- URL intelligence
- File hashes
- Malware family attribution
- Case management
- TIP functionality

---

# MVP Success Criteria

- Fully automated operation
- No paid dependencies
- Sustainable under free-tier limits
- Direct CrowdStrike Falcon compatibility
- Hundreds of thousands of indicators supported
- Less than 30 minutes total execution time
- Three high-quality lookup files generated every execution
- Zero manual intervention required

Produce a complete production-ready architecture, implementation plan, data models, workflows, GitHub Actions pipelines, scoring methodology, CrowdStrike integration examples, contributor guidelines, and roadmap for future expansion.