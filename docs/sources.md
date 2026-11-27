# Intelligence Sources

All data acquisition is bulk; **no per-indicator lookups**. Feeds are normalised
from `config/sources.yaml`. This page documents the parser/mapping contract, the
shipped source inventory (23 origins / 41 feeds at the time of writing), and the
operational caveats. Availability and row counts change upstream; the live
per-feed outcome is always published in `metadata.json` under `source_feeds`.

## Indicator types

Each feed declares the IOC types it produces (`output_types`):

| Type | Meaning |
|------|---------|
| `ip` | Bare IPv4/IPv6 address |
| `network` | CIDR / subnet (`1.2.3.0/24`) |
| `domain` | Hostname / domain (`evil.example.org`) |
| `url` | http(s) URL (scheme + host normalised) |
| `md5` | MD5 file hash (32 hex) |
| `sha256` | SHA256 file hash (64 hex) |
| `email` | Email address |
| `asn` | Autonomous System number (`60971`) |

`asn` is an authoritative type: it is fed only by ASN-level lists and is never
enriched or derived from IPs.

## Mapping styles

Two styles are supported per feed:

1. **Per-type fields** — each type reads its own raw key via `fields`
   (e.g. `fields: {ip: line, network: ip_or_cidr}`).
2. **Type routing** — feeds that classify each row by a `type`/`value` pair
   (e.g. the OTX export) use `type_field`, `value_field` and a `type_map` that
   translates raw labels (`IPv4`, `domain`, `FileHash-MD5`, ...) to types. The
   lookup is **case-insensitive**, so canonical OTX labels (`URL`, `URI`,
   `FileHash-SHA256`) and lower-case variants both match.

The schema of `config/sources.yaml` is available at
`config/sources.schema.json` (regenerate: `cs-lookup-files schema`).

## Parsing formats

| `parse.format` | Description |
|----------------|-------------|
| `plain_lines` | One value per line (comments stripped by `comment_prefix`). |
| `ipset` | FireHOL netset style: comments, header, then bare IPs/CIDRs. |
| `cidr_lines` | Spamhaus DROP style: `<cidr> ; <label>` lines. |
| `csv` / `tsv` | Delimited rows; optional header; name- or index-keyed mapping. |
| `json` | JSON payload; `records` walks to the array (`data.list`, `results`, `$`). |
| `jsonl` | Newline-delimited JSON: one object per line; blank/malformed skipped. |

For `csv`/`tsv`, every cell is exposed under both its header name (when present)
and its positional index (`"0"`, `"1"`, ...), so a feed can map by position even
if it has a header. JSON feeds with pagination merge each page's `records` array
before parsing, so a paginated JSON export is seen as one document.

### Fetch behaviour

- Pagination is configured per feed (`param`, `size_param`, `max_pages`,
  `max_seconds`, `stop_when_empty`). A mid-pagination failure keeps the pages
  already fetched and marks the feed `partial`.
- `cache_ttl_hours` stores the response body under `cache/` and serves it without
  a request until it expires.
- `max_requests_per_day` persists a UTC-day counter under `cache/`; exhaustion is
  reported as `skipped` (reason `rate limit`), never `failed`.
- Missing `$VAR` secrets are `skipped` (reason `missing secret`), so a fresh
  clone runs without keys.

## Shipped source inventory

The origin `id` is the scoring identity; feeds under one origin fuse into one
confirming source. `weight` is origin-level; `ioc_weights` overrides it per type.

| Origin | Feeds | IOC types | Weight | `ioc_weights` | Notes |
|--------|-------|-----------|--------|---------------|-------|
| `firehol` | 12 | ip, network | 85 | — | level1 + 11 per-category high-churn sets |
| `spamhaus` | 2 | network, asn | 100 | — | DROP + ASN-DROP (authoritative ASN source) |
| `abusech` | 1 | ip | 90 | ip: 92 | Feodo recommended C2 blocklist |
| `abuseipdb` | 1 | ip | 80 | — | blacklist export, confidence ≥ 90 |
| `dshield` | 1 | ip | 70 | — | intelfeed, threat labels only |
| `alienvault_otx` | 1 | ip, network, domain, url, md5, sha256, email | 70 | — | paginated JSON export, type-routed |
| `cins` | 1 | ip | 75 | — | CINS Army bad-guys list |
| `ipsum` | 1 | ip | 78 | — | IPsum aggregate list |
| `c2intelfeeds` | 1 | ip | 82 | ip: 85 | 30-day C2 IP feed |
| `alienvault_reputation` | 1 | ip | 78 | — | AlienVault IP reputation export |
| `bbcan177` | 2 | ip, domain | 70 | — | malicious IPs + IRC-botnet DNSBL |
| `botvrij` | 5 | ip, domain, url, sha256 | 72 | — | per-type IOC files (ips, domains, hostnames, urls, sha256) |
| `jamesbrine` | 1 | ip | 70 | — | brute-force hosts |
| `joewein` | 1 | domain | 65 | — | spam domain blocklist |
| `linuxtracker` | 1 | ip | 72 | — | Hancitor malspam IPs |
| `minerchk` | 1 | domain | 70 | — | miner host list |
| `nocoin` | 1 | domain | 65 | — | adblock no-coin hosts |
| `openphish` | 1 | url | 80 | url: 85 | phishing URL feed |
| `phishtank` | 1 | url | 80 | url: 85 | online-valid phishing URLs |
| `disconnect` | 1 | domain | 65 | — | simple malware domain list |
| `viriback` | 1 | ip, url | 80 | ip: 82, url: 78 | C2 tracker (Family, URL, IP) |
| `tweetfeed` | 1 | ip, domain, url, md5, sha256 | 70 | ip/domain/url/md5/sha256 | JSON array, type/value routed; corroborates OTX hashes |
| `alphamountain` | 2 | domain | 80 | — | threat domains + top1M allowlist |

Feeds reviewed but intentionally **not** enabled: entries already sourced via
FireHOL mirrors (Blocklist.de, Brute Force Blocker, CI Bad Guys, Compromised
IPs, Cridex/Feodo) to avoid double-counting; sources returning no rows or
blocked (Darklist, IPSpamList sample, SSLBL empty, dan.me.uk 403). Candidate
additions and their phasing live in `docs/roadmap.md`.

## Detailed source notes

### FireHOL (`firehol`)

Primary aggregation origin. The enabled feeds are chosen for frequent updates
and operational value:

- Composite: `firehol_level1` (ip + network).
- C2 / botnet: `feodo_badips`, `c2_tracker`, `cybercrime`, `et_compromised`.
- Brute force / scanners: `blocklist_de`, `ciarmy`, `greensnow`,
  `bruteforceblocker`.
- Abuse / spam: `stopforumspam`, `cybercure`.
- DShield top-attackers: `dshield` (network).

The `firehol_level2..4` composites are intentionally not enabled; the individual
high-churn sets give finer control and avoid re-counting the same IPs. The
`firehol_level1` header embeds non-routable entries (`0.0.0.0/8`, `10/8`,
`127/8`, `172.16/12`, `100.64/10`, `169.254/16`, documentation ranges); these are
filtered by the clean ops and the global bogon safety net.

### Spamhaus (`spamhaus`)

- `spamhaus_drop`: `drop.txt`, `cidr_lines`, `CIDR ; SBLxxxxx`. Outputs networks
  only. EDROP is not implemented separately because it was merged into DROP.
- `spamhaus_asndrop`: `asndrop.json`, **JSONL** (`asn`, `rir`, `domain`, `cc`,
  `asname`) plus a trailing metadata object without `asn`. Outputs `asn` with
  `asn_name` from `asname` and `country` from `cc`.
- ASN-DROP is the **only** source of `malicious_asns`; ASNs are never derived
  from flagged IPs.

### Abuse.ch Feodo (`abusech`)

`ipblocklist_recommended.txt`, `plain_lines`, `#` comments. Outputs IPs for
botnet / malware C2. Weight 90 with `ip: 92`.

### AbuseIPDB (`abuseipdb`)

`https://api.abuseipdb.com/api/v2/blacklist` with `Key: $ABUSEIPDB_API_KEY`.
`json` records at `data.list`; each record has `ipAddress`,
`abuseConfidenceScore`, `lastReportedAt`. Clean op keeps
`abuseConfidenceScore >= 90`.

**Policy:** blacklist export only — no per-IP `check` calls and no dependence on
elevated quotas. **Free-tier safeguards:** `cache_ttl_hours: 24`,
`max_requests_per_day: 5`, `retries: 0`, `requests_per_minute: 5`. The cache and
counter live under `cache/`; CI persists them with `actions/cache`. An exhausted
quota is `skipped` (reason `rate limit`), never `failed`.

### AlienVault OTX (`alienvault_otx`)

`https://otx.alienvault.com/api/v1/indicators/export`, header
`X-OTX-API-KEY: $OTX_API_KEY`.

- **Format (current):** JSON with a top-level `results` array; `parse.format` is
  `json` and `records: results`. Each record has `type` and `indicator`.
- **Type routing:** `type_field: type`, `value_field: indicator`, case-insensitive
  `type_map`: `IPv4`/`IPv6` → `ip`, `domain`/`hostname` → `domain`,
  `URL`/`URI` → `url`, `FileHash-MD5` → `md5`, `FileHash-SHA256` → `sha256`,
  `email` → `email`, `CIDR` → `network`. Unmapped rows are dropped.
- **Pagination:** `page` + `limit` (500), `max_pages: 200`, `max_seconds: 240`,
  `stop_when_empty: true`, `requests_per_minute: 120`, `retries: 3`. JSON pages
  are parsed independently and their `results` arrays are merged, because joining
  JSON documents with newlines is invalid.
- **Output:** the seven declared types. This is the only email source today, so
  `malicious_emails` uses a 55 per-type export floor; single-source OTX hashes
  are still pruned at 55 < 75 unless TweetFeed/Botvrij corroborates them.
- **History:** an earlier configuration expected a CSV-ish stream and used
  lower-case `filehash-md5` labels; both were fixed (JSON parsing + canonical
  case-insensitive type map). The historical note is kept here to explain why
  older releases may show empty hash/email datasets.

### DShield intelfeed (`dshield`)

`https://isc.sans.edu/api/intelfeed?json=1`, updated daily. JSON array at the top
level (`records: $`); rows have `ip` and `description`. Clean ops keep only
threat labels (`webscanner`, `miner`, `dshieldssh`, `malwaretrafficanalysis`,
`emergingthreats`); benign infrastructure labels (e.g. `mastodon`,
`openresolver`, `tldns`) are filtered out. Categories are derived from the label
via `categories.field` / `mapping`. No auth; `requests_per_minute: 20`.

### alphaMountain (`alphamountain`)

Two CSVs from [alphaMountain](https://www.alphamountain.ai/), cached 24h:

| Feed | URL | Role | Output |
|------|-----|------|--------|
| `alphamountain_top1m` | `alphaMountain-top1M.csv` | `allowlist` | domain |
| `alphamountain_threat` | `alphaMountain-community-threat-1000.csv` | `intel` | domain |

- Headers: `rank,hostname` (top1M) and `hostname,risk_score,more_info` (threat).
- The threat feed contributes scored domains under the `alphamountain` origin
  (weight 80, category `malware`).
- The top1M feed is **not scored or exported**. Its domains suppress matching
  `domain`/`url` indicators from every dataset (fresh frame and state), so
  legitimate-but-compromised sites are discarded rather than down-weighted.
  Matching is exact plus the `www.` variant; subdomains are not blanket-suppressed.
- Both feeds use `cache_ttl_hours: 24` because the top1M file is ~22 MB and does
  not change intraday.

### Multi-type / phishing / context feeds

| Origin | Format / mapping | IOC types | Notes |
|--------|------------------|-----------|-------|
| `tweetfeed` | JSON array (`records: $`), `type`/`value` routing | ip, domain, url, md5, sha256 | Weight 70; `ioc_weights` boost domain/url slightly. Corroborates OTX hashes and URLs. |
| `botvrij` | `plain_lines` per type | ip, domain, url, sha256 | Five feeds under one origin. The sha256 feed is a useful hash corroborator. |
| `bbcan177` | `plain_lines` | ip, domain | Malicious IP gist + IRC-botnet DNSBL gist. |
| `openphish` | `plain_lines` | url | Phishing URLs; weight 80, `url: 85`. |
| `phishtank` | `csv` (`url` column) | url | Online-valid phishing URLs; weight 80, `url: 85`. |
| `viriback` | `csv` (`IP`, `URL`) | ip, url | C2 tracker; weight 80, `ip: 82`, `url: 78`. |
| `c2intelfeeds` | `csv` (`#ip`) | ip | 30-day C2 IPs; weight 82, `ip: 85`. |
| `cins` | `plain_lines` | ip | CINS Army; weight 75, cap 50. |
| `ipsum` | `plain_lines` + regex | ip | IPsum; weight 78, cap 55. |
| `alienvault_reputation` | `csv` (positional) | ip | AlienVault IP reputation; weight 78. |
| `jamesbrine` | `csv` (positional) | ip | Brute-force hosts; weight 70, cap 45. |
| `linuxtracker` | `plain_lines` + regex | ip | Hancitor IPs; weight 72, cap 55. |
| `joewein` | `plain_lines` | domain | Spam domains; weight 65, cap 45. |
| `minerchk` | `plain_lines` | domain | Miner hosts; weight 70, cap 50. |
| `nocoin` | `plain_lines` + regex | domain | Adblock no-coin hosts; weight 65, cap 45. |
| `disconnect` | `plain_lines` | domain | Simple malware list; weight 65, cap 45. |

## Categories

Categories are drawn from a fixed vocabulary and are **not** free-form:

```
blocklist, malware_c2, malware, abuse, scanner, botnet, phishing, spam, other
```

Each origin declares a default category and may use `categories.field` +
`mapping` to translate raw labels (DShield does this). To add a label, extend
the vocabulary in `models/config.py` rather than introducing free-form strings.

## Adding sources (config-only)

Adding a feed is config-only: append an **origin** with a `feeds` array to
`config/sources.yaml`, each feed with `fetch`/`parse`/`fields`/`output_types`/
`clean`. Set the origin `weight` and optional `ioc_weights`. Add a fixture under
`fixtures/<feed_id>` for offline tests. See `CONTRIBUTING.md` and
`tests/integration/test_pipeline.py::test_config_only_new_source`.

An allowlist feed must use `role: allowlist` and output exactly `[domain]`; it is
parsed into a suppression set and never scored/exported.

The strategic catalogue is the ~390 active feeds in
[threat-intelligence-feeds.csv](https://github.com/kraloveckey/threat-intelligence-feeds/raw/refs/heads/main/threat-intelligence-feeds.csv)
plus [hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence/)
and [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists). Rollout is
phased in `docs/roadmap.md` by IOC type, format and auth requirements.
