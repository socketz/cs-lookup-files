# Intelligence Sources

All data acquisition is bulk; no per-indicator lookups. Feeds are normalised in
`config/sources.yaml`. This page documents each feed's canonical format (verified
at implementation time) and how it maps into the pipeline.

## Indicator types

Each source declares which IOC types it produces (`output_types`):

| Type       | Meaning                                 |
|------------|-----------------------------------------|
| `ip`       | Bare IPv4/IPv6 address                  |
| `network`  | CIDR / subnet (`1.2.3.0/24`)            |
| `domain`   | Hostname / domain (`evil.example.org`)  |
| `url`      | http(s) URL                             |
| `md5`      | MD5 file hash (32 hex)                  |
| `sha256`   | SHA256 file hash (64 hex)               |
| `email`    | Email address                           |

Two mapping styles are supported per source:

1. **Per-type fields** — each type reads its own raw key via `fields` (e.g.
   `fields: {ip: line, network: ip_or_cidr}`).
2. **Type routing** — feeds that classify each row by a `type`/`value` pair
   (e.g. the OTX export) use `type_field`, `value_field` and a `type_map` that
   translates raw labels (`IPv4`, `domain`, `filehash-md5`, ...) to types.

The schema of `config/sources.yaml` is available at
`config/sources.schema.json` (regenerate: `cs-lookup-files schema`).

## Parsing formats

| `parse.format`  | Description                                                            |
|-----------------|------------------------------------------------------------------------|
| `plain_lines`   | One value per line (comments stripped by `comment_prefix`).            |
| `ipset`         | FireHOL netset style: comments, header, then bare IPs/CIDRs.            |
| `cidr_lines`    | Spamhaus style: `<cidr> ; <label>` lines.                              |
| `csv` / `tsv`   | Delimited rows; optional header; index or name-keyed field mapping.    |
| `json`          | JSON payload; `records` path walks to the array (`data.list`).         |

Every parser exposes each value under **both** its name and its positional
index, so config can reference columns by position even when a header exists
(this is how the OTX stream is handled).

## MVP sources

### FireHOL level1 (`firehol_level1`)
- URL: `firehol_level1.netset`
- Format: `ipset`, comment prefix `#`. Header line `ipv4 hash:net` is dropped by
  IP/CIDR validation.
- Output: IPs and networks. Clean ops: `drop_private`, `require_globally_routable`.
- Note: the header embeds non-routable entries (`0.0.0.0/8`, `10/8`, `127/8`,
  `172.16/12`, `100.64/10`, `169.254/16`, documentation ranges). These are
  filtered both by the safety net and the declared ops.

### Spamhaus DROP (`spamhaus_drop`)
- URL: `drop.txt` (DROP only; EDROP was merged into DROP).
- Format: `cidr_lines`, comment prefix `;`. Lines are `CIDR ; SBLxxxxx`.
- Output: networks only.

### Abuse.ch Feodo Tracker (`abusech_feodo`)
- URL: `ipblocklist_recommended.txt`
- Format: `plain_lines`, comment prefix `#` (header + `#`-prefixed banner), then
  bare IPs under the `DstIP` section.
- Output: IPs (botnet / malware C2).

### AbuseIPDB (`abuseipdb`)
- URL: `https://api.abuseipdb.com/api/v2/blacklist`
- Header: `Key: $ABUSEIPDB_API_KEY` (env ref, never committed).
- Format: `json`, records path `data.list`. Each record has `ipAddress`,
  `abuseConfidenceScore`, `lastReportedAt`.
- Clean op: `field_ge` on `abuseConfidenceScore >= 90`.
- **Policy:** blacklist export only — no per-IP `check` calls, no reliance on
  elevated API quotas.

### AlienVault OTX (`alienvault_otx`)
- URL: `https://otx.alienvault.com/api/v1/indicators/export`
- Header: `X-OTX-API-KEY: $OTX_API_KEY`; paginated with `page`/`limit`, polite
  `requests_per_minute`.
- Format: per-line CSV-ish stream: `"type","indicator","pulse_name",...`
  (e.g. `"IPv4","1.2.3.4",...`). Classified by **type routing**:
  `type_field`/`value_field`/`type_map` map `IPv4` → `ip`, `domain`/`hostname`
  → `domain`, `url` → `url`, `filehash-md5` → `md5`, `filehash-sha256` →
  `sha256`, `email` → `email`. Rows whose type maps to nothing are dropped.
- Output: the declared `output_types` (currently ip/domain/url/md5/sha256/email).
- Categories default to `malware` (canonical vocabulary; see below).
- Pagination is bounded by `max_seconds` (wall-clock budget) so a slow/throttled
  OTX truncates gracefully instead of blocking the pipeline SLA; a mid-pagination
  failure keeps the pages already fetched and marks the feed `partial`.

### FireHOL per-category sets
The [firehol/blocklist-ipsets](https://github.com/firehol/blocklist-ipsets)
repository bundles many reliable sets. **Only feeds with frequent updates are
enabled** (from every 15 minutes to every few days); obsolete sets (no updates
for months) are excluded. See `config/sources.yaml` for the exact list; it
currently includes:

- Composite: `firehol_level1`.
- C2 / botnet: `feodo_badips`, `c2_tracker`, `cybercrime`, `et_compromised`.
- Brute force / scanners: `blocklist_de`, `ciarmy`, `dshield`, `greensnow`,
  `bruteforceblocker`.
- Abuse / spam: `stopforumspam`, `cybercure`.

The `firehol_level2..4` composites were dropped in favour of the individual
high-churn sets above for finer scoring control; the DShield top-attackers set
(`dshield`) is also mirrored directly from FireHOL.

### DShield intelfeed (`dshield_intelfeed`)
- URL: `https://isc.sans.edu/api/intelfeed` (`json=1`), updated daily.
- Format: JSON array at the top level (`records: "$"`): each row has `ip` and
  `description` (the feed/category label).
- Clean ops: keep only threat labels (`webscanner`, `miner`, `dshieldssh`,
  `malwaretrafficanalysis`, `emergingthreats`); benign infrastructure labels
  (e.g. `mastodon`, `openresolver`, `tldns`) are filtered out. Categories are
  derived from the label via `categories.field`/`mapping`.
- No authentication required; polite `requests_per_minute: 20`.

### ThreatFeeds.io additions (Status 200)

Feeds verified reachable (HTTP 200) on [threatfeeds.io](https://threatfeeds.io/)
and not already covered were added, grouped by origin:

| Source id | Feed(s) | IOC type(s) |
|-----------|---------|-------------|
| `alienvault_reputation` | `reputation.data` (CSV `#`-separated) | ip |
| `bbcan177` | malicious IPs, IRC-botnet DNSBL | ip, domain |
| `botvrij` | ips, domains, hostnames, urls | ip, domain, url |
| `jamesbrine` | brute-force hosts (CSV) | ip |
| `joewein` | domains blacklist | domain |
| `linuxtracker` | Hancitor malspam IPs | ip |
| `minerchk` | miner host list | domain |
| `nocoin` | adblock hosts (`0.0.0.0 domain`) | domain |
| `openphish` | phishing URLs | url |
| `phishtank` | online-valid phishing URLs (CSV) | url |
| `disconnect` | simple malware list | domain |
| `viriback` | C2 tracker (CSV: Family,URL,IP) | ip, url |

Feeds reviewed but intentionally **not** added: entries already sourced via
FireHOL mirrors (Blocklist.de, Brute Force Blocker, CI Bad Guys, Compromised
IPs, Cridex/Feodo) to avoid double-counting; sources returning no rows or
blocked (Darklist, IPSpamList sample, SSLBL empty, dan.me.uk 403).

## Categories

Categories are drawn from a fixed, canonical vocabulary and are **not**
free-form:

```
blocklist, malware_c2, malware, abuse, scanner, botnet, phishing, spam, other
```

Each source declares a default category (and optionally a `field` + `mapping`
to translate raw labels via the `map_values` op). To use a new label, extend the
vocabulary in `models/config.py` rather than introducing free-form strings.

## Adding sources (plugin pattern)

Adding a feed is config-only: an entry in `config/sources.yaml` with
`fetch`/`parse`/`fields`/`clean`, plus `weight` (global reliability) and optional
`ioc_weights` (per-IOC-type reliability). No core changes are required; see
`tests/integration/test_pipeline.py::test_config_only_new_source`.

The strategic catalogue is the ~390 active feeds in
[threat-intelligence-feeds.csv](https://github.com/kraloveckey/threat-intelligence-feeds/raw/refs/heads/main/threat-intelligence-feeds.csv)
and the curated lists at
[hslatman/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence/)
and [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists). Rollout is
phased in `docs/roadmap.md` by IOC type and effort; candidate feeds include:

- **IP/network**: CINS Army, IPsum, AlienVault IP Reputation, Emerging Threats
  Block IPs, C2IntelFeeds, Binarydefense, OffSeq Mirage, NetAPI.
- **Domain/url**: C2IntelFeeds domains, Cert.PL, OpenPhish, PhishTank, Phishing
  Army, spydisec, threatview.
- **Multi-type / hashes / email**: tweetfeed `today.csv` (type-routed),
  Botvrij.eu per-type IOC files, WSTNPHX email addresses, threatview
  MD5/SHA256, OffSeq Mirage URLs/hashes.
- **Contextual**: TOR exit/all lists, open proxies, VPN exit IPs
  (`mthcht/awesome-lists`).
- **Authenticated** (skipped until key configured): GreyNoise, Shadowserver,
  Malshare, snort.org.

Downloads run concurrently but bounded (`max_workers` in `settings.yaml`) with
optional per-source `requests_per_minute` rate limiting; secrets come from
`.env` / env and missing keys skip the source.