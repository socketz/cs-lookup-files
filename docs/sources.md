# Intelligence Sources

All data acquisition is bulk; no per-indicator lookups. Feeds are normalised in
`config/sources.yaml`. This page documents each feed's canonical format (verified
at implementation time) and how it maps into the pipeline.

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

### FireHOL (`firehol`)
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
- Header: `X-OTX-API-KEY: $OTX_API_KEY`; paginated with `page`/`limit`.
- Format: per-line CSV-ish stream: `"type","indicator","pulse_name",...`
  (e.g. `"IPv4","1.2.3.4",...`). Fields map by index: `type → 0`, `ip → 1`.
- Clean ops: `field_in` (`type` in `IPv4`/`IPv6`), `parse_and_validate_ip`,
  `drop_private`. `domain`/`url` rows are filtered out.
- Categories default to `malware` (canonical vocabulary; see below).

## Categories

Categories are drawn from a fixed, canonical vocabulary and are **not**
free-form:

```
blocklist, malware_c2, malware, abuse, scanner, botnet, phishing, spam, other
```

Each source declares a default category (and optionally a `field` + `mapping`
to translate raw labels via the `map_values` op). To use a new label, extend the
vocabulary in `models/config.py` rather than introducing free-form strings.

## Future sources (plugin pattern)

Adding a feed is config-only:

- **Blocklist.de** — `plain_lines` IP export.
- **DShield** — JSON top attackers (single bulk pull).
- **CINS Army** — `badguys.txt` IP list.
- **Emerging Threats** — `blocked-ips.txt`.
- **GreyNoise / Shadowserver** — authenticated bulk exports.

No changes to `engine.py`, scoring, or exporters are required; see
`docs/architecture.md` (config-driven sources) and
`tests/integration/test_pipeline.py::test_config_only_new_source`.