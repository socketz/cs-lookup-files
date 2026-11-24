# CrowdStrike Falcon Integration

The published lookup files are designed to be consumed by Falcon LogScale,
correlation rules and Fusion SOAR with no transformation. Stable URLs:

```
https://github.com/socketz/cs-lookup-files/releases/latest/download/malicious_ips.csv
https://github.com/socketz/cs-lookup-files/releases/latest/download/malicious_networks.csv
https://github.com/socketz/cs-lookup-files/releases/latest/download/malicious_asns.csv
https://github.com/socketz/cs-lookup-files/releases/latest/download/malicious_domains.csv
https://github.com/socketz/cs-lookup-files/releases/latest/download/malicious_urls.csv
https://github.com/socketz/cs-lookup-files/releases/latest/download/malicious_md5.csv
https://github.com/socketz/cs-lookup-files/releases/latest/download/malicious_sha256.csv
https://github.com/socketz/cs-lookup-files/releases/latest/download/malicious_emails.csv
https://github.com/socketz/cs-lookup-files/releases/latest/download/metadata.json
https://github.com/socketz/cs-lookup-files/releases/latest/download/state.json
```

## Falcon LogScale: scheduled scheduled import

Use a **Scheduled Search -> CSV ingest** (or a **File Upload by URL**) pointed at
`malicious_ips.csv`. The CSV has a header identical to the intended schema, so
ingest is direct.

Example ingest mapping (LogScale):

| CSV column        | Ingest field        |
|-------------------|---------------------|
| `ip`              | `malicious.ip`      |
| `asn`             | `malicious.asn`     |
| `country`         | `malicious.country` |
| `confidence_score`| `malicious.confidence` |
| `sources`         | `malicious.sources` |
| `categories`      | `malicious.categories` |
| `first_seen`      | `malicious.first_seen` |
| `last_seen`       | `malicious.last_seen` |

After ingest:

```
| malicious(lookup=malicious_ips) | table(remote_ip, confidence_score, sources)
```

### Real-time lookup (Falcon Query Language)

Ingest the file once as a lookup (`malicious_ips`). Then match on the fly:

```fql
// Match a remote IP address
event_simpleName=NetworkListenProcess
| lookup malicious_ips ipField=RemoteAddressIPv4 output=confidence_score, sources, categories
| RemoteAddressIPv4 IS NOT NULL

// Zone-scoped: only flag non-private remote IPs
| test(RemoteAddressIPv4)
| !cidrmatch("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", RemoteAddressIPv4)
| lookup malicious_ips ipField=RemoteAddressIPv4
```

## Fusion SOAR: HTTP / Webhook import

Point a SOAR workflow at the stable URL. Example (JSON body shown; CSV works the
same via file download):

```json
{
  "source_url": "https://github.com/socketz/cs-lookup-files/releases/latest/download/malicious_ips.csv",
  "format": "csv",
  "target_lookup": "malicious_ips",
  "schedule": "*/6 * * * *",
  "on_failure": "alert"
}
```

Fusion SOAR can `HTTP -> Fetch Media` then `Record Insert` into a LogScale
lookup, gated on `metadata.json`'s `version` to avoid redundant re-imports.

## Correlation Rules

Load `malicious_networks.csv` and use CIDR matching in a rule:

```
| !cidrmatch("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16", DestinationIP)
| lookup malicious_networks networkField=DestinationIP output=confidence_score, network
| confidence_score > 75
| alert("High-confidence egress to malicious network")
```

## ASN-level hunting

```
| DestinationIP IS NOT NULL
| lookup malicious_asns asnField=DestinationASN output=malicious_ip_count, sources
| malicious_ip_count >= 1
```

## Scheduled enrichment notes

- SIP multi-value (`ip`, `asn`, `asn_name`, `country`, `confidence_score`)
  columns are emitted as `;`-delimited strings matching the CSV sample in
  `README.md` — safe for LogScale string matching.
- `first_seen`/`last_seen` use ISO-8601 UTC, accepted by LogScale energy.
- Prefer `latest/download` for long-lived automations; pin a specific
  `YYYY.MM.DD.HHMM` asset for audit if you must reproduce an exact snapshot.