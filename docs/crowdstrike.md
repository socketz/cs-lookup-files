# CrowdStrike Falcon Integration

## Scope: read-only context for hunting and investigation

These lookup files are **read-only context** for Threat Hunting,
investigation, enrichment, LogScale and Fusion SOAR. Importing them does **not**
modify, create, or delete CrowdStrike IOCs, does not enroll indicators in IOC
Management, and does not trigger blocking or automated response. Nothing in this
project calls the Falcon IOC APIs; it only publishes release artifacts.

The intended use is: enrich events, join a lookup, filter by `confidence_score`,
and let a human (or a deliberately separate automation) decide what to do.
Use the files as a source of *additional context*, never as the authoritative
IOC store.

Stable URLs:

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

`latest/download` is just distribution. Pin a `YYYY.MM.DD.HHMM` tag when you need
a reproducible snapshot for an investigation. Every dataset also has a `.json`
mirror at the same URL with `.json` instead of `.csv`. `state.json` is an
internal build-to-build artifact for the next pipeline run; do not import it as
a hunting lookup.

Datasets with zero rows are **not written**. A missing file means "no qualifying
indicators this run", not a broken release; consumers must tolerate absence
(e.g. keep the previous lookup when the download 404s). `metadata.json` lists
`ioc_counts` (0 for absent datasets) and `empty_datasets`, so automation can
distinguish "empty" from "missing".

## The export is already filtered

`config/settings.yaml` sets `min_confidence: 75` as the global export floor, and
`min_confidence_by_type.email: 55` for `malicious_emails` (OTX is currently its
only email source). Every exported row is therefore already at or above its
dataset floor. Apply a **higher** threshold for hunting focus or automation;
never assume a lower one will discard much.

## Falcon LogScale: import as a lookup

Use a **Scheduled Search -> CSV ingest** (or **File Upload by URL**) pointed at
the CSV. The header matches the schema, so ingest is direct.

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

### Hunting: join + threshold (primary use)

```
// Enrich outbound connections and surface the highest-confidence matches.
event_simpleName=NetworkConnectIP4
| lookup malicious_ips ipField=RemoteAddressIP4 output=confidence_score, sources, categories, asn, asn_name
| RemoteAddressIP4 IS NOT NULL
| confidence_score >= 75
| table(timestamp, ComputerName, RemoteAddressIP4, confidence_score, sources, categories, asn, asn_name)
```

Raise the bar for triage queues that should be very precise:

```
| lookup malicious_ips ipField=RemoteAddressIP4 output=confidence_score, sources
| confidence_score >= 90
```

### Hunting: private-IP hygiene

```
| !cidrmatch("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16", RemoteAddressIP4)
| lookup malicious_ips ipField=RemoteAddressIP4 output=confidence_score, sources
```

### Hunting: CIDR ranges

Load `malicious_networks.csv` and match destinations:

```
| !cidrmatch("10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16", DestinationIP)
| lookup malicious_networks networkField=DestinationIP output=confidence_score, network, asn, asn_name
| confidence_score >= 75
| table(timestamp, ComputerName, DestinationIP, network, confidence_score, asn, asn_name)
```

### Hunting: ASN context vs authoritative ASN blocklist

`malicious_asns` is the authoritative Spamhaus ASN-DROP list (ASN-level
reputation). It is **not** derived from flagged IPs, so a hit is meaningful:

```
| DestinationIP IS NOT NULL
| lookup malicious_asns asnField=DestinationASN output=asn_name, confidence_score, sources
| confidence_score >= 75
| table(timestamp, ComputerName, DestinationASN, asn_name, confidence_score, sources)
```

To investigate an IP whose ASN looks interesting, use the **context** columns on
`malicious_ips`/`malicious_networks` (`asn`, `asn_name`, `country`). Those
columns describe the network owner; they do not assert that the ASN is
malicious. Cross-reference `malicious_asns` before drawing that conclusion.

## Fusion SOAR: pull and enrich (not IOC import)

Point a workflow at the stable URL and insert rows into a LogScale lookup or use
them for enrichment steps. Do **not** feed these rows into IOC Management.

```json
{
  "source_url": "https://github.com/socketz/cs-lookup-files/releases/latest/download/malicious_ips.csv",
  "format": "csv",
  "target_lookup": "malicious_ips",
  "schedule": "0 */6 * * *",
  "on_failure": "alert",
  "note": "read-only hunting context; does not modify Falcon IOCs"
}
```

Fusion SOAR can `HTTP -> Fetch Media` then `Record Insert` into a LogScale
lookup, gated on `metadata.json`'s `version` to avoid redundant re-imports.

## Combining with other lookup families

These datasets are designed to be composed with adjacent lookup projects such as
[`logscale-lookup-files`](https://github.com/socketz/logscale-lookup-files)
(IP usage classification and malicious packages). Join events to
`malicious_ips`/`malicious_networks` for malicious reputation, then to
`ip_classified_networks.csv` for `use`/`source` context. Do not treat
`vpn`/`datacenter`/`tor` as a second malicious verdict, and do not double-count
overlapping providers as independent confirmations. The full contract and field
mapping are in [`docs/integration.md`](integration.md).

## Non-goals

No blocking, no automated containment, and no IOC enrollment are implemented by
this project. Any response action is out of scope and must be built separately,
with its own review and approval path. Raising the lookup threshold to `90` in
that separate automation is recommended if it ever exists.

## Refresh notes

- `sources`, `categories` are `;`-delimited strings; `first_seen`/`last_seen`
  are ISO-8601 UTC.
- Prefer `latest/download` for long-lived automations; pin an exact
  `YYYY.MM.DD.HHMM` asset for audit reproduction.
- Importing an empty file can overwrite a lookup with nothing, which is why the
  pipeline omits empty datasets and reports them in `metadata.json`.
