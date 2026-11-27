# Integrating with adjacent lookup projects

`cs-lookup-files` is designed to be **composed**, not to absorb every data
source. The closest counterpart is
[`socketz/logscale-lookup-files`](https://github.com/socketz/logscale-lookup-files),
which publishes CrowdStrike LogScale lookups for malicious packages and IP usage
classification. This page describes a concrete, low-risk integration contract.

## What each project publishes

| Project | Files | Key contract |
|---------|-------|--------------|
| `cs-lookup-files` | `malicious_ips`, `malicious_networks`, `malicious_asns`, `malicious_domains`, `malicious_urls`, `malicious_md5`, `malicious_sha256`, `malicious_emails` (CSV + JSON) | GitHub Releases; `metadata.json` with version, source status/feeds, counts, empty datasets |
| `logscale-lookup-files` | `malicious_package_names.csv`, `malicious_packages.csv`, `by-ecosystem/*.csv`, `ip_classified_networks.csv` | committed `data/`; `manifest.json` with `data_hash`, per-file `sha256`/`rows`/`size_bytes` |

They are complementary:

- `cs-lookup-files`: **multi-type malicious IOC reputation** (confidence,
  sources, categories, first/last seen) and the authoritative Spamhaus ASN-DROP
  dataset.
- `logscale-lookup-files`: **package malware** coverage and **IP usage
  classification** (`malicious`, `tor`, `vpn`, `datacenter`) with provenance per
  network.

## Overlap and non-overlap

Both projects ingest FireHOL, Spamhaus, Feodo and similar blocklists. Treat that
overlap as **one signal**:

- Do not add `cs-lookup-files` and `logscale-lookup-files` source counts
  together to infer independent corroboration.
- `cs-lookup-files` owns IOC scoring and ASN-DROP.
- `logscale-lookup-files` owns package names and usage classification.
- Its `spamhaus-asndrop` source intentionally yields **0 networks**; use
  `cs-lookup-files/malicious_asns.csv` for ASNs.

## Pattern A — consumer-side composition in LogScale (no producer changes)

Upload both lookup families, then enrich events twice:

```logscale
// 1) Is the remote IP a known malicious indicator?
event_simpleName=NetworkConnectIP4
| lookup malicious_ips ipField=RemoteAddressIP4
    output=confidence_score, sources, categories, asn, asn_name
// 2) What is the network used for? (cidr mode; returns use/source)
| match(file="ip_classified_networks.csv", field=RemoteAddressIP4,
        column="network", mode=cidr, include=["use","source"], ignoreCase=true)
| confidence_score >= 75
| table(timestamp, ComputerName, RemoteAddressIP4, confidence_score,
        categories, asn, asn_name, use, source)
```

Use `use` as **triage context**, not as a second malicious verdict:

- `use=malicious` from the classification list may duplicate `cs-lookup-files`
  sources; keep the `confidence_score` from `cs-lookup-files`.
- `use=vpn|datacenter|tor` explains infrastructure and helps prioritize, but is
  not evidence of compromise by itself.

## Pattern B — shared manifest/hash contract (recommended next step)

Today `cs-lookup-files` publishes `metadata.json` without per-file hashes.
Aligning it with `manifest.json` enables one verification gate for both releases:

| Field | `cs-lookup-files` (proposed) | `logscale-lookup-files` (existing) |
|-------|------------------------------|------------------------------------|
| build time | `generated_at` | `generated_at` |
| version | `version` (`YYYY.MM.DD.HHMM`) | `source_commit_sha` / `data_hash` |
| per-file | `files[name] = {rows, sha256, size_bytes}` | same |
| aggregate | `data_hash` over sorted file hashes | `data_hash` |
| empty datasets | `empty_datasets` | n/a (files always present) |

This is a documentation/metadata change in `cs-lookup-files` (P0 in
`docs/roadmap.md`) and does not affect the current datasets.

## Pattern C — combined distribution bundle (new workflow)

A third workflow (or a small distribution repo) can:

1. Download the `latest` release of both projects.
2. Validate `metadata.json` (`version`, `ioc_counts`, `empty_datasets`) and
   `manifest.json` (`data_hash`, per-file `sha256`).
3. Optionally verify a pinned version/hash for audit.
4. Publish one “Falcon lookup bundle” or upload the selected lookups to LogScale.

Neither producer needs to know about the other; the bundle is the integration
point. This is the lowest-risk way to give consumers a single versioned artifact.

## Pattern D — producer-side context import (future code change)

`cs-lookup-files` could read `ip_classified_networks.csv` as a **context feed**
to attach `use`/provider categories to IP/network rows. Constraints:

- It must not be a generic allowlist: VPN, datacenter and Tor are not benign.
- It must not change `confidence_score`; classification is context.
- It needs new contextual columns (for example `network_use`,
  `classification_source`) and a documented overlap policy, so it is a core code
  change, not a config-only source.
- Gate it behind measurement of false-positive impact.

## Pattern E — downstream consumer (`falcon-hunting-toolkit`)

A hunting toolkit should:

- Gate imports on `metadata.version` (and `manifest.data_hash` once available).
- Consume `malicious_asns` from `cs-lookup-files` only.
- Use `ip_classified_networks.csv` for context and `malicious_package_names.csv`
  for package hunts.
- Keep the read-only contract: no IOC Management, blocking, or response.

## Field mapping

| `cs-lookup-files` | `logscale-lookup-files` | Notes |
|-------------------|-------------------------|-------|
| `malicious_ips.ip` | `ip_classified_networks.network` | Join with `mode=cidr`; hosts are `/32`. |
| `malicious_networks.network` | `ip_classified_networks.network` | CIDR containment/overlap; dedupe providers. |
| `malicious_asns.asn` | `spamhaus-asndrop` (0 rows) | Use `cs-lookup-files` as the ASN authority. |
| `sources` (origin ids) | `source` (feed slug) | Different granularity; map explicitly. |
| `categories` | `use` | Threat category vs usage classification. |
| `confidence_score` | — | Preserve the `cs-lookup-files` score. |
| `first_seen`/`last_seen` | `manifest.generated_at` | Indicator history vs build time. |

## Guardrails

- **Read-only.** No IOC import, blocking, containment, or automated response.
- **No double counting.** Overlapping feeds are one confirmation, not two.
- **Pin versions for audit.** Use `latest` for freshness and a pinned
  `YYYY.MM.DD.HHMM`/`data_hash` for investigations.
- **Missing files are meaningful.** A missing dataset means “no qualifying
  rows”, not “safe”; keep the previous lookup on 404 and read
  `metadata.empty_datasets`.
- **Respect licenses and rate limits** before combining or redistributing feeds.

## Suggested rollout

1. Document the contract (this page and `docs/roadmap.md`).
2. Add `sha256`/`size_bytes`/`data_hash` to `metadata.json` (P0).
3. Ship a combined bundle workflow (Pattern C).
4. Publish LogScale/Fusion examples that join both families (Pattern A).
5. Evaluate contextual ingestion (Pattern D) only with measured impact.
