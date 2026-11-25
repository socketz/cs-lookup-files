# cs-lookup-files

Aggregate free threat-intel feeds, normalize and score the indicators, then
publish a small set of lookup files tuned for **CrowdStrike Falcon**.

The project is intentionally **not** a full TIP. It consumes free and publicly
available feeds, merges them into consolidated datasets, and publishes them as
GitHub Release artifacts for Falcon LogScale hunts, correlation rules, Fusion
SOAR hunting playbooks, and investigations.

## Scope: read-only context for threat hunting

The datasets are **read-only lookup tables for Threat Hunting, investigation and
enrichment**. They are not IOC Management input: importing them does not create,
modify or delete CrowdStrike IOCs, does not enroll indicators for blocking, and
does not trigger automated response. Nothing in this project calls the Falcon
IOC APIs; it only publishes release artifacts.

Typical use: join a lookup to events, filter by `confidence_score` (the export is
already `>= 75`), and investigate. Docs: [`docs/crowdstrike.md`](docs/crowdstrike.md).

## Outputs

Eight lookup files, plus JSON mirrors and metadata:

| Dataset                | Purpose                                              |
|------------------------|------------------------------------------------------|
| `malicious_ips`        | Match IPv4/IPv6 in network, DNS, proxy and EDR logs (ASN context) |
| `malicious_networks`   | Subnet (CIDR) reputation and network investigations (ASN context) |
| `malicious_asns`       | Authoritative ASN blocklist (Spamhaus ASN-DROP only)  |
| `malicious_domains`    | Hostname / domain reputation                          |
| `malicious_urls`       | URL / URI reputation                                  |
| `malicious_md5`        | MD5 file hashes                                      |
| `malicious_sha256`     | SHA256 file hashes                                   |
| `malicious_emails`     | Sender / phishing email addresses                    |

Each row is deduplicated, ASN-enriched (for IPs/networks), scored 0–100 and
time-boxed by first/last observation. `malicious_asns` is **never** derived from
flagged IPs: an ASN is listed only when an authoritative ASN-level list
(Spamhaus ASN-DROP) names it, so a single bad IP cannot mark a whole provider.
The export applies `min_confidence: 75`, so only corroborated or authoritative
rows are published.

Datasets with zero rows are **not written**. A missing file means "no qualifying
indicators this run"; `metadata.json` reports `ioc_counts` (0) and
`empty_datasets`, and consumers should tolerate absence (keep the previous
lookup on 404) rather than importing an empty table.

See [`docs/`](docs/) for the scoring model, source catalogue, and CrowdStrike
integration examples.

### Example `malicious_ips.csv`

```csv
ip,asn,asn_name,country,confidence_score,source_count,sources,categories,first_seen,last_seen
1.2.3.4,13335,CLOUDFLARENET,US,98,4,"spamhaus_drop;firehol;abusech_feodo;alienvault_otx",blocklist,2026-11-23T00:00:00Z,2026-11-23T12:00:00Z
```

## Quick start

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run cs-lookup-files validate     # validate config/settings.yaml + sources.yaml
uv run cs-lookup-files build        # full pipeline -> output/
# Offline, using the bundled fixtures (no network, no API keys):
uv run cs-lookup-files build --offline --offline-dir fixtures --output-dir output
```

Optional flags: `--state <prev state.json>` to merge history, `--dry-run` to
collect without writing, `--offline` to run against `fixtures/`.

### Container

```bash
docker build -t cs-lookup-files .
docker run --rm -e ABUSEIPDB_API_KEY=$ABUSEIPDB_API_KEY \
  -e OTX_API_KEY=$OTX_API_KEY \
  -v "$PWD/output:/data/output" cs-lookup-files
```

## Releases

GitHub Actions runs the pipeline every 6 hours and publishes a versioned GitHub
Release. Consumers use the stable URLs:

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

`state.json` carries observation history so indicators persist across runs and
confidence decays with age, not on every rebuild.

## Configuration

- `config/sources.yaml` — ETL for each feed (add a source by appending a block; no code changes).
- `config/settings.yaml` — scoring thresholds, ip2asn endpoints, output columns.
- `config/sources.schema.json` / `config/settings.schema.json` — JSON Schema
  describing the accepted config structure (regenerated via `cs-lookup-files schema`).

Supported indicator types: `ip`, `network` (CIDR), `asn` (authoritative ASN
lists), `domain` (hostname), `url`, `md5`, `sha256`, `email`. Each source
declares its `output_types`; feeds that classify rows by a type/value pair
(e.g. OTX) use `type_field` + `value_field` + `type_map` (case-insensitive).
A feed may also set `role: allowlist` (e.g. alphaMountain top1M): it is parsed
but never scored or exported, and its hostnames suppress matching domain/url
indicators so legitimate-but-compromised sites are discarded, not down-weighted.

API keys referenced as `$VAR` in config are resolved from the shell environment,
the CI workflow `env:` block, or a local `.env` loaded at startup (python-dotenv;
real env vars take precedence). Copy `.env.example` to `.env` to configure them.
A source whose required key is missing is **skipped** (not failed) until the key
is configured, so a fresh clone works without any secrets. Optional per-source
`requests_per_minute` keeps parallel fetches polite; global `max_workers`
bounds concurrency in `settings.yaml`.

AbuseIPDB's free tier allows **5 blacklist requests/day**. The AbuseIPDB feed
therefore sets `cache_ttl_hours: 24`, `max_requests_per_day: 5`, `retries: 0`
and `requests_per_minute: 5`; the daily counter and cached body live under
`cache/`. The build workflow persists `cache/` with `actions/cache@v6`, so four
6-hourly runs make at most one call per day; if the cache is cold the worst case
is 4 calls, still within the limit. An exhausted quota is reported as `skipped`
(reason `rate limit`), never `failed`.

## Development

```bash
uv run pytest tests -q      # unit + offline integration tests
uv run ruff check src tests
uv run mypy src
```

Adding a new source is config-only: define its `fetch`/`parse`/`fields`/`clean`
in `config/sources.yaml` (optionally a fixture under `fixtures/<id>` for
offline testing) — see `tests/integration/test_pipeline.py::test_config_only_new_source`.

## Documentation

- [Architecture](docs/architecture.md)
- [Confidence scoring](docs/scoring.md)
- [Intelligence sources](docs/sources.md)
- [CrowdStrike integration](docs/crowdstrike.md)
- [Roadmap](docs/roadmap.md)

## License

MIT — see [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities and the project's
security posture.