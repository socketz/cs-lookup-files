# cs-lookup-files

Aggregate free threat-intel feeds, normalize and score the indicators, then
publish a small set of lookup files tuned for **CrowdStrike Falcon**.

The project is intentionally **not** a full TIP. It consumes free and publicly
available feeds, merges them into three consolidated datasets, and publishes
them as GitHub Release artifacts for automated ingestion via Fusion SOAR, Falcon
LogScale hunts, and correlation rules.

## Outputs

Nine lookup files, plus JSON mirrors and metadata:

| Dataset                | Purpose                                              |
|------------------------|------------------------------------------------------|
| `malicious_ips`        | Match IPv4/IPv6 in network, DNS, proxy and EDR logs  |
| `malicious_networks`   | Subnet (CIDR) reputation and network investigations  |
| `malicious_asns`       | Provider-level infrastructure reputation             |
| `malicious_domains`    | Hostname / domain reputation                          |
| `malicious_urls`       | URL / URI reputation                                  |
| `malicious_md5`        | MD5 file hashes                                      |
| `malicious_sha256`     | SHA256 file hashes                                   |
| `malicious_emails`     | Sender / phishing email addresses                    |

Each row is deduplicated, ASN-enriched (for IPs/networks), scored 0–100 and
time-boxed by first/last observation. See [`docs/`](docs/) for the scoring
model, source catalogue, and CrowdStrike integration examples.

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
https://github.com/<org>/cs-lookup-files/releases/latest/download/malicious_ips.csv
https://github.com/<org>/cs-lookup-files/releases/latest/download/malicious_networks.csv
https://github.com/<org>/cs-lookup-files/releases/latest/download/malicious_asns.csv
https://github.com/<org>/cs-lookup-files/releases/latest/download/malicious_domains.csv
https://github.com/<org>/cs-lookup-files/releases/latest/download/malicious_urls.csv
https://github.com/<org>/cs-lookup-files/releases/latest/download/malicious_md5.csv
https://github.com/<org>/cs-lookup-files/releases/latest/download/malicious_sha256.csv
https://github.com/<org>/cs-lookup-files/releases/latest/download/malicious_emails.csv
https://github.com/<org>/cs-lookup-files/releases/latest/download/metadata.json
https://github.com/<org>/cs-lookup-files/releases/latest/download/state.json
```

`state.json` carries observation history so indicators persist across runs and
confidence decays with age, not on every rebuild.

## Configuration

- `config/sources.yaml` — ETL for each feed (add a source by appending a block; no code changes).
- `config/settings.yaml` — scoring thresholds, ip2asn endpoints, output columns.
- `config/sources.schema.json` / `config/settings.schema.json` — JSON Schema
  describing the accepted config structure (regenerated via `cs-lookup-files schema`).

Supported indicator types: `ip`, `network` (CIDR), `domain` (hostname),
`url`, `md5`, `sha256`, `email`. Each source declares its `output_types`; feeds
that classify rows by a type/value pair (e.g. OTX) use `type_field` +
`value_field` + `type_map`.

API keys referenced as `$VAR` in config are resolved from the shell environment,
the CI workflow `env:` block, or a local `.env` loaded at startup (python-dotenv;
real env vars take precedence). Copy `.env.example` to `.env` to configure them.
A source whose required key is missing is **skipped** (not failed) until the key
is configured, so a fresh clone works without any secrets. Optional per-source
`requests_per_minute` keeps parallel fetches polite; global `max_workers`
bounds concurrency in `settings.yaml`.

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