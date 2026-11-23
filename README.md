# cs-lookup-files

Aggregate free threat-intel feeds, normalize and score the indicators, then
publish a small set of lookup files tuned for **CrowdStrike Falcon**.

The project is intentionally **not** a full TIP. It consumes free and publicly
available feeds, merges them into three consolidated datasets, and publishes
them as GitHub Release artifacts for automated ingestion via Fusion SOAR, Falcon
LogScale hunts, and correlation rules.

## Outputs

Three lookup files, plus JSON mirrors and metadata:

| Dataset            | Purpose                                              |
|--------------------|------------------------------------------------------|
| `malicious_ips`    | Match remote IPs in network, DNS, proxy and EDR logs |
| `malicious_networks` | Subnet reputation and network-level investigations |
| `malicious_asns`   | Provider-level infrastructure reputation            |

Each row is deduplicated, enriched with ASN info, scored 0–100 and time-boxed
by first/last observation. See [`docs/`](docs/) for the scoring model,
CrowdStrike integration examples, and source catalogue.

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
https://github.com/<org>/cs-lookup-files/releases/latest/download/metadata.json
https://github.com/<org>/cs-lookup-files/releases/latest/download/state.json
```

`state.json` carries observation history so indicators persist across runs and
confidence decays with age, not on every rebuild.

## Configuration

- `config/sources.yaml` — ETL for each feed (add a source by appending a block; no code changes).
- `config/settings.yaml` — scoring thresholds, ip2asn endpoints, output columns.

API keys are read from environment variables (`$VAR` references in headers) and
are set in the workflow's `env:` block — never committed.

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