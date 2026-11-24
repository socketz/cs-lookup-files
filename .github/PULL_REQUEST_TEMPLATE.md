# Pull Request

## Summary

What changed and why. Link the issue this closes (`Closes #...`).

## Type of change

- [ ] Config-only source addition (`config/sources.yaml`, optional `fixtures/<id>`)
- [ ] Pipeline, parsing, or cleaning logic
- [ ] Scoring model (`src/cs_lookup_files/scoring/`, `config/settings.yaml`)
- [ ] Exporters, column schema, or metadata
- [ ] ASN enrichment (ip2asn)
- [ ] CLI or configuration
- [ ] CI, releases, or Docker
- [ ] Documentation only

## Datasets and compatibility

Which datasets are affected?

- [ ] `malicious_ips`
- [ ] `malicious_networks`
- [ ] `malicious_asns`
- [ ] `metadata.json`
- [ ] `state.json`
- [ ] None (tooling, docs, CI)

Consumer-visible changes (tick any that apply):

- [ ] CSV header or column order changed
- [ ] `metadata.json` or `state.json` shape changed
- [ ] Confidence scores shift by more than a few points
- [ ] No schema or output changes

## How validated

Paste the commands and their results:

```bash
uv run ruff check src tests
uv run mypy src
uv run pytest tests -q
uv run cs-lookup-files build --offline --offline-dir fixtures --output-dir output
```

Include row-count deltas or sample rows when the output data changes.

## Checklist

- [ ] All code, tests, docs, and commit messages are in English
- [ ] Tests added or updated for the behaviour change
- [ ] Docs updated when behaviour, config, or output changes
- [ ] No secrets or `.env` files committed
- [ ] No generated artifacts committed (`output/`, `cache/`, `state/`; `state.json` is generated, never committed)
- [ ] The three-dataset promise and free-tier rules are respected
- [ ] Output remains deterministic and reproducible
