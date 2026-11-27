# Contributing

Thanks for taking the time to contribute to **cs-lookup-files**.

## Ground rules

- All code, tests, docs, commits, issues and PRs must be written in **English**.
- Keep the scope small. This project deliberately avoids becoming a full TIP;
  the goal is a handful of high-quality lookup files for CrowdStrike Falcon.
- Favour **simplicity, determinism and reproducibility** over feature count.
- New feeds should be added as **config** (see `config/sources.yaml`); core code
  changes are discouraged for source additions.
- Bulk downloads only. Do not add per-indicator API lookups.

## Development setup

```bash
uv sync                       # installs the environment (Python 3.13)
uv run pytest tests -q        # run unit + offline integration tests
uv run ruff check src tests   # lint
uv run mypy src               # type check
uv run cs-lookup-files validate
```

## Adding a new source (config-only)

1. Append an **origin** with a `feeds` array to `config/sources.yaml`.
   The origin `id` is the scoring identity; feeds under it share one weight.
2. Set the origin `weight` (0..100) and, when reliability differs by IOC type,
   an optional `ioc_weights` map.
3. Add a small sample at `fixtures/<feed_id>` (the feed `id`, or the URL basename
   when `id` is omitted) for offline tests.
4. Run `uv run cs-lookup-files validate` to check the schema.
5. Add a test in `tests/` demonstrating the feed works end-to-end. If a test
   copies every fixture, add the new key to `FIXTURE_FILES` in
   `tests/integration/test_pipeline.py`.
6. Never hardcode API keys; use `$VAR` header/param references (configured in
   `.env` from `.env.example`, the shell, or CI env). Missing keys skip the
   source until configured.

Example origin/feed:

```yaml
sources:
  - id: blocklist_de
    enabled: true
    weight: 75
    categories: {default: [scanner]}
    feeds:
      - id: blocklist_de
        fetch:
          url: https://www.blocklist.de/en/export.txt
          timeout_seconds: 60
        parse: {format: plain_lines, comment_prefix: "#"}
        output_types: [ip]
        fields: {ip: line}
        clean:
          - {op: parse_and_validate_ip}
          - {op: drop_private}
```

Notes:

- `output_types` drives which datasets a feed can populate. Each type needs a
  `fields` mapping (or `type_field`/`value_field`/`type_map` for type-routed
  feeds such as OTX).
- `role: allowlist` is only for suppression lists. Such a feed must output
  exactly `[domain]`; it is never scored or exported. Use it for legitimate
  host lists (e.g. alphaMountain top1M), not for VPN/datacenter/Tor.
- `json` feeds need a `records` path; `jsonl` feeds do not.
- Do not put secrets in `sources.yaml`. The config test rejects literal keys.
- If you change the config models (not just sources), regenerate the schemas:
  `uv run cs-lookup-files schema`.

## Source verification checklist

Before proposing a feed, confirm:

- final URL and HTTP status from a clean environment;
- stable format/headers and the exact field names/positions;
- expected indicator types and approximate row count;
- update cadence (skip feeds that go months without updates);
- license/terms and rate limits;
- secret requirements (prefer no auth);
- no overlap that would double-count an existing provider.

## Submitting a change

- Create a branch off `main`; keep commits focused and the history clean.
- Follow the existing code style (ruff enforces it).
- Include tests for any behaviour change, and make sure all checks pass.
- Open a PR with a short description; mention which lookup datasets or
  thresholds are affected.
- For scoring or export-floor changes, update `docs/scoring.md` and explain the
  precision/coverage trade-off.

## Reporting bugs / requesting features

Open an issue and label it appropriately (bug, enhancement, source-request).
For security issues, see [SECURITY.md](SECURITY.md).

## Questions

Prefer issues over direct contact so answers stay public and searchable.
