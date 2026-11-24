# Contributing

Thanks for taking the time to contribute to **cs-lookup-files**.

## Ground rules

- All code, tests, docs, commits, issues and PRs must be written in **English**.
- Keep the scope small. This project deliberately avoids becoming a full TIP;
  the goal is a handful of high-quality lookup files for CrowdStrike Falcon.
- Favour **simplicity, determinism and reproducibility** over feature count.
- New feeds should be added as **config** (see `config/sources.yaml`); core code
  changes are discouraged for source additions.

## Development setup

```bash
uv sync                       # installs the environment (Python 3.13)
uv run pytest tests -q        # run unit + offline integration tests
uv run ruff check src tests   # lint
uv run mypy src               # type check
```

## Adding a new source (config-only)

1. Append a block to `config/sources.yaml` describing `fetch`, `parse`,
   `fields`, `clean` and output types. See `docs/sources.md`.
2. Add a small sample feed at `fixtures/<source_id>` if you want an offline test.
3. Run `uv run cs-lookup-files validate` to check the schema.
4. Add/adjust a test in `tests/` demonstrating the source works end-to-end.
5. Never hardcode API keys; use `$VAR` header references (configured in
   `.env` from `.env.example`, the shell, or CI env). Missing keys skip the
   source until configured.

Example:

```yaml
- id: blocklist_de
  enabled: true
  weight: 75
  output_types: [ip]
  categories: {default: [scanner]}
  fetch: {url: "https://www.blocklist.de/en/export.txt"}
  parse: {format: plain_lines, comment_prefix: "#"}
  fields: {ip: line}
  clean: [{op: parse_and_validate_ip}, {op: drop_private}]
```

## Submitting a change

- Create a branch off `main`; keep commits focused and the history clean.
- Follow the existing code style (ruff enforces it).
- Include tests for any behaviour change, and make sure all checks pass.
- Open a PR with a short description; mention which lookup datasets or
  thresholds are affected.

## Reporting bugs / requesting features

Open an issue and label it appropriately (bug, enhancement, source-request).
For security issues, see [SECURITY.md](SECURITY.md).

## Questions

Prefer issues over direct contact so answers stay public and searchable.