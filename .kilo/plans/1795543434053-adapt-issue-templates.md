# Plan: adapt GitHub issue/PR templates to cs-lookup-files

## Goal

Replace the generic, PR-authored templates (`.github/ISSUE_TEMPLATE/bug_report.md`,
`feature_request.md`, `support_request.md`, currently merged in this branch) with
templates that fit this repository: a config-driven threat-intel ETL pipeline that
publishes three CrowdStrike Falcon lookup datasets every 6 hours.

The templates must collect the information maintainers actually need to triage:
which dataset, which source id, which execution mode (CLI / Docker / Actions),
which release version, and whether the issue reproduces offline against `fixtures/`.

## Decisions already made (do not re-litigate)

| Decision | Choice |
|---|---|
| Format | Markdown templates with YAML frontmatter (no Issue Forms). Keep files `.md`. |
| Scope | Adapt the 3 PR templates, add `source_request.md`, add `PULL_REQUEST_TEMPLATE.md`. |
| Labels | Create the missing `source-request` label so `CONTRIBUTING.md` ("bug, enhancement, source-request") becomes true. Reuse existing labels otherwise: `bug`, `enhancement`, `support`. |
| Issue types | Keep `type:` frontmatter. Issue types are GA for personal-account repos (socketz/cs-lookup-files is user-owned, not an org), defaults `Bug` / `Task` / `Feature`. Use `Bug`, `Feature`, `Task`, `Feature` respectively. |
| Chooser | Add `.github/ISSUE_TEMPLATE/config.yml` with `blank_issues_enabled: true` plus contact links (security advisory, docs). |
| Language | All template text in English (repo rule). |

## Files

All paths relative to repo root `D:\projects\cs-lookup-files\.kilo\worktrees\butter-respect`.

### 0. Create the label (repo mutation, needs `gh` auth)

```bash
gh label create source-request --description "Proposal for a new intelligence source (config-only feed)" --color 0e8a16
```

Idempotency: if it already exists, `gh label create` fails harmlessly — verify with
`gh label list` and treat "already exists" as success. Do not touch other labels.

### 1. `.github/ISSUE_TEMPLATE/bug_report.md` (rewrite)

Frontmatter:

```yaml
---
name: Bug report
about: Report a defect in the pipeline, a source collector, or a published lookup dataset
title: "[BUG] "
labels: bug
assignees: ''
type: Bug
---
```

Body sections (replace browser/smartphone boilerplate entirely):

- **Summary** — one or two sentences: what broke, where.
- **Dataset affected** — checkbox list: `malicious_ips`, `malicious_networks`,
  `malicious_asns`, `metadata.json` / `state.json`, not dataset-specific
  (collection, cleaning, scoring, ASN enrichment, CLI, CI).
- **How you ran it** — mode (`uv run cs-lookup-files build|collect|validate`,
  Docker image, or a GitHub Actions run link); release version
  (`YYYY.MM.DD.HHMM`) or commit SHA; source id(s) from `config/sources.yaml`;
  Python version and OS.
- **Steps to reproduce** — numbered; include exact commands, flags and any
  `config/*.yaml` change. Instruct: "Redact API keys."
- **Expected vs actual** — row counts, sample rows/scores; CSV snippet or
  `metadata.json` excerpt (`ioc_counts`, per-source `status`).
- **Does `--offline` reproduce it?** — checkboxes: yes
  (`uv run cs-lookup-files build --offline --offline-dir fixtures`), no, not tried.
- **Logs** — fenced block guidance; explicit warning: never paste
  `ABUSEIPDB_API_KEY` / `OTX_API_KEY` values or full request headers.
- **Additional context** — state that CSV/metadata excerpts are more useful than
  screenshots.

Reference real behaviour so the template stays accurate: one failing source must
not fail the run (only all-sources failure aborts), and `--state` merges history.

### 2. `.github/ISSUE_TEMPLATE/feature_request.md` (rewrite)

Frontmatter: `name: Feature request`, `about: Propose an improvement to the pipeline, scoring, exports, or automation`,
`title: "[FEAT] "`, `labels: enhancement`, `type: Feature`.

Body sections:

- **Problem** — what can't be done today, and why it matters operationally.
- **Proposed solution** — expected behaviour; for feed work, name the source and
  the `config/sources.yaml` block it would touch.
- **Area** — checkbox list: source collection/fetch, parsing/cleaning,
  ASN enrichment, confidence scoring, exporters/columns, CLI/config, CI/releases,
  docs/CrowdStrike integration.
- **Scope check** — required checkboxes stating the project charter:
  keeps the three-dataset promise (no source-specific outputs); uses bulk feed
  downloads (no per-indicator API lookups); stays within free tiers; respects
  out-of-scope items (domains/URLs/file hashes, malware-family attribution,
  case management/TIP).
- **Alternatives considered**.
- **Additional context**.
- One line pointing new feeds to the *Source request* template.

### 3. `.github/ISSUE_TEMPLATE/support_request.md` (rewrite, replaces `TBD`)

Frontmatter: `name: Support request`, `about: Ask for help running the pipeline or consuming the lookup files`,
`title: "[SUPPORT] "`, `labels: support`, `type: Task` (currently missing `type`).

Body sections:

- **What are you trying to do?** — consume lookups in Falcon LogScale, Fusion SOAR,
  correlation rules, run the pipeline locally/Docker, or add a source.
- **Environment** — release version or commit, run mode, OS, Python/uv version,
  Docker tag if applicable.
- **What you tried** — with links: `README.md` quick start, `docs/architecture.md`,
  `docs/sources.md`, `docs/scoring.md`, `docs/crowdstrike.md`.
- **Error / logs** — redact secrets (`ABUSEIPDB_API_KEY`, `OTX_API_KEY`).
- **Dataset + `metadata.json` excerpt** — dataset name, version, `ioc_counts`,
  failing source status.
- Notes: vulnerabilities go to the Security Advisory link in `SECURITY.md`,
  not public issues; new feeds belong in the *Source request* template.

### 4. `.github/ISSUE_TEMPLATE/source_request.md` (new)

Frontmatter: `name: Source request`, `about: Propose a new threat-intel feed as a config-only addition`,
`title: "[SOURCE] "`, `labels: source-request`, `type: Feature`.

Body sections (aligned with the config schema in `src/cs_lookup_files/models/config.py`
and `docs/sources.md`):

- **Feed name and proposed `id`** — lowercase snake_case matching
  `^[a-z0-9_]+$` (e.g. `blocklist_de`).
- **Bulk download URL** — must be a bulk export; state explicitly that
  per-indicator APIs are rejected.
- **Format** — one of `plain_lines`, `ipset`, `cidr_lines`, `csv`, `tsv`, `json`;
  plus comment prefix, header/delimiter, and JSON `records` path where relevant.
- **Indicators and field mapping** — IPs, networks, or both; which raw column
  maps to `ip` / `network` / `last_seen`.
- **Categories** — must come from the canonical vocabulary
  (`blocklist`, `malware_c2`, `malware`, `abuse`, `scanner`, `botnet`, `phishing`,
  `spam`, `other`) via `default` and/or `field` + `mapping`.
- **Proposed weight 0–100 and rationale** — note existing weights:
  Spamhaus DROP 100, Abuse.ch Feodo 90, FireHOL 85, AbuseIPDB 80, AlienVault OTX 70.
- **Cleaning needs** — e.g. `drop_private`, `drop_bogon_networks`,
  `require_globally_routable`, `field_ge`, `field_in`, `map_values`.
- **Licensing / terms and rate limits** — free-tier sustainability.
- **Sample rows** — 5–10 lines of the raw feed.
- **Willing to open a PR?** — config-only block + fixture under `fixtures/<id>`
  + integration test, per `CONTRIBUTING.md`.

### 5. `.github/PULL_REQUEST_TEMPLATE.md` (new)

Sections:

- **Summary** — what changed and why; link the issue.
- **Type of change** — checkboxes: config-only source addition; pipeline/cleaning
  logic; scoring model; exporters/column schema; CLI/config; CI/releases; docs only.
- **Datasets and compatibility** — which of `malicious_ips`, `malicious_networks`,
  `malicious_asns` are affected; whether CSV header/column order, `metadata.json`
  shape, `state.json` shape, or score bands change (consumer-visible break).
- **How validated** — paste results of `uv run ruff check src tests`,
  `uv run mypy src`, `uv run pytest tests -q`, and an offline build
  (`uv run cs-lookup-files build --offline --offline-dir fixtures --output-dir output`);
  include row-count deltas or sample rows when data output changes.
- **Checklist** — English only; tests added/updated; docs updated when behaviour
  changes; no secrets or `.env` committed; no generated artifacts committed;
  the three-dataset promise and free-tier rules respected; deterministic output.

### 6. `.github/ISSUE_TEMPLATE/config.yml` (new)

```yaml
blank_issues_enabled: true
contact_links:
  - name: Security vulnerability
    url: https://github.com/socketz/cs-lookup-files/security/advisories/new
    about: Do not open a public issue for security problems. See SECURITY.md.
  - name: CrowdStrike integration guide
    url: https://github.com/socketz/cs-lookup-files/blob/main/docs/crowdstrike.md
    about: LogScale lookups, Fusion SOAR imports and correlation rules.
  - name: Sources and scoring
    url: https://github.com/socketz/cs-lookup-files/blob/main/docs/sources.md
    about: Feed catalogue, parsing formats and the confidence model.
```

## Constraints and correctness notes

- Do not introduce new top-level frontmatter keys beyond `name`, `about`,
  `title`, `labels`, `assignees`, `type`.
- `name` must be longer than 3 characters; titles use a trailing space after the
  prefix (`"[BUG] "`).
- Every referenced label must exist before merge: `bug`, `enhancement`, `support`
  already exist; `source-request` is created in step 0.
- `type:` values must match the account's issue types; verify with
  `gh api repos/socketz/cs-lookup-files/issue-types` (defaults `Bug`, `Task`,
  `Feature`). If a value is unknown to the account, drop that key instead of
  inventing a type.
- Keep references to real paths/commands: `config/settings.yaml`,
  `config/sources.yaml`, `fixtures/<source_id>`, `--offline`, `--state`,
  `metadata.json`, `state.json`. Do not reference endpoints or flags that do not
  exist.
- Out of scope: source code, workflows, `README.md`, `CONTRIBUTING.md`,
  `SECURITY.md`, docs content, label descriptions for existing labels, and
  converting templates to Issue Forms. Do not commit unless asked.

## Validation

1. `gh label list` shows `source-request`.
2. `gh api repos/socketz/cs-lookup-files/issue-types` confirms `Bug`, `Task`,
   `Feature`.
3. Frontmatter parses and label/type keys are valid, e.g.
   `uv run python -c "import pathlib,yaml,sys; [print(p, yaml.safe_load(p.read_text(encoding='utf-8').split('---')[1])) for p in pathlib.Path('.github/ISSUE_TEMPLATE').glob('*.md')]"`
   (each file must also be checked that it has exactly one leading `---` block).
4. `git diff --stat` shows only the six `.github` files (plus the new label).
5. Optional but recommended after pushing the branch: open
   `https://github.com/socketz/cs-lookup-files/issues/new/choose` from the default
   branch preview to confirm all four templates and the contact links render.
   Templates only load from the default branch, so a local preview is not possible.

## Risks

- Private repo: templates and the chooser are only visible to collaborators; that
  is expected.
- Wrong `type:` value silently drops the type (or rejects creation); the API check
  in step 3 covers it.
- Over-specified bug template could feel heavy; keep it to the sections above and
  mark only the core ones as clearly needed.
