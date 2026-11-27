# Security Policy

## Reporting vulnerabilities

Please do **not** open a public GitHub issue for security vulnerabilities.

Report them privately and responsibly to:

- Open a [GitHub Security Advisory](https://github.com/socketz/cs-lookup-files/security/advisories/new) (recommended), or
- Email the repository maintainers directly if you have a contact channel.

We will acknowledge reports within 5 business days and coordinate disclosure
with you. Do not test against production services or the public release
artifacts beyond what is necessary to reproduce the issue.

## Scope

This repository publishes machine-readable threat-intel lookup files consumed
by CrowdStrike Falcon. The following are treated as security-relevant:

- Credential handling (AbuseIPDB, AlienVault OTX keys).
- Injection or spoofing of indicators/ASN data that could alter the published
  datasets.
- Supply-chain risks (feed tampering, malicious upstream content) affecting the
  generated lookup files.
- CI/CD pipeline integrity (secrets, release signing, artifact provenance).

## Security posture

- **Never store secrets in the repository.** API keys are supplied via the CI
  workflow `env:` block, the shell environment, or a local `.env` (python-dotenv,
  gitignored) and referenced as `$VAR` in `config/sources.yaml`. Keys missing at
  runtime cause the affected source to be **skipped**, not failed.
- **Bogon filtering.** A global safety net removes private/reserved/documentation
  ranges even if a source config omits the relevant clean ops.
- **Allowlist suppression.** Feeds configured with `role: allowlist` (e.g.
  alphaMountain top1M) are never scored or exported; their hostnames suppress
  matching domain/URL indicators from the fresh frame and carried-over state.
- **Output validation.** Config and metadata are validated by Pydantic models;
  the test suite checks dataset shape, authoritative ASNs, empty-dataset
  omission and score bounds (0–100).
- **Build artifacts.** `cache/` (HTTP bodies, daily quota, ip2asn) and
  `state.json` contain public indicator/build data, not secrets. `.env` and
  `cache/` are gitignored; do not commit either.
- **Dependency scanning.** Third-party dependencies are pinned via `uv.lock`;
  keep them current. GitHub Dependabot alerts are recommended to be enabled.
- **Least privilege.** CI tokens use the minimum scopes required (`contents` for
  release creation, `actions: read` for artifact download).
- **Release integrity.** Releases are distributed through GitHub Releases.
  Per-file hashes/sizes and optional signing/provenance are tracked as P0 in
  `docs/roadmap.md`; until they exist, pin a `YYYY.MM.DD.HHMM` release for audit
  and verify it through GitHub.

## Supported versions

Only the current default branch and the latest tagged release receive security
fixes.