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

- **Never store secrets in the repository.** API keys are supplied via the
  workflow `env:` block and referenced as `$VAR` in `config/sources.yaml`.
- **Bogon filtering.** A global safety net removes private/reserved/documentation
  ranges even if a source config omits the relevant clean ops.
- **Output validation.** Each dataset is validated by Pydantic schemas and the
  test suite, and scores are bounded to 0–100.
- **Dependency scanning.** Third-party dependencies are pinned via `uv.lock`;
  keep them current. GitHub Dependabot alerts are recommended to be enabled.
- **Least privilege.** CI tokens use the minimum scopes required (`contents` for
  release creation, `actions: read` for artifact download).

## Supported versions

Only the current default branch and the latest tagged `cs-lookup-files` package
receive security fixes.