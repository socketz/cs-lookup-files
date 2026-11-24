---
name: Source request
about: Propose a new threat-intel feed as a config-only addition
title: "[SOURCE] "
labels: source-request
assignees: ''
type: Feature

---

New feeds are added by appending a block to `config/sources.yaml`; no core code
changes are expected. Fill in what you can — see `docs/sources.md` and
`CONTRIBUTING.md` for the existing patterns.

**Feed name and proposed source `id`**
Name, homepage, and an id matching `^[a-z0-9_]+$` (e.g. `blocklist_de`).

**Bulk download URL**
The URL used by the collector. This project only consumes bulk downloads, bulk
JSON exports, TAXII, or authenticated bulk APIs — per-indicator lookups are
rejected.

**Format**
- [ ] `plain_lines`
- [ ] `ipset`
- [ ] `cidr_lines`
- [ ] `csv`
- [ ] `tsv`
- [ ] `json`

Comment prefix, header line, delimiter, JSON `records` path, and pagination
parameters where applicable:

**Indicators and field mapping**
- [ ] IP addresses
- [ ] Networks (CIDR)
- [ ] Both

Which raw column maps to `ip`, `network`, and `last_seen` (by name or position)?
Do the rows include non-IP indicators (domains, URLs, hashes) that must be
filtered?

**Categories**
Pick from the canonical vocabulary: `blocklist`, `malware_c2`, `malware`,
`abuse`, `scanner`, `botnet`, `phishing`, `spam`, `other`. State the `default`
category and, if the feed carries labels, the `field` + `mapping` to translate
them.

**Proposed weight (0–100) and rationale**
For reference, current weights: Spamhaus DROP 100, Abuse.ch Feodo 90, FireHOL 85,
AbuseIPDB 80, AlienVault OTX 70.

**Cleaning needs**
Which ops apply, e.g. `parse_and_validate_ip`, `drop_private`,
`drop_bogon_networks`, `require_globally_routable`, `field_in`, `field_ge`,
`map_values`.

**Licensing, terms, and rate limits**
License or terms of use, and any rate limits that affect free-tier sustainability.

**Sample rows**

```
paste 5-10 lines of the raw feed here
```

**Willing to open a PR?**
- [ ] Yes — config block in `config/sources.yaml`, a fixture under
  `fixtures/<id>`, and an integration test
- [ ] No, requesting the source only

---
Please write the request in English.
