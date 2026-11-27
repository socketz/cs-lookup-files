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

**Feed name and proposed ids**
Name, homepage, an origin `id` and a feed `id` matching `^[a-z0-9_]+$`
(e.g. origin `blocklist_de`, feed `blocklist_de`). Multiple feeds of the same
origin count as one confirming source.

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
- [ ] `jsonl`

Comment prefix, header line, delimiter, JSON `records` path, and pagination
parameters where applicable:

**Role and indicators**
- [ ] `intel` (normal feed; scored and exported)
- [ ] `allowlist` (suppression list; must output exactly `[domain]`; never scored
  or exported)

IOC types produced:
- [ ] IP addresses
- [ ] Networks (CIDR)
- [ ] ASN
- [ ] Domains / hostnames
- [ ] URLs
- [ ] MD5 / SHA256 hashes
- [ ] Email addresses

Which raw column/value maps to each type (by name or position)? For type-routed
feeds, list the raw `type` labels and their `type_map` targets.

**Categories**
Pick from the canonical vocabulary: `blocklist`, `malware_c2`, `malware`,
`abuse`, `scanner`, `botnet`, `phishing`, `spam`, `other`. State the `default`
category and, if the feed carries labels, the `field` + `mapping` to translate
them.

**Proposed weight (0–100) and rationale**
Weights and per-type `ioc_weights` are origin-level. See the full table in
`docs/scoring.md`; current anchors: Spamhaus 100, Abuse.ch 90, FireHOL 85,
AbuseIPDB 80, alphaMountain 80, AlienVault OTX 70.

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
  `fixtures/<feed_id>`, and an integration test
- [ ] No, requesting the source only

---
Please write the request in English.
