---
name: Feature request
about: Propose an improvement to the pipeline, scoring, exports, or automation
title: "[FEAT] "
labels: enhancement
assignees: ''
type: Feature

---

**Problem**
What can't you do today, and why does it matter operationally (LogScale hunting,
Fusion SOAR import, correlation rules, running the pipeline)?

**Proposed solution**
Describe the behaviour you want. If it touches feed handling, name the source and
the `config/sources.yaml` block it would affect.

**Area**
- [ ] Source collection / fetch (pagination, retries, headers)
- [ ] Parsing and cleaning (`parse`, `fields`, `clean` ops)
- [ ] ASN enrichment (ip2asn)
- [ ] Confidence scoring (`docs/scoring.md`, `config/settings.yaml`)
- [ ] Exporters and columns (CSV/JSON, `metadata.json`, `state.json`)
- [ ] CLI and configuration
- [ ] CI, releases, or Docker
- [ ] Documentation / CrowdStrike integration examples

**Scope check**
This project deliberately publishes only three consolidated datasets from free,
bulk feeds. Confirm the proposal fits:

- [ ] Keeps the three-dataset promise (`malicious_ips`, `malicious_networks`,
  `malicious_asns`) with no source-specific outputs
- [ ] Uses bulk feed downloads, not per-indicator API lookups
- [ ] Stays within free tiers and does not require paid data
- [ ] Does not add out-of-scope intelligence (domains, URLs, file hashes,
  malware-family attribution, case management or full TIP features)

**Alternatives considered**
Other approaches you considered, and why you rejected them.

**Additional context**
Links, upstream format samples, or prior art. If you are proposing a new feed,
use the **Source request** template instead.

---
Please write the request in English.
