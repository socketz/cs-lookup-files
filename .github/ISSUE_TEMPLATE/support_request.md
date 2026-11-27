---
name: Support request
about: Ask for help running the pipeline or consuming the lookup files
title: "[SUPPORT] "
labels: support
assignees: ''
type: Task

---

**What are you trying to do?**
- [ ] Run the pipeline locally (`uv run cs-lookup-files ...`)
- [ ] Run the pipeline in Docker
- [ ] Ingest the lookups into Falcon LogScale
- [ ] Import the lookups with a Fusion SOAR workflow
- [ ] Use the lookups in a correlation rule or scheduled enrichment
- [ ] Something else:

**Environment**
- Release version (`YYYY.MM.DD.HHMM`) or commit:
- Run mode (CLI / Docker image tag / GitHub Actions run link):
- OS, Python version (`uv --version`), and Docker version if applicable:
- Dataset(s) involved (`malicious_ips`, `malicious_networks`, `malicious_asns`,
  `malicious_domains`, `malicious_urls`, `malicious_md5`, `malicious_sha256`,
  `malicious_emails`, `metadata.json`, `state.json`) and whether it is the CSV or
  JSON form:

**What you tried**
Describe the steps and include links to the docs you followed:
[README quick start](https://github.com/socketz/cs-lookup-files/blob/master/README.md),
[architecture](https://github.com/socketz/cs-lookup-files/blob/master/docs/architecture.md),
[sources](https://github.com/socketz/cs-lookup-files/blob/master/docs/sources.md),
[scoring](https://github.com/socketz/cs-lookup-files/blob/master/docs/scoring.md),
[CrowdStrike integration](https://github.com/socketz/cs-lookup-files/blob/master/docs/crowdstrike.md),
[adjacent lookup integration](https://github.com/socketz/cs-lookup-files/blob/master/docs/integration.md).

**Error / logs**

```
paste the error or relevant log output here
```

**Dataset and `metadata.json` excerpt**
If the problem involves published data, include the release version, the
`ioc_counts` block, and the `source_status` map.

**Additional context**
Anything else that helps: lookup definitions, ingest mappings, or the FQL/SOAR
step that is failing.

---
Please write the request in English. Do **not** include `ABUSEIPDB_API_KEY` or
`OTX_API_KEY` values, request headers, or full `.env` files.

Security vulnerabilities must be reported through the Security Advisory link in
the template chooser (see `SECURITY.md`), not as public issues. New feed proposals
belong in the **Source request** template.
