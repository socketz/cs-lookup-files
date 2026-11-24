---
name: Bug report
about: Report a defect in the pipeline, a source collector, or a published lookup dataset
title: "[BUG] "
labels: bug
assignees: ''
type: Bug

---

**Summary**
One or two sentences: what broke, and where (collection, cleaning, scoring,
export, CLI, or a published dataset)?

**Dataset affected**
- [ ] `malicious_ips`
- [ ] `malicious_networks`
- [ ] `malicious_asns`
- [ ] `metadata.json` / `state.json`
- [ ] Not dataset-specific (collection, cleaning, scoring, ASN enrichment, CLI, CI)

**How you ran it**
- Mode: `uv run cs-lookup-files build`, `collect` or `validate` / Docker image / GitHub Actions run
  (link the run if applicable):
- Version or commit (release tags look like `YYYY.MM.DD.HHMM`):
- Source id(s) from `config/sources.yaml` involved (e.g. `spamhaus_drop`):
- Python version and OS:

**Steps to reproduce**
1.
2.
3.

Include the exact commands, flags (`--offline`, `--state`, `--version`, ...) and any
`config/*.yaml` change you made. **Redact API keys.**

**Expected vs actual**
What did you expect, and what happened? For data problems include row counts,
score values, a CSV snippet, or an excerpt of `metadata.json` (`ioc_counts`,
`source_status`).

**Does `--offline` reproduce it?**

- [ ] Yes, with `uv run cs-lookup-files build --offline --offline-dir fixtures`
- [ ] No
- [ ] Not tried

**Logs**

```
paste relevant log output here
```

Never paste `ABUSEIPDB_API_KEY` / `OTX_API_KEY` values, full request headers, or a
complete `.env` file. A single failing source is expected to leave the rest of the
run intact (the run only aborts when every source fails), so include the
`source_status` map when reporting partial data.

**Additional context**
CSV rows and `metadata.json` excerpts are more useful than screenshots. Mention
whether a previous `state.json` was passed with `--state`.

---
Please write the report in English. For security issues, do **not** open a public
issue; use the Security Advisory link in the template chooser (see `SECURITY.md`).
