# Confidence Scoring

Every indicator receives a confidence score in **0..100**. The model is fully
deterministic and combines source reputation, source overlap, observation
recency and historical persistence. It runs after allowlist suppression, so
allowlisted domains/URLs are never scored.

## Inputs

### Per-source weight `w_i`

Configured per **origin** in `config/sources.yaml` (`weight`). Feeds under the
same origin share one identity: an indicator confirmed by two feeds of the same
origin counts as **one** confirming source. The current shipped weights are:

| Origin | Weight | `ioc_weights` override | Primary IOC types |
|--------|--------|------------------------|-------------------|
| `spamhaus` | 100 | — | network, asn |
| `abusech` | 90 | ip: 92 | ip |
| `firehol` | 85 | — | ip, network |
| `c2intelfeeds` | 82 | ip: 85 | ip |
| `abuseipdb` | 80 | — | ip |
| `openphish` | 80 | url: 85 | url |
| `phishtank` | 80 | url: 85 | url |
| `viriback` | 80 | ip: 82, url: 78 | ip, url |
| `alphamountain` | 80 | — | domain (threat feed only) |
| `ipsum` | 78 | — | ip |
| `alienvault_reputation` | 78 | — | ip |
| `cins` | 75 | — | ip |
| `botvrij` | 72 | — | ip, domain, url, sha256 |
| `linuxtracker` | 72 | — | ip |
| `dshield` | 70 | — | ip |
| `alienvault_otx` | 70 | — | ip, network, domain, url, md5, sha256, email |
| `tweetfeed` | 70 | ip: 70, domain: 72, url: 75, md5: 70, sha256: 70 | ip, domain, url, md5, sha256 |
| `bbcan177` | 70 | — | ip, domain |
| `jamesbrine` | 70 | — | ip |
| `minerchk` | 70 | — | domain |
| `joewein` | 65 | — | domain |
| `nocoin` | 65 | — | domain |
| `disconnect` | 65 | — | domain |

An unknown source id (for example, config drift) defaults to weight **50**.

### Per-IOC-type weight (`ioc_weights`)

Sources are not equally reliable for every indicator type. The optional
`ioc_weights` map overrides the origin weight for a specific type:

```yaml
- id: c2intelfeeds
  weight: 82              # global fallback
  ioc_weights:
    ip: 85                # stronger on IPs
```

For a row of type `t`, the effective weight is
`ioc_weights[source].get(t, weight)`. The global table stays stable while each
feed expresses type-specific reliability without core changes.

### Probability model

Each source `i` is treated as an independent confirmation with probability

```
p_i = w_i / 100
```

Over the set of origins that flagged an indicator:

```
p_comb = 1 - prod_i (1 - p_i)
```

Multiple independent confirmations push `p_comb` toward 1.0; a single source
saturates at its own weight.

### Recency

```
age_days = max(0, (run_time - last_seen) / 86400)
r        = 0.5 ** (age_days / half_life_days)
```

`half_life_days = 30`: fresh observations score near full and confidence halves
for every 30 days since the last observation. Because `last_seen` is merged
through state, a rebuild does not reset the clock unless the indicator is
observed again.

### Persistence bonus

```
b = persistence_bonus_max
    * (1 - exp(-first_age_days / persistence_half_life_days))
```

With `persistence_bonus_max = 5` and `persistence_half_life_days = 60`, an
indicator observed across many runs earns a small bounded lift toward +5. The
bonus never pushes a row above its band cap.

### Source-count / single-source caps

Scores are capped by the number of **distinct origins** that reported the
indicator. These are maxima, not guaranteed scores:

| Sources | Cap |
|---------|-----|
| 1 | per-source `max_single_source_score`, else `default_single_source_score` (70) |
| 2 | 90 (`source_count_caps[2]`) |
| 3+ | 100 (`source_count_caps[3]`) |

Shipped single-source caps (`config/settings.yaml`):

| Origin | Single-source cap | Rationale |
|--------|-------------------|-----------|
| `spamhaus` | 90 | Authoritative DROP / ASN-DROP; must clear the 75 floor |
| `alienvault_otx` | 55 | Broad, noisy multi-type feed |
| `ipsum`, `linuxtracker` | 55 | Weak single-signal lists |
| `cins`, `dshield`, `bbcan177`, `minerchk` | 50 | Low-specificity scanner/block lists |
| `jamesbrine`, `joewein`, `nocoin`, `disconnect` | 45 | Low-specificity hosts/lists |
| all other origins | 70 (default) | Single non-authoritative confirmation |

A per-source cap only affects **single-source** rows. Corroborated rows use the
2/3+ bands, but their raw score still depends on the weights and recency; two
weak sources can remain below 75 and three weak sources can remain below 90.

### ASN scores come from ASN lists, not from IPs

`malicious_asns` is a first-class `asn` indicator type fed **only** by
authoritative ASN-level lists (Spamhaus ASN-DROP). An ASN is never derived by
rolling up flagged IPs: a single malicious IP inside a large provider would
otherwise mark the entire ASN as malicious (a false positive with major
operational cost). The `asn`/`asn_name`/`country` columns on `malicious_ips` and
`malicious_networks` are **context only** and do not imply the ASN is bad.

## Export floors

`config/settings.yaml` applies a precision floor at export:

- `min_confidence: 75` is the global default.
- `min_confidence_by_type` overrides it per IOC type. Today only
  `email: 55` is set.

Consequences:

- Single-source non-authoritative rows (default cap 70) are dropped.
- OTX-only `ip`/`network`/`domain`/`url`/`md5`/`sha256` rows (cap 55) are
  dropped, so those datasets need another source to corroborate OTX.
- `malicious_emails` is the deliberate exception: OTX is currently its only
  email source, so the 55 per-type floor keeps OTX-only emails publishable.
  Raise `min_confidence_by_type.email` to 75 if you prefer corroboration only.
- Spamhaus DROP/ASN-DROP rows survive because `spamhaus` has a single-source cap
  of 90.
- `ttl_days: 90` removes rows whose `last_seen` is older than 90 days.

Consumers receive a pre-filtered, precision-oriented dataset and can apply their
own higher thresholds (for example, 90) for automated response. Raising a floor
trades coverage for precision; lowering it restores coverage.

## Allowlist feeds

Feeds declared with `role: allowlist` (for example alphaMountain top1M) are
never scored and never appear in the confidence bands. Their canonical hostnames
are removed from the fresh frame and from carried-over state before scoring, so
matching `domain`/`url` indicators are suppressed outright rather than
down-weighted. Matching is exact, plus the `www.` variant (`example.com` matches
`www.example.com`); URL rows are matched by hostname. Subdomains are **not**
blanket-suppressed, which avoids discarding user content on popular platforms.

## Final formula

```
p_comb = 1 - prod_i (1 - w_i/100)
r      = 0.5 ** (age_days / half_life_days)
b      = persistence_bonus_max * (1 - exp(-first_age_days / persistence_half_life_days))

score = clamp(round(100 * p_comb * r + b), 0, 100)
score = min(score, band_cap)
```

## Guarantees (covered by unit tests)

- **A single source cannot exceed its cap**: 70 by default, 90 for `spamhaus`,
  55 for OTX and the other capped origins, 45–50 for low-specificity lists.
- **Two origins cannot exceed 90; three or more cannot exceed 100.** These are
  ceilings, not floors: the raw score can be lower for weak sources or stale
  observations.
- **One low-confidence source never scores very high** (OTX is capped at 55).
- **Score decays with age** toward the persistence floor, never upward with time.
- **Persistence raises an aged indicator** (old `first_seen`) within its band.
- **Per-type `ioc_weights` override** the global weight for that row's type.
- Scores are always integers in `0..100`.

## Configuration

All thresholds live in `config/settings.yaml` under `scoring:`: `half_life_days`,
`ttl_days`, `persistence_bonus_max`, `persistence_half_life_days`,
`default_single_source_score`, `max_single_source_score`, `source_count_caps`,
`min_confidence` and `min_confidence_by_type`. Per-origin reliability
(`weight`) and per-type relevance (`ioc_weights`) live in `config/sources.yaml`.
No core change is needed to tune the model.
