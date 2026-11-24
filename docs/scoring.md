# Confidence Scoring

Every indicator is assigned a confidence score in **0..100** that is fully
deterministic and documented. The model combines source reputation, source
overlap, observation recency and historical persistence.

## Inputs

### Per-source weight `w_i`

Configured in `config/sources.yaml` (`weight`). Baselines:

| Source            | Weight |
|-------------------|--------|
| Spamhaus DROP     | 100    |
| Abuse.ch Feodo    | 90     |
| FireHOL           | 85     |
| AbuseIPDB         | 80     |
| AlienVault OTX    | 70     |

An unknown source id (e.g. future config drift) defaults to weight **50**.

### Per-IOC-type weight (`ioc_weights`)

Not every source is equally reliable for every indicator type a C2 tracker is
more trustworthy on `ip` than on `domain`; a phishing feed is stronger on
`url`/`domain`. Set an optional per-type override:

```yaml
- id: c2_intelfeeds
  weight: 75            # global fallback
  ioc_weights:
    ip: 85              # stronger on IPs
    domain: 50          # weaker on domains
```

For a given row, the effective weight is
`ioc_weights[source].get(type, weight)`. This keeps the global table stable
while letting each feed express type-specific reliability without core changes.

### Probability model

Each source ``i`` is treated as an independent confirmation with probability

```
p_i = w_i / 100
```

Over the set of sources that flagged an indicator, the combined probability is

```
p_comb = 1 - prod_i (1 - p_i)
```

Single high-trust sources saturate quickly; multiple confirmations push the
result toward 1.0.

### Recency

```
age_days   = max(0, (run_time - last_seen) / 86400)
r          = 0.5 ** (age_days / half_life_days)      # half_life_days = 30
```

Fresh observations score near full; confidence halves every 30 days since the
last observation.

### Persistence bonus

```
b = persistence_bonus_max * (1 - exp(-first_age_days / persistence_half_life_days))
```

Where `persistence_bonus_max = 5`, `persistence_half_life_days = 60`, and
`first_age_days` is the age of `first_seen`. Indicators observed across many
runs earn a small, bounded lift toward +5.

### Source-count / single-source caps

Scores are forced into documented bands so a lone low-trust source can never be
treated as very high confidence:

| Sources | Cap |
|---------|-----|
| 1       | per-source `max_single_source_score` (default 70; OTX 55) |
| 2       | 90  |
| 3+      | 100 |

## Final formula

```
score = clamp( round( 100 * p_comb * r + b ), 0, 100 )
score = min(score, band_cap)
```

## Guarantees (covered by unit tests)

- **Single source → 40–70.** A fresh trusted source lands at its band cap.
- **Two trusted sources → 75–90.**
- **Three or more trusted sources → 90–100.**
- **One low-confidence source never scores very high** (OTX is capped at 55).
- **Score decays with age** toward the persistence floor, never upward with time.
- **Persistence raises an aged indicator** (old `first_seen`) within its band.
- Scores are always integers in `0..100`.

## Configuration

All thresholds live in `config/settings.yaml` under `scoring:`. Adjust
`half_life_days`, `ttl_days`, `persistence_*`, `max_single_source_score`,
`source_count_caps` and `min_confidence` without touching code. Per-source
reliability (`weight`) and per-type relevance (`ioc_weights`) are set in each
entry of `config/sources.yaml`.