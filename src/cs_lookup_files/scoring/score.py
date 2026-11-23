from __future__ import annotations

import math
from datetime import datetime

import polars as pl

from ..models.config import ScoringSettings


def score_df(
    df: pl.DataFrame,
    weights: dict[str, int],
    settings: ScoringSettings,
    source_max_scores: dict[str, int],
    run_time: datetime,
    key_column: str,
) -> pl.DataFrame:
    """Compute ``confidence_score`` and ``source_count`` for every row.

    Formula (documented in docs/scoring.md):

    ``p_comb = 1 - prod(1 - w_i/100)`` over the row's sources,
    ``r = 0.5 ** (age_days / half_life)``,
    ``b = bonus_max * (1 - exp(-first_age_days / bonus_half_life))``,
    ``score = clamp(round(100 * p_comb * r + b), 0, 100)``,
    then capped by source-count band (70/90/100) and, for single-source rows,
    by the per-source ``max_single_source_score`` (e.g. OTX 55).

    ``df`` must contain ``sources`` (List[Utf8]), ``first_seen``/``last_seen``
    (Datetime UTC) and a unique ``key_column``. Returns ``df`` (order
    preserved) with ``confidence_score``/``source_count`` appended.
    """
    now_ts = int(run_time.timestamp())
    half_life = max(settings.half_life_days, 1e-9)
    DEFAULT_WEIGHT = 50  # unknown source ids (future config drift) are mildly trusted
    default_single = settings.default_single_source_score

    # Row-wise probabilities from the fused sources list.
    sources = df["sources"].to_list()
    # Per-row: p_comb, single-source max cap.
    row_probs: list[float] = []
    row_cap: list[int] = []
    row_source_count: list[int] = []
    for srcs in sources:
        row_source_count.append(len(srcs))
        p = 1.0
        # The single-source cap is the explicit per-source cap when it applies,
        # otherwise the default; multi-source rows fall back to the bands.
        single_cap = max(source_max_scores.get(s, 0) for s in srcs) or default_single
        for s in srcs:
            w = weights.get(s, DEFAULT_WEIGHT)
            p *= 1.0 - w / 100.0
        row_probs.append(1.0 - p)
        row_cap.append(single_cap)

    first_ts = (
        [int(x.timestamp()) for x in df["first_seen"].to_list()]
        if "first_seen" in df.columns
        else [now_ts] * len(sources)
    )
    last_ts = (
        [int(x.timestamp()) for x in df["last_seen"].to_list()]
        if "last_seen" in df.columns
        else [now_ts] * len(sources)
    )

    scores: list[int] = []
    for i in range(len(sources)):
        age_days = max(0.0, (now_ts - last_ts[i]) / 86400.0)
        first_age_days = max(0.0, (now_ts - first_ts[i]) / 86400.0)
        r = 0.5 ** (age_days / half_life)
        b = settings.persistence_bonus_max * (
            1.0
            - math.exp(
                -first_age_days / max(settings.persistence_half_life_days, 1e-9)
            )
        )
        raw = 100.0 * row_probs[i] * r + b
        raw = max(0.0, min(100.0, round(raw)))
        cnt = row_source_count[i]
        if cnt >= 3:
            band = settings.source_count_caps.get(3, 100)
        elif cnt == 2:
            band = settings.source_count_caps.get(2, 90)
        else:
            band = row_cap[i]
        scores.append(int(min(raw, band)))

    result = df.with_columns(
        pl.Series("source_count", row_source_count, dtype=pl.Int64),
        pl.Series("confidence_score", scores, dtype=pl.Int64),
    )
    return result
