"""Confidence-scoring golden tests (tests/unit)."""
from datetime import UTC, datetime

import polars as pl

from cs_lookup_files.models.config import ScoringSettings
from cs_lookup_files.scoring import score

RUN_TIME = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)

# Weights aligned with config/settings.yaml and config/sources.yaml.
WEIGHTS = {
    "spamhaus_drop": 100,
    "abusech_feodo": 90,
    "firehol": 85,
    "abuseipdb": 80,
    "alienvault_otx": 70,
}
MAX_SCORES = {"alienvault_otx": 55}


def _df(sources_per_row, first_days_ago=None, last_days_ago=None):
    n = len(sources_per_row)
    first = first_days_ago or [0] * n
    last = last_days_ago or [0] * n
    first_seen = [datetime.fromtimestamp(RUN_TIME.timestamp() - f * 86400, tz=UTC) for f in first]
    last_seen = [datetime.fromtimestamp(RUN_TIME.timestamp() - d * 86400, tz=UTC) for d in last]
    return pl.DataFrame(
        {
            "k": [str(i) for i in range(n)],
            "sources": sources_per_row,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
    )


def _scores(df):
    return score.score_df(df, WEIGHTS, ScoringSettings(max_single_source_score=dict(MAX_SCORES)),
                          dict(MAX_SCORES), RUN_TIME, "k")["confidence_score"].to_list()


def test_single_trusted_source_in_band():
    df = _df([["spamhaus_drop"]])
    assert _scores(df) == [70]  # cap for the single-source band


def test_single_low_trust_source_capped():
    df = _df([["alienvault_otx"]])
    assert _scores(df) == [55]


def test_two_trusted_sources_hit_upper_band():
    df = _df([["spamhaus_drop", "abusech_feodo"]])
    assert _scores(df) == [90]


def test_three_or_more_sources_max():
    df = _df([["spamhaus_drop", "abusech_feodo", "firehol"]])
    assert _scores(df) == [100]


def test_confidence_decays_with_age():
    fresh = _df([["spamhaus_drop"]], first_days_ago=[0], last_days_ago=[0])
    old = _df([["spamhaus_drop"]], first_days_ago=[120], last_days_ago=[120])
    fresh_s, old_s = _scores(fresh)[0], _scores(old)[0]
    assert old_s < fresh_s


def test_persistence_bonus_increases_with_old_first_seen():
    # Same (aged) last_seen leaves headroom below the single-source cap, so the
    # persistence bonus is observable: old first_seen > recent first_seen.
    young = _df([["firehol"]], first_days_ago=[1], last_days_ago=[120])
    persistent = _df([["firehol"]], first_days_ago=[200], last_days_ago=[120])
    assert _scores(persistent)[0] > _scores(young)[0]


def test_low_conf_source_never_exceeds_cap_even_when_fresh():
    assert _scores(_df([["alienvault_otx"]])) == [55]


def test_score_always_bounded():
    df = _df([["spamhaus_drop", "abusech_feodo", "firehol", "abuseipdb", "alienvault_otx"]])
    vals = _scores(df)
    assert all(0 <= v <= 100 for v in vals)


def test_ioc_weights_override_per_type():
    """A source can be more (or less) weighted for one IOC type than another."""

    df = _df([["alienvault_otx"]], last_days_ago=[120], first_days_ago=[121]).with_columns(
        pl.Series("type", ["domain"])
    )
    # default: otx weight 70 -> decays low with age
    default = score.score_df(df, WEIGHTS, ScoringSettings(max_single_source_score=dict(MAX_SCORES)),
                             dict(MAX_SCORES), RUN_TIME, "k")["confidence_score"].to_list()[0]
    # override: otx strongly weighted for domain -> higher
    strong = score.score_df(df, WEIGHTS, ScoringSettings(max_single_source_score=dict(MAX_SCORES)),
                            dict(MAX_SCORES), RUN_TIME, "k",
                            ioc_weights={"alienvault_otx": {"domain": 95}})["confidence_score"].to_list()[0]
    assert strong > default
    # a weak override lowers it
    weak = score.score_df(df, WEIGHTS, ScoringSettings(max_single_source_score=dict(MAX_SCORES)),
                          dict(MAX_SCORES), RUN_TIME, "k",
                          ioc_weights={"alienvault_otx": {"domain": 30}})["confidence_score"].to_list()[0]
    assert weak < default
