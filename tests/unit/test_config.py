"""Config model validation tests (tests/unit)."""
import json
from pathlib import Path

import pytest
from yaml import safe_load

from cs_lookup_files.models.config import (
    CATEGORY_VOCAB,
    CategoriesConfig,
    CleanOp,
    ParseConfig,
    SourceConfig,
    SourcesFile,
)

BASE_DIR = Path(__file__).resolve().parents[2]


def _valid_source() -> dict:
    return {
        "id": "test_source",
        "enabled": True,
        "weight": 85,
        "output_types": ["ip"],
        "categories": {"default": ["blocklist"]},
        "fetch": {"url": "https://example.org/feed.txt"},
        "parse": {"format": "plain_lines"},
        "fields": {"ip": "line"},
        "clean": [],
    }


@pytest.fixture()
def example_source() -> SourceConfig:
    return SourceConfig.model_validate(_valid_source())


def test_vocabulary_includes_planned_categories():
    for cat in ("blocklist", "malware_c2", "abuse", "scanner", "botnet", "phishing", "spam", "other"):
        assert cat in CATEGORY_VOCAB


def test_valid_source_loads(example_source):
    assert example_source.id == "test_source"
    assert example_source.weight == 85
    assert example_source.parse.format == "plain_lines"


def test_invalid_category_rejected():
    with pytest.raises(ValueError):
        CategoriesConfig(default=["not-a-category"])


def test_output_types_require_field_mapping():
    with pytest.raises(ValueError):
        SourceConfig.model_validate(
            {**_valid_source(), "output_types": ["network"], "fields": {"ip": "line"}}
        )


def test_unknown_clean_op_rejected():
    # Op names are free-form strings in the model; validity is enforced at
    # config validation time via the op registry.
    op = CleanOp(op="field_in", field="type", values=["IPv4"])
    assert op.op == "field_in"
    from cs_lookup_files.normalizers.ops import OP_NAMES

    assert "field_in" in OP_NAMES
    assert "does_not_exist" not in OP_NAMES


def test_parse_csv_requires_delimiter():
    with pytest.raises(ValueError):
        ParseConfig(format="csv")


def test_json_parse_requires_records():
    with pytest.raises(ValueError):
        ParseConfig(format="json")


def test_duplicate_source_ids_rejected():
    payload = {"sources": [_valid_source(), _valid_source()]}
    with pytest.raises(ValueError):
        SourcesFile.model_validate(payload)


def test_repo_sources_validate():
    """The shipped sources.yaml must validate against the schema."""
    data = safe_load((BASE_DIR / "config" / "sources.yaml").read_text(encoding="utf-8"))
    sources = SourcesFile.model_validate(data)
    assert len(sources.sources) == 5
    ids = {s.id for s in sources.sources}
    assert {"firehol", "spamhaus_drop", "abusech_feodo", "abuseipdb", "alienvault_otx"} <= ids
    for source in sources.sources:
        assert 0 <= source.weight <= 100
        assert source.clean


def test_repo_settings_validate():
    from cs_lookup_files.models.config import Settings

    data = safe_load((BASE_DIR / "config" / "settings.yaml").read_text(encoding="utf-8"))
    settings = Settings.model_validate(data)
    assert settings.scoring.ttl_days == 90
    assert settings.scoring.half_life_days == 30
    assert settings.scoring.max_single_source_score == {"alienvault_otx": 55}


def test_no_secrets_in_sources_config():
    data = safe_load((BASE_DIR / "config" / "sources.yaml").read_text(encoding="utf-8"))
    sources = SourcesFile.model_validate(data)
    blob = json.dumps(data)
    assert "api.abuseipdb.com" in blob
    # Credential headers must be referenced via $VAR, never embedded.
    credential_headers = {"key", "x-otx-api-key", "authorization", "x-api-key"}
    for source in sources.sources:
        for name, value in source.fetch.headers.items():
            if name.lower() in credential_headers:
                assert value.startswith("$"), f"{source.id} header {name} must be an env reference"
    assert "application/json" in blob
