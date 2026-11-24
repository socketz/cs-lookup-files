"""Offline integration tests for the full pipeline (tests/integration)."""
import csv
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from yaml import safe_load

from cs_lookup_files.models.config import SourcesFile
from cs_lookup_files.pipeline import Pipeline

BASE_DIR = Path(__file__).resolve().parents[2]
FIXTURES = BASE_DIR / "fixtures"

# Fixture files (named by feed id) and the origin ids they back.
FIXTURE_FILES = [
    "firehol_level1", "spamhaus_drop", "abusech_feodo", "abuseipdb", "alienvault_otx",
    "dshield_intelfeed", "ip2asn-v4.tsv", "ip2asn-v6.tsv",
]
# Origin source ids that have at least one fixture-backed feed.
SOURCE_IDS = ["firehol", "spamhaus", "abusech", "abuseipdb", "alienvault_otx", "dshield"]


def _settings():
    from cs_lookup_files.models.config import Settings

    return Settings.model_validate(safe_load((BASE_DIR / "config" / "settings.yaml").read_text()))


def _sources(config_path: Path) -> SourcesFile:
    return SourcesFile.model_validate(safe_load(config_path.read_text()))


def _run(config_path: Path, output_dir: Path, state_path: Path | None = None, offline_dir: Path | None = None):
    pipeline = Pipeline(
        _settings(),
        _sources(config_path),
        output_dir=output_dir,
        state_path=state_path,
        cache_dir=output_dir / "cache",
        offline=True,
        offline_dir=offline_dir or FIXTURES,
        run_time=datetime(2026, 11, 23, 12, 0, tzinfo=UTC),
        version="2026.11.23.1200",
    )
    return pipeline.run()


@pytest.fixture()
def output_dir(tmp_path: Path) -> Path:
    return tmp_path / "out"


def _read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_offline_build_writes_all_artifacts(output_dir):
    result = _run(BASE_DIR / "config" / "sources.yaml", output_dir)
    names = set(result.output_files)
    assert "malicious_ips.csv" in names
    assert "malicious_asns.csv" in names
    assert "metadata.json" in names
    for dataset in (
        "malicious_ips", "malicious_networks", "malicious_asns", "malicious_domains",
        "malicious_urls", "malicious_md5", "malicious_sha256", "malicious_emails",
    ):
        assert (output_dir / f"{dataset}.csv").exists()
        assert (output_dir / f"{dataset}.json").exists()
    assert (output_dir / "metadata.json").exists()
    assert (output_dir / "state.json").exists()


def test_metadata_counts_and_version(output_dir):
    _run(BASE_DIR / "config" / "sources.yaml", output_dir)
    meta = json.loads((output_dir / "metadata.json").read_text())
    assert meta["version"] == "2026.11.23.1200"
    assert set(SOURCE_IDS) <= set(meta["sources"])
    assert meta["ioc_counts"]["malicious_ips"] > 0
    assert meta["ioc_counts"]["malicious_networks"] > 0
    assert meta["ioc_counts"]["malicious_asns"] > 0
    assert meta["ioc_counts"]["malicious_domains"] > 0
    assert meta["ioc_counts"]["malicious_md5"] > 0
    assert meta["ioc_counts"]["malicious_sha256"] > 0


def test_private_ips_never_exported(output_dir):
    # The abuseipdb fixture includes 10.1.1.1 (private) which the global safety
    # net must drop despite the source config lacking a drop_private op.
    _run(BASE_DIR / "config" / "sources.yaml", output_dir)
    rows = _read_csv(output_dir / "malicious_ips.csv")
    ips = {r["ip"] for r in rows}
    assert "10.1.1.1" not in ips
    for r in rows:
        assert 0 <= int(r["confidence_score"]) <= 100


def test_otx_confidence_capped_and_multi_type(output_dir):
    _run(BASE_DIR / "config" / "sources.yaml", output_dir)
    rows = _read_csv(output_dir / "malicious_ips.csv")
    otx = [r for r in rows if "alienvault_otx" in r["sources"]]
    assert otx
    for r in otx:
        assert int(r["confidence_score"]) <= 55
    # Domains and hashes are distinct datasets.
    domains = _read_csv(output_dir / "malicious_domains.csv")
    assert any(r["domain"] == "evil.example.org" for r in domains)
    # URLs land in their own dataset, not in the IP dataset.
    all_ips = "\n".join(r["ip"] for r in _read_csv(output_dir / "malicious_ips.csv"))
    assert "evil.example.org/download" not in all_ips
    urls = _read_csv(output_dir / "malicious_urls.csv")
    assert any(r["url"] == "https://evil.example.org/download" for r in urls)
    assert _read_csv(output_dir / "malicious_md5.csv")
    assert _read_csv(output_dir / "malicious_sha256.csv")
    emails = _read_csv(output_dir / "malicious_emails.csv")
    assert any(r["email"] == "badactor@phishy-mail.com" for r in emails)


def test_state_merges_across_runs(output_dir):
    _run(BASE_DIR / "config" / "sources.yaml", output_dir)
    assert (output_dir / "state.json").exists()
    rows1 = _read_csv(output_dir / "malicious_ips.csv")
    out2 = output_dir.parent / "out2"
    _run(BASE_DIR / "config" / "sources.yaml", out2, state_path=output_dir / "state.json")
    rows2 = _read_csv(out2 / "malicious_ips.csv")
    assert len(rows2) == len(rows1)


def test_config_only_new_source(tmp_path):
    """Proving plugin-style extensibility: adding a source is config-only."""
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    source_text = (BASE_DIR / "config" / "sources.yaml").read_text()
    data = safe_load(source_text)

    data["sources"].append(
        {
            "id": "custom_fixture_source",
            "enabled": True,
            "weight": 60,
            "categories": {"default": ["malware"]},
            "feeds": [
                {
                    "id": "custom_feed",
                    "fetch": {"url": "https://example.org/feed.txt"},
                    "parse": {"format": "plain_lines", "comment_prefix": "#"},
                    "output_types": ["domain"],
                    "fields": {"domain": "line"},
                    "clean": [],
                }
            ],
        }
    )
    sources_file = config_dir / "sources.yaml"
    sources_file.write_text(json.dumps(data), encoding="utf-8")
    (config_dir / "settings.yaml").write_text(
        (BASE_DIR / "config" / "settings.yaml").read_text(), encoding="utf-8"
    )

    offline_dir = tmp_path / "fixtures"
    offline_dir.mkdir()
    for fixture in FIXTURE_FILES:
        (offline_dir / fixture).write_bytes((FIXTURES / fixture).read_bytes())
    (offline_dir / "custom_feed").write_text("# x\nevil-example.com\nnot-a-real-tld\n", encoding="utf-8")

    out = tmp_path / "out"
    _run(sources_file, out, offline_dir=offline_dir)
    domains = _read_csv(out / "malicious_domains.csv")
    vals = {r["domain"] for r in domains}
    assert "evil-example.com" in vals
    added = [r for r in domains if "custom_fixture_source" in r["sources"]]
    assert added and all("malware" in r["categories"] for r in added)
