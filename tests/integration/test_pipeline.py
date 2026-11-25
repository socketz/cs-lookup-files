"""Offline integration tests for the full pipeline (tests/integration)."""
import csv
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from yaml import safe_dump, safe_load

from cs_lookup_files.models.config import Settings, SourcesFile
from cs_lookup_files.pipeline import Pipeline

BASE_DIR = Path(__file__).resolve().parents[2]
FIXTURES = BASE_DIR / "fixtures"

# Fixture files (named by feed id) and the origin ids they back.
FIXTURE_FILES = [
    "firehol_level1", "spamhaus_drop", "spamhaus_asndrop", "abusech_feodo",
    "abuseipdb", "alienvault_otx", "dshield_intelfeed", "cins_army",
    "openphish", "joewein_domains", "alphamountain_top1m", "alphamountain_threat",
    "ip2asn-v4.tsv", "ip2asn-v6.tsv",
]
# Origin source ids that have at least one fixture-backed feed.
SOURCE_IDS = ["firehol", "spamhaus", "abusech", "abuseipdb", "alienvault_otx", "dshield"]
ALL_DATASETS = (
    "malicious_ips", "malicious_networks", "malicious_asns", "malicious_domains",
    "malicious_urls", "malicious_md5", "malicious_sha256", "malicious_emails",
)


def _settings(min_confidence: int | None = None) -> Settings:
    data = safe_load((BASE_DIR / "config" / "settings.yaml").read_text())
    if min_confidence is not None:
        data["scoring"]["min_confidence"] = min_confidence
    return Settings.model_validate(data)


def _sources(config_path: Path) -> SourcesFile:
    return SourcesFile.model_validate(safe_load(config_path.read_text()))


def _run(
    config_path: Path,
    output_dir: Path,
    state_path: Path | None = None,
    offline_dir: Path | None = None,
    min_confidence: int | None = None,
):
    pipeline = Pipeline(
        _settings(min_confidence),
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


def _header(path: Path) -> list[str]:
    with path.open(newline="", encoding="utf-8") as handle:
        return next(csv.reader(handle))


def test_offline_build_writes_consolidated_artifacts(output_dir):
    """With min_confidence lowered, every IOC type produces CSV + JSON."""
    result = _run(BASE_DIR / "config" / "sources.yaml", output_dir, min_confidence=0)
    names = set(result.output_files)
    assert "malicious_ips.csv" in names
    assert "malicious_asns.csv" in names
    assert "metadata.json" in names
    for dataset in ALL_DATASETS:
        assert (output_dir / f"{dataset}.csv").exists()
        assert (output_dir / f"{dataset}.json").exists()
    assert (output_dir / "metadata.json").exists()
    assert (output_dir / "state.json").exists()


def test_metadata_counts_and_version(output_dir):
    _run(BASE_DIR / "config" / "sources.yaml", output_dir, min_confidence=0)
    meta = json.loads((output_dir / "metadata.json").read_text())
    assert meta["version"] == "2026.11.23.1200"
    assert set(SOURCE_IDS) <= set(meta["sources"])
    for dataset in ALL_DATASETS:
        assert meta["ioc_counts"][dataset] > 0, dataset
    assert meta["empty_datasets"] == []


def test_metadata_reports_per_feed_status(output_dir):
    _run(BASE_DIR / "config" / "sources.yaml", output_dir, min_confidence=0)
    meta = json.loads((output_dir / "metadata.json").read_text())
    spamhaus = {run["feed"]: run for run in meta["source_feeds"]["spamhaus"]}
    assert spamhaus["spamhaus_asndrop"]["status"] == "ok"
    assert spamhaus["spamhaus_asndrop"]["rows"] == 3
    assert spamhaus["spamhaus_asndrop"]["types"] == {"asn": 3}


def test_private_ips_never_exported(output_dir):
    # The abuseipdb fixture includes 10.1.1.1 (private) which the global safety
    # net must drop despite the source config lacking a drop_private op.
    _run(BASE_DIR / "config" / "sources.yaml", output_dir, min_confidence=0)
    rows = _read_csv(output_dir / "malicious_ips.csv")
    ips = {r["ip"] for r in rows}
    assert "10.1.1.1" not in ips
    for r in rows:
        assert 0 <= int(r["confidence_score"]) <= 100


def test_otx_confidence_capped_and_multi_type(output_dir):
    _run(BASE_DIR / "config" / "sources.yaml", output_dir, min_confidence=0)
    rows = _read_csv(output_dir / "malicious_ips.csv")
    otx_only = [r for r in rows if r["ip"] == "168.121.0.3"]
    assert otx_only and int(otx_only[0]["confidence_score"]) <= 55
    # Domains and hashes are distinct datasets.
    domains = _read_csv(output_dir / "malicious_domains.csv")
    assert any(r["domain"] == "evil.example.org" for r in domains)
    # URLs land in their own dataset, not in the IP dataset.
    all_ips = "\n".join(r["ip"] for r in rows)
    assert "evil.example.org" not in all_ips
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


def test_default_threshold_prunes_single_source_rows(output_dir):
    """min_confidence: 75 keeps only corroborated or authoritative rows."""
    _run(BASE_DIR / "config" / "sources.yaml", output_dir)
    ips = _read_csv(output_dir / "malicious_ips.csv")
    ip_values = {r["ip"] for r in ips}
    # OTX + CINS corroboration survives; an Abuse.ch-only IP does not.
    assert "222.186.0.9" in ip_values
    assert "185.220.101.0" not in ip_values
    for row in ips:
        assert int(row["confidence_score"]) >= 75

    domains = {r["domain"] for r in _read_csv(output_dir / "malicious_domains.csv")}
    assert "evil.example.org" in domains  # OTX + joewein
    assert "maltracker.net" not in domains  # OTX only

    urls = {r["url"] for r in _read_csv(output_dir / "malicious_urls.csv")}
    assert "https://evil.example.org/download" in urls  # OTX + OpenPhish

    # Spamhaus DROP networks are authoritative single-source rows.
    networks = {r["network"] for r in _read_csv(output_dir / "malicious_networks.csv")}
    assert "46.36.200.0/24" in networks


def test_malicious_asns_is_authoritative_only(output_dir):
    """malicious_asns comes from Spamhaus ASN-DROP, never from flagged IPs."""
    _run(BASE_DIR / "config" / "sources.yaml", output_dir)
    meta = json.loads((output_dir / "metadata.json").read_text())
    assert meta["ioc_counts"]["malicious_asns"] == 3

    header = _header(output_dir / "malicious_asns.csv")
    assert "malicious_ip_count" not in header
    assert header[:3] == ["asn", "asn_name", "country"]

    rows = _read_csv(output_dir / "malicious_asns.csv")
    assert {r["asn"] for r in rows} == {"211468", "37631", "60971"}
    by_asn = {r["asn"]: r for r in rows}
    assert by_asn["211468"]["asn_name"] == "AS211468-MALIWARE"
    assert by_asn["211468"]["country"] == "DE"

    # The flagged IP 222.186.0.9 belongs to ASN 56046, which is NOT in
    # ASN-DROP: it must not produce an ASN row, but its ASN context is kept.
    assert "56046" not in by_asn
    ips = _read_csv(output_dir / "malicious_ips.csv")
    row = next(r for r in ips if r["ip"] == "222.186.0.9")
    assert row["asn"] == "56046"
    assert row["asn_name"].startswith("CMNET")


def test_asn_carryover_keeps_identity_and_numeric_json(tmp_path):
    """ASN-DROP outage: carried ASN rows keep name/country and numeric JSON."""
    out1 = tmp_path / "out1"
    _run(BASE_DIR / "config" / "sources.yaml", out1)

    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    for fixture in FIXTURE_FILES:
        if fixture == "spamhaus_asndrop":
            continue
        (fixtures / fixture).write_bytes((FIXTURES / fixture).read_bytes())

    out2 = tmp_path / "out2"
    _run(BASE_DIR / "config" / "sources.yaml", out2, state_path=out1 / "state.json",
         offline_dir=fixtures)

    meta = json.loads((out2 / "metadata.json").read_text())
    feeds = {run["feed"]: run for run in meta["source_feeds"]["spamhaus"]}
    assert feeds["spamhaus_asndrop"]["status"] == "failed"
    assert meta["source_status"]["spamhaus"] == "ok"

    rows = _read_csv(out2 / "malicious_asns.csv")
    by_asn = {r["asn"]: r for r in rows}
    assert by_asn["211468"]["asn_name"] == "AS211468-MALIWARE"
    assert by_asn["211468"]["country"] == "DE"

    records = json.loads((out2 / "malicious_asns.json").read_text())
    assert records and all(isinstance(r["asn"], int) for r in records)


def test_allowlist_suppresses_legitimate_domains(output_dir):
    """alphaMountain top1M is an allowlist: matching domains are discarded."""
    _run(BASE_DIR / "config" / "sources.yaml", output_dir, min_confidence=0)
    meta = json.loads((output_dir / "metadata.json").read_text())
    feeds = {run["feed"]: run for run in meta["source_feeds"]["alphamountain"]}
    assert feeds["alphamountain_top1m"]["status"] == "ok"
    assert feeds["alphamountain_top1m"]["rows"] == 3
    assert feeds["alphamountain_threat"]["status"] == "ok"

    domains = {r["domain"] for r in _read_csv(output_dir / "malicious_domains.csv")}
    # Allowlisted domains are suppressed, including "www." normalization.
    assert "legit.example.com" not in domains
    assert "www.legit.example.com" not in domains
    # Allowlist-only values are never exported as threat indicators.
    assert "corp.example.net" not in domains
    assert "www.legit.example.org" not in domains
    # A non-allowlisted threat domain remains.
    assert "malicious.example.com" in domains


def test_empty_datasets_are_omitted_and_reported(tmp_path):
    """OTX-only hashes are below 75; no empty lookup is published.

    TweetFeed is disabled here so hashes stay single-source (OTX only) and are
    pruned by the precision floor. Emails have their own floor and still publish.
    """
    data = safe_load((BASE_DIR / "config" / "sources.yaml").read_text())
    for source in data["sources"]:
        if source["id"] in {"tweetfeed", "botvrij"}:
            source["enabled"] = False
    config_path = tmp_path / "sources.yaml"
    config_path.write_text(safe_dump(data), encoding="utf-8")

    output_dir = tmp_path / "out"
    _run(config_path, output_dir)
    meta = json.loads((output_dir / "metadata.json").read_text())
    for dataset in ("malicious_md5", "malicious_sha256"):
        assert not (output_dir / f"{dataset}.csv").exists()
        assert not (output_dir / f"{dataset}.json").exists()
        assert meta["ioc_counts"][dataset] == 0
        assert dataset in meta["empty_datasets"]
    # Emails are published because min_confidence_by_type.email keeps them.
    assert (output_dir / "malicious_emails.csv").exists()
    assert meta["ioc_counts"]["malicious_emails"] > 0
    # Non-empty datasets are still published.
    assert (output_dir / "malicious_ips.csv").exists()
    otx = {run["feed"]: run for run in meta["source_feeds"]["alienvault_otx"]}
    assert otx["alienvault_otx"]["status"] == "ok"


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
    _run(sources_file, out, offline_dir=offline_dir, min_confidence=0)
    domains = _read_csv(out / "malicious_domains.csv")
    vals = {r["domain"] for r in domains}
    assert "evil-example.com" in vals
    added = [r for r in domains if "custom_fixture_source" in r["sources"]]
    assert added and all("malware" in r["categories"] for r in added)
