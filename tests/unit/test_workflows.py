"""GitHub Actions limits/configuration tests (tests/unit)."""
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"


def _read(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def test_build_workflow_caches_http_and_asn_data():
    text = _read("build-lookups.yaml")
    assert "actions/cache@" in text
    assert "path: cache" in text
    # Per-day key (bounded cache store), not run_id.
    assert "steps.cachekey.outputs.date" in text
    assert "run_id" not in text


def test_build_workflow_respects_free_tier_limits():
    text = _read("build-lookups.yaml")
    assert "timeout-minutes: 30" in text
    assert "retention-days: 1" in text
    assert "if-no-files-found: error" in text


def test_build_workflow_refuses_datasetless_publish():
    # Empty datasets are omitted, so a build with zero rows would still upload
    # metadata/state. The guard must fail before publish-release can replace
    # the stable `latest` URLs with 404s.
    text = _read("build-lookups.yaml")
    assert "ioc_counts" in text
    assert "refusing to publish" in text


def test_publish_workflow_has_timeout():
    assert "timeout-minutes: 10" in _read("publish-release.yaml")
