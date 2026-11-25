"""Allowlist matching tests (tests/unit)."""
from cs_lookup_files.pipeline import Pipeline


def test_domain_allowlist_matches_exact_and_www():
    allow = {"legit.example.com"}
    assert Pipeline._is_allowlisted("legit.example.com", "domain", allow)
    assert Pipeline._is_allowlisted("www.legit.example.com", "domain", allow)
    assert not Pipeline._is_allowlisted("evil.example.com", "domain", allow)
    # Exact hostname matching only: subdomains are not blanket-suppressed.
    assert not Pipeline._is_allowlisted("sub.legit.example.com", "domain", allow)


def test_url_allowlist_extracts_hostname():
    allow = {"legit.example.com"}
    assert Pipeline._is_allowlisted("https://www.legit.example.com/path", "url", allow)
    assert Pipeline._is_allowlisted("https://legit.example.com/path?q=1", "url", allow)
    assert not Pipeline._is_allowlisted("https://evil.example.com/path", "url", allow)
    assert not Pipeline._is_allowlisted("https://legit.example.com.evil.com/path", "url", allow)


def test_non_domain_types_are_not_allowlisted():
    assert not Pipeline._is_allowlisted("8.8.8.8", "ip", {"legit.example.com"})
