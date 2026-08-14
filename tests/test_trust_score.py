from slopguard.scoring.trust_score import RegistryTrustScorer


def mock_pypi_fetcher_non_existent(pkg: str):
    return {
        "exists": False,
        "age_days": 0.0,
        "release_count": 0,
        "maintainers": [],
        "weekly_downloads": 0
    }


def mock_pypi_fetcher_suspicious_new(pkg: str):
    return {
        "exists": True,
        "age_days": 2.0,  # Published 2 days ago
        "release_count": 1,
        "maintainers": ["unknown_user"],
        "weekly_downloads": 3
    }


def mock_pypi_fetcher_established(pkg: str):
    return {
        "exists": True,
        "age_days": 1500.0,  # Years old
        "release_count": 45,
        "maintainers": ["core_dev"],
        "weekly_downloads": 500000
    }


def test_trust_score_non_existent_package():
    scorer = RegistryTrustScorer(pypi_fetcher=mock_pypi_fetcher_non_existent)
    result = scorer.calculate_score("fake-hallucinated-package-12345", "pypi")
    assert result["risk_score"] >= 60.0
    assert any(f["factor"] == "non_existent_package" for f in result["factors"])


def test_trust_score_suspicious_new_package():
    scorer = RegistryTrustScorer(pypi_fetcher=mock_pypi_fetcher_suspicious_new)
    result = scorer.calculate_score("brand-new-package", "pypi")
    assert result["risk_score"] >= 50.0
    assert any(f["factor"] == "very_recent_creation" for f in result["factors"])


def test_trust_score_established_package():
    scorer = RegistryTrustScorer(pypi_fetcher=mock_pypi_fetcher_established)
    result = scorer.calculate_score("requests", "pypi")
    assert result["risk_score"] == 0.0
