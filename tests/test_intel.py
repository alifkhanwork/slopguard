from slopguard.config import SlopGuardConfig
from slopguard.intel.feed_sync import sync_intel_feed, check_malicious_feed, save_cached_intel, load_cached_intel


def test_intel_feed_sync_and_cache(tmp_path, monkeypatch):
    test_cache = tmp_path / "test_intel_cache.json"
    monkeypatch.setattr("slopguard.intel.feed_sync.get_cache_file_path", lambda: test_cache)

    config = SlopGuardConfig(feed_cache_ttl_hours=24)
    success = sync_intel_feed(config, force=True)
    assert success is True
    assert test_cache.exists()

    # Pre-populate cache with a mock malware entry
    cache_data = {
        "last_updated": 1000000,
        "malicious_packages": {
            "npm:slop-malware-test": {
                "id": "MAL-2025-0001",
                "summary": "Mock malicious slopsquatting package"
            }
        }
    }
    save_cached_intel(cache_data)

    hit = check_malicious_feed("slop-malware-test", "npm", config)
    assert hit is not None
    assert hit["id"] == "MAL-2025-0001"
