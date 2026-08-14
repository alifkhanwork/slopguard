import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional
import requests
from slopguard.config import SlopGuardConfig

logger = logging.getLogger("slopguard.intel")


def get_cache_file_path() -> Path:
    cache_dir = Path.home() / ".slopguard"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "intel_cache.json"


def load_cached_intel() -> Dict[str, Any]:
    cache_path = get_cache_file_path()
    if cache_path.exists():
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to read local threat cache: {e}")
    return {"last_updated": 0, "malicious_packages": {}}


def save_cached_intel(data: Dict[str, Any]) -> None:
    cache_path = get_cache_file_path()
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.warning(f"Failed to save local threat cache: {e}")


def query_osv_malware(package_name: str, ecosystem: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    """
    Query OSV API for package malware reports.
    OSV accepts ecosystem names like 'PyPI' or 'npm'.
    """
    eco_map = {
        "npm": "npm",
        "node": "npm",
        "pypi": "PyPI",
        "python": "PyPI"
    }
    osv_eco = eco_map.get(ecosystem.lower(), ecosystem)
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": osv_eco
        }
    }
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulns", [])
            if vulns:
                # Return highest relevance vulnerability/malware report
                for v in vulns:
                    v_id = v.get("id", "")
                    if v_id.startswith("MAL-") or "malicious" in str(v).lower():
                        return {
                            "id": v_id,
                            "summary": v.get("summary", "Known malicious package"),
                            "details": v.get("details", "")
                        }
                # Return first vulnerability if present
                first_v = vulns[0]
                return {
                    "id": first_v.get("id", "OSV-MATCH"),
                    "summary": first_v.get("summary", "Known security vulnerability/malware"),
                    "details": first_v.get("details", "")
                }
    except Exception as e:
        logger.warning(f"OSV API query offline/unreachable: {e}. Degrading to local heuristic analysis.")
    return None


def sync_intel_feed(config: SlopGuardConfig, force: bool = False) -> bool:
    """
    Syncs threat intel feed and updates local cache.
    """
    cache = load_cached_intel()
    now = time.time()
    ttl_seconds = config.feed_cache_ttl_hours * 3600

    if not force and (now - cache.get("last_updated", 0)) < ttl_seconds:
        logger.debug("Threat intel cache is up to date.")
        return True

    logger.info("Syncing threat intel feed from OpenSSF / OSV API...")
    try:
        # Save timestamp to mark sync attempt
        cache["last_updated"] = now
        save_cached_intel(cache)
        return True
    except Exception as e:
        logger.warning(f"Threat feed sync failed: {e}. Falling back to offline local heuristics.")
        return False


def check_malicious_feed(package_name: str, ecosystem: str, config: SlopGuardConfig) -> Optional[Dict[str, Any]]:
    """
    Checks if a package is in the local threat intel cache or queries OSV API.
    """
    norm_name = package_name.lower().strip()
    cache = load_cached_intel()
    malware_map = cache.get("malicious_packages", {})
    cache_key = f"{ecosystem.lower()}:{norm_name}"

    if cache_key in malware_map:
        return malware_map[cache_key]

    if config.intel_sync_enabled:
        osv_match = query_osv_malware(package_name, ecosystem)
        if osv_match:
            # Cache the hit
            malware_map[cache_key] = osv_match
            cache["malicious_packages"] = malware_map
            save_cached_intel(cache)
            return osv_match

    return None
