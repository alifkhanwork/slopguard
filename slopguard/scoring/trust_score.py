from datetime import datetime, timezone
from typing import Dict, Any, Optional, Callable
import requests


def parse_iso_datetime(dt_str: str) -> Optional[datetime]:
    if not dt_str:
        return None
    try:
        # Handle trailing Z
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1] + "+00:00"
        return datetime.fromisoformat(dt_str)
    except Exception:
        return None


def fetch_pypi_metadata(package_name: str, timeout: float = 3.0) -> Dict[str, Any]:
    url = f"https://pypi.org/pypi/{package_name}/json"
    result = {
        "exists": False,
        "age_days": 0.0,
        "release_count": 0,
        "maintainers": [],
        "weekly_downloads": 0,
        "first_published": None,
        "latest_version": None,
        "error": None
    }
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 404:
            return result
        if resp.status_code != 200:
            result["error"] = f"PyPI API returned status {resp.status_code}"
            return result

        data = resp.json()
        result["exists"] = True
        info = data.get("info", {})
        result["latest_version"] = info.get("version")
        
        # Collect maintainers
        author = info.get("author") or info.get("maintainer")
        if author:
            result["maintainers"].append(author)

        # Calculate package age from earliest release
        releases = data.get("releases", {})
        result["release_count"] = len(releases)
        earliest_dt: Optional[datetime] = None

        for ver, files in releases.items():
            for f in files:
                upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                if upload_time:
                    dt = parse_iso_datetime(upload_time)
                    if dt and (earliest_dt is None or dt < earliest_dt):
                        earliest_dt = dt

        if earliest_dt:
            now = datetime.now(timezone.utc)
            if earliest_dt.tzinfo is None:
                earliest_dt = earliest_dt.replace(tzinfo=timezone.utc)
            age_days = (now - earliest_dt).total_seconds() / 86400.0
            result["age_days"] = max(0.0, age_days)
            result["first_published"] = earliest_dt.isoformat()

        # Fetch download stats from pypistats
        try:
            stats_resp = requests.get(f"https://pypistats.org/api/packages/{package_name}/recent", timeout=2.0)
            if stats_resp.status_code == 200:
                stats_data = stats_resp.json()
                result["weekly_downloads"] = stats_data.get("data", {}).get("last_week", 0)
        except Exception:
            pass

    except Exception as e:
        result["error"] = str(e)

    return result


def fetch_npm_metadata(package_name: str, timeout: float = 3.0) -> Dict[str, Any]:
    url = f"https://registry.npmjs.org/{package_name}"
    result = {
        "exists": False,
        "age_days": 0.0,
        "release_count": 0,
        "maintainers": [],
        "weekly_downloads": 0,
        "first_published": None,
        "latest_version": None,
        "error": None
    }
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 404:
            return result
        if resp.status_code != 200:
            result["error"] = f"npm API returned status {resp.status_code}"
            return result

        data = resp.json()
        result["exists"] = True
        
        # Maintainers
        maintainers = data.get("maintainers", [])
        if isinstance(maintainers, list):
            result["maintainers"] = [m.get("name") if isinstance(m, dict) else str(m) for m in maintainers]

        # Version count
        versions = data.get("versions", {})
        result["release_count"] = len(versions)
        dist_tags = data.get("dist-tags", {})
        result["latest_version"] = dist_tags.get("latest")

        # Age calculation from 'time'
        time_data = data.get("time", {})
        created_str = time_data.get("created")
        if created_str:
            created_dt = parse_iso_datetime(created_str)
            if created_dt:
                now = datetime.now(timezone.utc)
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                result["age_days"] = max(0.0, (now - created_dt).total_seconds() / 86400.0)
                result["first_published"] = created_dt.isoformat()

        # Fetch npm downloads
        try:
            dl_resp = requests.get(f"https://api.npmjs.org/downloads/point/last-week/{package_name}", timeout=2.0)
            if dl_resp.status_code == 200:
                dl_data = dl_resp.json()
                result["weekly_downloads"] = dl_data.get("downloads", 0)
        except Exception:
            pass

    except Exception as e:
        result["error"] = str(e)

    return result


class RegistryTrustScorer:
    """
    Computes a 0-100 composite risk score based on registry metadata.
    0 = Highly trusted, 100 = Maximum risk.
    """

    def __init__(
        self,
        pypi_fetcher: Callable[[str], Dict[str, Any]] = fetch_pypi_metadata,
        npm_fetcher: Callable[[str], Dict[str, Any]] = fetch_npm_metadata
    ):
        self.pypi_fetcher = pypi_fetcher
        self.npm_fetcher = npm_fetcher

    def get_metadata(self, package_name: str, ecosystem: str) -> Dict[str, Any]:
        eco = ecosystem.lower()
        if eco in ("pypi", "python"):
            return self.pypi_fetcher(package_name)
        elif eco in ("npm", "node", "typescript", "javascript"):
            return self.npm_fetcher(package_name)
        else:
            return self.npm_fetcher(package_name)

    def calculate_score(self, package_name: str, ecosystem: str) -> Dict[str, Any]:
        metadata = self.get_metadata(package_name, ecosystem)
        risk_score = 0.0
        factors = []

        if not metadata.get("exists"):
            risk_score += 65.0
            factors.append({
                "factor": "non_existent_package",
                "impact": 65.0,
                "description": f"Package '{package_name}' does not exist on {ecosystem} registry."
            })
            return {
                "risk_score": min(100.0, risk_score),
                "metadata": metadata,
                "factors": factors
            }

        age_days = metadata.get("age_days", 999.0)
        weekly_dl = metadata.get("weekly_downloads", 0)
        release_count = metadata.get("release_count", 99)

        # Age scoring
        if age_days < 7.0:
            risk_score += 35.0
            factors.append({"factor": "very_recent_creation", "impact": 35.0, "description": f"Published <7 days ago ({age_days:.1f} days)"})
        elif age_days < 30.0:
            risk_score += 20.0
            factors.append({"factor": "recent_creation", "impact": 20.0, "description": f"Published <30 days ago ({age_days:.1f} days)"})
        elif age_days < 90.0:
            risk_score += 10.0
            factors.append({"factor": "relatively_new", "impact": 10.0, "description": f"Published <90 days ago ({age_days:.1f} days)"})

        # Download velocity scoring
        if weekly_dl < 10:
            risk_score += 15.0
            factors.append({"factor": "negligible_downloads", "impact": 15.0, "description": f"Only {weekly_dl} weekly downloads"})
        elif weekly_dl < 200:
            risk_score += 5.0
            factors.append({"factor": "low_downloads", "impact": 5.0, "description": f"Low download count ({weekly_dl}/week)"})

        # Single release / minimal history
        if release_count == 1:
            risk_score += 10.0
            factors.append({"factor": "single_release", "impact": 10.0, "description": "Only 1 release published"})

        return {
            "risk_score": min(100.0, risk_score),
            "metadata": metadata,
            "factors": factors
        }
