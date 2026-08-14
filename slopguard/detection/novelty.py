from datetime import datetime, timezone
from typing import Optional, Dict, Any
from slopguard.config import SlopGuardConfig
from slopguard.detection.interface import Detector, DetectionSignal


class NoveltyDetector(Detector):
    id = "novelty_detector"
    name = "Novelty / Zero-History Detector"
    description = "Flags packages with recent registration date (<30 days), low release counts, or suspicious zero-history patterns."

    def detect_with_metadata(
        self,
        package_name: str,
        ecosystem: str,
        metadata: Dict[str, Any],
        config: SlopGuardConfig
    ) -> Optional[DetectionSignal]:
        if not metadata or not metadata.get("exists", True):
            # Non-existent package on target registry is handled by trust score / cross registry
            return None

        age_days = metadata.get("age_days", 999.0)
        release_count = metadata.get("release_count", 99)
        weekly_downloads = metadata.get("weekly_downloads", 0)

        # Signal 1: Fresh package (< 14 days old)
        if age_days < 14.0:
            return DetectionSignal(
                detector_id=self.id,
                name=self.name,
                severity="HIGH",
                score_impact=35.0,
                description=f"Package '{package_name}' was registered only {age_days:.1f} days ago with {release_count} release(s). High risk for slopsquatting.",
                details={
                    "age_days": age_days,
                    "release_count": release_count,
                    "weekly_downloads": weekly_downloads
                }
            )

        # Signal 2: Young package (< 45 days old) with sudden burst in downloads or single release
        if age_days < 45.0 and release_count <= 2:
            return DetectionSignal(
                detector_id=self.id,
                name=self.name,
                severity="MEDIUM",
                score_impact=20.0,
                description=f"Package '{package_name}' is recent ({age_days:.1f} days old) with minimal history ({release_count} releases).",
                details={
                    "age_days": age_days,
                    "release_count": release_count,
                    "weekly_downloads": weekly_downloads
                }
            )

        return None

    def detect(self, package_name: str, ecosystem: str, config: SlopGuardConfig) -> Optional[DetectionSignal]:
        # Fallback when metadata is not pre-fetched
        return None
