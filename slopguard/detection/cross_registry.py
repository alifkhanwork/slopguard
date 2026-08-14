import requests
from typing import Optional, Callable
from slopguard.config import SlopGuardConfig
from slopguard.detection.interface import Detector, DetectionSignal


def default_check_pypi_exists(package_name: str) -> bool:
    try:
        resp = requests.head(f"https://pypi.org/pypi/{package_name}/json", timeout=3.0)
        return resp.status_code == 200
    except Exception:
        return False


def default_check_npm_exists(package_name: str) -> bool:
    try:
        resp = requests.head(f"https://registry.npmjs.org/{package_name}", timeout=3.0)
        return resp.status_code == 200
    except Exception:
        return False


class CrossRegistryDetector(Detector):
    id = "cross_registry_confusion"
    name = "Cross-Registry Confusion Detector"
    description = "Detects package names that exist on a different registry (npm vs PyPI) but not on the target registry."

    def __init__(
        self,
        pypi_checker: Callable[[str], bool] = default_check_pypi_exists,
        npm_checker: Callable[[str], bool] = default_check_npm_exists
    ):
        self.pypi_checker = pypi_checker
        self.npm_checker = npm_checker

    def detect(self, package_name: str, ecosystem: str, config: SlopGuardConfig) -> Optional[DetectionSignal]:
        eco = ecosystem.lower()

        if eco in ("npm", "node"):
            target_exists = self.npm_checker(package_name)
            if target_exists:
                return None  # Package exists on npm, no mismatch
            other_exists = self.pypi_checker(package_name)
            if other_exists:
                return DetectionSignal(
                    detector_id=self.id,
                    name=self.name,
                    severity="HIGH",
                    score_impact=40.0,
                    description=f"Package '{package_name}' exists on PyPI but does NOT exist on npm. Potential cross-registry confusion.",
                    details={"target_ecosystem": "npm", "other_ecosystem": "PyPI"}
                )

        elif eco in ("pypi", "python"):
            target_exists = self.pypi_checker(package_name)
            if target_exists:
                return None  # Package exists on PyPI, no mismatch
            other_exists = self.npm_checker(package_name)
            if other_exists:
                return DetectionSignal(
                    detector_id=self.id,
                    name=self.name,
                    severity="HIGH",
                    score_impact=40.0,
                    description=f"Package '{package_name}' exists on npm but does NOT exist on PyPI. Potential cross-registry confusion.",
                    details={"target_ecosystem": "PyPI", "other_ecosystem": "npm"}
                )

        return None
