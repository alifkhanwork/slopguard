from typing import List, Optional
from slopguard.config import SlopGuardConfig, load_config
from slopguard.detection.interface import Detector, DetectionResult, DetectionSignal
from slopguard.detection.conflation import NameConflationDetector
from slopguard.detection.cross_registry import CrossRegistryDetector
from slopguard.detection.novelty import NoveltyDetector
from slopguard.scoring.trust_score import RegistryTrustScorer
from slopguard.intel.feed_sync import check_malicious_feed


class DetectionEngine:
    """
    Main detection engine combining heuristic detectors, registry trust scoring,
    and threat intel feeds into a composite risk score.
    """

    def __init__(self, detectors: Optional[List[Detector]] = None, trust_scorer: Optional[RegistryTrustScorer] = None):
        self.detectors: List[Detector] = detectors if detectors is not None else [
            NameConflationDetector(),
            CrossRegistryDetector(),
            NoveltyDetector()
        ]
        self.trust_scorer = trust_scorer if trust_scorer is not None else RegistryTrustScorer()

    def analyze_package(self, package_name: str, ecosystem: str = "npm", config: Optional[SlopGuardConfig] = None) -> DetectionResult:
        if config is None:
            config = load_config()

        norm_name = package_name.lower().strip()

        # Check Allowlist
        if norm_name in [p.lower() for p in config.allowlist]:
            return DetectionResult(
                package_name=package_name,
                ecosystem=ecosystem,
                is_suspicious=False,
                risk_score=0.0,
                signals=[DetectionSignal(
                    detector_id="allowlist",
                    name="Allowlist Match",
                    severity="LOW",
                    score_impact=0.0,
                    description=f"Package '{package_name}' is explicitly allowlisted."
                )]
            )

        result = DetectionResult(
            package_name=package_name,
            ecosystem=ecosystem,
            is_suspicious=False,
            risk_score=0.0
        )

        # 1. Threat Intel Feed Check (Critical priority)
        feed_hit = check_malicious_feed(package_name, ecosystem, config)
        if feed_hit:
            result.add_signal(DetectionSignal(
                detector_id="threat_intel_feed",
                name="Known Malicious Package Feed Match",
                severity="CRITICAL",
                score_impact=100.0,
                description=f"Package '{package_name}' matched known malware database ({feed_hit.get('id')}): {feed_hit.get('summary')}",
                details=feed_hit
            ))
            return result

        # 2. Registry Trust Scoring
        trust_data = self.trust_scorer.calculate_score(package_name, ecosystem)
        trust_score = trust_data.get("risk_score", 0.0)
        metadata = trust_data.get("metadata", {})

        if trust_score > 0:
            result.risk_score = min(100.0, result.risk_score + trust_score * 0.5)
            for factor in trust_data.get("factors", []):
                result.signals.append(DetectionSignal(
                    detector_id="trust_score_factor",
                    name=factor["factor"],
                    severity="MEDIUM" if factor["impact"] < 30 else "HIGH",
                    score_impact=factor["impact"] * 0.5,
                    description=factor["description"]
                ))

        # 3. Run Registered Heuristic Detectors
        for detector in self.detectors:
            if isinstance(detector, NoveltyDetector):
                sig = detector.detect_with_metadata(package_name, ecosystem, metadata, config)
            else:
                sig = detector.detect(package_name, ecosystem, config)

            if sig:
                result.add_signal(sig)

        result.risk_score = min(100.0, result.risk_score)
        if result.risk_score >= config.warn_threshold:
            result.is_suspicious = True

        return result
