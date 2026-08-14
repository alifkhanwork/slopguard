import re
from typing import Optional, List, Tuple
from slopguard.config import SlopGuardConfig
from slopguard.detection.interface import Detector, DetectionSignal
from slopguard.detection.popular_packages import get_popular_packages


class NameConflationDetector(Detector):
    id = "name_conflation"
    name = "Name Conflation Detector"
    description = "Detects package names that appear to be hallucinated blends of two popular package names."

    def _tokenize(self, name: str) -> List[str]:
        # Split by dash, underscore, dot, or transition between lower and upper
        tokens = re.split(r'[-_.]', name)
        result = []
        for t in tokens:
            # Handle camelCase
            camel_tokens = re.findall(r'[a-zA-Z][a-z0-9]*', t)
            result.extend([c.lower() for c in camel_tokens if len(c) > 1])
        return result

    def detect(self, package_name: str, ecosystem: str, config: SlopGuardConfig) -> Optional[DetectionSignal]:
        norm_name = package_name.lower().strip()
        popular_set = get_popular_packages(ecosystem)

        # If it is an exact match for a known popular package, it is not a conflation hallucination
        if norm_name in popular_set:
            return None

        tokens = self._tokenize(norm_name)
        if len(tokens) < 2:
            # Single word package name - check substring blend against popular package words
            for pop1 in popular_set:
                for pop2 in popular_set:
                    if pop1 == pop2 or len(pop1) < 4 or len(pop2) < 4:
                        continue
                    if pop1 in norm_name and pop2 in norm_name and norm_name not in (pop1, pop2):
                        return DetectionSignal(
                            detector_id=self.id,
                            name=self.name,
                            severity="MEDIUM",
                            score_impact=30.0,
                            description=f"Package name '{package_name}' blends keywords from '{pop1}' and '{pop2}'.",
                            details={"parent_packages": [pop1, pop2], "match_type": "substring_blend"}
                        )
            return None

        # Multi-token package name (e.g. react-codeshift, fastapi-pydantic)
        matched_popular: List[Tuple[str, str]] = []  # (token, popular_pkg_name)

        for token in tokens:
            if len(token) < 3:
                continue
            for pop_pkg in popular_set:
                pop_tokens = self._tokenize(pop_pkg)
                if token in pop_tokens or token in pop_pkg:
                    matched_popular.append((token, pop_pkg))
                    break

        # Check if matched tokens come from at least 2 distinct popular packages
        distinct_parents = set(pkg for _, pkg in matched_popular)
        if len(distinct_parents) >= 2:
            parents_list = list(distinct_parents)[:3]
            return DetectionSignal(
                detector_id=self.id,
                name=self.name,
                severity="MEDIUM",
                score_impact=35.0,
                description=f"Package name '{package_name}' appears to conflate terms from popular packages: {', '.join(parents_list)}.",
                details={"conflated_parents": parents_list, "tokens": tokens}
            )

        return None
