# Contributing to SlopGuard

Thank you for contributing to SlopGuard! SlopGuard uses a modular, extensible architecture (matching the `Detector` design in `agent-leak-guard`) to allow adding new detectors and extending registry trust scoring easily.

---

## Codebase Architecture

```
slopguard/
├── detection/
│   ├── interface.py           # Extensible Detector base class & DetectionSignal
│   ├── conflation.py          # Name conflation detector
│   ├── cross_registry.py      # Cross-registry confusion detector
│   ├── novelty.py             # Novelty / zero-history detector
│   └── popular_packages.py    # Curated popular package lists
├── scoring/
│   └── trust_score.py         # Registry API fetcher & composite risk scorer
├── intel/
│   └── feed_sync.py           # OpenSSF / OSV threat feed sync & offline cache
├── interceptor/
│   └── shell_hook.py          # Command parser & TTY/CI enforcement
├── config.py                  # Settings loader (.slopguard.json)
└── cli.py                     # Click CLI entrypoints

packages/ts-bindings/          # @svgph/slopguard TS bindings & agent_permit.ts
```

---

## Adding a New Detector

To add a new detector heuristic:

1. Create a new file in `slopguard/detection/` (e.g. `slopguard/detection/my_custom_detector.py`).
2. Subclass `Detector` from `slopguard.detection.interface`:

```python
from typing import Optional
from slopguard.config import SlopGuardConfig
from slopguard.detection.interface import Detector, DetectionSignal

class MyCustomDetector(Detector):
    id = "my_custom_detector"
    name = "My Custom Detector"
    description = "Detects specific suspicious pattern XYZ."

    def detect(self, package_name: str, ecosystem: str, config: SlopGuardConfig) -> Optional[DetectionSignal]:
        if "suspicious_keyword" in package_name.lower():
            return DetectionSignal(
                detector_id=self.id,
                name=self.name,
                severity="MEDIUM",
                score_impact=25.0,
                description=f"Package '{package_name}' matches suspicious pattern XYZ."
            )
        return None
```

3. Register your detector in `slopguard/detection/engine.py`:

```python
from slopguard.detection.my_custom_detector import MyCustomDetector

# Add to default detectors list in DetectionEngine.__init__
```

4. Add unit tests in `tests/test_my_custom_detector.py`.

---

## Extending the Registry Trust Scorer

`slopguard/scoring/trust_score.py` contains registry fetchers (`fetch_pypi_metadata` and `fetch_npm_metadata`) and the `RegistryTrustScorer` class.

To add new risk factors (e.g. author email domain reputation, missing repository URL):
1. Extract the field inside `fetch_pypi_metadata` or `fetch_npm_metadata`.
2. Add a scoring rule in `RegistryTrustScorer.calculate_score`:

```python
if metadata.get("repository_missing"):
    risk_score += 10.0
    factors.append({
        "factor": "missing_repository_url",
        "impact": 10.0,
        "description": "Package metadata lacks a public repository URL."
    })
```

---

## Running Tests

### Python Core (`pytest`)
```bash
pip install -e .[dev]
pytest
```

### TypeScript Bindings (`vitest`)
```bash
cd packages/ts-bindings
npm install
npm test
npm run build
```
