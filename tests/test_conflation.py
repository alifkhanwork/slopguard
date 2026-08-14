from slopguard.config import SlopGuardConfig
from slopguard.detection.conflation import NameConflationDetector


def test_react_codeshift_conflation_detected():
    detector = NameConflationDetector()
    config = SlopGuardConfig()
    # react-codeshift is a known hallucinated blend of react-codemod + jscodeshift
    signal = detector.detect("react-codeshift", "npm", config)
    assert signal is not None
    assert signal.detector_id == "name_conflation"
    assert signal.score_impact >= 30.0
    assert "conflate" in signal.description.lower() or "blend" in signal.description.lower()


def test_fastapi_pydantic_conflation_detected():
    detector = NameConflationDetector()
    config = SlopGuardConfig()
    # fastapi-pydantic is a blend of popular PyPI packages fastapi + pydantic
    signal = detector.detect("fastapi-pydantic", "pypi", config)
    assert signal is not None
    assert signal.detector_id == "name_conflation"


def test_popular_package_not_flagged_as_conflation():
    detector = NameConflationDetector()
    config = SlopGuardConfig()
    # express, react, requests are legitimate popular packages
    assert detector.detect("express", "npm", config) is None
    assert detector.detect("react", "npm", config) is None
    assert detector.detect("requests", "pypi", config) is None
